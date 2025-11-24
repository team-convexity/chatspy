import os
import re
import jwt
import json
from typing import Pattern, List

from django import http
from django.apps import apps
from django.conf import settings
from django.http import HttpRequest
from ninja.responses import Response
from asgiref.sync import sync_to_async
from chatspy.models import ChatsRecord
from chatspy.secret import Secret, Service
from django.core.exceptions import ObjectDoesNotExist

from chatspy.utils import logger
from chatspy.activity import get_activity_service
from chatspy.clients import Services, KafkaEvent


class BaseAuthMiddleware:
    @sync_to_async
    def aget_user_from_token(self, token: str):
        """Async version of get_user_from_token"""
        return self.get_user_from_token(token)

    def get_user_from_token(self, token: str):
        try:
            payload = jwt.decode(jwt=token, algorithms=["RS256"], key=Secret.get_service_key(service=Service.AUTH))
            user_id = payload.get("sub")
            if user_id is not None:
                # if we are in auth service, user is the real django User model.
                if "authy" not in os.getenv("DJANGO_SETTINGS_MODULE", ""):
                    UserProfile = apps.get_model("core.UserProfile", require_ready=False)
                    user = UserProfile.objects.get(auth_user_id=ChatsRecord.from_global_id(user_id)[1])
                else:
                    User = apps.get_model("core.User", require_ready=False)
                    user = User.objects.get(id=ChatsRecord.from_global_id(user_id)[1])

                # inject auth profile here for use in views
                setattr(user, "auth_profile", payload.get("profile", {}))

                logger.i(f"Successfully authenticated {user}")
                return True, user

            return False, ({"success": False, "data": "User does not exists"}, 499)
        except jwt.DecodeError as e:
            logger.e(
                f"Cannot decode JWT token ({token}): {e}",
                service=Service.AUTH.value,
                description=f"Invalid Token: {token}",
            )
            return False, ({"success": False, "error": {"message": "Invalid Token"}}, 499)

        except jwt.ExpiredSignatureError as e:
            return False, ({"success": False, "error": {"message": "Token has expired"}}, 499)

        except ObjectDoesNotExist as e:
            logger.e(
                f"Auth UserProfile not found: {e}",
                service=Service.AUTH.value,
                description=f"Profile not found: {token}",
            )
            return False, ({"success": False, "error": {"message": "Invalid Token"}}, 499)

        except Exception as e:
            logger.e(
                f"[AuthenticationMiddleware]: {e}", service=Service.AUTH.value, description=f"An error occured: {token}"
            )
            return False, ({"success": False, "error": {"message": "An error occured"}}, 500)


class AuthenticationMiddleware(BaseAuthMiddleware):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        authorization = request.headers.get("Authorization", None)
        if not authorization:
            return self.get_response(request)

        try:
            auth_type, token = authorization.split(" ")
        except ValueError:
            return Response({"success": False, "error": {"message": "Invalid authorization header"}}, status=499)

        if auth_type.lower() != "bearer":
            return Response({"success": False, "error": {"message": "Invalid authorization type"}}, status=499)

        authenticated, user_or_error_response = self.get_user_from_token(token)
        if authenticated:
            request.user = user_or_error_response
        else:
            return Response(user_or_error_response[0], status=user_or_error_response[1])

        return self.get_response(request)


class CorsMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.origin_regexes: List[Pattern] = [
            re.compile(pattern) for pattern in getattr(settings, "CORS_ALLOWED_ORIGIN_REGEXES", [])
        ]

    def _is_origin_allowed(self, origin: str) -> bool:
        return any(pattern.match(origin) for pattern in self.origin_regexes)

    def __call__(self, request):
        response = (
            http.HttpResponse(headers={"Content-Length": "0"})
            if request.method == "OPTIONS" and "Access-Control-Request-Method" in request.headers
            else self.get_response(request)
        )

        origin = request.headers.get("Origin")
        if origin and self._is_origin_allowed(origin):
            response["Access-Control-Allow-Origin"] = origin
            response["Access-Control-Allow-Methods"] = "DELETE, GET, OPTIONS, PATCH, POST, PUT"
            response["Access-Control-Allow-Headers"] = (
                "accept, accept-encoding, authorization, content-type, dnt, origin, user-agent, x-csrftoken, x-requested-with"
            )
            response["Vary"] = "Origin"

        return response


class ActivityTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        try:
            self.activity_service = get_activity_service()
        except Exception as e:
            logger.e("Failed to initialize activity service", description=str(e))
            self.activity_service = None

    def __call__(self, request: HttpRequest):
        response = self.get_response(request)

        if not self.activity_service:
            return response

        try:
            if not self._should_track_request(request, response):
                return response
        except Exception as e:
            logger.w("Error in _should_track_request check", description=str(e))
            return response

        try:
            self._track_activity(request, response)
        except Exception as e:
            logger.e("Failed to track activity", description=str(e))

        return response

    def _should_track_request(self, request: HttpRequest, response) -> bool:
        try:
            if request.method not in ["POST", "PUT", "PATCH", "DELETE"]:
                return False

            if not hasattr(response, "status_code") or response.status_code >= 400:
                return False

            should_track = self.activity_service.should_track_endpoint(request)
            return should_track
        except Exception as e:
            logger.w("Error checking if request should be tracked", description=str(e))
            return False

    def _track_activity(self, request: HttpRequest, response):
        try:
            response_data = self._extract_response_data(response)

            activity_data = self.activity_service.extract_activity_metadata(request, response_data)

            if not activity_data:
                return

            # Try to get user_id from request first
            user_id = None
            if hasattr(request, "user") and request.user and hasattr(request.user, "id"):
                user_id = request.user.id

            # If not on request, try to extract from response data
            if not user_id:
                user_id = self._extract_user_id_from_response(response_data)

            # Decode global ID to Django integer ID if needed
            if user_id and isinstance(user_id, str):
                try:
                    _, user_id = ChatsRecord.from_global_id(user_id)
                except Exception as e:
                    logger.w(f"Failed to decode user_id from global ID: {user_id}", description=str(e))
                    user_id = None

            self._emit_activity_event(activity_data, user_id)
        except Exception as e:
            logger.w("Error in _track_activity", description=str(e))

    def _extract_user_id_from_response(self, response_data: dict) -> int | None:
        """Extract user_id from response data for cases where user isn't authenticated on request"""
        try:
            # Common patterns for user data in responses
            data = response_data.get("data", {})

            # Direct user_id in data
            if "user_id" in data:
                return data["user_id"]

            # User object in data
            if "user" in data:
                user = data["user"]
                if isinstance(user, dict) and "id" in user:
                    return user["id"]

            # User profile with nested user
            if "user_profile" in data:
                user_profile = data["user_profile"]
                if isinstance(user_profile, dict):
                    if "user" in user_profile:
                        user = user_profile["user"]
                        if isinstance(user, dict) and "id" in user:
                            return user["id"]
                    if "user_id" in user_profile:
                        return user_profile["user_id"]

            return None
        except Exception as e:
            logger.w("Error extracting user_id from response", description=str(e))
            return None

    def _extract_response_data(self, response) -> dict:
        try:
            if not hasattr(response, "content"):
                return {}

            content = response.content
            if isinstance(content, bytes):
                content = content.decode("utf-8")

            if not content or not content.strip():
                return {}

            return json.loads(content)
        except json.JSONDecodeError as e:
            status_code = getattr(response, "status_code", "unknown")
            content_type = (
                getattr(response, "get", lambda x, default=None: None)("Content-Type")
                or getattr(response, "_headers", {}).get("content-type", ("", "unknown"))[1]
            )

            logger.w(
                "Failed to parse response content for activity tracking - invalid JSON",
                description=f"JSONDecodeError: {str(e)} | Status: {status_code} | Content-Type: {content_type} | Content preview: {content[:200] if content else 'empty'}",
            )
            return {}
        except Exception as e:
            logger.w(
                "Failed to parse response content for activity tracking - unexpected error",
                description=f"{type(e).__name__}: {str(e)} | Has content attr: {hasattr(response, 'content')} | Content type: {type(getattr(response, 'content', None))}",
            )
            return {}

    def _emit_activity_event(self, activity_data, user_id):
        try:
            activity_dict = activity_data.to_dict()
            activity_dict["user_id"] = user_id

            logger.i(f"Activity tracked: {activity_data.activity_type} for user {user_id}")

            producer = Services.get_client("producer")
            if not producer:
                logger.w("Kafka producer not available, activity not emitted to Kafka")
                return

            producer.send(
                topic=KafkaEvent.UserActivityTracked.value,
                key=user_id,
                value=activity_dict,
            )

            logger.d(f"Activity emitted to Kafka: {activity_data.activity_type}")
        except Exception as e:
            logger.w("Failed to emit activity event", description=str(e))
