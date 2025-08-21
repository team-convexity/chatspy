import os
import re
import jwt
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
