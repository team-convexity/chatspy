import os
import jwt

from django.apps import apps
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
            payload = jwt.decode(
                jwt=token,
                algorithms=["RS256"],
                key=Secret.get_service_key(service=Service.AUTH)
            )
            user_id = payload.get("sub")
            if user_id is not None:
                # if we are in auth service, user is the real django User model.
                if 'authy' not in os.getenv("DJANGO_SETTINGS_MODULE", ""):
                    UserProfile = apps.get_model("core.UserProfile", require_ready=False)
                    user = UserProfile.objects.get(auth_user_id=ChatsRecord.from_global_id(user_id)[1])
                else:
                    User = apps.get_model("core.User", require_ready=False)
                    user = User.objects.get(id=ChatsRecord.from_global_id(user_id)[1])

                logger.i(f"Successfully authenticated {user}")
                return True, user
            
            return False, ({"success": False, "data": "User does not exists"}, 401)
        except jwt.DecodeError as e:
            logger.e(f"Cannot decode JWT token ({token}): {e}", service=Service.AUTH.value, description=f"Invalid Token: {token}")
            return False, ({"success": False, "error": {"message": "Invalid Token"}}, 401)
        
        except jwt.ExpiredSignatureError as e:
            return False, ({"success": False, "error": {"message": "Token has expired"}}, 401)
        
        except ObjectDoesNotExist as e:
            logger.e(f"Auth UserProfile not found: {e}", service=Service.AUTH.value, description=f"Profile not found: {token}")
            return False, ({"success": False, "error": {"message": "Invalid Token"}}, 401)
        
        except Exception as e:
            logger.e(f"[AuthenticationMiddleware]: {e}", service=Service.AUTH.value, description=f"An error occured: {token}")
            return False, ({"success": False, "error": {"message": "An error occured"}}, 500)


class AuthenticationMiddleware(BaseAuthMiddleware):
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request: HttpRequest):
        authorization = request.headers.get("Authorization", None)
        if not authorization:
            response = self.get_response(request)
            return response
        
        auth_type, token = authorization.split(" ")
        if auth_type.lower() != "bearer":
            return Response("Unsupported authorization type", status=400)
        
        authenticated, user_or_error_response = self.get_user_from_token(token)
        if authenticated:
            request.user = user_or_error_response
        else:
            return Response(user_or_error_response[0], status=user_or_error_response[1])
        
        return self.get_response(request)
