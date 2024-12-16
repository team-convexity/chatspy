import jwt
from typing import Any
from ninja.security import HttpBearer
from django.contrib.auth import get_user_model

from .secret import Secret
from chatspy.utils import logger
from .services import Service
from .clients import RedisClient


class JWTAuth(HttpBearer):
    def authenticate(self, request, token):
        User = get_user_model()
        key = Secret.get_service_key(service=Service.AUTH)
        
        try:
            payload = jwt.decode(token, key, algorithms=["RS256"])
            user_id = payload.get("sub")

            logger.e("\n\n\nHHHHHIII")
            logger.e(user_id)
            logger.e("\n\n\n")
            if user_id is not None:
                try:
                    user = User.objects.get(pk=user_id)
                    # try to get cached permissions
                    key = f"user:{user_id}:permissions"
                    cached_perms = RedisClient().get(key)
                    if cached_perms:
                        roles_permissions = eval(cached_perms)
                    else:
                        # fallback to token's claims
                        roles_permissions = {
                            "roles": payload.get("roles", []),
                            "permissions": payload.get("permissions", []),
                        }
                    setattr(user, "permissions", roles_permissions)
                    return user
                except User.DoesNotExist:
                    return None
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return None


class AllowAny:
    def __init__(self, request) -> None:
        pass

    def __call__(self, request) -> Any:
        return False
