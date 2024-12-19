import jwt
from typing import Any
from django.apps import apps
from django.conf import settings
from asgiref.sync import sync_to_async
from ninja.security import HttpBearer
from django.contrib.auth import get_user_model

from .utils import logger
from .secret import Secret
from .services import Service
from .models import ChatsRecord
from .clients import Services, RedisClient


class JWTAuth(HttpBearer):
    async def authenticate(self, request, token):
        User = get_user_model()
        key = Secret.get_service_key(service=Service.AUTH)
        
        try:
            payload = jwt.decode(token, key, algorithms=["RS256"])
            user_id = payload.get("sub")
            if user_id is not None:
                try:
                    project_name = settings.SETTINGS_MODULE.split('.')[0]
                    # if we are in auth service, use User else use UserProfile
                    user_id = ChatsRecord.from_global_id(user_id)[1]
                    if project_name == 'authy':
                        user = await User.objects.aget(pk=user_id)
                    else:
                        UserProfile = apps.get_model("core.UserProfile", require_ready=False)
                        user = await UserProfile.objects.aget(auth_user_id=user_id)
                    # try to get cached permissions
                    key = f"user:{user_id}:permissions"
                    redis_client: RedisClient = Services.get_client("redis")
                    cached_perms = redis_client.get(key)
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
                    logger.e(f"User Does not exists: {user_id}")

                    return None
        except (jwt.DecodeError, jwt.ExpiredSignatureError) as e:
            logger.e(f"An error occured while authenticating: {e}")
            return None


class AllowAny:
    def __init__(self, request) -> None:
        pass

    def __call__(self, request) -> Any:
        return False
