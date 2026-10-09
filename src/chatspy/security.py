import jwt
import ast
import os
import redis
import time
from functools import lru_cache
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
from django.core.cache import cache


LOGIN_CHALLENGE_PATHS = frozenset({"/auth/auth/verify-otp", "/auth/auth/resend-otp"})


@lru_cache(maxsize=1)
def _revocation_redis():
    location = os.getenv("REDIS_LOCATION")
    return redis.Redis.from_url(location, socket_connect_timeout=2, socket_timeout=2) if location else None


def _revocation_key(jti):
    return f"chats:revoked:{jti}"


def is_token_revoked(payload):
    jti = payload.get("jti")
    if not jti:
        return True
    client = _revocation_redis()
    if client:
        return bool(client.exists(_revocation_key(jti)))
    if not settings.DEBUG and not getattr(settings, "TESTING", False):
        raise RuntimeError("REDIS_LOCATION is required for token revocation")
    return bool(cache.get(_revocation_key(jti)))


def revoke_token(payload):
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not jti or not exp:
        return False
    ttl = max(1, int(exp) - int(time.time()))
    client = _revocation_redis()
    if client:
        return bool(client.set(_revocation_key(jti), "1", ex=ttl, nx=True))
    if not settings.DEBUG and not getattr(settings, "TESTING", False):
        raise RuntimeError("REDIS_LOCATION is required for token revocation")
    return cache.add(_revocation_key(jti), True, timeout=ttl)


def token_allowed_for_request(payload, path):
    token_type = payload.get("token_type")
    if token_type == "access":
        return not is_token_revoked(payload)
    if token_type == "login_challenge" and path.rstrip("/") in LOGIN_CHALLENGE_PATHS:
        jti = payload.get("jti")
        return bool(jti) and not cache.get(f"login_challenge_used:{jti}")
    return False


class JWTAuth(HttpBearer):
    async def authenticate(self, request, token):
        User = get_user_model()
        key = Secret.get_service_key(service=Service.AUTH)
        
        try:
            payload = jwt.decode(token, key, algorithms=["RS256"])
            if not token_allowed_for_request(payload, request.path):
                return None
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

                        jwt_user_type = payload.get("user_type")
                        if jwt_user_type and user.user_type != jwt_user_type:
                            user.user_type = jwt_user_type
                            await user.asave(update_fields=["user_type"])

                    # try to get cached permissions
                    key = f"user:{user_id}:permissions"
                    redis_client: RedisClient = Services.get_client("redis")
                    cached_perms = redis_client.get(key)
                    if cached_perms:
                        roles_permissions = ast.literal_eval(cached_perms)
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
