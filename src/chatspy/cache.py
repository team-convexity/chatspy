"""
Fail-open Redis cache backend. Returns defaults on Redis failures.
"""

import logging
from django.core.cache.backends.redis import RedisCache

logger = logging.getLogger(__name__)


class RedisCacheBackend(RedisCache):
    """Graceful Redis cache - returns defaults when Redis is unavailable."""

    def __init__(self, server, params):
        self._redis_available = True
        try:
            super().__init__(server, params)
        except Exception as e:
            logger.warning(f"[Cache] Redis init failed: {e}")
            self._redis_available = False

    def get(self, key, default=None, version=None):
        if not self._redis_available:
            return default
        try:
            return super().get(key, default=default, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis get failed for {key}: {e}")
            return default

    def set(self, key, value, timeout=None, version=None):
        if not self._redis_available:
            return False
        try:
            return super().set(key, value, timeout=timeout, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis set failed for {key}: {e}")
            return False

    def delete(self, key, version=None):
        if not self._redis_available:
            return False
        try:
            return super().delete(key, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis delete failed for {key}: {e}")
            return False

    def clear(self):
        if not self._redis_available:
            return
        try:
            return super().clear()
        except Exception as e:
            logger.warning(f"[Cache] Redis clear failed: {e}")

    def get_many(self, keys, version=None):
        if not self._redis_available:
            return {}
        try:
            return super().get_many(keys, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis get_many failed: {e}")
            return {}

    def set_many(self, mapping, timeout=None, version=None):
        if not self._redis_available:
            return list(mapping.keys())
        try:
            return super().set_many(mapping, timeout=timeout, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis set_many failed: {e}")
            return list(mapping.keys())

    def delete_many(self, keys, version=None):
        if not self._redis_available:
            return
        try:
            return super().delete_many(keys, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis delete_many failed: {e}")

    def has_key(self, key, version=None):
        if not self._redis_available:
            return False
        try:
            return super().has_key(key, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis has_key failed for {key}: {e}")
            return False

    def incr(self, key, delta=1, version=None):
        if not self._redis_available:
            raise ValueError("Key '%s' not found" % key)
        try:
            return super().incr(key, delta=delta, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis incr failed for {key}: {e}")
            raise ValueError("Key '%s' not found" % key)

    def decr(self, key, delta=1, version=None):
        if not self._redis_available:
            raise ValueError("Key '%s' not found" % key)
        try:
            return super().decr(key, delta=delta, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis decr failed for {key}: {e}")
            raise ValueError("Key '%s' not found" % key)

    async def aget(self, key, default=None, version=None):
        if not self._redis_available:
            return default
        try:
            return await super().aget(key, default=default, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis aget failed for {key}: {e}")
            return default

    async def aset(self, key, value, timeout=None, version=None):
        if not self._redis_available:
            return False
        try:
            return await super().aset(key, value, timeout=timeout, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis aset failed for {key}: {e}")
            return False

    async def adelete(self, key, version=None):
        if not self._redis_available:
            return False
        try:
            return await super().adelete(key, version=version)
        except Exception as e:
            logger.warning(f"[Cache] Redis adelete failed for {key}: {e}")
            return False
