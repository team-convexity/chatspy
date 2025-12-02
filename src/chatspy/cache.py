"""
Fail-open Redis cache backend. Returns defaults on Redis failures.
Includes automatic recovery attempts after initial failures.
"""

import time
from django.core.cache.backends.redis import RedisCache
from .utils import logger


class RedisCacheBackend(RedisCache):
    """Graceful Redis cache - returns defaults when Redis is unavailable."""

    RETRY_INTERVAL = 60

    def __init__(self, server, params):
        self._redis_available = True
        self._last_failure_time = 0
        self._server = server
        self._params = params
        try:
            super().__init__(server, params)
            logger.i("[Cache] Redis initialized successfully")
        except Exception as e:
            logger.w(f"[Cache] Redis init failed: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()

    def _try_reconnect(self):
        """Attempt to reconnect to Redis if enough time has passed since last failure."""
        if self._redis_available:
            return True

        now = time.time()
        if now - self._last_failure_time < self.RETRY_INTERVAL:
            return False

        try:
            super().__init__(self._server, self._params)
            self._redis_available = True
            logger.i("[Cache] Redis reconnected successfully")
            return True
        except Exception as e:
            logger.w(f"[Cache] Redis reconnect failed: {e}")
            self._last_failure_time = now
            return False

    def get(self, key, default=None, version=None):
        if not self._try_reconnect():
            return default
        try:
            return super().get(key, default=default, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis get failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return default

    def set(self, key, value, timeout=None, version=None):
        if not self._try_reconnect():
            return False
        try:
            return super().set(key, value, timeout=timeout, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis set failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return False

    def delete(self, key, version=None):
        if not self._try_reconnect():
            return False
        try:
            return super().delete(key, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis delete failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return False

    def clear(self):
        if not self._try_reconnect():
            return
        try:
            return super().clear()
        except Exception as e:
            logger.w(f"[Cache] Redis clear failed: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()

    def get_many(self, keys, version=None):
        if not self._try_reconnect():
            return {}
        try:
            return super().get_many(keys, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis get_many failed: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return {}

    def set_many(self, mapping, timeout=None, version=None):
        if not self._try_reconnect():
            return list(mapping.keys())
        try:
            return super().set_many(mapping, timeout=timeout, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis set_many failed: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return list(mapping.keys())

    def delete_many(self, keys, version=None):
        if not self._try_reconnect():
            return
        try:
            return super().delete_many(keys, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis delete_many failed: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()

    def has_key(self, key, version=None):
        if not self._try_reconnect():
            return False
        try:
            return super().has_key(key, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis has_key failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return False

    def incr(self, key, delta=1, version=None):
        if not self._try_reconnect():
            raise ValueError("Key '%s' not found" % key)
        try:
            return super().incr(key, delta=delta, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis incr failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            raise ValueError("Key '%s' not found" % key)

    def decr(self, key, delta=1, version=None):
        if not self._try_reconnect():
            raise ValueError("Key '%s' not found" % key)
        try:
            return super().decr(key, delta=delta, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis decr failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            raise ValueError("Key '%s' not found" % key)

    async def aget(self, key, default=None, version=None):
        if not self._try_reconnect():
            return default
        try:
            return await super().aget(key, default=default, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis aget failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return default

    async def aset(self, key, value, timeout=None, version=None):
        if not self._try_reconnect():
            return False
        try:
            return await super().aset(key, value, timeout=timeout, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis aset failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return False

    async def adelete(self, key, version=None):
        if not self._try_reconnect():
            return False
        try:
            return await super().adelete(key, version=version)
        except Exception as e:
            logger.w(f"[Cache] Redis adelete failed for {key}: {e}")
            self._redis_available = False
            self._last_failure_time = time.time()
            return False
