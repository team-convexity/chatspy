"""
Resilient cache utilities that gracefully handle Redis failures.
Falls back to local memory cache when Redis is unavailable.
"""
import asyncio
from typing import Any, Optional
from django.core.cache import cache, caches
from django.core.cache.backends.base import BaseCache

from chatspy.utils import logger


class ResilientCache:
    """
    A cache wrapper that gracefully handles Redis connection failures.
    Automatically falls back to local memory cache when Redis is unavailable.
    """

    def __init__(self):
        self._fallback_data = {}

    def _get_cache(self) -> BaseCache:
        try:
            return cache
        except Exception:
            return None

    def _get_fallback(self) -> Optional[BaseCache]:
        try:
            return caches["fallback"]
        except Exception:
            return None

    def get(self, key: str, default: Any = None) -> Any:
        try:
            result = cache.get(key, default)
            return result
        except Exception as e:
            logger.e(f"[Cache] Redis get failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                return fallback.get(key, default)
            return self._fallback_data.get(key, default)

    def set(self, key: str, value: Any, timeout: Optional[int] = 300) -> bool:
        try:
            cache.set(key, value, timeout)
            return True
        except Exception as e:
            logger.e(f"[Cache] Redis set failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                fallback.set(key, value, timeout)
                return True
            self._fallback_data[key] = value
            return True

    def delete(self, key: str) -> bool:
        try:
            cache.delete(key)
            return True
        except Exception as e:
            logger.e(f"[Cache] Redis delete failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                fallback.delete(key)
            self._fallback_data.pop(key, None)
            return True

    async def aget(self, key: str, default: Any = None) -> Any:
        try:
            result = await cache.aget(key, default)
            return result
        except Exception as e:
            logger.e(f"[Cache] Redis aget failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                return await asyncio.to_thread(fallback.get, key, default)
            return self._fallback_data.get(key, default)

    async def aset(self, key: str, value: Any, timeout: Optional[int] = 300) -> bool:
        try:
            await cache.aset(key, value, timeout)
            return True
        except Exception as e:
            logger.e(f"[Cache] Redis aset failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                await asyncio.to_thread(fallback.set, key, value, timeout)
                return True
            self._fallback_data[key] = value
            return True

    async def adelete(self, key: str) -> bool:
        try:
            await cache.adelete(key)
            return True
        except Exception as e:
            logger.e(f"[Cache] Redis adelete failed for {key}: {e}")
            fallback = self._get_fallback()
            if fallback:
                await asyncio.to_thread(fallback.delete, key)
            self._fallback_data.pop(key, None)
            return True


resilient_cache = ResilientCache()
