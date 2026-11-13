"""Middleware utilities for async static file serving and resilient session persistence."""

import asyncio
import logging

from asgiref.sync import iscoroutinefunction, markcoroutinefunction
from django.contrib.sessions.middleware import SessionMiddleware
from django.utils.cache import patch_vary_headers
from whitenoise.middleware import WhiteNoiseFileResponse, WhiteNoiseMiddleware

try:
    from redis.exceptions import RedisError as _RedisError
except ImportError:
    _RedisError = ()

logger = logging.getLogger(__name__)

_SESSION_BACKEND_ERRORS = (ConnectionError, TimeoutError, OSError) + (
    (_RedisError,) if isinstance(_RedisError, type) else tuple(_RedisError)
)


def is_session_backend_error(exc: BaseException) -> bool:
    """Returns True when an exception indicates cache or Redis backend unavailability."""
    if isinstance(exc, _SESSION_BACKEND_ERRORS):
        return True
    # Django's cache SessionStore raises RuntimeError after exhausting retries when cache writes fail
    return isinstance(exc, RuntimeError) and "cache is unavailable" in str(exc).lower()


class ResilientSessionMiddleware(SessionMiddleware):
    """Prevents cache session backend outages from raising HTTP 500 during response persistence."""

    def process_response(self, request, response):
        try:
            return super().process_response(request, response)
        except Exception as exc:
            if not is_session_backend_error(exc):
                raise
            try:
                request.session.modified = False
            except AttributeError:
                pass
            logger.warning(
                "Response session persistence skipped due to cache backend unavailability (%s)",
                type(exc).__name__,
            )
            patch_vary_headers(response, ("Cookie",))
            return response


_STATIC_STREAM_CHUNK_SIZE = 65536


class AsyncWhiteNoiseMiddleware(WhiteNoiseMiddleware):
    """Async-capable WhiteNoise middleware that avoids sync bridging on the ASGI event loop."""

    sync_capable = True
    async_capable = True

    def __init__(self, get_response=None, *args, **kwargs):
        super().__init__(get_response, *args, **kwargs)
        self.async_mode = iscoroutinefunction(self.get_response)
        if self.async_mode:
            markcoroutinefunction(self)

    def __call__(self, request):
        if self.async_mode:
            return self.__acall__(request)
        return super().__call__(request)

    async def __acall__(self, request):
        if self.autorefresh:
            static_file = await asyncio.to_thread(self.find_file, request.path_info)
        else:
            static_file = self.files.get(request.path_info)
        if static_file is not None:
            return await self.aserve(static_file, request)
        return await self.get_response(request)

    @staticmethod
    async def _empty_async_stream():
        if False:
            yield b""

    @staticmethod
    async def _iter_file_async(filelike, chunk_size: int = _STATIC_STREAM_CHUNK_SIZE):
        try:
            while chunk := await asyncio.to_thread(filelike.read, chunk_size):
                yield chunk
        finally:
            await asyncio.to_thread(filelike.close)

    @classmethod
    async def aserve(cls, static_file, request):
        """Serve a matched WhiteNoise static file with an async byte stream."""
        response = await asyncio.to_thread(static_file.get_response, request.method, request.META)
        status = int(response.status)
        filelike = response.file
        # Provide an async iterator even for empty bodies so ASGIHandler avoids sync fallback warnings
        stream = cls._empty_async_stream() if filelike is None else cls._iter_file_async(filelike)
        http_response = WhiteNoiseFileResponse(stream, status=status)
        if filelike is not None and hasattr(filelike, "close"):
            # Register file closer in case the client disconnects before body iteration begins
            http_response._resource_closers.append(filelike.close)
        del http_response["content-type"]
        for key, value in response.headers:
            http_response[key] = value
        return http_response
