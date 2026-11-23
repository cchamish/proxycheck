"""Gunicorn worker with access logging handled exclusively by ASGI middleware."""

from uvicorn_worker import UvicornWorker


class PrivateUvicornWorker(UvicornWorker):
    CONFIG_KWARGS = {**UvicornWorker.CONFIG_KWARGS, "access_log": False}
