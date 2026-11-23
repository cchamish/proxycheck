"""
ASGI application entrypoint for Uvicorn workers.
"""

import os

from django.core.asgi import get_asgi_application

from proxycheck.access_log import AccessLogMiddleware

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proxycheck.settings")

application = AccessLogMiddleware(get_asgi_application())
