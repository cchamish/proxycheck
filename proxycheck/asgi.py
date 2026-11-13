"""
ASGI application entrypoint for Uvicorn workers.
"""

import os

from django.core.asgi import get_asgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "proxycheck.settings")

application = get_asgi_application()
