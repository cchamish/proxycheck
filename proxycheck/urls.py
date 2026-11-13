"""
Root URL configuration.
Mounts the v1 API and delegates remaining routes to the compiled SPA entrypoint.
"""

import asyncio
import mimetypes
from pathlib import Path
from typing import Optional, Tuple

from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound
from django.urls import include, path, re_path

from detector import views as detector_views

_FALLBACK_SPA_HTML = """<!doctype html>
<html lang="en-GB">
<head><meta charset="utf-8"><title>Proxy Detector</title></head>
<body><div id="app">Loading Proxy Detector...</div></body>
</html>"""


def _read_text_if_exists(file_path: Path) -> Optional[str]:
    if file_path.is_file():
        return file_path.read_text(encoding="utf-8")
    return None


def _read_favicon_svg(base_dir: Path) -> Optional[bytes]:
    for candidate in (base_dir / "dist" / "Toolforge.svg", base_dir / "public" / "Toolforge.svg"):
        if candidate.is_file():
            return candidate.read_bytes()
    return None


def _read_asset_bytes(assets_root: Path, rel_path: str) -> Optional[Tuple[bytes, str]]:
    root = assets_root.resolve()
    target = (root / rel_path).resolve()
    if not target.is_relative_to(root) or not target.is_file():
        return None
    content_type, _ = mimetypes.guess_type(str(target))
    return target.read_bytes(), content_type or "application/octet-stream"


async def spa_index(_request):
    """Serves the compiled index page for client-side SPA routes outside API, OAuth, and static asset paths."""
    index_path = Path(settings.BASE_DIR) / "dist" / "index.html"
    html_content = await asyncio.to_thread(_read_text_if_exists, index_path)
    if html_content is not None:
        return HttpResponse(html_content, content_type="text/html; charset=utf-8")
    return HttpResponse(_FALLBACK_SPA_HTML, content_type="text/html; charset=utf-8")


async def serve_favicon(_request):
    """Serves the Toolforge SVG icon asynchronously for icon endpoints without blocking ASGI."""
    svg_bytes = await asyncio.to_thread(_read_favicon_svg, Path(settings.BASE_DIR))
    if svg_bytes is None:
        return HttpResponseNotFound()
    return HttpResponse(svg_bytes, content_type="image/svg+xml")


async def serve_debug_asset(_request, asset_path: str):
    """Serves built Vite assets asynchronously in DEBUG mode when WhiteNoise staticfiles are not active."""
    assets_root = Path(settings.BASE_DIR) / "dist" / "assets"
    loaded = await asyncio.to_thread(_read_asset_bytes, assets_root, asset_path)
    if loaded is None:
        return HttpResponseNotFound()
    content, content_type = loaded
    return HttpResponse(content, content_type=content_type)


urlpatterns = [
    path("oauth/callback", detector_views.oauth_callback, name="oauth_callback_root"),
    path("oauth/callback/", detector_views.oauth_callback),
    path("api/oauth/callback", detector_views.oauth_callback),
    path("api/oauth/callback/", detector_views.oauth_callback),
    path("api/v1/", include("detector.urls")),
]

if settings.DEBUG:
    urlpatterns += [
        re_path(r"^assets/(?P<asset_path>.*)$", serve_debug_asset),
    ]

urlpatterns += [
    path("Toolforge.svg", serve_favicon),
    path("favicon.svg", serve_favicon),
    path("favicon.ico", serve_favicon),
    re_path(
        r"^(?!api/|oauth/|assets/|Toolforge\.svg|favicon\.svg|favicon\.ico).*$",
        spa_index,
        name="spa_index",
    ),
]
