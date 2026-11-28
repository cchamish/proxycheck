"""
URL routing for the v1 API namespace.
Accepts both trailing-slash and non-trailing-slash paths to avoid POST redirects
behind Toolforge ingress and Vite development proxies.
"""

from django.urls import path

from . import views

urlpatterns = [
    path("detect", views.detect_ip, name="detect_ip"),
    path("detect/", views.detect_ip),
    path("detect/stream", views.detect_ip_stream, name="detect_ip_stream"),
    path("detect/stream/", views.detect_ip_stream),
    path("detect/refresh", views.refresh_ip_detection, name="refresh_ip_detection"),
    path("detect/refresh/", views.refresh_ip_detection),
    path("detect/batch", views.detect_ip_batch, name="detect_ip_batch"),
    path("detect/batch/", views.detect_ip_batch),
    path("rangeblock", views.rangeblock_lookup, name="rangeblock_lookup"),
    path("rangeblock/", views.rangeblock_lookup),
    path("rangeblock/batch", views.rangeblock_lookup_batch, name="rangeblock_lookup_batch"),
    path("rangeblock/batch/", views.rangeblock_lookup_batch),
    path("auth/user/", views.get_current_user, name="auth_user"),
    path("auth/user", views.get_current_user),
    path("auth/login/", views.oauth_login, name="auth_login"),
    path("auth/login", views.oauth_login),
    path("auth/callback/", views.oauth_callback, name="auth_callback"),
    path("auth/callback", views.oauth_callback),
    path("auth/logout/", views.oauth_logout, name="auth_logout"),
    path("auth/logout", views.oauth_logout),
    path("auth/gadget-token/", views.exchange_gadget_token, name="auth_gadget_token"),
    path("auth/gadget-token", views.exchange_gadget_token),
    path("auth/switch-role/", views.switch_test_role, name="switch_test_role"),
    path("auth/switch-role", views.switch_test_role),
    path("admin/provider-dashboard/", views.admin_provider_dashboard, name="admin_provider_dashboard"),
    path("admin/provider-dashboard", views.admin_provider_dashboard),
    path("status/", views.system_status, name="system_status"),
    path("status", views.system_status),
]
