"""
URL routing for the v1 API endpoint namespace.
Supports both trailing-slash and non-trailing-slash paths to avoid redirect issues
on POST requests behind Toolforge ingress and Vite development proxies.
"""

from django.urls import path, re_path

from . import views

urlpatterns = [
    path("detect", views.detect_ip, name="detect_ip"),
    path("detect/", views.detect_ip),
    path("auth/user/", views.get_current_user, name="auth_user"),
    re_path(r"^auth/user$", views.get_current_user),
    path("auth/login/", views.oauth_login, name="auth_login"),
    re_path(r"^auth/login$", views.oauth_login),
    path("auth/callback/", views.oauth_callback, name="auth_callback"),
    re_path(r"^auth/callback$", views.oauth_callback),
    path("auth/logout/", views.oauth_logout, name="auth_logout"),
    re_path(r"^auth/logout$", views.oauth_logout),
    path("auth/gadget-token/", views.exchange_gadget_token, name="auth_gadget_token"),
    re_path(r"^auth/gadget-token$", views.exchange_gadget_token),
    path("auth/switch-role/", views.switch_test_role, name="switch_test_role"),
    re_path(r"^auth/switch-role$", views.switch_test_role),
]
