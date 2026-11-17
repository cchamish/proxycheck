"""Tests for event-loop isolation, Redis degradation fallbacks, and session resilience."""

import asyncio
import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import redis.exceptions
from django.contrib.sessions.backends.base import UpdateError
from django.contrib.sessions.middleware import SessionInterrupted
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings

from detector import cache_backends, detection_service, http_client, views
from detector.middleware import ResilientSessionMiddleware

from .helpers import (
    MAXMIND_STUB,
    _login_authorised,
    _mock_response,
    _ptr_or_clean_dns_side_effect,
    start_non_dnsbl_provider_stubs,
)


class LoopIsolationAndSessionSettingsTests(TestCase):
    """Tests per-loop Redis and HTTP client isolation, empty error logging, and Redis sessions."""

    def tearDown(self):
        with http_client.http_client_lock:
            http_client.http_clients_by_loop.clear()
        with cache_backends._redis_client_lock:
            cache_backends._redis_clients_by_loop.clear()
        cache_backends.reset_redis_circuit_breaker()

    def test_redis_client_reused_within_loop_and_isolated_across_closed_loops(self):
        created_clients = []

        def _make_fake_redis(*args, **kwargs):
            client = MagicMock(name=f"redis-{len(created_clients)}")
            created_clients.append((args, kwargs, client))
            return client

        async def _acquire_twice():
            first = cache_backends._get_redis_client()
            second = cache_backends._get_redis_client()
            self.assertIs(first, second)
            return first

        with patch.object(cache_backends.aioredis, "from_url", side_effect=_make_fake_redis):
            client_one = asyncio.run(_acquire_twice())
            client_two = asyncio.run(_acquire_twice())

        self.assertIsNot(client_one, client_two)
        self.assertEqual(len(created_clients), 2)

    def test_concurrent_open_loops_in_separate_threads_keep_distinct_clients(self):
        import concurrent.futures

        barrier = threading.Barrier(2)
        results = []

        def _worker():
            async def _inner():
                redis_first = cache_backends._get_redis_client()
                http_first = await http_client.get_shared_http_client()
                barrier.wait(timeout=5)
                redis_second = cache_backends._get_redis_client()
                http_second = await http_client.get_shared_http_client()
                self.assertIs(redis_first, redis_second)
                self.assertIs(http_first, http_second)
                self.assertFalse(http_first.is_closed)
                await http_client.close_http_client_safely(http_first)
                return redis_first, http_first

            return asyncio.run(_inner())

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_worker)
            f2 = pool.submit(_worker)
            results.append(f1.result(timeout=10))
            results.append(f2.result(timeout=10))

        self.assertIsNot(results[0][0], results[1][0])
        self.assertIsNot(results[0][1], results[1][1])

    def test_collectstatic_does_not_require_secret_key(self):
        import subprocess

        env = {k: v for k, v in os.environ.items() if k != "DJANGO_SECRET_KEY"}
        env["DJANGO_DEBUG"] = "False"
        proc = subprocess.run(
            [sys.executable, "manage.py", "collectstatic", "--dry-run", "--noinput"],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr or proc.stdout)

    def test_dotenv_resolver_supports_tool_data_dir(self):
        from proxycheck.settings import resolve_dotenv_path

        with tempfile.TemporaryDirectory() as tmpdir:
            tool_root = Path(tmpdir) / "tool"
            python_dir = tool_root / "www" / "python"
            python_dir.mkdir(parents=True)

            env_file = python_dir / ".env"
            env_file.write_text("DJANGO_DEBUG=False\n", encoding="utf-8")

            resolved_env = resolve_dotenv_path(Path(tmpdir) / "workspace", str(tool_root))
            self.assertEqual(resolved_env, env_file)


class RedisDegradationAndOAuthFallbackTests(TestCase):
    """Tests Redis cache fault tolerance, OAuth upstream error handling, and callback route aliases."""

    def tearDown(self):
        detection_service._ip_detect_inflight.clear()
        with cache_backends._redis_client_lock:
            cache_backends._redis_clients_by_loop.clear()
        cache_backends.reset_redis_circuit_breaker()

    @staticmethod
    def _ok_google_row(name: str) -> dict:
        return {
            "provider": name,
            "status": "200 OK",
            "statusCode": 200,
            "asn": "AS15169",
            "isp": "Google",
            "organisation": "Google",
            "location": "United States",
            "usageType": "isp",
            "securityFlags": [{"label": "No Flags", "isHighRisk": False}],
            "countryCode": "US",
            "rawJson": {},
        }

    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
    def test_detect_ip_returns_200_when_redis_raises_connection_or_timeout_errors(self, _mock_dns):
        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=self._ok_google_row,
        )

        _login_authorised(self)
        bearer_token = views.issue_gadget_token("SysopUser")
        failures = (
            ("connection_error", redis.exceptions.ConnectionError("Redis unreachable")),
            ("timeout_error", redis.exceptions.TimeoutError("Redis read timed out")),
        )
        sample_ips = {
            ("connection_error", "session"): "8.8.8.8",
            ("connection_error", "bearer"): "8.8.4.4",
            ("timeout_error", "session"): "1.1.1.1",
            ("timeout_error", "bearer"): "9.9.9.9",
        }
        for label, exc in failures:
            for auth_mode, headers in (
                ("session", {}),
                ("bearer", {"HTTP_AUTHORIZATION": f"Bearer {bearer_token}"}),
            ):
                target_ip = sample_ips[(label, auth_mode)]
                with self.subTest(failure=label, auth_mode=auth_mode):
                    mock_redis = MagicMock()
                    mock_redis.get = AsyncMock(side_effect=exc)
                    mock_redis.set = AsyncMock(side_effect=exc)

                    with (
                        patch("detector.cache_backends.redis_client", mock_redis),
                        self.assertLogs("detector.views", level="WARNING") as captured_logs,
                    ):
                        resp = self.client.get(f"/api/v1/detect?ip={target_ip}", **headers)

                    self.assertEqual(resp.status_code, 200)
                    payload = resp.json()
                    self.assertEqual(payload["ip"], target_ip)
                    self.assertFalse(payload["isCached"])
                    self.assertEqual(payload["cacheMeta"]["status"], "miss")
                    self.assertTrue(any("Redis cache" in line for line in captured_logs.output))

    @override_settings(REDIS_CIRCUIT_BREAKER_SECONDS=5.0)
    async def test_redis_circuit_breaker_opens_on_timeout_and_recovers_after_cooldown(self):
        from detector import quota_telemetry

        monotonic_clock = [100.0]
        loop_client = MagicMock(name="default-loop-redis")
        loop_client.get = AsyncMock(side_effect=[redis.exceptions.TimeoutError("Timed out"), "cached-ok"])
        loop_client.set = AsyncMock(return_value=True)

        cache_backends.reset_redis_circuit_breaker()
        with (
            patch.object(cache_backends.aioredis, "from_url", return_value=loop_client),
            patch("detector.cache_backends.time.monotonic", side_effect=lambda: monotonic_clock[0]),
        ):
            self.assertFalse(cache_backends.is_redis_circuit_open())
            self.assertIs(cache_backends._get_redis_client(), loop_client)

            # Non-connection exceptions must not trip the circuit breaker
            cache_backends.mark_redis_failure(ValueError("unexpected serialization error"))
            self.assertFalse(cache_backends.is_redis_circuit_open())

            with self.assertLogs("detector.views", level="WARNING") as captured_logs:
                first_read = await cache_backends._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8")

            self.assertIsNone(first_read)
            self.assertTrue(cache_backends.is_redis_circuit_open())
            self.assertTrue(any("circuit breaker opened" in line for line in captured_logs.output))
            self.assertEqual(loop_client.get.await_count, 1)

            # Within the cooldown window, client acquisition fails open immediately without calling Redis
            monotonic_clock[0] = 104.9
            self.assertIsNone(cache_backends._get_redis_client())
            self.assertIsNone(quota_telemetry._get_redis_client())
            self.assertIsNone(await cache_backends._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8"))
            await cache_backends._safe_redis_set("proxycheck:v1:prov:proxycheck:8.8.8.8", "{}", ex=60)
            self.assertEqual(loop_client.get.await_count, 1)
            self.assertEqual(loop_client.set.await_count, 0)

            # Once the cooldown elapses, the default client resumes automatically
            monotonic_clock[0] = 105.0
            self.assertFalse(cache_backends.is_redis_circuit_open())
            self.assertIs(cache_backends._get_redis_client(), loop_client)
            recovered_read = await cache_backends._safe_redis_get("proxycheck:v1:prov:proxycheck:8.8.8.8")
            self.assertEqual(recovered_read, "cached-ok")
            self.assertEqual(loop_client.get.await_count, 2)

            # Write errors also trip the breaker and explicit reset closes it immediately
            loop_client.set = AsyncMock(side_effect=ConnectionError("Connection reset by peer"))
            await cache_backends._safe_redis_set("proxycheck:v1:prov:proxycheck:8.8.8.8", "{}", ex=60)
            self.assertTrue(cache_backends.is_redis_circuit_open())
            self.assertIsNone(cache_backends._get_redis_client())
            cache_backends.reset_redis_circuit_breaker()
            self.assertFalse(cache_backends.is_redis_circuit_open())
            self.assertIs(cache_backends._get_redis_client(), loop_client)

    @override_settings(REDIS_CIRCUIT_BREAKER_SECONDS=5.0)
    @patch(
        "dns.asyncresolver.Resolver.resolve",
        new_callable=AsyncMock,
        side_effect=_ptr_or_clean_dns_side_effect(ptr_hostname="dns.google."),
    )
    async def test_redis_circuit_breaker_short_circuits_multistage_detect_request(self, _mock_dns):
        from django.test import AsyncClient

        start_non_dnsbl_provider_stubs(
            self,
            overrides={"maxmind": dict(MAXMIND_STUB)},
            row_builder=self._ok_google_row,
        )

        loop_client = MagicMock(name="hanging-default-loop-redis")
        loop_client.mget = AsyncMock(side_effect=redis.exceptions.TimeoutError("Socket read timed out"))
        loop_client.get = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected get call"))
        loop_client.set = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected set call"))
        loop_client.eval = AsyncMock(side_effect=redis.exceptions.TimeoutError("Unexpected eval call"))
        loop_client.pipeline = MagicMock(side_effect=AssertionError("Pipeline should be skipped once circuit is open"))

        bearer_token = views.issue_gadget_token("SysopUser")
        asgi_client = AsyncClient()
        cache_backends.reset_redis_circuit_breaker()

        with (
            patch.object(cache_backends.aioredis, "from_url", return_value=loop_client),
            patch("detector.cache_backends.time.monotonic", return_value=200.0),
        ):
            resp = await asgi_client.get(
                "/api/v1/detect?ip=8.8.8.8",
                headers={"Authorization": f"Bearer {bearer_token}"},
            )
            self.assertEqual(resp.status_code, 200)
            self.assertTrue(cache_backends.is_redis_circuit_open())
            # Only the first cache-read stage contacts Redis; provider reads, cooldown, quota, writes, and telemetry fail open cleanly
            self.assertEqual(loop_client.get.await_count, 1)
            self.assertEqual(loop_client.mget.await_count, 0)
            self.assertEqual(loop_client.set.await_count, 0)
            self.assertEqual(loop_client.eval.await_count, 0)
            self.assertEqual(loop_client.pipeline.call_count, 0)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_upstream_failures_log_without_leaks_and_redirect_home(self, mock_async_client_cls):
        failure_cases = (
            (
                "token_http_500",
                _mock_response(status_code=500, text="token error super_secret_oauth_value_999"),
                None,
                "token exchange failed",
            ),
            (
                "token_missing_access_token",
                _mock_response(status_code=200, json_value={"token_type": "Bearer"}),
                None,
                "contained no access_token",
            ),
            (
                "profile_http_502",
                _mock_response(status_code=200, json_value={"access_token": "tok_runtime_secret_888"}),
                _mock_response(
                    status_code=502,
                    text="profile bad gateway Bearer tok_runtime_secret_888 super_secret_oauth_value_999",
                ),
                "profile fetch failed",
            ),
            (
                "network_timeout",
                httpx.ReadTimeout("request timed out super_secret_oauth_value_999"),
                None,
                "callback processing error",
            ),
            (
                "profile_exception_with_token",
                _mock_response(status_code=200, json_value={"access_token": "tok_runtime_secret_888"}),
                RuntimeError("unexpected crash with tok_runtime_secret_888 and super_secret_oauth_value_999"),
                "callback processing error",
            ),
            (
                "invalid_json",
                _mock_response(status_code=200, json_error=ValueError("Invalid JSON payload")),
                None,
                "callback processing error",
            ),
        )

        for label, token_outcome, profile_outcome, expected_log_fragment in failure_cases:
            with self.subTest(case=label):
                mock_client = AsyncMock()
                mock_async_client_cls.return_value.__aenter__.return_value = mock_client
                if isinstance(token_outcome, Exception):
                    mock_client.post.side_effect = token_outcome
                else:
                    mock_client.post.return_value = token_outcome
                if isinstance(profile_outcome, Exception):
                    mock_client.get.side_effect = profile_outcome
                elif profile_outcome is not None:
                    mock_client.get.return_value = profile_outcome

                session = self.client.session
                session["oauth_state"] = f"state_{label}"
                session.pop("wikimedia_user", None)
                session.save()

                with self.assertLogs("detector.views", level="ERROR") as captured_logs:
                    resp = self.client.get(f"/api/v1/auth/callback/?code=code_{label}&state=state_{label}")

                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp["Location"], "/")
                self.assertIsNone(self.client.session.get("oauth_state"))
                self.assertIsNone(self.client.session.get("wikimedia_user"))
                log_output = "\n".join(captured_logs.output)
                self.assertIn(expected_log_fragment, log_output)
                self.assertNotIn("super_secret_oauth_value_999", log_output)
                self.assertNotIn("tok_runtime_secret_888", log_output)
                self.assertNotIn("Traceback (most recent call last):", log_output)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="test_client_secret",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.oauth.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_alias_routes_authenticate_and_consume_state(self, mock_async_client_cls, mock_fetch_meta):
        mock_fetch_meta.return_value = {
            "global_groups": ["steward"],
            "global_rights": ["checkuser-temporary-account-no-preference"],
            "merged_projects": [],
        }
        alias_paths = ("/oauth/callback", "/oauth/callback/", "/api/oauth/callback")

        for index, route in enumerate(alias_paths):
            with self.subTest(route=route):
                mock_client = AsyncMock()
                mock_async_client_cls.return_value.__aenter__.return_value = mock_client
                mock_client.post.return_value = _mock_response(
                    status_code=200,
                    json_value={"access_token": f"token_{index}"},
                )
                mock_client.get.return_value = _mock_response(
                    status_code=200,
                    json_value={"username": f"AliasSteward_{index}", "groups": ["user"]},
                )

                state_val = f"alias_state_{index}"
                session = self.client.session
                session["oauth_state"] = state_val
                session.pop("wikimedia_user", None)
                session.save()

                resp = self.client.get(f"{route}?code=alias_code_{index}&state={state_val}")

                self.assertEqual(resp.status_code, 302)
                self.assertEqual(resp["Location"], "/")
                self.assertIsNone(self.client.session.get("oauth_state"))
                user_session = self.client.session.get("wikimedia_user")
                self.assertIsNotNone(user_session)
                self.assertEqual(user_session["username"], f"AliasSteward_{index}")
                self.assertTrue(user_session["hasAccess"])

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    def test_oauth_login_returns_503_without_leaks_when_session_backend_fails(self):
        failures = (
            ("redis_conn", redis.exceptions.ConnectionError("redis://secret@127.0.0.1:6379 down")),
            ("redis_timeout", redis.exceptions.TimeoutError("socket timeout")),
            ("os_error", OSError("network unreachable")),
        )
        for label, exc in failures:
            with self.subTest(failure=label):
                with (
                    patch(
                        "django.contrib.sessions.backends.cache.SessionStore.save",
                        side_effect=exc,
                    ),
                    self.assertLogs("detector.views", level="WARNING") as captured_logs,
                ):
                    resp = self.client.get("/api/v1/auth/login/")

                self.assertEqual(resp.status_code, 503)
                self.assertIn("unavailable", resp.json()["error"].lower())
                log_output = "\n".join(captured_logs.output)
                self.assertNotIn("super_secret_oauth_value_999", log_output)
                self.assertNotIn("redis://secret", log_output)

    @override_settings(
        WIKIMEDIA_CLIENT_ID="test_client_id",
        WIKIMEDIA_CLIENT_SECRET="super_secret_oauth_value_999",
        WIKIMEDIA_REDIRECT_URI="https://proxycheck.toolforge.org/oauth/callback",
    )
    @patch("detector.oauth.fetch_user_rights_from_meta", new_callable=AsyncMock)
    @patch("detector.http_client.httpx.AsyncClient")
    def test_oauth_callback_returns_503_when_session_save_fails_at_state_or_login(
        self, mock_async_client_cls, mock_fetch_meta
    ):
        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis write refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            state_fail_resp = self.client.get("/api/v1/auth/callback/?code=abc&state=xyz")

        self.assertEqual(state_fail_resp.status_code, 503)
        self.assertIn("unavailable", state_fail_resp.json()["error"].lower())
        mock_async_client_cls.assert_not_called()

        session = self.client.session
        session["oauth_state"] = "state_persist_fail"
        session.save()

        mock_client = AsyncMock()
        mock_async_client_cls.return_value.__aenter__.return_value = mock_client
        mock_client.post.return_value = _mock_response(
            status_code=200,
            json_value={"access_token": "secret_oauth_access_tok_555"},
        )
        mock_client.get.return_value = _mock_response(
            status_code=200,
            json_value={"username": "StewardUser", "groups": ["user"]},
        )
        mock_fetch_meta.return_value = {
            "global_groups": ["steward"],
            "global_rights": ["checkuser-temporary-account-no-preference"],
            "merged_projects": [],
        }

        original_save = __import__(
            "django.contrib.sessions.backends.cache",
            fromlist=["SessionStore"],
        ).SessionStore.save
        save_calls = {"count": 0}

        def _fail_second_save(store_self, *args, **kwargs):
            save_calls["count"] += 1
            if save_calls["count"] == 1:
                return original_save(store_self, *args, **kwargs)
            raise redis.exceptions.TimeoutError("Timed out persisting session secret_oauth_access_tok_555")

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                autospec=True,
                side_effect=_fail_second_save,
            ),
            self.assertLogs("detector.views", level="WARNING") as captured_logs,
        ):
            persist_fail_resp = self.client.get("/api/v1/auth/callback/?code=abc&state=state_persist_fail")

        self.assertEqual(persist_fail_resp.status_code, 503)
        self.assertIn("unavailable", persist_fail_resp.json()["error"].lower())
        self.assertIsNone(self.client.session.get("wikimedia_user"))
        log_output = "\n".join(captured_logs.output)
        self.assertNotIn("secret_oauth_access_tok_555", log_output)
        self.assertNotIn("super_secret_oauth_value_999", log_output)

    @override_settings(SESSION_RIGHTS_TTL_SECONDS=60)
    def test_auth_user_detect_and_logout_degrade_safely_when_redis_session_fails(self):
        with patch(
            "django.contrib.sessions.backends.cache.SessionStore.load",
            side_effect=redis.exceptions.ConnectionError("load fallback"),
        ):
            unauth_user_resp = self.client.get("/api/v1/auth/user/")
            self.assertEqual(unauth_user_resp.status_code, 200)
            self.assertFalse(unauth_user_resp.json()["isLoggedIn"])

            unauth_detect_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")
            self.assertEqual(unauth_detect_resp.status_code, 401)

        expired_user = {
            "isLoggedIn": True,
            "username": "ExpiredSysop",
            "role": "Local Administrator (sysop)",
            "hasAccess": True,
            "localGroups": ["sysop"],
            "globalGroups": [],
            "rights_updated_at": time.time() - 120,
        }
        session = self.client.session
        session["wikimedia_user"] = expired_user
        session.save()

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.save",
                side_effect=redis.exceptions.ConnectionError("Redis save refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            user_resp = self.client.get("/api/v1/auth/user/")
            detect_resp = self.client.get("/api/v1/detect?ip=8.8.8.8")

        self.assertEqual(user_resp.status_code, 200)
        self.assertFalse(user_resp.json()["isLoggedIn"])
        self.assertEqual(detect_resp.status_code, 401)

        session = self.client.session
        session["wikimedia_user"] = {
            **expired_user,
            "rights_updated_at": time.time(),
        }
        session.save()
        session_cookie_value = self.client.cookies["proxycheck_sessionid"].value

        with (
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.delete",
                side_effect=redis.exceptions.ConnectionError("Redis delete refused"),
            ),
            self.assertLogs("detector.views", level="WARNING") as captured_logs,
        ):
            logout_resp = self.client.get("/api/v1/auth/logout/")

        self.assertEqual(logout_resp.status_code, 200)
        self.assertEqual(logout_resp.json()["status"], "logged_out")
        log_output = "\n".join(captured_logs.output)
        self.assertNotIn(session_cookie_value, log_output)

        with (
            override_settings(DEBUG=True, ENABLE_TEST_AUTH=True),
            patch(
                "django.contrib.sessions.backends.cache.SessionStore.delete",
                side_effect=redis.exceptions.ConnectionError("Redis delete refused"),
            ),
            self.assertLogs("detector.views", level="WARNING"),
        ):
            switch_flush_resp = self.client.post(
                "/api/v1/auth/switch-role/",
                data=json.dumps({"role": "unauthenticated"}),
                content_type="application/json",
            )
        self.assertEqual(switch_flush_resp.status_code, 200)
        self.assertFalse(switch_flush_resp.json()["isLoggedIn"])

    def test_resilient_session_middleware_guards_backend_outage_without_hiding_update_error(self):

        rf = RequestFactory()
        middleware = ResilientSessionMiddleware(lambda req: HttpResponse("ok"))

        req_outage = rf.get("/")
        req_outage.session = MagicMock()
        req_outage.session.accessed = True
        req_outage.session.modified = True
        req_outage.session.is_empty.return_value = False
        req_outage.session.get_expire_at_browser_close.return_value = False
        req_outage.session.get_expiry_age.return_value = 3600
        req_outage.session.save.side_effect = redis.exceptions.ConnectionError("Redis unreachable")

        with self.assertLogs("detector.middleware", level="WARNING"):
            res = middleware.process_response(req_outage, HttpResponse("ok"))

        self.assertEqual(res.status_code, 200)
        self.assertFalse(req_outage.session.modified)
        self.assertIn("Cookie", res.headers.get("Vary", ""))
        self.assertNotIn("proxycheck_sessionid", res.cookies)

        req_conflict = rf.get("/")
        req_conflict.session = MagicMock()
        req_conflict.session.accessed = True
        req_conflict.session.modified = True
        req_conflict.session.is_empty.return_value = False
        req_conflict.session.get_expire_at_browser_close.return_value = False
        req_conflict.session.get_expiry_age.return_value = 3600
        req_conflict.session.save.side_effect = UpdateError("concurrent logout")

        with self.assertRaises(SessionInterrupted):
            middleware.process_response(req_conflict, HttpResponse("ok"))
