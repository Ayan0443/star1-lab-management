#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §19 安全加固测试（管理鉴权/锁定/CIDR/响应头/并发上限/日志脱敏）。

只依赖 stdlib；每个测试类用独立 mock server（MockServer 来自 test_api_mock），
不联网、不需要 root、结束自动清理临时目录与子进程。
"""

import json
import os
import re
import socket
import sys
import time
import unittest

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), PROJECT_ROOT, TESTS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from test_api_mock import (  # noqa: E402
    ADMIN_TOKEN,
    EMAIL_SMTP_PASSWORD,
    MockApiTestCase,
    STRONG_PW,
    _header,
)

CJK_RE = re.compile(r"[\u4e00-\u9fff]")


def _wait_log_contains(testcase, needle, timeout=3.0):
    """等待 server 日志文件中出现 needle（子进程 stdout flush 与客户端读文件有微小时序差）。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if needle in testcase.server.log_text():
            return True
        time.sleep(0.05)
    return needle in testcase.server.log_text()


class AdminQueryTokenHardeningTest(MockApiTestCase):
    """SPEC §19.1：默认不再支持 ?token=，只接受 X-Admin-Token 头。"""

    def test_query_token_rejected_by_default(self):
        status, _headers, data, raw = self.call(
            "GET",
            "/api/admin/users?token=" + ADMIN_TOKEN,
        )
        self.assertEqual(status, 403, "默认应拒绝 ?token=，body=%r" % (raw[:500],))
        self.assert_error(data, "ADMIN_AUTH")

        status, _headers, data, raw = self.call(
            "POST",
            "/api/admin/set-registration?token=" + ADMIN_TOKEN,
            body={"enabled": True},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.40.0.9",
            },
        )
        self.assertEqual(status, 403, "管理 POST 的 ?token= 也应拒绝，body=%r" % (raw[:500],))
        self.assert_error(data, "ADMIN_AUTH")

    def test_header_token_still_works(self):
        status, _headers, data, raw = self.call(
            "GET",
            "/api/admin/users",
            headers={"X-Admin-Token": ADMIN_TOKEN},
        )
        self.assertEqual(status, 200, "header token 应可用，body=%r" % (raw[:500],))
        self.assertIs(data.get("ok"), True)


class AdminQueryTokenOptInTest(MockApiTestCase):
    """SPEC §19.1：allow_query_token=true 时仅 127.0.0.1 可用 query token。"""

    config_overrides = {"security": {"allow_query_token": True}}

    def test_query_token_allowed_from_localhost_only(self):
        path = "/api/admin/users?token=" + ADMIN_TOKEN
        # 来源 IP=127.0.0.1（mock 下无 X-Test-Client-IP 即本机回环）→ 允许
        status, _headers, data, raw = self.call("GET", path)
        self.assertEqual(
            status, 200, "allow_query_token=true 且本机来源应允许，body=%r" % (raw[:500],)
        )
        self.assertIs(data.get("ok"), True)
        # 非本机来源 → 拒绝
        status, _headers, data, raw = self.call(
            "GET", path, headers={"X-Test-Client-IP": "10.40.1.1"}
        )
        self.assertEqual(
            status, 403, "非 127.0.0.1 来源不得使用 query token，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "ADMIN_AUTH")


class AdminLockoutTest(MockApiTestCase):
    """SPEC §19.1：同 IP 15 分钟内鉴权失败 ≥10 次 → 403 ADMIN_LOCKED；成功清零。"""

    def _admin_get(self, ip, token=None):
        headers = {"X-Test-Client-IP": ip}
        if token is not None:
            headers["X-Admin-Token"] = token
        return self.call("GET", "/api/admin/users", headers=headers)

    def test_lock_after_10_failures(self):
        ip = "10.40.2.1"
        locked_at = None
        for attempt in range(1, 13):
            status, _headers, data, _raw = self._admin_get(ip, token="wrong-token")
            self.assertEqual(status, 403, "错误 token 应 403（attempt=%d）" % attempt)
            self.assertFalse(data.get("ok"))
            code = data["error"]["code"]
            self.assertIn(code, ("ADMIN_AUTH", "ADMIN_LOCKED"))
            if code == "ADMIN_LOCKED" and locked_at is None:
                locked_at = attempt
            if locked_at is not None:
                break
        self.assertIsNotNone(locked_at, "连续错误 token 后应触发 ADMIN_LOCKED")
        self.assertLessEqual(locked_at, 12)
        # 锁定后即使 token 正确也被拒绝
        status, _headers, data, raw = self._admin_get(ip, token=ADMIN_TOKEN)
        self.assertEqual(status, 403, "锁定后正确 token 也应 403，body=%r" % (raw[:500],))
        self.assert_error(data, "ADMIN_LOCKED")
        # 安全事件日志
        log = self.server.log_text()
        self.assertIn("admin_auth_locked", log, "锁定事件应记录到日志（SPEC §19.1/§19.6）")

    def test_success_resets_failure_counter(self):
        ip = "10.40.2.2"
        for _ in range(9):
            status, _headers, _data, _raw = self._admin_get(ip, token="wrong-token")
            self.assertEqual(status, 403)
        # 9 次失败后正确 token 仍可成功（未达 10 次）；且成功应清零计数
        status, _headers, data, _raw = self._admin_get(ip, token=ADMIN_TOKEN)
        self.assertEqual(status, 200, "9 次失败后正确 token 应成功")
        self.assertIs(data.get("ok"), True)
        for _ in range(9):
            status, _headers, _data, _raw = self._admin_get(ip, token="wrong-token")
            self.assertEqual(status, 403)
        status, _headers, data, raw = self._admin_get(ip, token=ADMIN_TOKEN)
        self.assertEqual(
            status, 200, "成功鉴权应清零失败计数（否则第 10 次失败会锁定），body=%r" % (raw[:500],)
        )

    def test_lock_is_per_ip(self):
        locked_ip = "10.40.2.3"
        for _ in range(11):
            status, _headers, data, _raw = self._admin_get(locked_ip, token="wrong-token")
            if data.get("error", {}).get("code") == "ADMIN_LOCKED":
                break
            self.assertEqual(status, 403)
        status, _headers, data, _raw = self._admin_get(locked_ip, token=ADMIN_TOKEN)
        self.assertEqual(status, 403)
        self.assertEqual(data["error"]["code"], "ADMIN_LOCKED")
        # 其他 IP 不受影响
        status, _headers, data, _raw = self._admin_get("10.40.2.4", token=ADMIN_TOKEN)
        self.assertEqual(status, 200, "其他 IP 不应被连带锁定")


class AdminCidrTest(MockApiTestCase):
    """SPEC §19.1：security.admin_allowed_cidrs 限制 /admin 与 /api/admin/*。"""

    config_overrides = {
        "security": {"admin_allowed_cidrs": ["10.0.0.0/8", "127.0.0.1/32"]}
    }

    def _get(self, path, ip, token=None):
        headers = {"X-Test-Client-IP": ip}
        if token is not None:
            headers["X-Admin-Token"] = token
        return self.call("GET", path, headers=headers)

    def test_allowed_cidrs(self):
        for ip in ("10.1.2.3", "127.0.0.1"):
            with self.subTest(ip=ip):
                status, headers, _data, raw = self.call(
                    "GET", "/admin", headers={"X-Test-Client-IP": ip}
                )
                self.assertEqual(status, 200, "允许来源应可访问 /admin（ip=%s）" % ip)
                status, _headers, data, raw = self._get(
                    "/api/admin/users", ip, token=ADMIN_TOKEN
                )
                self.assertEqual(status, 200, "允许来源应可访问管理 API（ip=%s）" % ip)
                self.assertIs(data.get("ok"), True)

    def test_disallowed_cidrs(self):
        ip = "192.168.5.6"
        status, _headers, data, raw = self._get("/admin", ip)
        self.assertEqual(status, 403, "非允许来源访问 /admin 应 403，body=%r" % (raw[:500],))
        self.assertFalse(data.get("ok"))
        status, _headers, data, raw = self._get(
            "/api/admin/users", ip, token=ADMIN_TOKEN
        )
        self.assertEqual(status, 403, "非允许来源访问管理 API 应 403，body=%r" % (raw[:500],))
        self.assertFalse(data.get("ok"))
        # 普通公开接口不受 admin CIDR 影响
        status, _headers, data, _raw = self._get("/api/health", ip)
        self.assertEqual(status, 200, "admin CIDR 不应影响公开 health")
        self.assertIs(data.get("ok"), True)


class HardeningHeadersTest(MockApiTestCase):
    """SPEC §19.3：HSTS/COOP/CORP/Permissions-Policy/X-Robots-Tag。"""

    def test_hardening_headers_on_all_responses(self):
        for path in ("/api/health", "/", "/admin", "/api/unknown"):
            with self.subTest(path=path):
                status, headers, _data, _raw = self.call("GET", path)
                self.assertIn(status, (200, 404))
                # assert_security_headers 已包含 §19.3 的 HSTS/COOP/CORP/Permissions-Policy
                self.assert_security_headers(headers)

    def test_robots_tag_on_admin_and_api(self):
        for path in ("/api/health", "/admin"):
            with self.subTest(path=path):
                _status, headers, _data, _raw = self.call("GET", path)
                robots = (_header(headers, "X-Robots-Tag") or "").lower()
                self.assertIn("noindex", robots, "X-Robots-Tag 缺少 noindex: %r" % (robots,))
                self.assertIn("nofollow", robots, "X-Robots-Tag 缺少 nofollow: %r" % (robots,))

    def test_method_whitelist(self):
        for method in ("PUT", "DELETE", "PATCH", "OPTIONS"):
            for path in ("/", "/api/health"):
                with self.subTest(method=method, path=path):
                    status, _headers, data, raw = self.call(method, path)
                    self.assertEqual(
                        status, 405, "%s %s 应 405，body=%r" % (method, path, raw[:300])
                    )
                    self.assert_error(data, "METHOD_NOT_ALLOWED")

    def test_head_only_static(self):
        # HEAD 静态资源：允许且 200
        status, headers, _data, _raw = self.call("HEAD", "/")
        self.assertEqual(status, 200, "HEAD / 应 200")
        self.assertIn("text/html", (_header(headers, "Content-Type") or "").lower())
        # HEAD 非静态（API）→ 405（SPEC §19.2：HEAD 仅静态资源）
        status, _headers, data, raw = self.call("HEAD", "/api/health")
        self.assertEqual(status, 405, "HEAD /api/health 应 405，body=%r" % (raw[:300],))


class ConcurrencyLimitTest(MockApiTestCase):
    """SPEC §19.2：并发上限（可配置）生效 → 超限 503，且不阻塞正常请求。"""

    # 将上限调小到 8，便于稳定验证（SPEC 允许配置；生产默认 64）
    config_overrides = {"server": {"max_concurrent_connections": 8}}

    def test_low_load_requests_served(self):
        idle = []
        try:
            for _ in range(3):
                idle.append(
                    socket.create_connection(("127.0.0.1", self.server.port), timeout=5.0)
                )
            time.sleep(0.2)
            status, _headers, _body = self.server.request("GET", "/healthz", timeout=5.0)
            self.assertEqual(status, 200, "上限以下并发连接不应影响正常请求")
        finally:
            for connection in idle:
                try:
                    connection.close()
                except OSError:
                    pass

    def test_connection_cap_returns_503_and_recovers(self):
        sockets = []
        rejected = 0
        served = 0
        try:
            # 上限 8：开 24 个不发请求的空闲连接，超出部分应收到 503
            for _ in range(24):
                try:
                    sockets.append(
                        socket.create_connection(
                            ("127.0.0.1", self.server.port), timeout=3.0
                        )
                    )
                except OSError:
                    time.sleep(0.05)
                    continue
                time.sleep(0.01)
            time.sleep(1.2)
            for connection in sockets:
                connection.settimeout(0.8)
                payload = b""
                try:
                    payload = connection.recv(4096)
                except socket.timeout:
                    payload = b""
                except OSError:
                    payload = b""
                first_line = payload.split(b"\r\n", 1)[0] if payload else b""
                if b"503" in first_line:
                    rejected += 1
                elif not first_line:
                    served += 1
            self.assertGreaterEqual(
                rejected, 1, "超过并发上限时应有连接收到 503（SPEC §19.2）"
            )
            self.assertGreaterEqual(
                served, 1, "上限内的连接应被服务（不会全部 503）"
            )
            self.assertTrue(
                _wait_log_contains(self, "connection_rejected"),
                "超限拒绝应有结构化安全日志（SPEC §19.6）",
            )
        finally:
            for connection in sockets:
                try:
                    connection.close()
                except OSError:
                    pass
        # 连接释放后服务应恢复
        deadline = time.time() + 10.0
        last_status = None
        while time.time() < deadline:
            try:
                last_status, _headers, _body = self.server.request(
                    "GET", "/healthz", timeout=3.0
                )
                if last_status == 200:
                    break
            except Exception:
                last_status = None
            time.sleep(0.15)
        self.assertEqual(last_status, 200, "并发释放后服务应恢复正常")


class LogHygieneTest(MockApiTestCase):
    """SPEC §19.6：日志不得出现明文验证码/SMTP 密码/token/完整邮箱。"""

    def test_logs_are_redacted(self):
        email = self.new_email()
        data, _raw = self.send_code_ok(email, "10.41.0.1")
        code = str(data["debug_code"])
        self.register_ok("日志测试", "10.41.0.1", email=email, email_code=code)
        log = self.server.log_text()
        self.assertNotIn(code, log, "日志不得出现明文验证码（SPEC §18.3/§19.6）")
        self.assertNotIn(EMAIL_SMTP_PASSWORD, log, "日志不得出现 SMTP 密码")
        self.assertNotIn(ADMIN_TOKEN, log, "日志不得出现 admin token")
        self.assertNotIn(STRONG_PW, log, "日志不得出现密码")
        # SPEC §19.6：完整邮箱应掩码
        self.assertNotIn(email, log, "日志不应记录完整邮箱（应掩码，如 h***5@...）")


class AdminLockoutConfigTest(MockApiTestCase):
    """SPEC §19.1：security.admin_lockout 可配置（阈值 + 锁定恢复）。"""

    config_overrides = {
        "security": {
            "admin_lockout": {
                "window_seconds": 60,
                "max_failures": 2,
                "lockout_seconds": 2,
            }
        }
    }

    def _admin_get(self, ip, token=None):
        headers = {"X-Test-Client-IP": ip}
        if token is not None:
            headers["X-Admin-Token"] = token
        return self.call("GET", "/api/admin/users", headers=headers)

    def test_custom_threshold_and_auto_recovery(self):
        ip = "10.42.0.10"
        for _ in range(2):
            status, _headers, data, _raw = self._admin_get(ip, "wrong-token")
            self.assertEqual(status, 403)
            self.assertFalse(data.get("ok"))
        status, _headers, data, raw = self._admin_get(ip, ADMIN_TOKEN)
        self.assertEqual(status, 403, "自定义阈值 2 次后应锁定，body=%r" % (raw[:500],))
        self.assert_error(data, "ADMIN_LOCKED")
        # lockout_seconds=2：等待后应自动恢复
        time.sleep(2.4)
        status, _headers, data, raw = self._admin_get(ip, ADMIN_TOKEN)
        self.assertEqual(
            status, 200, "lockout_seconds 到期后应恢复，body=%r" % (raw[:500],)
        )
        self.assertIs(data.get("ok"), True)


class AdminLockoutWindowTest(MockApiTestCase):
    """SPEC §19.1：失败计数窗口 window_seconds 过期后重置（不累计锁定）。"""

    config_overrides = {
        "security": {
            "admin_lockout": {
                "window_seconds": 2,
                "max_failures": 2,
                "lockout_seconds": 60,
            }
        }
    }

    def _admin_get(self, ip, token=None):
        headers = {"X-Test-Client-IP": ip}
        if token is not None:
            headers["X-Admin-Token"] = token
        return self.call("GET", "/api/admin/users", headers=headers)

    def test_failures_outside_window_not_accumulated(self):
        ip = "10.42.0.11"
        status, _headers, _data, _raw = self._admin_get(ip, "wrong-token")
        self.assertEqual(status, 403)
        time.sleep(2.4)  # 超过 window_seconds=2，旧失败应被清理
        status, _headers, data, raw = self._admin_get(ip, "wrong-token")
        self.assertEqual(status, 403)
        self.assertEqual(
            data["error"]["code"], "ADMIN_AUTH", "窗口外失败不应累计到锁定，body=%r" % (raw[:500],)
        )
        status, _headers, data, _raw = self._admin_get(ip, ADMIN_TOKEN)
        self.assertEqual(status, 200, "窗口重置后正确 token 应可用")
        self.assertIs(data.get("ok"), True)


class DeployConfigTemplateTest(unittest.TestCase):
    """SPEC §19 部署模板契约（只读校验 deploy/config.example.json）。"""

    @classmethod
    def setUpClass(cls):
        path = os.path.join(PROJECT_ROOT, "deploy", "config.example.json")
        if not os.path.isfile(path):
            raise unittest.SkipTest("deploy/config.example.json 不存在")
        with open(path, "r", encoding="utf-8") as handle:
            cls.cfg = json.load(handle)

    def test_bind_and_concurrency(self):
        self.assertEqual(self.cfg["server"]["bind"], "10.0.0.10")
        self.assertEqual(self.cfg["server"].get("max_concurrent_connections"), 64)
        self.assertIs(self.cfg["tls"]["enabled"], True)

    def test_admin_security_fields(self):
        security = self.cfg["security"]
        self.assertIs(security.get("allow_query_token"), False)
        allowed = security.get("admin_allowed_cidrs") or []
        self.assertIn("10.0.0.0/8", allowed)
        self.assertIn("127.0.0.1/32", allowed)
        lockout = security.get("admin_lockout") or {}
        self.assertEqual(
            set(lockout.keys()), {"window_seconds", "max_failures", "lockout_seconds"}
        )
        self.assertEqual(lockout["window_seconds"], 900)
        self.assertEqual(lockout["max_failures"], 10)
        self.assertEqual(lockout["lockout_seconds"], 900)

    def test_email_config_placeholders_safe(self):
        email = self.cfg["email"]
        self.assertEqual(
            email.get("allowed_domains"), ["mails.example.edu.cn", "example.edu.cn"]
        )
        self.assertIs(email.get("tls_verify") if "tls_verify" in email else email["smtp"].get("tls_verify"), True)
        self.assertEqual(email["smtp"].get("username"), "")
        self.assertEqual(email["smtp"].get("password"), "")
        self.assertEqual(email.get("code_secret"), "")
        self.assertEqual(email.get("max_send_global_per_day"), 300)
        rate = self.cfg["rate_limits"]["email_send"]
        self.assertEqual(rate.get("max_requests"), 20)
        self.assertEqual(rate.get("window_seconds"), 3600)

    def test_password_reset_config(self):
        """SPEC §21.3：rate_limits.password_reset 默认 20 次/小时（模板）。"""
        rate = self.cfg["rate_limits"]["password_reset"]
        self.assertEqual(rate.get("max_requests"), 20)
        self.assertEqual(rate.get("window_seconds"), 3600)

    def test_v15_bind_config(self):
        """SPEC §22.4/§22.6（F11 后）：rate_limits.bind 默认 10 次/小时；
        security.bind_lockout 未配置时使用默认 900s/5 次/900s（模板可显式覆盖）。"""
        rate = self.cfg["rate_limits"]["bind"]
        self.assertEqual(rate.get("max_requests"), 10)
        self.assertEqual(rate.get("window_seconds"), 3600)
        lockout = self.cfg["security"].get("bind_lockout")
        if lockout is not None:
            self.assertEqual(
                set(lockout.keys()),
                {"window_seconds", "max_failures", "lockout_seconds"},
            )
            self.assertEqual(lockout["window_seconds"], 900)
            self.assertEqual(lockout["max_failures"], 5)
            self.assertEqual(lockout["lockout_seconds"], 900)



if __name__ == "__main__":
    unittest.main(verbosity=2)
