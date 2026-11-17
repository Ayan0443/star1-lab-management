#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §22（v1.5）production 路径集成测试：绑定邮箱 / 全用户管理 / 禁用删除用户。

做法：production 模式 app/server.py + 本地 SMTP sink（真实 smtplib 发码）+ fake Unix-socket provisioner
（实现 list_users / verify_password / user_status / reset_password / set_lock，并模拟特权/不可管理账号）。
不联网、不用真实 SMTP 凭据；结束清理临时目录、socket 与子进程。
"""

import email
import email.policy
import json
import os
import re
import shutil
import socket
import sqlite3
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), PROJECT_ROOT, TESTS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from app.security import validate_password as app_validate_password  # noqa: E402
from test_api_mock import (  # noqa: E402
    EMAIL_ALLOWED_DOMAINS,
    EMAIL_CODE_SECRET,
    EMAIL_FROM_ADDR,
    EMAIL_FROM_NAME,
    EMAIL_SUBJECT,
    EMAIL_TTL_SECONDS,
    NEW_STRONG_PW,
    STRONG_PW,
    MockServer,
    _next_email,
)
from test_email_smtp import SmtpSink  # noqa: E402

CODE_RE = re.compile(r"\b\d{6}\b")
OLD_PW = "Old#ServerPw9!x2"
SYS_PW = "Sys#UserPw8!x3"


class FakeProvisioner15(object):
    """v1.5 所需最小 provisioner（Unix socket 换行 JSON）。"""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.requests = []
        self.create_requests = []
        self.reset_requests = []
        self.lock_requests = []
        self.passwords = {}
        self.manageable = {}
        self.locked = {}
        self.privileged = {}
        self.meta = {}
        self.list_users_mode = "ok"   # ok | unavailable
        self.reset_mode = "ok"        # ok | missing
        self._next_uid = 2000
        self._lock = threading.Lock()
        self._stop = threading.Event()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(socket_path)
        self._sock.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # ---- 测试辅助 ----

    def set_user(self, username, password, uid=None, real_name="已有用户",
                 locked=False, privileged=False, manageable=None, home=None):
        if uid is None:
            uid = self._next_uid
            self._next_uid += 1
        with self._lock:
            self.passwords[username] = password
            self.privileged[username] = bool(privileged)
            self.locked[username] = bool(locked)
            self.manageable[username] = (
                bool(manageable) if manageable is not None else not privileged
            )
            self.meta[username] = {
                "uid": uid,
                "gid": uid,
                "home": home or ("/home/" + username),
                "real_name": real_name,
            }
        return username

    # ---- socket 服务 ----

    def _serve(self):
        while not self._stop.is_set():
            try:
                connection, _address = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(connection,), daemon=True).start()

    def _handle(self, connection):
        try:
            stream = connection.makefile("rb")
            for line in stream:
                if not line.strip():
                    continue
                request = json.loads(line.decode("utf-8"))
                response = self._dispatch(request)
                connection.sendall(
                    json.dumps(response, ensure_ascii=False).encode("utf-8") + b"\n"
                )
        except (OSError, ValueError):
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    def _user_status(self, username):
        if username not in self.meta:
            return {"exists": False}
        info = self.meta[username]
        groups = [username]
        if self.privileged.get(username):
            groups.append("sudo")
        return {
            "exists": True,
            "uid": info["uid"],
            "gid": info["gid"],
            "home": info["home"],
            "locked": bool(self.locked.get(username)),
            "groups": groups,
            "privileged": bool(self.privileged.get(username)),
        }

    def _dispatch(self, request):
        with self._lock:
            self.requests.append(request)
        op = request.get("op")
        if op == "ping":
            return {"ok": True}
        if op == "create_user":
            username = request.get("username")
            with self._lock:
                self.create_requests.append(request)
            if username not in self.meta:
                self.set_user(
                    username,
                    request.get("password") or "",
                    real_name=request.get("real_name") or username,
                )
            info = self.meta[username]
            return {
                "ok": True,
                "username": username,
                "uid": info["uid"],
                "gid": info["gid"],
                "home": info["home"],
                "workspace": info["home"],
                "real_name": request.get("real_name"),
            }
        if op == "verify_password":
            username = request.get("username")
            password = request.get("password")
            if username not in self.meta:
                return {"ok": True, "exists": False, "manageable": False, "locked": False}
            if not self.manageable.get(username, True) or self.privileged.get(username):
                return {
                    "ok": True,
                    "exists": True,
                    "manageable": False,
                    "locked": bool(self.locked.get(username)),
                }
            return {
                "ok": True,
                "exists": True,
                "manageable": bool(self.passwords.get(username) == password),
                "locked": bool(self.locked.get(username)),
            }
        if op == "list_users":
            if self.list_users_mode == "unavailable":
                return {"ok": False, "error": {"code": "INTERNAL", "message": "provisioner 不可用"}}
            users = []
            for username, info in sorted(self.meta.items()):
                groups = [username]
                if self.privileged.get(username):
                    groups.append("sudo")
                users.append({
                    "username": username,
                    "uid": info["uid"],
                    "gid": info["gid"],
                    "home": info["home"],
                    "shell": "/bin/bash",
                    "real_name": info["real_name"],
                    "groups": groups,
                    "privileged": bool(self.privileged.get(username)),
                    "locked": bool(self.locked.get(username)),
                })
            return {"ok": True, "users": users}
        if op == "user_status":
            usernames = request.get("usernames") or []
            return {"ok": True, "users": {name: self._user_status(name) for name in usernames}}
        if op == "reset_password":
            username = request.get("username")
            with self._lock:
                self.reset_requests.append(request)
                mode = self.reset_mode
            if mode == "missing" or username not in self.meta:
                return {"ok": False, "error": {"code": "INVALID", "message": "用户不存在"}}
            with self._lock:
                self.passwords[username] = request.get("password") or ""
            return {"ok": True, "username": username}
        if op == "set_lock":
            username = request.get("username")
            with self._lock:
                self.lock_requests.append(request)
            if username not in self.meta:
                return {"ok": False, "error": {"code": "INVALID", "message": "用户不存在"}}
            with self._lock:
                self.locked[username] = bool(request.get("locked"))
            return {"ok": True, "username": username, "locked": bool(request.get("locked"))}
        if op == "delete_user":
            return {
                "ok": False,
                "error": {"code": "INVALID", "message": "删除用户功能已禁用"},
            }
        return {"ok": False, "error": {"code": "INVALID", "message": "未知操作"}}

    def stop(self):
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
        self._thread.join(timeout=3)
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass


def _email_config(smtp_port):
    return {
        "enabled": True,
        "allowed_domains": list(EMAIL_ALLOWED_DOMAINS),
        "smtp": {
            "host": "127.0.0.1",
            "port": smtp_port,
            "security": "none",
            "username": "",
            "password": "",
            "from_name": EMAIL_FROM_NAME,
            "from_addr": EMAIL_FROM_ADDR,
            "tls_verify": False,
            "timeout_seconds": 3,
        },
        "code_secret": EMAIL_CODE_SECRET,
        "code_ttl_seconds": EMAIL_TTL_SECONDS,
        "resend_cooldown_seconds": 60,
        "max_verify_attempts": 5,
        "max_send_per_email_per_day": 10,
        "max_send_global_per_day": 300,
        "subject": EMAIL_SUBJECT,
    }


class ProductionHarness(object):
    def __init__(self, rate_overrides=None, security_overrides=None):
        tag = os.environ.get("QA_RUN_TAG", "").strip()
        self.workdir = tempfile.mkdtemp(prefix="csqa-" + (tag + "-" if tag else "") + "bind-")
        self.provisioner_socket = os.path.join(self.workdir, "p.sock")
        self.sink = SmtpSink()
        self.fake = FakeProvisioner15(self.provisioner_socket)
        rate_limits = {
            "preview": {"window_seconds": 60, "max_requests": 120},
            "generate_password": {"window_seconds": 60, "max_requests": 120},
            "register": {"window_seconds": 600, "max_requests": 50},
            "admin": {"window_seconds": 60, "max_requests": 200},
            "announcement": {"window_seconds": 60, "max_requests": 120},
            "email_send": {"window_seconds": 3600, "max_requests": 100},
            "password_reset": {"window_seconds": 3600, "max_requests": 100},
            "bind": {"window_seconds": 3600, "max_requests": 1000},
        }
        if rate_overrides:
            for key, value in rate_overrides.items():
                rate_limits[key] = value
        security = {"trusted_proxies": ["127.0.0.1/32"]}
        if security_overrides:
            security.update(security_overrides)
        self.server = MockServer(
            {
                "mode": "production",
                "tls": {"enabled": False},
                "provisioner": {
                    "socket": self.provisioner_socket,
                    "timeout_seconds": 5,
                    "allowed_peer_uid": -1,
                },
                "security": security,
                "email": _email_config(self.sink.port),
                "rate_limits": rate_limits,
            }
        )

    def stop(self):
        try:
            self.server.stop()
        finally:
            self.fake.stop()
            self.sink.close()
            shutil.rmtree(self.workdir, ignore_errors=True)

    @property
    def db_path(self):
        return os.path.join(self.server.tmpdir, "registrations.db")

    # ---- HTTP ----

    def request(self, method, path, body=None, ip="10.90.0.1", headers=None, timeout=15.0):
        request_headers = {"X-Forwarded-For": ip}
        if body is not None:
            request_headers["X-Requested-With"] = "campus-signup"
        if headers:
            request_headers.update(headers)
        status, response_headers, raw = self.server.request(
            method, path, body=body, headers=request_headers, timeout=timeout
        )
        data = None
        if raw:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                data = None
        return status, response_headers, data, raw

    def post(self, path, body, ip="10.90.0.1"):
        return self.request("POST", path, body=body, ip=ip)

    # ---- 邮件验证码 ----

    def next_code(self, address, timeout=10.0):
        seen = getattr(self, "_seen", None)
        if seen is None:
            seen = self._seen = {}
        deadline = time.time() + timeout
        while time.time() < deadline:
            messages = self.sink.wait_for_messages(1, timeout=0.5)
            with self.sink._lock:  # noqa: SLF001
                relevant = [
                    item for item in messages
                    if item.get("rcpt") and item["rcpt"][0] == address
                ]
            index = seen.get(address, 0)
            if len(relevant) > index:
                seen[address] = index + 1
                parsed = email.parser.BytesParser(
                    policy=email.policy.default
                ).parsebytes(relevant[index]["data"])
                codes = CODE_RE.findall(parsed.get_content())
                if not codes:
                    continue
                return codes[0], parsed
            time.sleep(0.05)
        raise AssertionError("未收到发往 %r 的验证码邮件" % (address,))

    # ---- DB ----

    def query_user_emails(self, email=None):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            if email is None:
                rows = conn.execute("SELECT * FROM user_emails").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM user_emails WHERE email = ?", (email,)
                ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def query_email_codes(self, email):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM email_codes WHERE email = ? ORDER BY id", (email,)
            ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def verify_password_calls(self):
        return sum(
            1 for request in self.fake.requests if request.get("op") == "verify_password"
        )

    def clear_email_codes(self, email):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("DELETE FROM email_codes WHERE email = ?", (email,))
            conn.commit()
        finally:
            conn.close()

    def expire_email_code(self, email):
        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute(
                "UPDATE email_codes SET expires_at = ? WHERE email = ?",
                (int(time.time()) - 10, email),
            )
            conn.commit()
        finally:
            conn.close()

    def admin_headers(self):
        from test_api_mock import ADMIN_TOKEN
        return {"X-Admin-Token": ADMIN_TOKEN}


# ---------------------------------------------------------------------------
# 自助绑定邮箱（SPEC §22.4）
# ---------------------------------------------------------------------------

class BindEmailFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = ProductionHarness()
        cls.fake = cls.harness.fake
        cls.fake.set_user("olduser", OLD_PW, uid=1500, real_name="旧用户")
        cls.fake.set_user(
            "privuser", OLD_PW, uid=1050, real_name="特权用户", privileged=True
        )

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def setUp(self):
        self.fake.reset_mode = "ok"
        self.fake.list_users_mode = "ok"

    # ---- helpers ----

    def _bind_request(self, username, password, email, ip="10.91.0.1"):
        return self.harness.post(
            "/api/email/bind-request",
            {"username": username, "password": password, "email": email},
            ip=ip,
        )

    def _bind(self, username, password, email, code, ip="10.91.0.1"):
        return self.harness.post(
            "/api/email/bind",
            {"username": username, "password": password, "email": email, "code": code},
            ip=ip,
        )

    def _bind_ok(self, username, password, email, ip="10.91.0.1"):
        status, _headers, _data, raw = self._bind_request(username, password, email, ip)
        self.assertEqual(status, 200, "bind-request 应 200，body=%r" % (raw[:800],))
        code, _mail = self.harness.next_code(email)
        status, _headers, _data, raw = self._bind(username, password, email, code, ip)
        self.assertEqual(status, 200, "bind 应 200，body=%r" % (raw[:800],))
        return json.loads(raw.decode("utf-8")), code

    # ---- tests ----

    def test_bind_success_and_forgot_password(self):
        self.fake.set_user("bindusera", OLD_PW, uid=1900, real_name="绑定用户A")
        email = _next_email()
        status, _headers, _data, raw = self._bind_request("bindusera", OLD_PW, email)
        self.assertEqual(status, 200, "bind-request 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("email"), email)
        self.assertNotIn(OLD_PW, raw.decode("utf-8"), "响应不得回显密码")
        code, mail = self.harness.next_code(email)
        self.assertIn("绑定", mail.get_content(), "bind 用途邮件正文应说明绑定邮箱")

        status, _headers, _data, raw = self._bind("bindusera", OLD_PW, email, code)
        self.assertEqual(status, 200, "bind 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual(data.get("username"), "bindusera")
        self.assertEqual(data.get("email"), email)
        rows = self.harness.query_user_emails(email)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "bindusera")
        self.assertEqual(rows[0]["source"], "self")

        # 绑定后可走忘记密码
        self.harness.clear_email_codes(email)
        status, _headers, _data, raw = self.harness.post(
            "/api/password/reset-request", {"email": email}, ip="10.91.0.2"
        )
        self.assertEqual(status, 200, "绑定邮箱 reset-request 应 200，body=%r" % (raw[:800],))
        reset_code, _mail = self.harness.next_code(email)
        before = len(self.fake.reset_requests)
        status, _headers, _data, raw = self.harness.post(
            "/api/password/reset",
            {"email": email, "code": reset_code, "new_password": NEW_STRONG_PW},
            ip="10.91.0.2",
        )
        self.assertEqual(status, 200, "绑定后重置密码应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual(data.get("username"), "bindusera")
        self.assertEqual(len(self.fake.reset_requests), before + 1)
        self.assertEqual(self.fake.reset_requests[-1]["username"], "bindusera")
        self.assertEqual(self.fake.reset_requests[-1]["password"], NEW_STRONG_PW)
        ok, message = app_validate_password(NEW_STRONG_PW, "bindusera")
        self.assertTrue(ok, "新密码应满足策略: %r" % (message,))

    def test_invalid_credentials_unified_no_enumeration(self):
        self.fake.set_user("creduser", OLD_PW, uid=1910, real_name="凭据用户")
        email1 = _next_email()
        status, _headers, _data, raw = self._bind_request("creduser", "Wrong#Password1", email1)
        self.assertEqual(status, 400, "错误密码应 400，body=%r" % (raw[:600],))
        data_wrong = json.loads(raw.decode("utf-8"))
        self.assertEqual(data_wrong["error"]["code"], "INVALID_CREDENTIALS")
        self.assertNotIn("Wrong#Password1", raw.decode("utf-8"))

        email2 = _next_email()
        status, _headers, _data, raw = self._bind_request("nosuchuser", OLD_PW, email2)
        self.assertEqual(status, 400, "不存在用户应 400（统一错误），body=%r" % (raw[:600],))
        data_missing = json.loads(raw.decode("utf-8"))
        self.assertEqual(data_missing["error"]["code"], "INVALID_CREDENTIALS")

        email3 = _next_email()
        status, _headers, _data, raw = self._bind_request("privuser", OLD_PW, email3)
        self.assertEqual(status, 400, "不可管理账号应 400（统一错误），body=%r" % (raw[:600],))
        data_priv = json.loads(raw.decode("utf-8"))
        self.assertEqual(data_priv["error"]["code"], "INVALID_CREDENTIALS")

        # 三种失败提示完全一致（不区分账号不存在/密码错/不可管理）
        self.assertEqual(
            data_wrong["error"]["message"],
            data_missing["error"]["message"],
            "错误提示必须统一，避免账号枚举",
        )
        self.assertEqual(
            data_wrong["error"]["message"], data_priv["error"]["message"]
        )
        log = self.harness.server.log_text()
        self.assertNotIn(OLD_PW, log, "日志不得出现绑定密码")
        self.assertNotIn("Wrong#Password1", log)

    def test_invalid_email_username_domain(self):
        self.fake.set_user("formatcheck", OLD_PW, uid=1920, real_name="格式用户")
        status, _headers, data, raw = self._bind_request(
            "formatcheck", OLD_PW, "x@qq.com"
        )
        self.assertEqual(status, 400, "非学校邮箱应 400，body=%r" % (raw[:500],))
        self.assert_error_code(data, "INVALID_EMAIL")
        status, _headers, data, raw = self._bind_request(
            "Bad_Name!", OLD_PW, _next_email()
        )
        self.assertEqual(status, 400, "非法用户名应 400，body=%r" % (raw[:500],))
        self.assert_error_code(data, "INVALID_USERNAME")

    def assert_error_code(self, data, expected):
        self.assertIsInstance(data, dict)
        self.assertFalse(data.get("ok"))
        self.assertEqual((data.get("error") or {}).get("code"), expected)

    def test_email_already_bound_and_account_already_bound(self):
        self.fake.set_user("bounduser", OLD_PW, uid=1930, real_name="已绑用户")
        self.fake.set_user("otheruser", SYS_PW, uid=1600, real_name="其他用户")
        bound_email = _next_email()
        self._bind_ok("bounduser", OLD_PW, bound_email)

        status, _headers, data, raw = self._bind_request(
            "otheruser", SYS_PW, bound_email
        )
        self.assertEqual(status, 409, "邮箱已被占用应 409，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "EMAIL_ALREADY_BOUND")

        # 已绑定账号再绑另一个邮箱 → 409 EMAIL_ALREADY_BOUND（先于验证码）
        new_email = _next_email()
        status, _headers, data, raw = self._bind_request(
            "bounduser", OLD_PW, new_email
        )
        self.assertEqual(status, 409, "已绑定账号重复绑定应 409，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "EMAIL_ALREADY_BOUND")

    def test_purpose_isolation_bind_vs_register_and_reset(self):
        # A) 注册验证码不能用于绑定
        reg_email = _next_email()
        status, _headers, data, raw = self.harness.post(
            "/api/email/send-code", {"email": reg_email}, ip="10.91.1.1"
        )
        self.assertEqual(status, 200, "send-code 应 200，body=%r" % (raw[:500],))
        register_code = json.loads(raw.decode("utf-8")).get("debug_code")
        if not register_code:  # production 模式从 sink 取码
            register_code, _mail = self.harness.next_code(reg_email)
        self.fake.set_user("binduser1", OLD_PW, uid=1610, real_name="绑定一")
        status, _headers, data, raw = self._bind(
            "binduser1", OLD_PW, reg_email, register_code
        )
        self.assertEqual(status, 400, "注册码用于绑定应 400，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "EMAIL_CODE_INVALID")

        # B) 绑定验证码不能用于注册
        bind_email = _next_email()
        status, _headers, _data, _raw = self._bind_request("binduser1", OLD_PW, bind_email)
        self.assertEqual(status, 200, "bind-request 应 200")
        bind_code, _mail = self.harness.next_code(bind_email)
        status, _headers, data, raw = self.harness.post(
            "/api/register",
            {
                "name": "越权尝试",
                "password": STRONG_PW,
                "email": bind_email,
                "email_code": bind_code,
            },
            ip="10.91.1.2",
        )
        self.assertEqual(status, 400, "绑定码用于注册应 400，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "EMAIL_CODE_INVALID")

    def test_code_invalid_expired_too_many_one_time(self):
        self.fake.set_user("codeuser", OLD_PW, uid=1620, real_name="验证码用户")
        self.fake.set_user("oneuser", OLD_PW, uid=1621, real_name="一次性用户")
        # 错误验证码 → INVALID
        email = _next_email()
        self._bind_request("codeuser", OLD_PW, email)
        self.harness.next_code(email)
        status, _headers, data, raw = self._bind("codeuser", OLD_PW, email, "000000")
        self.assertEqual(status, 400, "错误验证码应 400，body=%r" % (raw[:500],))
        self.assert_error_code(data, "EMAIL_CODE_INVALID")
        self.harness.clear_email_codes(email)
        # 过期 → EXPIRED
        email_exp = _next_email()
        self._bind_request("codeuser", OLD_PW, email_exp)
        exp_code, _mail = self.harness.next_code(email_exp)
        self.harness.expire_email_code(email_exp)
        status, _headers, data, raw = self._bind(
            "codeuser", OLD_PW, email_exp, exp_code
        )
        self.assertEqual(status, 400, "过期验证码应 400，body=%r" % (raw[:500],))
        self.assert_error_code(data, "EMAIL_CODE_EXPIRED")
        self.harness.clear_email_codes(email_exp)
        # 错 5 次 → TOO_MANY；正确码也需重发
        email_lim = _next_email()
        self._bind_request("codeuser", OLD_PW, email_lim)
        lim_code, _mail = self.harness.next_code(email_lim)
        error_codes = []
        for _ in range(6):
            status, _headers, data, _raw = self._bind(
                "codeuser", OLD_PW, email_lim, "111111"
            )
            error_codes.append((data.get("error") or {}).get("code"))
        self.assertIn("EMAIL_TOO_MANY_ATTEMPTS", error_codes[-2:], error_codes)
        status, _headers, data, _raw = self._bind(
            "codeuser", OLD_PW, email_lim, lim_code
        )
        self.assertEqual(status, 400)
        self.assert_error_code(data, "EMAIL_TOO_MANY_ATTEMPTS")
        # 一次性：成功绑定后 DB used=1；重放同一绑定（已绑定邮箱）→ 409 EMAIL_ALREADY_BOUND
        email_ok = _next_email()
        self._bind_ok("oneuser", OLD_PW, email_ok)
        rows = self.harness.query_email_codes(email_ok)
        self.assertTrue(rows)
        self.assertEqual(rows[-1].get("purpose"), "bind")
        self.assertEqual(int(rows[-1].get("used") or 0), 1)
        status, _headers, data, _raw = self._bind(
            "oneuser", OLD_PW, email_ok, "123456"
        )
        self.assertEqual(status, 409)
        self.assert_error_code(data, "EMAIL_ALREADY_BOUND")

    def test_concurrent_bind_attempts_atomic(self):
        self.fake.set_user("concurrentuser", OLD_PW, uid=1630, real_name="并发用户")
        email = _next_email()
        status, _headers, _data, _raw = self._bind_request("concurrentuser", OLD_PW, email)
        self.assertEqual(status, 200, "bind-request 应 200")
        self.harness.next_code(email)
        results = []
        lock = threading.Lock()

        def attempt(index):
            status, _headers, data, _raw = self._bind(
                "concurrentuser", OLD_PW, email, "000000", ip="10.91.2.%d" % (index + 10)
            )
            code = (data.get("error") or {}).get("code") if isinstance(data, dict) else None
            with lock:
                results.append((status, code))

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        invalid = sum(1 for _s, code in results if code == "EMAIL_CODE_INVALID")
        too_many = sum(1 for _s, code in results if code == "EMAIL_TOO_MANY_ATTEMPTS")
        self.assertLessEqual(invalid, 4, "并发放行错误验证码次数超限: %r" % (results,))
        self.assertGreaterEqual(too_many, 1, results)
        rows = self.harness.query_email_codes(email)
        self.assertTrue(rows)
        self.assertLessEqual(int(rows[-1].get("attempts") or 0), 5)


class BindRateLimitTest(unittest.TestCase):
    """SPEC §22.4（F11 后）：bind-request 的 IP 限流使用 rate_limits.bind；每邮箱冷却仍生效。"""

    @classmethod
    def setUpClass(cls):
        cls.harness = ProductionHarness(
            rate_overrides={
                "bind": {"window_seconds": 60, "max_requests": 2},
            }
        )
        cls.fake = cls.harness.fake

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def _bind_request(self, username, password, email, ip):
        return self.harness.post(
            "/api/email/bind-request",
            {"username": username, "password": password, "email": email},
            ip=ip,
        )

    def test_ip_rate_limited(self):
        ip = "10.92.0.1"
        for index in range(2):
            self.fake.set_user("limituser%d" % index, OLD_PW, uid=1700 + index)
            status, _headers, _data, raw = self._bind_request(
                "limituser%d" % index, OLD_PW, _next_email(), ip
            )
            self.assertEqual(status, 200, "限额内应 200，body=%r" % (raw[:600],))
        self.fake.set_user("limituser9", OLD_PW, uid=1710)
        status, headers, data, raw = self._bind_request(
            "limituser9", OLD_PW, _next_email(), ip
        )
        self.assertEqual(status, 429, "超过 rate_limits.bind 限额应 429，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")
        self.assertTrue(str(headers.get("Retry-After") or "").strip().isdigit())

    def test_per_email_cooldown(self):
        ip = "10.92.0.2"
        self.fake.set_user("cooldownuser", OLD_PW, uid=1720)
        email = _next_email()
        status, _headers, _data, raw = self._bind_request("cooldownuser", OLD_PW, email, ip)
        self.assertEqual(status, 200, "首次应 200，body=%r" % (raw[:600],))
        status, _headers, data, raw = self._bind_request(
            "cooldownuser", OLD_PW, email, ip
        )
        self.assertEqual(status, 429, "60s 冷却内重复发码应 429，body=%r" % (raw[:600],))
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")


# ---------------------------------------------------------------------------
# 全用户管理 / 删除禁用（SPEC §22.4）
# ---------------------------------------------------------------------------

class AdminUsersV15Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.harness = ProductionHarness()
        cls.fake = cls.harness.fake
        cls.fake.set_user("sysuser", SYS_PW, uid=1800, real_name="系统已有用户")
        cls.fake.set_user(
            "privuser", SYS_PW, uid=1051, real_name="特权用户", privileged=True
        )
        # portal 注册一个用户用于 source=portal / reset-ip 测试
        email = _next_email()
        status, _headers, _data, raw = cls.harness.post(
            "/api/email/send-code", {"email": email}, ip="10.93.0.1"
        )
        assert status == 200, raw
        code, _mail = cls.harness.next_code(email)
        status, _headers, _data, raw = cls.harness.post(
            "/api/register",
            {
                "name": "门户用户",
                "password": STRONG_PW,
                "email": email,
                "email_code": code,
            },
            ip="10.93.0.1",
        )
        assert status == 201, raw
        cls.portal_username = json.loads(raw.decode("utf-8"))["account"]["username"]
        cls.portal_email = email

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def setUp(self):
        self.fake.list_users_mode = "ok"

    def _admin_get(self, path):
        return self.harness.request(
            "GET", path, ip="10.93.9.9", headers=self.harness.admin_headers()
        )

    def _admin_post(self, path, body):
        return self.harness.post(path, body, ip="10.93.9.9")

    def _post_with_admin(self, path, body):
        return self.harness.request(
            "POST", path, body=body, ip="10.93.9.9",
            headers=self.harness.admin_headers(),
        )

    def test_01_admin_users_fields_and_stats(self):
        status, _headers, _data, raw = self.harness.request(
            "GET", "/api/admin/users", ip="10.93.9.9",
            headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200, "admin/users 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("ok"), True)
        users = {item["username"]: item for item in data["users"]}
        self.assertIn(self.portal_username, users)
        self.assertIn("sysuser", users)
        self.assertIn("privuser", users)
        portal = users[self.portal_username]
        self.assertEqual(portal.get("source"), "portal")
        self.assertIsInstance(portal.get("registration_id"), int)
        self.assertEqual(portal.get("email"), self.portal_email)
        self.assertEqual(portal.get("os_status"), "active")
        imported = users["sysuser"]
        self.assertEqual(imported.get("source"), "imported")
        self.assertIsNone(imported.get("registration_id"))
        self.assertIs(imported.get("privileged"), False)
        self.assertIs(users["privuser"].get("privileged"), True)
        stats = data.get("stats")
        for key in ("total", "active", "locked", "missing", "with_email", "portal", "imported"):
            self.assertIn(key, stats)
            self.assertIsInstance(stats[key], int)
        self.assertGreaterEqual(stats["total"], 3)
        self.assertGreaterEqual(stats["portal"], 1)
        self.assertGreaterEqual(stats["imported"], 2)
        self.assertGreaterEqual(stats["with_email"], 1)

    def test_02_admin_users_degraded_when_provisioner_unavailable(self):
        self.fake.list_users_mode = "unavailable"
        try:
            status, _headers, _data, raw = self.harness.request(
                "GET", "/api/admin/users", ip="10.93.9.9",
                headers=self.harness.admin_headers(),
            )
        finally:
            self.fake.list_users_mode = "ok"
        self.assertEqual(status, 200, "provisioner 不可用应降级但仍 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("ok"), True)
        users = {item["username"]: item for item in data["users"]}
        self.assertIn(self.portal_username, users, "降级时至少返回 portal 记录")
        for item in data["users"]:
            self.assertIn(item.get("os_status"), ("unknown", "active", "locked", "missing"))

    def test_03_admin_user_ops_by_username_and_privileged(self):
        # 正常用户 reset-password/set-locked 成功
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/reset-password", body={"username": "sysuser"},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200, "reset-password 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual(data.get("username"), "sysuser")
        password = data.get("password")
        ok, message = app_validate_password(password, "sysuser")
        self.assertTrue(ok, "管理员重置密码应满足策略: %r" % (message,))
        self.assertEqual(self.fake.reset_requests[-1]["username"], "sysuser")
        self.assertEqual(self.fake.reset_requests[-1]["password"], password)
        self.assertNotIn(password, self.harness.server.log_text(), "日志不得记录一次性密码")

        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/set-locked", body={"username": "sysuser", "locked": True},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200, "set-locked 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("locked"), True)

        # 特权账号 → 403 USER_NOT_MANAGEABLE
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/reset-password", body={"username": "privuser"},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 403, "特权账号应 403，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual((data.get("error") or {}).get("code"), "USER_NOT_MANAGEABLE")

        # 不存在用户 → 409 USER_MISSING
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/reset-password", body={"username": "nosuchuser"},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 409, "不存在用户应 409，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual((data.get("error") or {}).get("code"), "USER_MISSING")

    def test_04_admin_bind_email(self):
        email = _next_email()
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/bind-email", body={"username": "sysuser", "email": email},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200, "管理员绑定邮箱应 200，body=%r" % (raw[:800],))
        rows = self.harness.query_user_emails(email)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "sysuser")
        self.assertEqual(rows[0]["source"], "admin")
        # 重复绑定同一邮箱到另一账号 → 409
        self.fake.set_user("sysuser2", SYS_PW, uid=1810, real_name="系统用户二")
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/bind-email",
            body={"username": "sysuser2", "email": email},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 409, "邮箱被占用应 409，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual((data.get("error") or {}).get("code"), "EMAIL_ALREADY_BOUND")
        # 非学校邮箱 → 400
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/bind-email",
            body={"username": "sysuser2", "email": "x@qq.com"},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 400, "非学校邮箱应 400，body=%r" % (raw[:600],))

    def test_05_reset_ip_portal_only_and_old_routes_removed(self):
        status, _headers, _data, raw = self.harness.request(
            "GET", "/api/admin/users", ip="10.93.9.9",
            headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200)
        data = json.loads(raw.decode("utf-8"))
        users = {item["username"]: item for item in data["users"]}
        registration_id = users[self.portal_username]["registration_id"]
        # imported 用户无 registration_id；对随机 id reset-ip → 404
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/reset-ip", body={"id": 999999},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 404, "不存在 registration 应 404，body=%r" % (raw[:600],))
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/admin/reset-ip", body={"id": registration_id},
            ip="10.93.9.9", headers=self.harness.admin_headers(),
        )
        self.assertEqual(status, 200, "reset-ip 应 200，body=%r" % (raw[:800],))
        # 旧接口/删除接口移除
        status, _headers, _data, _raw = self.harness.request(
            "GET", "/api/admin/registrations", ip="10.93.9.9",
            headers=self.harness.admin_headers(),
        )
        self.assertIn(status, (404, 405), "旧 registrations 接口应移除")
        for body in (
            {"id": 1, "confirm_username": "sysuser"},
            {"username": "sysuser"},
        ):
            with self.subTest(body=body):
                status, _headers, _data, _raw = self.harness.request(
                    "POST", "/api/admin/delete-user", body=body,
                    ip="10.93.9.9", headers=self.harness.admin_headers(),
                )
                self.assertIn(
                    status, (404, 405), "delete-user 路由应移除（实际 %s）" % status
                )
        # 用户仍存在（fake provisioner 未被删除）
        self.assertIn("sysuser", self.fake.meta)

    def test_06_bind_password_never_logged(self):
        self.fake.set_user("loguser", SYS_PW, uid=1830, real_name="日志用户")
        email = _next_email()
        status, _headers, _data, raw = self.harness.request(
            "POST", "/api/email/bind-request",
            body={"username": "loguser", "password": SYS_PW, "email": email},
            ip="10.93.1.1",
        )
        self.assertEqual(status, 200, "bind-request 应 200，body=%r" % (raw[:800],))
        self.assertNotIn(SYS_PW, raw.decode("utf-8"))
        log = self.harness.server.log_text()
        self.assertNotIn(SYS_PW, log, "日志不得出现服务器密码")
        self.assertNotIn(email, log, "日志不应记录完整邮箱（应掩码）")



    def test_07_privileged_and_protected_admin_ops_denied(self):
        """SPEC §22.1/§22.4：特权账号只读，保护名单账号不可管理。"""
        cases = [
            ("/api/admin/reset-password", {"username": "privuser"}),
            ("/api/admin/set-locked", {"username": "privuser", "locked": True}),
            ("/api/admin/bind-email", {"username": "privuser", "email": _next_email()}),
            ("/api/admin/reset-password", {"username": "root"}),
        ]
        for path, body in cases:
            with self.subTest(path=path, body=body):
                status, _headers, data, raw = self.harness.request(
                    "POST", path, body=body, ip="10.93.9.9",
                    headers=self.harness.admin_headers(),
                )
                self.assertEqual(
                    status, 403,
                    "%s 对特权/保护账号应 403，body=%r" % (path, raw[:600]),
                )
                self.assertEqual(
                    ((data or {}).get("error") or {}).get("code"),
                    "USER_NOT_MANAGEABLE",
                )



class BindCredentialRateLimitTest(unittest.TestCase):
    """F11 回归（SPEC §22.4/§22.6）：bind 的 IP 限流必须在 verify_password 之前；
    错误密码也消耗额度；额度耗尽后即使密码正确也 429，且 provisioner verify_password 调用次数有界。"""

    @classmethod
    def setUpClass(cls):
        cls.harness = ProductionHarness(
            rate_overrides={"bind": {"window_seconds": 3600, "max_requests": 3}},
            security_overrides={
                "bind_lockout": {
                    "window_seconds": 60,
                    "max_failures": 5,
                    "lockout_seconds": 60,
                }
            },
        )
        cls.fake = cls.harness.fake
        for index in range(6):
            cls.fake.set_user("quota%d" % index, OLD_PW, uid=2200 + index)

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def _bind_request(self, username, password, email, ip):
        return self.harness.post(
            "/api/email/bind-request",
            {"username": username, "password": password, "email": email},
            ip=ip,
        )

    def test_ip_quota_applies_before_password_verify(self):
        ip = "10.95.0.1"
        before = self.harness.verify_password_calls()
        messages = []
        for index in range(3):
            status, _headers, data, raw = self._bind_request(
                "quota%d" % index, "Wrong#Pw%d" % index, _next_email(), ip
            )
            self.assertEqual(
                status, 400, "错误密码应 400 INVALID_CREDENTIALS，body=%r" % (raw[:500],)
            )
            self.assertEqual((data.get("error") or {}).get("code"), "INVALID_CREDENTIALS")
            messages.append((data.get("error") or {}).get("message"))
        # 三种失败提示统一（不泄露账号不存在/密码错/不可管理）
        self.assertEqual(len(set(messages)), 1, messages)
        # 额度用尽后：正确密码也被 429 拦截，且不再调用 verify_password
        calls_after_quota = self.harness.verify_password_calls()
        self.assertEqual(calls_after_quota - before, 3, "错误密码也必须消耗 bind 额度")
        status, _headers, data, raw = self._bind_request(
            "quota4", OLD_PW, _next_email(), ip
        )
        self.assertEqual(
            status, 429, "bind IP 额度耗尽后应 429，body=%r" % (raw[:500],)
        )
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")
        self.assertEqual(
            self.harness.verify_password_calls() - before,
            3,
            "429 必须发生在 verify_password 之前（provisioner 调用次数有界）",
        )

    def test_invalid_email_does_not_consume_bind_quota(self):
        # 本类 bind 额度=3：3 个非学校邮箱 400 不应消耗额度
        ip = "10.95.0.2"
        for _ in range(3):
            status, _headers, data, raw = self._bind_request(
                "quota0", OLD_PW, "someone@qq.com", ip
            )
            self.assertEqual(status, 400, "非学校邮箱应 400，body=%r" % (raw[:500],))
            self.assertEqual((data.get("error") or {}).get("code"), "INVALID_EMAIL")
        before = self.harness.verify_password_calls()
        status, _headers, data, raw = self._bind_request(
            "quota0", "Wrong#Pw", _next_email(), ip
        )
        self.assertEqual(
            status, 400, "格式校验不消耗 bind 额度，首个合法请求应 400，body=%r" % (raw[:500],)
        )
        self.assertEqual((data.get("error") or {}).get("code"), "INVALID_CREDENTIALS")
        self.assertEqual(self.harness.verify_password_calls(), before + 1)

    def test_bind_endpoint_shares_ip_quota_before_verify(self):
        ip = "10.95.0.3"
        # bind-request 消耗 3 次额度
        for index in range(3):
            self._bind_request("quota5", "Wrong#Pw", _next_email(), ip)
        before = self.harness.verify_password_calls()
        status, _headers, data, raw = self.harness.post(
            "/api/email/bind",
            {
                "username": "quota5",
                "password": OLD_PW,
                "email": _next_email(),
                "code": "123456",
            },
            ip=ip,
        )
        self.assertEqual(status, 429, "bind 提交与 bind-request 共享额度，body=%r" % (raw[:500],))
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")
        self.assertEqual(
            self.harness.verify_password_calls(),
            before,
            "共享额度 429 应先于 bind 的 verify_password",
        )


class BindFailureLockTest(unittest.TestCase):
    """F11 回归：同一 username+IP 密码校验失败 ≥5 次 → 锁 15 分钟（429，不泄露账号状态）。"""

    @classmethod
    def setUpClass(cls):
        cls.harness = ProductionHarness(
            rate_overrides={"bind": {"window_seconds": 3600, "max_requests": 100}},
            security_overrides={
                "bind_lockout": {
                    "window_seconds": 60,
                    "max_failures": 5,
                    "lockout_seconds": 60,
                }
            },
        )
        cls.fake = cls.harness.fake
        cls.fake.set_user("lockuser", OLD_PW, uid=2300, real_name="锁定用户")

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def _bind_request(self, username, password, email, ip):
        return self.harness.post(
            "/api/email/bind-request",
            {"username": username, "password": password, "email": email},
            ip=ip,
        )

    def test_failure_lock_per_username_and_ip(self):
        ip = "10.96.0.1"
        before = self.harness.verify_password_calls()
        for index in range(4):
            status, _headers, data, raw = self._bind_request(
                "lockuser", "Wrong#Pw%d" % index, _next_email(), ip
            )
            self.assertEqual(status, 400, "失败密码应 400，body=%r" % (raw[:500],))
            self.assertEqual((data.get("error") or {}).get("code"), "INVALID_CREDENTIALS")
        # 第 5 次失败立即触发锁定（429 RATE_LIMITED，提示与 400 统一）
        status, _headers, data, raw = self._bind_request(
            "lockuser", "Wrong#Pw5", _next_email(), ip
        )
        self.assertEqual(status, 429, "第 5 次失败应触发锁定 429，body=%r" % (raw[:500],))
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")
        self.assertEqual(self.harness.verify_password_calls() - before, 5)
        # 锁定期内即使密码正确也 429，且不再调用 verify_password
        status, _headers, data, raw = self._bind_request(
            "lockuser", OLD_PW, _next_email(), ip
        )
        self.assertEqual(status, 429, "锁定期间应 429，body=%r" % (raw[:500],))
        self.assertEqual((data.get("error") or {}).get("code"), "RATE_LIMITED")
        self.assertEqual(
            self.harness.verify_password_calls() - before,
            5,
            "锁定 429 应先于 verify_password",
        )
        # 同一用户名换 IP 不受影响（锁定按 username+IP）
        status, _headers, data, raw = self._bind_request(
            "lockuser", OLD_PW, _next_email(), "10.96.0.2"
        )
        self.assertEqual(
            status, 200, "不同 IP 不应被 username+IP 锁定影响，body=%r" % (raw[:800],)
        )



if __name__ == "__main__":
    unittest.main(verbosity=2)
