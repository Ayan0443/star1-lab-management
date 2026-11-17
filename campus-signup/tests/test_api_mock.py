#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §13 mock 模式黑盒端到端测试。

覆盖 SPEC §17 验收清单（v1.2 用户管理/公告/health/ssh_login_ipv6；
v1.3 §18 学校邮箱验证码注册：send-code/register/HMAC/冷却/每日上限/TTL/attempts）。

做法：
- 在 tempfile 临时目录生成 mock config（static 指向项目 static 绝对路径、端口用空闲端口）；
- ``subprocess`` 启动 ``python3 app/server.py --config <mock-config.json>``；
- 只用 stdlib ``urllib`` 做黑盒 HTTP 断言，结束后终止子进程并删除临时目录；
- 不依赖外部网络、不依赖 root、不连接真实 provisioner。

只依赖 stdlib，Python 3.9 兼容。
"""

import hashlib
import hmac
import itertools
import json
import os
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

SERVER_PATH = os.path.join(PROJECT_ROOT, "app", "server.py")
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")

# 每次 run_all.sh 注入独立 tag（shell PID）：并发跑测试时不互删对方临时目录/进程
_QA_RUN_TAG = os.environ.get("QA_RUN_TAG", "").strip()
QA_TMP_PREFIX = "campus-signup-qa-" + (_QA_RUN_TAG + "-" if _QA_RUN_TAG else "")

# mock config（SPEC §4/§13 示例；除端口/路径/公告外与契约一致）
ADMIN_TOKEN = "test-admin-token-0123456789"
STRONG_PW = "K7#mQ2$vX9!pR4@t"
SERVER_NAME = "测试服务器"
SITE_TITLE = "校园网服务器账号自助申请"
CONTACT = "测试管理员"
SSH_HOST = "127.0.0.1"
SSH_PORT = 22
SSH_IPV6 = "::1"
SSH_IPV6_PORT = 2222
DEFAULT_ANNOUNCEMENT = "测试公告内容：服务器 127.0.0.1，校外 IPv6 登录端口 2222。"
ALLOWED_SYMBOLS = "!@#$%^&*()-_=+[]{};,.?/|~"
AMBIGUOUS_CHARS = "0O1lI"

# ---- SPEC v1.3 §18 邮箱验证码（mock 模式） ----
EMAIL_ALLOWED_DOMAINS = ["mails.example.edu.cn", "example.edu.cn"]
EMAIL_SUBJECT = "【star1 实验室服务器】账号申请验证码"
EMAIL_CODE_SECRET = "0123456789abcdef" * 4  # 64 位 hex（测试用假密钥，非真实凭据）
EMAIL_FROM_NAME = "star1 实验室服务器"
EMAIL_FROM_ADDR = "no-reply@mails.example.edu.cn"
EMAIL_SMTP_PASSWORD = "qa-smtp-fake-password"  # 测试用假凭据，只写在 tests/ 里
EMAIL_TTL_SECONDS = 600
EMAIL_COOLDOWN_SECONDS = 60
EMAIL_MAX_ATTEMPTS = 5
EMAIL_MAX_PER_EMAIL_DAY = 10
EMAIL_MAX_GLOBAL_DAY = 300
# 重置密码用强密码（满足 §9 策略、不含测试用户名）
NEW_STRONG_PW = "N3w#Passw0rd!xQ"
NEW_STRONG_PW_2 = "R3set#Pwd9!mK2v"
_EMAIL_SEQ = itertools.count(1)
_PRESET_SEQ = itertools.count(1)  # 预置注册行唯一 IP 计数


def _next_email(prefix="qa", domain="mails.example.edu.cn"):
    """生成测试用学校邮箱（全局递增，避免跨 server/用例重复）。"""
    return "%s%05d@%s" % (prefix, next(_EMAIL_SEQ), domain)

# 交叉校验 reset-password 返回密码（SPEC §9.1）；单元测试已覆盖该模块。
try:
    from app.security import validate_password as _app_validate_password
except Exception:  # pragma: no cover - 单元测试已覆盖，缺失时退化为本地策略检查
    _app_validate_password = None


# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------

def _find_free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]
    finally:
        sock.close()


def _header(headers, name):
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return None


def _is_cjk(text):
    return bool(re.search(r"[\u4e00-\u9fff]", text or ""))


def _deep_update(base, extra):
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _deep_update(base[key], value)
        else:
            base[key] = value
    return base


def _read_file_bytes(path):
    if not os.path.isfile(path):
        return b""
    with open(path, "rb") as handle:
        return handle.read()


def _raw_http_get(port, path, timeout=5.0):
    """用裸 socket 发送 GET（避免 urllib 客户端把 ``..`` 规范化掉）。"""
    sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    try:
        request = (
            "GET %s HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n" % path
        ).encode("latin-1")
        sock.sendall(request)
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            try:
                chunk = sock.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                break
            buffer += chunk
        head, separator, rest = buffer.partition(b"\r\n\r\n")
        status = 0
        if head:
            match = re.match(rb"HTTP/\d(?:\.\d)?\s+(\d{3})", head.split(b"\r\n")[0])
            if match:
                status = int(match.group(1))
        if not separator:
            return status, b""
        body = rest
        content_length = None
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                try:
                    content_length = int(line.split(b":", 1)[1].strip())
                except ValueError:
                    content_length = None
        if content_length is not None:
            while len(body) < content_length:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                body += chunk
        else:
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                body += chunk
        return status, body
    finally:
        sock.close()


def _assert_password_policy(testcase, password):
    """独立实现 SPEC §9.1 的结构检查（黑盒断言用）。"""
    testcase.assertIsInstance(password, str)
    testcase.assertTrue(12 <= len(password) <= 64, "密码长度应为 12–64: %r" % (password,))
    testcase.assertTrue(re.search(r"[a-z]", password), "缺少小写字母: %r" % (password,))
    testcase.assertTrue(re.search(r"[A-Z]", password), "缺少大写字母: %r" % (password,))
    testcase.assertTrue(re.search(r"[0-9]", password), "缺少数字: %r" % (password,))
    testcase.assertTrue(
        any(ch in ALLOWED_SYMBOLS for ch in password), "缺少符号: %r" % (password,)
    )
    for ch in password:
        testcase.assertTrue(
            ch.isascii() and (ch.isalnum() or ch in ALLOWED_SYMBOLS),
            "密码含非法字符 %r: %r" % (ch, password),
        )
    # 不得有 4 个及以上连续相同字符
    run = best = 1
    for i in range(1, len(password)):
        run = run + 1 if password[i] == password[i - 1] else 1
        best = max(best, run)
    testcase.assertLess(best, 4, "密码含 4 个以上连续相同字符: %r" % (password,))
    if _app_validate_password is not None:
        ok, message = _app_validate_password(password, "")
        testcase.assertTrue(ok, "app.security.validate_password 拒绝了该密码: %r（%r）" % (password, message))


# ---------------------------------------------------------------------------
# mock server 管理
# ---------------------------------------------------------------------------

class MockServer(object):
    """启动 / 停止一个 mock 模式的 app/server.py 子进程。"""

    def __init__(self, config_overrides=None):
        self.tmpdir = tempfile.mkdtemp(prefix=QA_TMP_PREFIX)
        self.config_path = os.path.join(self.tmpdir, "config.json")
        self.log_path = os.path.join(self.tmpdir, "server.log")
        self._config_overrides = config_overrides or {}
        self.proc = None
        self._logfile = None
        self.port = None
        self._write_config()
        self._start()
        try:
            self.wait_ready()
        except Exception:
            self.stop()
            raise

    # ---- 生命周期 ----

    def _build_config(self):
        http_port = _find_free_port()
        https_port = _find_free_port()
        config = {
            "mode": "mock",
            "server": {
                "bind": "127.0.0.1",
                "public_host": "127.0.0.1",
                "ports": {"https": https_port, "http": http_port},
            },
            "tls": {"enabled": False},
            "paths": {
                "static": STATIC_DIR,
                "db": os.path.join(self.tmpdir, "registrations.db"),
                "lock": os.path.join(self.tmpdir, "register.lock"),
            },
            "provisioner": {
                "socket": os.path.join(self.tmpdir, "provision.sock"),
                "timeout_seconds": 10,
                "allowed_peer_uid": -1,
            },
            "security": {
                "admin_token": ADMIN_TOKEN,
                "allowed_client_cidrs": [],
                "trusted_proxies": [],
                "allow_query_token": False,     # SPEC §19.1：默认禁用 ?token=
                "admin_allowed_cidrs": [],
            },
            "ui": {
                "server_name": SERVER_NAME,
                "site_title": SITE_TITLE,
                "ssh_host": SSH_HOST,
                "ssh_port": SSH_PORT,
                "ssh_ipv6": SSH_IPV6,
                "ssh_ipv6_port": SSH_IPV6_PORT,
                "contact": CONTACT,
                "default_announcement": DEFAULT_ANNOUNCEMENT,
            },
            "email": {
                "enabled": True,
                "allowed_domains": list(EMAIL_ALLOWED_DOMAINS),
                "smtp": {
                    "host": "smtp.invalid",
                    "port": 465,
                    "security": "ssl",
                    "username": "qa@mails.example.edu.cn",
                    "password": EMAIL_SMTP_PASSWORD,
                    "from_name": EMAIL_FROM_NAME,
                    "from_addr": EMAIL_FROM_ADDR,
                    "tls_verify": True,
                    "timeout_seconds": 2,
                },
                "code_secret": EMAIL_CODE_SECRET,
                "code_ttl_seconds": EMAIL_TTL_SECONDS,
                "resend_cooldown_seconds": EMAIL_COOLDOWN_SECONDS,
                "max_verify_attempts": EMAIL_MAX_ATTEMPTS,
                "max_send_per_email_per_day": EMAIL_MAX_PER_EMAIL_DAY,
                "max_send_global_per_day": EMAIL_MAX_GLOBAL_DAY,
                "subject": EMAIL_SUBJECT,
            },
            "rate_limits": {
                "preview": {"window_seconds": 60, "max_requests": 120},
                "generate_password": {"window_seconds": 60, "max_requests": 120},
                "register": {"window_seconds": 600, "max_requests": 50},
                "admin": {"window_seconds": 60, "max_requests": 60},
                "announcement": {"window_seconds": 60, "max_requests": 120},
                "email_send": {"window_seconds": 3600, "max_requests": 1000},
                "password_reset": {"window_seconds": 3600, "max_requests": 1000},
                "bind": {"window_seconds": 3600, "max_requests": 1000},
            },
        }
        _deep_update(config, self._config_overrides)
        return config

    def _write_config(self):
        config = self._build_config()
        with open(self.config_path, "w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)
        self.port = config["server"]["ports"]["http"]
        self.db_path = config["paths"]["db"]

    def _start(self):
        env = dict(os.environ)
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        self._logfile = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, SERVER_PATH, "--config", self.config_path],
            cwd=PROJECT_ROOT,
            stdout=self._logfile,
            stderr=subprocess.STDOUT,
            env=env,
        )

    def wait_ready(self, timeout=25.0):
        deadline = time.time() + timeout
        last_error = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(
                    "server 启动即退出（code=%r）\n--- server log ---\n%s"
                    % (self.proc.returncode, self.log_tail())
                )
            try:
                status, _hdrs, body = self.request("GET", "/healthz", timeout=1.5)
                if status == 200:
                    return
                last_error = "status=%s body=%r" % (status, body[:200])
            except Exception as exc:  # 连接未就绪
                last_error = repr(exc)
            time.sleep(0.1)
        raise RuntimeError(
            "server 未在 %.1fs 内就绪：%s\n--- server log ---\n%s"
            % (timeout, last_error, self.log_tail())
        )

    def restart(self):
        """停止后用同一临时目录/DB、新端口重启（验证 DB 持久化）。"""
        self._shutdown()
        self._write_config()
        self._start()
        self.wait_ready()

    def _shutdown(self):
        proc = self.proc
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.proc = None
        if self._logfile is not None:
            try:
                self._logfile.close()
            except OSError:
                pass
            self._logfile = None

    def stop(self):
        self._shutdown()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ---- 日志 ----

    def log_text(self):
        try:
            with open(self.log_path, "rb") as handle:
                return handle.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def log_tail(self, limit=4000):
        text = self.log_text()
        return text[-limit:]

    # ---- HTTP ----

    def request(self, method, path, body=None, headers=None, timeout=10.0):
        url = "http://127.0.0.1:%d%s" % (self.port, path)
        request_headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            if isinstance(body, bytes):
                data = body
            elif isinstance(body, str):
                data = body.encode("utf-8")
                request_headers["Content-Type"] = "application/json; charset=utf-8"
            else:
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
                request_headers["Content-Type"] = "application/json; charset=utf-8"
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return int(response.status), dict(response.headers), response.read()
        except urllib.error.HTTPError as exc:
            return int(exc.code), dict(exc.headers), exc.read()


# ---------------------------------------------------------------------------
# 测试基类
# ---------------------------------------------------------------------------

class MockApiTestCase(unittest.TestCase):
    config_overrides = None

    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(SERVER_PATH):
            raise unittest.SkipTest("app/server.py 尚未实现（等待 backend 完成）")
        cls.server = MockServer(cls.config_overrides)

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.stop()
            cls.server = None

    # ---- HTTP 断言 helpers ----

    def call(self, method, path, body=None, headers=None):
        status, response_headers, raw = self.server.request(
            method, path, body=body, headers=headers
        )
        data = None
        if raw:
            try:
                data = json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                data = None
        return status, response_headers, data, raw

    def assert_json_content_type(self, headers):
        content_type = (_header(headers, "Content-Type") or "").lower().replace(" ", "")
        self.assertIn("application/json", content_type)
        self.assertIn("charset=utf-8", content_type)

    def assert_error(self, data, code):
        self.assertIsInstance(data, dict, "错误响应必须是 JSON 对象: %r" % (data,))
        self.assertFalse(data.get("ok"), "错误响应 ok 必须为 false: %r" % (data,))
        error = data.get("error")
        self.assertIsInstance(error, dict, "缺少 error 对象: %r" % (data,))
        self.assertEqual(error.get("code"), code, "错误码不符: %r" % (data,))
        self.assertIsInstance(error.get("message"), str)
        self.assertTrue(error["message"].strip(), "错误信息不能为空: %r" % (data,))
        self.assertTrue(_is_cjk(error["message"]), "错误信息应为中文: %r" % (data,))

    def assert_security_headers(self, headers):
        csp = _header(headers, "Content-Security-Policy") or ""
        for fragment in (
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'none'",
            "form-action 'self'",
        ):
            self.assertIn(fragment, csp, "CSP 缺少 %r: %r" % (fragment, csp))
        self.assertEqual(
            (_header(headers, "X-Content-Type-Options") or "").lower(), "nosniff"
        )
        self.assertEqual((_header(headers, "X-Frame-Options") or "").upper(), "DENY")
        self.assertEqual(
            (_header(headers, "Referrer-Policy") or "").lower(), "no-referrer"
        )
        self.assertIn(
            "no-store", (_header(headers, "Cache-Control") or "").lower()
        )
        # SPEC §19.3：传输与响应头加固
        hsts = _header(headers, "Strict-Transport-Security") or ""
        self.assertIn("max-age=15552000", hsts, "HSTS 缺失/不正确: %r" % (hsts,))
        self.assertEqual(
            (_header(headers, "Cross-Origin-Opener-Policy") or "").lower(),
            "same-origin",
        )
        self.assertEqual(
            (_header(headers, "Cross-Origin-Resource-Policy") or "").lower(),
            "same-origin",
        )
        permissions = _header(headers, "Permissions-Policy") or ""
        for fragment in ("camera=()", "microphone=()", "geolocation=()", "payment=()"):
            self.assertIn(
                fragment,
                permissions,
                "Permissions-Policy 缺少 %r: %r" % (fragment, permissions),
            )

    def get_ok_json(self, path, headers=None):
        status, response_headers, data, raw = self.call("GET", path, headers=headers)
        self.assertEqual(
            status, 200, "GET %s 期望 200，实际 %s，body=%r" % (path, status, raw[:500])
        )
        self.assert_json_content_type(response_headers)
        self.assertIsInstance(data, dict)
        return data, raw

    def post(self, path, body=None, headers=None):
        request_headers = {"X-Requested-With": "campus-signup"}
        if headers:
            request_headers.update(headers)
        return self.call("POST", path, body=body, headers=request_headers)

    def admin_headers(self, token=ADMIN_TOKEN):
        return {"X-Admin-Token": token}

    def admin_get(self, path):
        return self.call("GET", path, headers=self.admin_headers())

    def admin_post(self, path, body, token=ADMIN_TOKEN):
        return self.post(path, body=body, headers=self.admin_headers(token) if token else {})

    # ---- 邮箱验证码 helpers（SPEC §18） ----

    def new_email(self, prefix="qa", domain="mails.example.edu.cn"):
        return _next_email(prefix, domain)

    def send_code(self, email, ip="10.99.0.1"):
        return self.call(
            "POST",
            "/api/email/send-code",
            body={"email": email},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": ip,
            },
        )

    def send_code_ok(self, email, ip="10.99.0.1"):
        status, headers, data, raw = self.send_code(email, ip)
        self.assertEqual(
            status, 200, "send-code 应 200: email=%r body=%r" % (email, raw[:600])
        )
        self.assert_json_content_type(headers)
        self.assertIsInstance(data, dict)
        self.assertIs(data.get("ok"), True, "send-code ok 应为 true: %r" % (data,))
        return data, raw

    def mock_emails(self):
        path = os.path.join(self.server.tmpdir, "mock-emails.jsonl")
        entries = []
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except ValueError:
                        continue
        return entries

    def db_path(self):
        return os.path.join(self.server.tmpdir, "registrations.db")

    def query_email_codes(self, email=None):
        conn = sqlite3.connect(self.db_path())
        try:
            conn.row_factory = sqlite3.Row
            if email is None:
                rows = conn.execute("SELECT * FROM email_codes ORDER BY id").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM email_codes WHERE email = ? ORDER BY id", (email,)
                ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    # ---- 忘记密码/重置 helpers（SPEC §21） ----

    def reset_request(self, email, ip="10.99.0.2"):
        return self.call(
            "POST",
            "/api/password/reset-request",
            body={"email": email},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": ip,
            },
        )

    def reset_request_ok(self, email, ip="10.99.0.2"):
        status, headers, data, raw = self.reset_request(email, ip)
        self.assertEqual(
            status, 200,
            "reset-request 应 200: email=%r body=%r" % (email, raw[:600]),
        )
        self.assert_json_content_type(headers)
        self.assertIsInstance(data, dict)
        self.assertIs(data.get("ok"), True)
        return data, raw

    def password_reset(self, email, code, new_password, ip="10.99.0.2"):
        return self.call(
            "POST",
            "/api/password/reset",
            body={"email": email, "code": code, "new_password": new_password},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": ip,
            },
        )

    def password_reset_ok(self, email, code, new_password, ip="10.99.0.2"):
        status, headers, data, raw = self.password_reset(
            email, code, new_password, ip
        )
        self.assertEqual(
            status, 200,
            "password/reset 应 200: email=%r body=%r" % (email, raw[:800]),
        )
        self.assert_json_content_type(headers)
        self.assertIsInstance(data, dict)
        self.assertIs(data.get("ok"), True)
        return data, raw

    def create_account(self, name, ip):
        """注册一个真实 mock 账号，返回 (account, email)。"""
        email = self.new_email()
        account, _data, _raw = self.register_ok(name, ip, email=email)
        return account, email

    def insert_registration_row(self, email, username="presetuser", real_name="预置用户",
                                create_system_user=True):
        """直接向 DB 插入一条 active 注册记录（用于注册流程受限制的场景，如 email 停用）。"""
        seq = next(_PRESET_SEQ)
        ip = "10.98.%d.%d" % (seq // 250, seq % 250)
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = sqlite3.connect(self.db_path())
        try:
            conn.execute(
                "INSERT INTO registrations "
                "(ip, real_name, pinyin, username, email, uid, gid, home, "
                " workspace, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    ip, real_name, username, username, email,
                    2000 + seq, 2000 + seq,
                    "/home/" + username, "/home/" + username, now, now,
                ),
            )
            conn.commit()
        finally:
            conn.close()
        if create_system_user:
            self.add_mock_user(username, uid=2500 + seq, real_name=real_name)
        return ip, username

    def clear_email_codes(self, email):
        """测试加速：清除某邮箱的验证码记录（规避 §21.2 共享 60s 冷却；不影响被测逻辑）。"""
        conn = sqlite3.connect(self.db_path())
        try:
            conn.execute("DELETE FROM email_codes WHERE email = ?", (email,))
            conn.commit()
        finally:
            conn.close()

    def query_user_emails(self, email=None, db_path=None):
        conn = sqlite3.connect(db_path or self.db_path())
        try:
            conn.row_factory = sqlite3.Row
            if email is None:
                rows = conn.execute("SELECT * FROM user_emails ORDER BY username").fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM user_emails WHERE email = ?", (email,)
                ).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    @staticmethod
    def expected_code_hash(email, code):
        """SPEC §18.3：HMAC-SHA256(code_secret, email + ":" + code) 的 hex。"""
        message = ("%s:%s" % (email, code)).encode("utf-8")
        return hmac.new(
            EMAIL_CODE_SECRET.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()

    # ---- 业务 helpers ----

    def register(self, name, ip, password=STRONG_PW, email=None, email_code=None):
        """注册：未显式传 email/email_code 时自动 send-code 并取 mock debug_code。"""
        if email is None:
            email = self.new_email()
        if email_code is None:
            status, _headers, code_data, _raw = self.send_code(email, ip)
            if status == 200 and isinstance(code_data, dict):
                email_code = code_data.get("debug_code") or "000000"
            else:
                email_code = "000000"
        return self.call(
            "POST",
            "/api/register",
            body={
                "name": name,
                "password": password,
                "email": email,
                "email_code": email_code,
            },
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": ip,
            },
        )

    def register_ok(self, name, ip, password=STRONG_PW, email=None, email_code=None):
        if email is None:
            email = self.new_email()
        status, headers, data, raw = self.register(
            name, ip, password=password, email=email, email_code=email_code
        )
        self.assertEqual(
            status,
            201,
            "注册应成功: name=%r ip=%r email=%r status=%s body=%r"
            % (name, ip, email, status, raw[:800]),
        )
        self.assert_json_content_type(headers)
        self.assertIsInstance(data, dict)
        self.assertIs(data.get("ok"), True, "注册响应 ok 应为 true: %r" % (data,))
        account = data.get("account")
        self.assertIsInstance(account, dict, "注册响应缺少 account: %r" % (data,))
        return account, data, raw

    # ---- 管理员用户列表（SPEC §22.4：GET /api/admin/users） ----

    def list_users(self):
        status, headers, data, raw = self.admin_get("/api/admin/users")
        self.assertEqual(
            status, 200, "管理员用户列表应 200，实际 %s，body=%r" % (status, raw[:800])
        )
        self.assert_json_content_type(headers)
        self.assertIsInstance(data, dict)
        self.assertIs(data.get("ok"), True)
        self.assertIsInstance(data.get("users"), list)
        return data

    def find_user(self, username=None, ip=None, email=None):
        data = self.list_users()
        record = None
        for item in data["users"]:
            if username is not None and item.get("username") == username:
                record = item
            if ip is not None and item.get("ip") == ip:
                record = item
            if email is not None and item.get("email") == email:
                record = item
        return record, data

    def find_registration(self, username=None, ip=None):
        """兼容旧调用：返回 /api/admin/users 中对应条目。"""
        return self.find_user(username=username, ip=ip)

    def list_registrations(self):
        """兼容旧调用：把 users 列表包装成旧 registrations 结构。"""
        data = self.list_users()
        try:
            health, _raw = self.get_ok_json("/api/health")
            enabled = health.get("registration_enabled")
        except Exception:
            enabled = None
        return {
            "ok": True,
            "registration_enabled": enabled,
            "stats": data.get("stats") or {},
            "registrations": data.get("users") or [],
        }

    # ---- mock 文件系统 helpers ----

    @property
    def mock_users_dir(self):
        db_path = getattr(
            self.server, "db_path", os.path.join(self.server.tmpdir, "registrations.db")
        )
        return os.path.join(os.path.dirname(db_path), "mock-users")

    def mock_home(self, username):
        return os.path.join(self.mock_users_dir, username)

    def read_mock_users(self):
        path = os.path.join(self.mock_users_dir, "users.json")
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)

    def assert_mock_home_created(self, username):
        path = self.mock_home(username)
        self.assertTrue(os.path.isdir(path), "mock 家目录未创建: %s" % path)
        mode = stat.S_IMODE(os.stat(path).st_mode)
        self.assertEqual(mode, 0o750, "mock 家目录权限应为 0750，实际 %o" % mode)

    def simulate_missing_system_user(self, username):
        """模拟「DB 有记录、系统用户已消失」：从 mock users.json 移除并删 mock 家目录。"""
        users_path = os.path.join(self.mock_users_dir, "users.json")
        users = self.read_mock_users()
        users.pop(username, None)
        with open(users_path, "w", encoding="utf-8") as handle:
            json.dump(users, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        shutil.rmtree(self.mock_home(username), ignore_errors=True)

    def add_mock_user(self, username, uid=None, real_name="预置用户", home=None, locked=False,
                      privileged=False):
        """向 mock provisioner 的 users.json 注入一个「系统已有用户」（用于绑定/管理测试）。"""
        os.makedirs(self.mock_users_dir, exist_ok=True)
        users_path = os.path.join(self.mock_users_dir, "users.json")
        users = self.read_mock_users() if os.path.isfile(users_path) else {}
        if uid is None:
            uid = 3000 + len(users)
        users[username] = {
            "uid": uid,
            "gid": uid,
            "home": home or ("/home/" + username),
            "real_name": real_name,
            "locked": bool(locked),
            "privileged": bool(privileged),
        }
        with open(users_path, "w", encoding="utf-8") as handle:
            json.dump(users, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        home_dir = self.mock_home(username)
        os.makedirs(home_dir, exist_ok=True)
        try:
            os.chmod(home_dir, 0o750)
        except OSError:
            pass
        return username


# ---------------------------------------------------------------------------
# 主流程：API 契约
# ---------------------------------------------------------------------------

class ApiContractTest(MockApiTestCase):
    """SPEC §7/§17 全部 HTTP 项（mock 模式）。"""

    # ---- 基础 ----

    def test_health_fields(self):
        data, raw = self.get_ok_json("/api/health")
        self.assertIs(data.get("ok"), True)
        self.assertIsInstance(data.get("version"), str)
        self.assertTrue(data["version"])
        self.assertIs(data.get("registration_enabled"), True)
        self.assertEqual(data.get("server_name"), SERVER_NAME)
        self.assertEqual(data.get("site_title"), SITE_TITLE)
        self.assertEqual(data.get("contact"), CONTACT)
        self.assertEqual(data.get("ssh_host"), SSH_HOST)
        self.assertEqual(data.get("ssh_port"), SSH_PORT)
        self.assertEqual(data.get("ssh_ipv6"), SSH_IPV6)
        self.assertEqual(data.get("ssh_ipv6_port"), SSH_IPV6_PORT)
        # SPEC §18.4：邮箱验证开关与允许域名
        self.assertIs(data.get("email_verification_enabled"), True)
        self.assertEqual(data.get("allowed_email_domains"), list(EMAIL_ALLOWED_DOMAINS))
        # UTF-8 原样中文（ensure_ascii=False）
        self.assertIn(SERVER_NAME, raw.decode("utf-8"))

        status, headers, healthz, raw = self.call("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assert_json_content_type(headers)
        self.assertIs(healthz.get("ok"), True)

    def test_security_headers(self):
        for path in ("/api/health", "/api/unknown-path"):
            with self.subTest(path=path):
                status, headers, _data, _raw = self.call("GET", path)
                self.assert_security_headers(headers)
                if path == "/api/health":
                    self.assertEqual(status, 200)

    def test_method_not_allowed(self):
        status, headers, data, raw = self.call("GET", "/api/register")
        self.assertEqual(status, 405, "已存在的 POST 路径用 GET 应 405，body=%r" % (raw[:500],))
        self.assert_error(data, "METHOD_NOT_ALLOWED")

    def test_unknown_path_404(self):
        for path in ("/api/nope", "/no-such-page"):
            with self.subTest(path=path):
                status, headers, data, raw = self.call("GET", path)
                self.assertEqual(status, 404, "未知路径应 404: %s body=%r" % (path, raw[:300]))
                self.assert_error(data, "NOT_FOUND")

    # ---- preview ----

    def test_preview_normal(self):
        name = "欧阳锋"
        data, raw = self.get_ok_json(
            "/api/preview?name=" + urllib.parse.quote(name)
        )
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("real_name"), name)
        self.assertEqual(data.get("pinyin"), "ouyangfeng")
        self.assertEqual(data.get("base_username"), "ouyangfeng")
        self.assertEqual(data.get("username"), "ouyangfeng")
        self.assertEqual(data.get("duplicate_index"), 0)
        self.assertIs(data.get("available"), True)
        self.assertEqual(data.get("note"), "")
        self.assertIn(name, raw.decode("utf-8"))

    def test_preview_invalid_name(self):
        for bad_name in ("张", "张3", "张三; rm -rf /"):
            with self.subTest(name=bad_name):
                status, headers, data, raw = self.call(
                    "GET", "/api/preview?name=" + urllib.parse.quote(bad_name)
                )
                self.assertEqual(status, 400, "非法姓名应 400: %r body=%r" % (bad_name, raw[:500]))
                self.assert_json_content_type(headers)
                self.assert_error(data, "INVALID_NAME")

    def test_preview_duplicate_suffix(self):
        account, _data, _raw = self.register_ok("王小明", "10.20.2.1")
        self.assertEqual(account.get("username"), "wangxiaoming")

        data, _raw = self.get_ok_json("/api/preview?name=" + urllib.parse.quote("王小明"))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("base_username"), "wangxiaoming")
        self.assertEqual(data.get("username"), "wangxiaoming2")
        self.assertEqual(data.get("duplicate_index"), 2)
        self.assertIs(data.get("available"), True)
        self.assertTrue(data.get("note"))
        self.assertIn("wangxiaoming2", data["note"])

    # ---- generate-password ----

    def test_generate_password(self):
        passwords = []
        for _ in range(2):
            status, headers, data, raw = self.post("/api/generate-password", body={})
            self.assertEqual(status, 200, "generate-password 应 200，body=%r" % (raw[:500],))
            self.assert_json_content_type(headers)
            self.assertIs(data.get("ok"), True)
            password = data.get("password")
            _assert_password_policy(self, password)
            self.assertEqual(data.get("length"), len(password))
            strength = data.get("strength")
            self.assertIsInstance(strength, dict)
            self.assertIsInstance(strength.get("score"), int)
            self.assertTrue(0 <= strength["score"] <= 4)
            self.assertIsInstance(strength.get("label"), str)
            self.assertIsInstance(strength.get("percent"), int)
            self.assertTrue(0 <= strength["percent"] <= 100)
            for ch in password:
                self.assertNotIn(ch, AMBIGUOUS_CHARS, "生成密码不应含易混淆字符: %r" % (password,))
                self.assertNotEqual(ch, ":")
            passwords.append(password)
        self.assertNotEqual(passwords[0], passwords[1], "两次生成的密码不应相同")

    # ---- register ----

    def test_register_flow_and_ip_limit(self):
        ip1, ip2, ip3 = "10.20.1.1", "10.20.1.2", "10.20.1.3"
        email1 = self.new_email()
        account1, _data, raw1 = self.register_ok("张三", ip1, email=email1)
        self.assertEqual(account1.get("username"), "zhangsan")
        self.assertEqual(account1.get("real_name"), "张三")
        self.assertEqual(account1.get("pinyin"), "zhangsan")
        self.assertEqual(account1.get("email"), email1, "注册响应 account 应含 email（SPEC §18.4）")
        self.assertIsInstance(account1.get("uid"), int)
        self.assertIsInstance(account1.get("gid"), int)
        self.assertIsInstance(account1.get("home"), str)
        self.assertIn("zhangsan", account1["home"])
        self.assertEqual(account1.get("workspace"), account1.get("home"))
        self.assertEqual(account1.get("ssh_login"), "ssh zhangsan@127.0.0.1")
        self.assertEqual(
            account1.get("ssh_login_ipv6"),
            "ssh -6 -p 2222 zhangsan@::1",
        )
        self.assertNotIn(STRONG_PW, raw1.decode("utf-8"), "注册响应不应包含密码")
        self.assert_mock_home_created("zhangsan")
        users = self.read_mock_users()
        self.assertIn("zhangsan", users)

        # 同一 IP 第二次申请 → 409 IP_LIMIT
        status, headers, data, raw = self.register("李四", ip1)
        self.assertEqual(
            status, 409, "同一 IP 二次申请应 409，实际 %s body=%r" % (status, raw[:500])
        )
        self.assert_json_content_type(headers)
        self.assert_error(data, "IP_LIMIT")

        # 不同 IP 同名 → 后缀 2；再来一个 → 后缀 3
        account2, _data, raw2 = self.register_ok("张三", ip2)
        self.assertEqual(account2.get("username"), "zhangsan2")
        self.assertEqual(
            account2.get("ssh_login_ipv6"), "ssh -6 -p 2222 zhangsan2@::1"
        )
        self.assert_mock_home_created("zhangsan2")

        account3, _data, raw3 = self.register_ok("张三", ip3)
        self.assertEqual(account3.get("username"), "zhangsan3")
        self.assert_mock_home_created("zhangsan3")

        # 响应与日志均不含密码（SPEC §17）
        for raw_response in (raw1, raw2, raw3):
            self.assertNotIn(STRONG_PW, raw_response.decode("utf-8"))
        log = self.server.log_text()
        self.assertNotIn(STRONG_PW, log, "日志不应包含密码")
        self.assertNotIn('"password"', log, "日志不应记录请求体")

    def test_register_weak_password(self):
        status, headers, data, raw = self.register("王五", "10.20.3.1", password="abc123456")
        self.assertEqual(status, 400, "弱密码应 400，body=%r" % (raw[:500],))
        self.assert_json_content_type(headers)
        self.assert_error(data, "WEAK_PASSWORD")

        # 结构上满足四类字符、但在弱密码列表中的密码同样必须拒绝
        status, headers, data, raw = self.register(
            "王五", "10.20.3.1", password="Aa123456789!"
        )
        self.assertEqual(status, 400)
        self.assert_error(data, "WEAK_PASSWORD")

    def test_register_invalid_name(self):
        for bad_name in ("张", "张三; rm -rf /"):
            with self.subTest(name=bad_name):
                status, headers, data, raw = self.register(bad_name, "10.20.3.2")
                self.assertEqual(status, 400, "非法姓名应 400，body=%r" % (raw[:500],))
                self.assert_json_content_type(headers)
                self.assert_error(data, "INVALID_NAME")

    def test_register_requires_headers(self):
        body = {"name": "王五", "password": STRONG_PW}
        # 缺 X-Requested-With
        status, headers, data, raw = self.call(
            "POST",
            "/api/register",
            body=body,
            headers={"X-Test-Client-IP": "10.20.3.3"},
        )
        self.assertEqual(status, 403, "缺 X-Requested-With 应 403，body=%r" % (raw[:500],))
        self.assert_error(data, "BAD_REQUEST")

        # 缺 Content-Type
        raw_body = json.dumps(body, ensure_ascii=False).encode("utf-8")
        status, headers, data, raw = self.call(
            "POST",
            "/api/register",
            body=raw_body,
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.20.3.3",
            },
        )
        self.assertEqual(status, 403, "缺 Content-Type 应 403，body=%r" % (raw[:500],))

        # 错误 Content-Type
        status, headers, data, raw = self.call(
            "POST",
            "/api/register",
            body=raw_body,
            headers={
                "X-Requested-With": "campus-signup",
                "Content-Type": "text/plain",
                "X-Test-Client-IP": "10.20.3.3",
            },
        )
        self.assertEqual(status, 403, "错误 Content-Type 应 403，body=%r" % (raw[:500],))

        # 非法 JSON → 400 INVALID_JSON
        status, headers, data, raw = self.call(
            "POST",
            "/api/register",
            body=b"{not-json",
            headers={
                "X-Requested-With": "campus-signup",
                "Content-Type": "application/json",
                "X-Test-Client-IP": "10.20.3.3",
            },
        )
        self.assertEqual(status, 400, "非法 JSON 应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "INVALID_JSON")

    def test_register_payload_too_large(self):
        body = {"name": "王五", "password": STRONG_PW, "padding": "A" * 9000}
        status, headers, data, raw = self.call(
            "POST",
            "/api/register",
            body=body,
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.20.3.4",
            },
        )
        self.assertEqual(status, 413, "超长 body 应 413，实际 %s body=%r" % (status, raw[:500]))
        self.assert_error(data, "PAYLOAD_TOO_LARGE")

    # ---- 管理员：鉴权与用户列表（SPEC §22.4） ----

    def test_admin_auth(self):
        for path in ("/api/admin/users",):
            status, headers, data, raw = self.call("GET", path)
            self.assertEqual(status, 403, "无 token 应 403，body=%r" % (raw[:500],))
            self.assert_error(data, "ADMIN_AUTH")
            status, headers, data, raw = self.call(
                "GET", path, headers={"X-Admin-Token": "wrong-token"}
            )
            self.assertEqual(status, 403, "错误 token 应 403，body=%r" % (raw[:500],))
            self.assert_error(data, "ADMIN_AUTH")

        for path, body in (
            ("/api/admin/reset-ip", {"id": 1}),
            ("/api/admin/reset-password", {"username": "x"}),
            ("/api/admin/set-locked", {"username": "x", "locked": True}),
            ("/api/admin/bind-email", {"username": "x", "email": "a@mails.example.edu.cn"}),
            ("/api/admin/announcement", {"content": "x"}),
            ("/api/admin/set-registration", {"enabled": True}),
        ):
            with self.subTest(path=path):
                status, headers, data, raw = self.admin_post(path, body, token=None)
                self.assertEqual(
                    status, 403, "%s 无 token 应 403，body=%r" % (path, raw[:500])
                )
                self.assert_error(data, "ADMIN_AUTH")

    def test_admin_old_registrations_endpoint_removed(self):
        """SPEC §22.4：旧 GET /api/admin/registrations 已移除。"""
        status, _headers, _data, raw = self.admin_get("/api/admin/registrations")
        self.assertIn(
            status, (404, 405), "旧 registrations 接口应移除（404/405），body=%r" % (raw[:300],)
        )

    def test_admin_users(self):
        email = self.new_email()
        account, _data, _raw = self.register_ok("刘洋", "10.20.0.1", email=email)
        self.assertEqual(account.get("username"), "liuyang")

        data = self.list_users()
        stats = data.get("stats")
        self.assertIsInstance(stats, dict)
        for key in ("total", "active", "locked", "missing", "with_email", "portal", "imported"):
            with self.subTest(stats_key=key):
                self.assertIn(key, stats)
                self.assertIsInstance(stats[key], int)
        self.assertGreaterEqual(stats["total"], 1)
        self.assertGreaterEqual(stats["portal"], 1)
        self.assertGreaterEqual(stats["with_email"], 1)

        record, _list = self.find_user(username="liuyang")
        self.assertIsNotNone(record, "用户列表找不到刚注册的 liuyang")
        self.assertEqual(record.get("ip"), "10.20.0.1")
        self.assertEqual(record.get("real_name"), "刘洋")
        self.assertEqual(record.get("email"), email)
        self.assertEqual(record.get("source"), "portal")
        self.assertIsInstance(record.get("registration_id"), int)
        self.assertIs(record.get("privileged"), False)
        self.assertEqual(record.get("os_status"), "active")
        self.assertIs(record.get("locked"), False)
        for key in ("username", "uid", "gid", "home"):
            self.assertIn(key, record)

        # SPEC §19.1：默认（allow_query_token=false）必须拒绝 ?token=
        status, _headers, query_data, raw = self.call(
            "GET",
            "/api/admin/users?token=" + urllib.parse.quote(ADMIN_TOKEN),
        )
        self.assertEqual(status, 403, "默认应拒绝 ?token=，body=%r" % (raw[:500],))
        self.assert_error(query_data, "ADMIN_AUTH")

    def test_admin_disable_registration(self):
        try:
            status, headers, data, raw = self.admin_post(
                "/api/admin/set-registration", {"enabled": False}
            )
            self.assertEqual(status, 200, "停用申请应 200，body=%r" % (raw[:500],))
            self.assertIs(data.get("registration_enabled"), False)

            health, _raw = self.get_ok_json("/api/health")
            self.assertIs(health.get("registration_enabled"), False)

            status, headers, data, raw = self.register("周杰伦", "10.20.0.5")
            self.assertEqual(
                status, 409, "停用后注册应 409，实际 %s body=%r" % (status, raw[:500])
            )
            self.assert_error(data, "REGISTRATION_DISABLED")
        finally:
            status, headers, data, raw = self.admin_post(
                "/api/admin/set-registration", {"enabled": True}
            )
            self.assertEqual(status, 200, "恢复申请应 200，body=%r" % (raw[:500],))
            self.assertIs(data.get("registration_enabled"), True)

        health, _raw = self.get_ok_json("/api/health")
        self.assertIs(health.get("registration_enabled"), True)

    def test_admin_reset_ip(self):
        account, _data, _raw = self.register_ok("李四", "10.20.0.4")
        self.assertEqual(account.get("username"), "lisi")

        record, _list = self.find_user(username="lisi")
        self.assertIsNotNone(record)
        registration_id = record.get("registration_id")
        self.assertIsInstance(registration_id, int)

        # 不存在的 id → 404 NOT_FOUND
        status, headers, data, raw = self.admin_post("/api/admin/reset-ip", {"id": 999999})
        self.assertEqual(status, 404, "不存在 id 应 404，body=%r" % (raw[:500],))
        self.assert_error(data, "NOT_FOUND")

        status, headers, data, raw = self.admin_post(
            "/api/admin/reset-ip", {"id": registration_id}
        )
        self.assertEqual(status, 200, "reset-ip 应 200，body=%r" % (raw[:500],))
        deleted = data.get("deleted")
        self.assertIsInstance(deleted, dict)
        self.assertEqual(deleted.get("id"), registration_id)
        self.assertEqual(deleted.get("ip"), "10.20.0.4")
        self.assertEqual(deleted.get("username"), "lisi")

        # reset-ip 不删除系统用户：mock 家目录仍在；用户以 imported 出现在全用户列表
        self.assertTrue(os.path.isdir(self.mock_home("lisi")), "reset-ip 不应删除 mock 家目录")
        imported, _list = self.find_user(username="lisi")
        self.assertIsNotNone(imported, "系统用户应仍出现在全用户列表（imported）")
        self.assertEqual(imported.get("source"), "imported")
        self.assertIsNone(imported.get("registration_id"))
        gone, _list = self.find_user(ip="10.20.0.4")
        self.assertIsNone(gone, "reset-ip 后不应再有该 IP 的 portal 记录")

        # 同一 IP 可重新申请（系统用户仍在 → 后缀 2）
        account2, _data, _raw = self.register_ok("李四", "10.20.0.4")
        self.assertEqual(account2.get("username"), "lisi2")

    # ---- 管理员：用户管理（v1.5 按 username 操作）----

    def test_admin_lock_unlock(self):
        account, _data, _raw = self.register_ok("王芳", "10.20.0.2")
        username = account.get("username")
        record, _list = self.find_user(username=username)
        self.assertIsNotNone(record)
        self.assertEqual(record.get("os_status"), "active")

        status, headers, data, raw = self.admin_post(
            "/api/admin/set-locked", {"username": username, "locked": True}
        )
        self.assertEqual(status, 200, "锁定应 200，body=%r" % (raw[:500],))
        self.assertEqual(data.get("username"), username)
        self.assertIs(data.get("locked"), True)

        locked_record, list_data = self.find_user(username=username)
        self.assertEqual(locked_record.get("os_status"), "locked")
        self.assertIs(locked_record.get("locked"), True)
        self.assertGreaterEqual(list_data["stats"]["locked"], 1)

        status, headers, data, raw = self.admin_post(
            "/api/admin/set-locked", {"username": username, "locked": False}
        )
        self.assertEqual(status, 200, "解锁应 200，body=%r" % (raw[:500],))
        self.assertIs(data.get("locked"), False)
        unlocked_record, _list = self.find_user(username=username)
        self.assertEqual(unlocked_record.get("os_status"), "active")

        status, headers, data, raw = self.admin_post(
            "/api/admin/set-locked", {"username": "nosuchuser", "locked": True}
        )
        self.assertEqual(status, 409, "不存在用户应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "USER_MISSING")

    def test_admin_missing_system_user(self):
        """SPEC §22.4：全用户列表中系统用户缺失 → os_status=missing / 管理操作 409 USER_MISSING。"""
        account, _data, _raw = self.register_ok("吴磊", "10.20.0.7")
        username = account.get("username")
        self.simulate_missing_system_user(username)

        missing_record, list_data = self.find_user(username=username)
        self.assertIsNotNone(missing_record)
        self.assertEqual(missing_record.get("os_status"), "missing")
        self.assertIs(missing_record.get("privileged"), False)
        self.assertGreaterEqual(list_data["stats"]["missing"], 1)

        for path, body in (
            ("/api/admin/reset-password", {"username": username}),
            ("/api/admin/set-locked", {"username": username, "locked": True}),
        ):
            with self.subTest(path=path):
                status, headers, data, raw = self.admin_post(path, body)
                self.assertEqual(
                    status, 409, "%s 系统用户缺失应 409，body=%r" % (path, raw[:500])
                )
                self.assert_error(data, "USER_MISSING")

    def test_admin_reset_password(self):
        account, _data, _raw = self.register_ok("韩梅梅", "10.20.0.6")
        username = account.get("username")

        status, headers, data, raw = self.admin_post(
            "/api/admin/reset-password", {"username": username}
        )
        self.assertEqual(status, 200, "reset-password 应 200，body=%r" % (raw[:500],))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("username"), username)
        password = data.get("password")
        _assert_password_policy(self, password)

        users_path = os.path.join(self.mock_users_dir, "users.json")
        self.assertNotIn(password.encode("utf-8"), _read_file_bytes(users_path))
        self.assertNotIn(password, self.server.log_text(), "日志不应记录一次性密码")
        db_path = os.path.join(self.server.tmpdir, "registrations.db")
        for suffix in ("", "-wal", "-shm"):
            self.assertNotIn(password.encode("utf-8"), _read_file_bytes(db_path + suffix))

        status, headers, data, raw = self.admin_post(
            "/api/admin/reset-password", {"username": "nosuchuser"}
        )
        self.assertEqual(status, 409, "不存在用户应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "USER_MISSING")

    def test_admin_delete_user_disabled(self):
        """SPEC §22.1/§22.7：删除用户功能彻底禁用（web 路由移除、数据不受影响）。"""
        account, _data, _raw = self.register_ok("赵敏", "10.20.0.3")
        username = account.get("username")
        home_dir = self.mock_home(username)
        self.assertTrue(os.path.isdir(home_dir))

        for body in (
            {"id": 1, "confirm_username": username},
            {"username": username},
            {"id": 1},
        ):
            with self.subTest(body=body):
                status, _headers, _data, raw = self.admin_post(
                    "/api/admin/delete-user", body
                )
                self.assertIn(
                    status,
                    (404, 405),
                    "delete-user 路由应已移除（404/405），实际 %s body=%r"
                    % (status, raw[:300]),
                )
        # 无 token 也应是路由不存在（404/405），而不是 403
        status, _headers, _data, _raw = self.admin_post(
            "/api/admin/delete-user", {"id": 1}, token=None
        )
        self.assertIn(status, (404, 405), "delete-user 路由应彻底不存在")

        # 用户/家目录/DB 记录不受影响
        self.assertTrue(os.path.isdir(home_dir), "delete-user 调用不得删除家目录")
        self.assertIn(username, self.read_mock_users(), "delete-user 调用不得删除系统用户")
        still, _list = self.find_user(username=username)
        self.assertIsNotNone(still, "delete-user 调用不得删除注册记录")
        self.assertIsInstance(still.get("registration_id"), int)

    def test_admin_bind_email(self):
        """SPEC §22.4：管理员直接为已有用户绑定邮箱（source=admin，无验证码）。"""
        imported = self.add_mock_user("oldstaff", real_name="旧员工")
        email = self.new_email()
        status, headers, data, raw = self.admin_post(
            "/api/admin/bind-email", {"username": imported, "email": email}
        )
        self.assertEqual(status, 200, "管理员绑定邮箱应 200，body=%r" % (raw[:500],))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("username"), imported)
        self.assertEqual(data.get("email"), email)

        record, _list = self.find_user(username=imported)
        self.assertEqual(record.get("email"), email)
        self.assertEqual(record.get("source"), "imported")
        rows = self.query_user_emails(email)
        self.assertTrue(rows, "user_emails 应落库")
        self.assertEqual(rows[0].get("username"), imported)
        self.assertEqual(rows[0].get("source"), "admin")

        # 邮箱被占用 → 409
        another = self.add_mock_user("oldstaff2", real_name="旧员工二")
        status, _headers, data, raw = self.admin_post(
            "/api/admin/bind-email", {"username": another, "email": email}
        )
        self.assertEqual(status, 409, "邮箱已占用应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_ALREADY_BOUND")
        # 非学校邮箱 → 400；不存在用户 → 409 USER_MISSING
        status, _headers, data, _raw = self.admin_post(
            "/api/admin/bind-email", {"username": another, "email": "x@qq.com"}
        )
        self.assertEqual(status, 400, "非学校邮箱应 400")
        self.assert_error(data, "INVALID_EMAIL")
        status, _headers, data, raw = self.admin_post(
            "/api/admin/bind-email",
            {"username": "nosuchuser", "email": self.new_email()},
        )
        self.assertEqual(status, 409, "不存在用户应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "USER_MISSING")

    # ---- v1.5：user_emails 跨表唯一性 / portal 同步 ----

    def test_user_emails_sync_and_cross_table_uniqueness(self):
        # portal 注册同步 registrations.email 与 user_emails(source=portal)
        email = self.new_email()
        account, _data, _raw = self.register_ok("同步用户", "10.21.1.1", email=email)
        username = account.get("username")
        rows = self.query_user_emails(email)
        self.assertEqual(len(rows), 1, "portal 注册应同步 user_emails")
        self.assertEqual(rows[0].get("username"), username)
        self.assertEqual(rows[0].get("source"), "portal")
        self.assertTrue(str(rows[0].get("verified_at") or "").strip())

        # 系统已有用户经管理员绑定邮箱后，该邮箱不能再注册（send-code 409）
        imported = self.add_mock_user("oldbind", real_name="旧绑定")
        bound_email = self.new_email()
        status, _headers, _data, raw = self.admin_post(
            "/api/admin/bind-email", {"username": imported, "email": bound_email}
        )
        self.assertEqual(status, 200, "管理员绑定邮箱应 200，body=%r" % (raw[:500],))
        status, _headers, data, raw = self.send_code(bound_email, "10.21.1.2")
        self.assertEqual(
            status, 409, "已绑定邮箱 send-code 应 409，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "EMAIL_REGISTERED")
    # ---- 公告（SPEC v1.2）----

    def test_announcement_01_default(self):
        data, raw = self.get_ok_json("/api/announcement")
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("content"), DEFAULT_ANNOUNCEMENT)
        self.assertTrue(data["content"].strip(), "默认公告内容不能为空")
        self.assertIsInstance(data.get("updated_at"), str)
        self.assertIn("公告", raw.decode("utf-8"))

    def test_announcement_02_admin_update_immediate(self):
        content = "更新后的公告\n第二行：校外 IPv6 登录端口 2222\t（制表符允许）"
        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": content}
        )
        self.assertEqual(status, 200, "更新公告应 200，body=%r" % (raw[:500],))
        self.assertIs(data.get("ok"), True)
        self.assertIsInstance(data.get("updated_at"), str)
        self.assertTrue(data["updated_at"].strip())

        # GET 立即生效
        current, _raw = self.get_ok_json("/api/announcement")
        self.assertEqual(current.get("content"), content)
        self.assertEqual(current.get("updated_at"), data.get("updated_at"))

    def test_announcement_03_invalid(self):
        # 空内容 → 400
        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": ""}
        )
        self.assertEqual(status, 400, "空公告应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "INVALID_REQUEST")

        # 控制字符 → 400
        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": "公告\x07内容"}
        )
        self.assertEqual(status, 400, "控制字符应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "INVALID_REQUEST")

        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": "公告\x00内容"}
        )
        self.assertEqual(status, 400, "NUL 控制字符应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "INVALID_REQUEST")

        # Unicode 格式字符（Cf，如 U+202E 双向覆盖）按「其他控制字符」拒绝（F5 回归）
        for cf_char in ("\u202e", "\u200b", "\u2066"):
            with self.subTest(cf_char=repr(cf_char)):
                status, headers, data, raw = self.admin_post(
                    "/api/admin/announcement", {"content": "公告%s内容" % cf_char}
                )
                self.assertEqual(
                    status, 400, "Cf 格式字符应 400，body=%r" % (raw[:500])
                )
                self.assert_error(data, "INVALID_REQUEST")

        # 超长内容（> 20000 字符）。注意 §7 的 8KB body 上限可能先于内容校验触发：
        # 400（INVALID_REQUEST）或 413（PAYLOAD_TOO_LARGE）都属于「拒绝」，均可接受。
        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": "a" * 20001}
        )
        self.assertIn(
            status, (400, 413), "超长公告应被拒绝，实际 %s body=%r" % (status, raw[:300])
        )
        if status == 400:
            self.assert_error(data, "INVALID_REQUEST")
        else:
            self.assert_error(data, "PAYLOAD_TOO_LARGE")

    # ---- 静态资源 ----

    def test_static_index_page(self):
        status, headers, _data, raw = self.call("GET", "/")
        self.assertEqual(status, 200, "首页应 200，body=%r" % (raw[:500],))
        content_type = (_header(headers, "Content-Type") or "").lower()
        self.assertIn("text/html", content_type)
        html = raw.decode("utf-8", "replace")
        self.assertTrue(_is_cjk(html), "首页应包含中文")
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.S | re.I)
        self.assertIsNotNone(title_match, "首页缺少 <title>")
        self.assertTrue(_is_cjk(title_match.group(1)), "首页标题应为中文")
        self.assertIn("/static/", html, "首页应引用本地 /static/* 资源")
        self.assertIsNotNone(
            re.search(r'(?:src|href)="/static/[^"]+\.(?:js|css)', html),
            "首页应引用本地 /static/*.js 或 .css",
        )
        # v1.2：公告面板容器
        self.assertIn("公告", html, "首页应包含公告面板")
        # v1.4 §21.4：忘记密码入口
        self.assertIn("忘记密码", html, "首页应包含忘记密码入口（SPEC §21.4）")
        self.assert_security_headers(headers)

    def test_static_admin_page(self):
        status, headers, _data, raw = self.call("GET", "/admin")
        self.assertEqual(status, 200, "管理页应 200，body=%r" % (raw[:500],))
        content_type = (_header(headers, "Content-Type") or "").lower()
        self.assertIn("text/html", content_type)
        html = raw.decode("utf-8", "replace")
        self.assertTrue(_is_cjk(html), "管理页应包含中文")
        self.assertIn("/static/", html, "管理页应引用本地 /static/* 资源")
        self.assert_security_headers(headers)

    def test_static_v15_contract(self):
        """SPEC §22.5：前端三入口/管理页改 users 接口/删除功能彻底移除。"""
        static_dir = os.path.join(PROJECT_ROOT, "static")

        def read(name):
            path = os.path.join(static_dir, name)
            self.assertTrue(os.path.isfile(path), "缺少静态文件 %s" % name)
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()

        index_html = read("index.html")
        app_js = read("app.js")
        admin_html = read("admin.html")
        admin_js = read("admin.js")
        frontend = index_html + "\n" + app_js
        admin_frontend = admin_html + "\n" + admin_js
        # 三个入口：申请账号 / 绑定已有账号邮箱 / 忘记密码
        self.assertIn("忘记密码", frontend)
        self.assertIn("绑定", frontend, "申请页应提供绑定已有账号邮箱入口（SPEC §22.5）")
        # 管理页改用 /api/admin/users，不再调用旧 registrations / delete-user
        self.assertIn("/api/admin/users", admin_js)
        self.assertNotIn("/api/admin/registrations", admin_js)
        self.assertNotIn("delete-user", admin_frontend, "前端不得再调用 delete-user")
        self.assertNotIn("/api/admin/delete", admin_frontend)
        self.assertNotIn("data-action=\"delete", admin_frontend, "不得存在删除操作按钮")
        self.assertNotIn("删除账号按钮", admin_frontend, "删除账号按钮应移除")
        # 管理页包含绑定邮箱操作
        self.assertIn("绑定邮箱", admin_frontend)

    def test_static_path_traversal(self):
        cases = [
            "/static/../app/server.py",
            "/static/%2e%2e/app/server.py",
            "/static/..%2fapp/server.py",
            "/static/../../etc/passwd",
            "/static/../SPEC.md",
        ]
        for path in cases:
            with self.subTest(path=path):
                status, body = _raw_http_get(self.server.port, path)
                self.assertIn(
                    status,
                    (400, 403, 404),
                    "路径穿越应被拒绝: %s（实际 %s）" % (path, status),
                )
                self.assertNotIn(b"def do_", body, "路径穿越不应泄露源码")
                self.assertNotIn(b"import ", body, "路径穿越不应泄露源码")
                self.assertNotIn(b"root:", body, "路径穿越不应泄露系统文件")


# ---------------------------------------------------------------------------
# 限流（可配置验证；独立 server 避免污染主流程）
# ---------------------------------------------------------------------------

class RateLimitTest(MockApiTestCase):
    config_overrides = {
        "rate_limits": {"preview": {"window_seconds": 60, "max_requests": 2}}
    }

    def test_preview_rate_limited(self):
        path = "/api/preview?name=" + urllib.parse.quote("张三")
        headers = {"X-Test-Client-IP": "10.30.0.1"}
        for _ in range(2):
            status, _headers, data, raw = self.call("GET", path, headers=headers)
            self.assertEqual(status, 200, "限流窗口内应 200，body=%r" % (raw[:500],))

        status, response_headers, data, raw = self.call("GET", path, headers=headers)
        self.assertEqual(
            status, 429, "超过限流应 429，实际 %s body=%r" % (status, raw[:500])
        )
        self.assert_error(data, "RATE_LIMITED")
        retry_after = _header(response_headers, "Retry-After")
        self.assertIsNotNone(retry_after, "429 响应应带 Retry-After")
        self.assertTrue(str(retry_after).strip().isdigit(), "Retry-After 应为秒数: %r" % (retry_after,))
        self.assertGreaterEqual(int(retry_after), 1)


# ---------------------------------------------------------------------------
# 公告持久化（重启后仍生效；独立 server）
# ---------------------------------------------------------------------------

class AnnouncementPersistenceTest(MockApiTestCase):
    def test_01_default_announcement(self):
        data, _raw = self.get_ok_json("/api/announcement")
        self.assertEqual(data.get("content"), DEFAULT_ANNOUNCEMENT)

    def test_02_update_persists_after_restart(self):
        content = "重启后仍生效的公告\n第二行：校外 IPv6 登录端口 2222"
        status, headers, data, raw = self.admin_post(
            "/api/admin/announcement", {"content": content}
        )
        self.assertEqual(status, 200, "更新公告应 200，body=%r" % (raw[:500],))
        updated_at = data.get("updated_at")

        current, _raw = self.get_ok_json("/api/announcement")
        self.assertEqual(current.get("content"), content)

        # 重启 server（同一 DB，新端口）→ 公告应仍然生效
        self.server.restart()
        current, _raw = self.get_ok_json("/api/announcement")
        self.assertEqual(current.get("content"), content, "重启后公告内容应持久化")
        if updated_at:
            self.assertEqual(current.get("updated_at"), updated_at)


# ---------------------------------------------------------------------------
# v1.3 §18：邮箱验证码（mock 模式）
# ---------------------------------------------------------------------------

class EmailSendCodeTest(MockApiTestCase):
    """SPEC §18.4/§18.6 send-code：域名、规范化、debug_code、HMAC、冷却、已注册。"""

    def test_allowed_domains_and_debug_code(self):
        for domain in EMAIL_ALLOWED_DOMAINS:
            email = self.new_email(domain=domain)
            data, raw = self.send_code_ok(email, "10.0.1.1")
            self.assertEqual(data.get("email"), email)
            self.assertIsInstance(data.get("expires_in"), int)
            self.assertEqual(data.get("expires_in"), EMAIL_TTL_SECONDS)
            self.assertIsInstance(data.get("cooldown"), int)
            self.assertEqual(data.get("cooldown"), EMAIL_COOLDOWN_SECONDS)
            debug_code = data.get("debug_code")
            self.assertIsNotNone(debug_code, "mock 模式 send-code 必须返回 debug_code")
            self.assertRegex(str(debug_code), r"^\d{6}$")
            entries = [item for item in self.mock_emails() if item.get("email") == email]
            self.assertTrue(entries, "mock 模式应写入 mock-emails.jsonl")
            self.assertEqual(str(entries[-1].get("code")), str(debug_code))
            self.assertIn("created_at", entries[-1])
            rows = self.query_email_codes(email)
            self.assertTrue(rows, "email_codes 表应有记录")
            latest = rows[-1]
            self.assertEqual(latest.get("used"), 0)
            self.assertNotEqual(latest.get("code_hash"), str(debug_code))
            self.assertEqual(
                latest.get("code_hash"),
                self.expected_code_hash(email, str(debug_code)),
                "验证码必须以 HMAC-SHA256(code_secret, email+':'+code) 存储（SPEC §18.3）",
            )
            self.assertNotIn(EMAIL_CODE_SECRET, raw.decode("utf-8"))

    def test_uppercase_email_normalized(self):
        raw_email = self.new_email(prefix="QA").upper()
        data, _raw = self.send_code_ok(raw_email, "10.0.1.2")
        self.assertEqual(data.get("email"), raw_email.lower())

    def test_rejects_non_school_domains(self):
        for email in (
            "someone@qq.com",
            "someone@gmail.com",
            "someone@mails.example.edu.cn.evil.com",
            "someone@xmails.example.edu.cn",
            "someone@mail.example.edu.cn",
            "someone@example.edu.cn.cn",
        ):
            with self.subTest(email=email):
                status, headers, data, raw = self.send_code(email, "10.0.1.3")
                self.assertEqual(
                    status, 400, "非学校邮箱应 400: %r body=%r" % (email, raw[:500])
                )
                self.assert_json_content_type(headers)
                self.assert_error(data, "INVALID_EMAIL")

    def test_rejects_invalid_formats(self):
        invalid = [
            "",
            "abc",
            "a@b",
            "a b@mails.example.edu.cn",
            "a@@mails.example.edu.cn",
            "a@mails.example.edu.cn\r\nBcc: evil@example.com",
            ("a" * 250) + "@mails.example.edu.cn",
        ]
        for email in invalid:
            with self.subTest(email=repr(email)):
                status, _headers, data, raw = self.send_code(email, "10.0.1.4")
                self.assertEqual(
                    status, 400, "非法邮箱应 400: %r body=%r" % (email, raw[:500])
                )
                self.assert_error(data, "INVALID_EMAIL")

    def test_requires_json_headers(self):
        email = self.new_email()
        status, _headers, data, _raw = self.call(
            "POST",
            "/api/email/send-code",
            body={"email": email},
            headers={"X-Test-Client-IP": "10.0.1.5"},
        )
        self.assertEqual(status, 403, "缺 X-Requested-With 应 403")
        self.assert_error(data, "BAD_REQUEST")
        raw_body = json.dumps({"email": email}, ensure_ascii=False).encode("utf-8")
        status, _headers, _data, _raw = self.call(
            "POST",
            "/api/email/send-code",
            body=raw_body,
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.0.1.5",
            },
        )
        self.assertEqual(status, 403, "缺 Content-Type 应 403")

    def test_cooldown_60s(self):
        email = self.new_email()
        self.send_code_ok(email, "10.0.1.6")
        status, headers, data, raw = self.send_code(email, "10.0.1.6")
        self.assertEqual(status, 429, "60s 冷却内重复发送应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        retry_after = _header(headers, "Retry-After")
        self.assertIsNotNone(retry_after, "冷却 429 应带 Retry-After")
        self.assertTrue(str(retry_after).strip().isdigit())
        self.assertGreaterEqual(int(retry_after), 1)

    def test_registered_email_409(self):
        email = self.new_email()
        self.register_ok("孙一", "10.0.1.7", email=email)
        status, _headers, data, raw = self.send_code(email, "10.0.9.9")
        self.assertEqual(status, 409, "已注册邮箱 send-code 应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_REGISTERED")


class EmailRegisterFlowTest(MockApiTestCase):
    """SPEC §18.4 register：验证码校验、一次性、attempts、不占 IP/email。"""

    def test_success_one_time_and_account_email(self):
        email = self.new_email()
        code_data, _raw = self.send_code_ok(email, "10.61.1.1")
        code = str(code_data["debug_code"])
        account, _data, raw = self.register_ok(
            "张三", "10.61.1.1", email=email, email_code=code
        )
        response_text = raw.decode("utf-8")
        self.assertEqual(account.get("email"), email)
        self.assertNotIn(STRONG_PW, response_text, "注册响应不应包含密码")
        self.assertNotIn(code, response_text, "注册响应不应包含验证码")
        # SPEC §18.8（v1.3 更新）：成功后同一码再次注册必须失败；
        # 已注册邮箱返回 409 EMAIL_REGISTERED（优先）或验证码层 400 EMAIL_CODE_INVALID 均允许。
        status, _headers, err, raw2 = self.register(
            "李四", "10.61.1.2", email=email, email_code=code
        )
        self.assertIn(
            status,
            (400, 409),
            "复用验证码/已注册邮箱应失败，body=%r" % (raw2[:500],),
        )
        self.assertIn(
            err["error"]["code"],
            ("EMAIL_REGISTERED", "EMAIL_CODE_INVALID"),
            "一次性失败码不符: %r" % (err,),
        )
        # 已注册邮箱 + 错误验证码：EMAIL_REGISTERED 优先于验证码错误（不泄露验证码状态）
        status, _headers, err, raw3 = self.register(
            "李四", "10.61.1.2", email=email, email_code="000000"
        )
        self.assertEqual(status, 409, "已注册邮箱应优先 409，body=%r" % (raw3[:500],))
        self.assert_error(err, "EMAIL_REGISTERED")
        # 该验证码给另一个未注册邮箱 → EMAIL_CODE_INVALID（码已被消费）
        other_email = self.new_email()
        status, _headers, err, raw4 = self.register(
            "李四", "10.61.1.3", email=other_email, email_code=code
        )
        self.assertEqual(status, 400, "已消费验证码给其他邮箱应 400，body=%r" % (raw4[:500],))
        self.assert_error(err, "EMAIL_CODE_INVALID")
        # 失败请求不占用 IP：IP2 可用新邮箱正常注册
        account2, _d, _raw = self.register_ok("李四", "10.61.1.2")
        self.assertEqual(account2.get("username"), "lisi")

    def test_wrong_code_invalid_then_correct(self):
        email = self.new_email()
        code = str(self.send_code_ok(email, "10.61.2.1")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        status, _headers, data, raw = self.register(
            "赵七", "10.61.2.1", email=email, email_code=wrong
        )
        self.assertEqual(status, 400, "错误验证码应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_INVALID")
        account, _d, _raw = self.register_ok(
            "赵七", "10.61.2.1", email=email, email_code=code
        )
        self.assertEqual(account.get("username"), "zhaoqi")

    def test_missing_email_fields(self):
        status, _headers, data, raw = self.call(
            "POST",
            "/api/register",
            body={"name": "李雷", "password": STRONG_PW},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.61.3.1",
            },
        )
        self.assertEqual(status, 400, "缺 email 应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "INVALID_EMAIL")
        email = self.new_email()
        status, _headers, data, raw = self.call(
            "POST",
            "/api/register",
            body={"name": "李雷", "password": STRONG_PW, "email": email},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.61.3.1",
            },
        )
        self.assertEqual(status, 400, "缺 email_code 应 400，body=%r" % (raw[:500],))
        self.assertFalse(data.get("ok"))
        self.assertIn(data["error"]["code"], ("EMAIL_CODE_INVALID", "INVALID_REQUEST"))

    def test_rejects_non_school_email(self):
        for email in ("a@qq.com", "not-an-email"):
            with self.subTest(email=email):
                status, _headers, data, raw = self.register(
                    "李雷", "10.61.3.2", email=email, email_code="123456"
                )
                self.assertEqual(
                    status, 400, "非学校邮箱注册应 400，body=%r" % (raw[:500],)
                )
                self.assert_error(data, "INVALID_EMAIL")

    def test_email_normalized_on_register(self):
        raw_email = self.new_email(prefix="QA").upper()
        code = str(self.send_code_ok(raw_email, "10.61.3.3")[0]["debug_code"])
        account, _d, _raw = self.register_ok(
            "韩梅", "10.61.3.3", email=raw_email, email_code=code
        )
        self.assertEqual(account.get("email"), raw_email.lower())

    def test_too_many_attempts(self):
        email = self.new_email()
        code = str(self.send_code_ok(email, "10.61.4.1")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        error_codes = []
        for _ in range(6):
            status, _headers, data, raw = self.register(
                "周杰", "10.61.4.1", email=email, email_code=wrong
            )
            self.assertEqual(status, 400, "错误验证码应 400，body=%r" % (raw[:500],))
            error_codes.append(data["error"]["code"])
        self.assertEqual(error_codes[0], "EMAIL_CODE_INVALID")
        self.assertIn(
            "EMAIL_TOO_MANY_ATTEMPTS",
            error_codes[-2:],
            "错 5 次后应返回 EMAIL_TOO_MANY_ATTEMPTS: %r" % (error_codes,),
        )
        status, _headers, data, raw = self.register(
            "周杰", "10.61.4.1", email=email, email_code=code
        )
        self.assertEqual(status, 400)
        self.assert_error(data, "EMAIL_TOO_MANY_ATTEMPTS")


class EmailUniquenessRegisterTest(MockApiTestCase):
    """SPEC §18.4 第 6 步：register 时 email DB UNIQUE 冲突 → 409 EMAIL_REGISTERED。"""

    def test_register_same_email_conflict(self):
        email = self.new_email()
        self.register_ok("钱一", "10.62.1.1", email=email)
        code = "123456"
        conn = sqlite3.connect(self.db_path())
        try:
            conn.execute(
                "INSERT INTO email_codes "
                "(email, code_hash, expires_at, used, attempts, ip, created_at) "
                "VALUES (?, ?, ?, 0, 0, ?, ?)",
                (
                    email,
                    self.expected_code_hash(email, code),
                    int(time.time()) + 600,
                    "10.62.9.9",
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                ),
            )
            conn.commit()
        finally:
            conn.close()
        status, _headers, data, raw = self.register(
            "钱二", "10.62.1.2", email=email, email_code=code
        )
        self.assertEqual(status, 409, "同邮箱注册应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_REGISTERED")
        record, _list = self.find_registration(username="qianer")
        self.assertIsNone(record, "EMAIL_REGISTERED 时不得创建用户")
        account, _d, _raw = self.register_ok("钱二", "10.62.1.2")
        self.assertEqual(account.get("username"), "qianer")


class EmailTtlTest(MockApiTestCase):
    config_overrides = {"email": {"code_ttl_seconds": 1}}

    def test_expired_code(self):
        email = self.new_email()
        code = str(self.send_code_ok(email, "10.63.1.1")[0]["debug_code"])
        time.sleep(1.4)
        status, _headers, data, raw = self.register(
            "吴迪", "10.63.1.1", email=email, email_code=code
        )
        self.assertEqual(status, 400, "过期验证码应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_EXPIRED")
        record, _list = self.find_registration(username="wudi")
        self.assertIsNone(record, "过期验证码不得创建用户")


class EmailPerEmailDailyTest(MockApiTestCase):
    config_overrides = {
        "email": {
            "resend_cooldown_seconds": 1,
            "max_send_per_email_per_day": 2,
            "max_send_global_per_day": 100,
        }
    }

    def test_per_email_daily_limit(self):
        email = self.new_email()
        self.send_code_ok(email, "10.64.1.1")
        time.sleep(1.2)
        self.send_code_ok(email, "10.64.1.1")
        time.sleep(1.2)
        status, headers, data, raw = self.send_code(email, "10.64.1.1")
        self.assertEqual(status, 429, "每邮箱每日上限应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        self.assertTrue((_header(headers, "Retry-After") or "").strip().isdigit())


class EmailGlobalDailyTest(MockApiTestCase):
    config_overrides = {"email": {"max_send_global_per_day": 2}}

    def test_global_daily_limit(self):
        for _ in range(2):
            self.send_code_ok(self.new_email(), "10.65.1.1")
        status, _headers, data, raw = self.send_code(self.new_email(), "10.65.1.2")
        self.assertEqual(status, 429, "全局每日上限应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")


class EmailIpRateLimitTest(MockApiTestCase):
    config_overrides = {
        "rate_limits": {"email_send": {"window_seconds": 60, "max_requests": 2}}
    }

    def test_ip_rate_limited(self):
        ip = "10.0.0.1"
        for _ in range(2):
            self.send_code_ok(self.new_email(), ip)
        status, headers, data, raw = self.send_code(self.new_email(), ip)
        self.assertEqual(status, 429, "每 IP email_send 限流应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        self.assertTrue((_header(headers, "Retry-After") or "").strip().isdigit())


class EmailDisabledTest(MockApiTestCase):
    config_overrides = {"email": {"enabled": False}}

    def test_send_code_disabled(self):
        status, _headers, data, raw = self.send_code(self.new_email(), "10.67.0.1")
        self.assertEqual(status, 409, "email.enabled=false 应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_DISABLED")
        health, _raw = self.get_ok_json("/api/health")
        self.assertIs(health.get("email_verification_enabled"), False)

    def test_register_disabled(self):
        """SPEC §19 定稿：email.enabled=false 时 register 也返回 409 EMAIL_DISABLED。"""
        email = self.new_email()
        status, _headers, data, raw = self.call(
            "POST",
            "/api/register",
            body={
                "name": "李雷",
                "password": STRONG_PW,
                "email": email,
                "email_code": "123456",
            },
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.67.0.2",
            },
        )
        self.assertEqual(status, 409, "邮箱验证停用时 register 应 409，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_DISABLED")

    def test_reset_request_disabled(self):
        """SPEC §21.1：email.enabled=false 时 reset-request 返回 409 EMAIL_DISABLED。"""
        email = self.new_email()
        self.insert_registration_row(email, username="disabledreset")
        status, _headers, data, raw = self.reset_request(email, "10.67.0.3")
        self.assertEqual(
            status, 409, "邮箱验证停用时 reset-request 应 409，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "EMAIL_DISABLED")



class MigrationHistoricalDataTest(MockApiTestCase):
    """SPEC §18.3/§21.2：旧库（v1.2，无 email/email_codes）迁移到 v3，历史记录 email=null 保留。"""

    @classmethod
    def setUpClass(cls):
        cls.legacy_dir = tempfile.mkdtemp(prefix=QA_TMP_PREFIX + "migrate-")
        cls.legacy_db = os.path.join(cls.legacy_dir, "registrations.db")
        conn = sqlite3.connect(cls.legacy_db)
        try:
            conn.executescript(
                """
                CREATE TABLE registrations (
                  id           INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip           TEXT    NOT NULL UNIQUE,
                  real_name    TEXT    NOT NULL,
                  pinyin       TEXT    NOT NULL,
                  username     TEXT    NOT NULL UNIQUE,
                  uid          INTEGER,
                  gid          INTEGER,
                  home         TEXT,
                  workspace    TEXT,
                  status       TEXT    NOT NULL,
                  created_at   TEXT    NOT NULL,
                  updated_at   TEXT    NOT NULL
                );
                CREATE TABLE meta (
                  key   TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO registrations "
                "(ip, real_name, pinyin, username, uid, gid, home, workspace, "
                " status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "10.99.9.9",
                    "旧用户",
                    "jiuyonghu",
                    "legacyuser",
                    1001,
                    1001,
                    "/home/legacyuser",
                    "/home/legacyuser",
                    "active",
                    "2026-10-24T07:05:00Z",
                    "2026-10-24T07:05:00Z",
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '1')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) "
                "VALUES('registration_enabled', 'true')"
            )
            conn.commit()
        finally:
            conn.close()
        cls.server = MockServer(
            {
                "paths": {
                    "db": cls.legacy_db,
                    "lock": os.path.join(cls.legacy_dir, "register.lock"),
                }
            }
        )

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.stop()
            cls.server = None
        shutil.rmtree(getattr(cls, "legacy_dir", ""), ignore_errors=True)

    def test_01_historical_row_preserved_with_null_email(self):
        data = self.list_registrations()
        legacy = [r for r in data["registrations"] if r.get("username") == "legacyuser"]
        self.assertEqual(len(legacy), 1, "历史注册记录必须保留（SPEC §18.3/§18.8）")
        self.assertIsNone(legacy[0].get("email"), "历史记录 email 应为 null")
        self.assertEqual(legacy[0].get("real_name"), "旧用户")
        # schema_version 升级到 4；email/user_emails/email_codes.purpose 齐全（SPEC §22.2）
        conn = sqlite3.connect(self.legacy_db)
        try:
            version = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            reg_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(registrations)").fetchall()
            }
            code_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(email_codes)").fetchall()
            }
            user_email_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(user_emails)").fetchall()
            }
            backfilled = conn.execute(
                "SELECT COUNT(*) FROM user_emails"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(version[0], "4")
        self.assertIn("email", reg_columns)
        self.assertIn("purpose", code_columns, "email_codes 必须有 purpose 列")
        self.assertEqual(
            set(user_email_columns),
            {"username", "email", "source", "verified_at", "created_at"},
            "user_emails 表结构应符合 SPEC §22.2",
        )
        self.assertEqual(backfilled, 0, "历史记录 email=null 不产生 user_emails 回填")

    def test_02_new_email_registration_coexists(self):
        email = self.new_email()
        account, _data, _raw = self.register_ok("新用户", "10.80.1.1", email=email)
        username = account.get("username")
        self.assertEqual(account.get("email"), email)
        data = self.list_users()
        legacy = [r for r in data["users"] if r.get("username") == "legacyuser"]
        self.assertEqual(legacy[0].get("email"), None, "新注册不应修改历史记录")
        emails = [r.get("email") for r in data["users"]]
        self.assertIn(email, emails)
        rows = self.query_user_emails(email, db_path=self.legacy_db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].get("username"), username)
        self.assertEqual(rows[0].get("source"), "portal")



class EmailAttemptsConcurrencyTest(MockApiTestCase):
    """F10 回归：并发错误验证码不得绕过 5 次尝试上限（SPEC §18.4/§19.4）。"""

    def test_concurrent_wrong_codes_capped(self):
        email = self.new_email()
        code = str(self.send_code_ok(email, "10.68.0.1")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        results = []
        lock = threading.Lock()

        def attempt(index):
            status, _headers, data, _raw = self.register(
                "并发测",
                "10.68.0.%d" % (index + 10),
                email=email,
                email_code=wrong,
            )
            error_code = None
            if isinstance(data, dict):
                error_code = (data.get("error") or {}).get("code")
            with lock:
                results.append((status, error_code))

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), 8)
        invalid = sum(1 for _status, err in results if err == "EMAIL_CODE_INVALID")
        too_many = sum(
            1 for _status, err in results if err == "EMAIL_TOO_MANY_ATTEMPTS"
        )
        # 最多允许 4 次真正的「错误猜测」（第 5 次起必须 TOO_MANY），不允许并发放大
        self.assertLessEqual(
            invalid, EMAIL_MAX_ATTEMPTS - 1,
            "并发错误验证码被放行次数超过上限: %r" % (results,),
        )
        self.assertGreaterEqual(too_many, 1, "超限请求应返回 EMAIL_TOO_MANY_ATTEMPTS: %r" % (results,))
        # 上限已达后，正确验证码同样必须被拒绝（需重新发送）
        status, _headers, data, _raw = self.register(
            "并发测", "10.68.1.1", email=email, email_code=code
        )
        self.assertEqual(status, 400)
        self.assert_error(data, "EMAIL_TOO_MANY_ATTEMPTS")
        # DB 中 attempts 不得超过配置上限
        rows = self.query_email_codes(email)
        self.assertTrue(rows)
        self.assertLessEqual(
            max(int(row.get("attempts") or 0) for row in rows),
            EMAIL_MAX_ATTEMPTS,
            "email_codes.attempts 超过上限",
        )



class MigrationV13ToV4Test(MockApiTestCase):
    """SPEC §21.2/§22.2：v1.3 旧库（email_codes 无 purpose）迁移到 v4；回填 user_emails 且旧码默认 register。"""

    LEGACY_EMAIL = "oldv13user@mails.example.edu.cn"
    LEGACY_CODE = "246810"

    @classmethod
    def setUpClass(cls):
        cls.legacy_dir = tempfile.mkdtemp(prefix=QA_TMP_PREFIX + "migrate-")
        cls.legacy_db = os.path.join(cls.legacy_dir, "registrations.db")
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = sqlite3.connect(cls.legacy_db)
        try:
            conn.executescript(
                """
                CREATE TABLE registrations (
                  id           INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip           TEXT    NOT NULL UNIQUE,
                  real_name    TEXT    NOT NULL,
                  pinyin       TEXT    NOT NULL,
                  username     TEXT    NOT NULL UNIQUE,
                  email        TEXT,
                  uid          INTEGER,
                  gid          INTEGER,
                  home         TEXT,
                  workspace    TEXT,
                  status       TEXT    NOT NULL,
                  created_at   TEXT    NOT NULL,
                  updated_at   TEXT    NOT NULL
                );
                CREATE UNIQUE INDEX idx_registrations_email ON registrations(email);
                CREATE TABLE email_codes (
                  id         INTEGER PRIMARY KEY AUTOINCREMENT,
                  email      TEXT NOT NULL,
                  code_hash  TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  used       INTEGER NOT NULL DEFAULT 0,
                  attempts   INTEGER NOT NULL DEFAULT 0,
                  ip         TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE TABLE meta (
                  key   TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                """
            )
            conn.execute(
                "INSERT INTO registrations "
                "(ip, real_name, pinyin, username, email, uid, gid, home, "
                " workspace, status, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                (
                    "10.97.9.9", "旧版用户", "jiuban", "oldv13user",
                    cls.LEGACY_EMAIL, 1200, 1200,
                    "/home/oldv13user", "/home/oldv13user", now_iso, now_iso,
                ),
            )
            message = ("%s:%s" % (cls.LEGACY_EMAIL, cls.LEGACY_CODE)).encode("utf-8")
            code_hash = hmac.new(
                EMAIL_CODE_SECRET.encode("utf-8"), message, hashlib.sha256
            ).hexdigest()
            conn.execute(
                "INSERT INTO email_codes "
                "(email, code_hash, expires_at, used, attempts, ip, created_at) "
                "VALUES (?, ?, ?, 0, 0, ?, ?)",
                (
                    cls.LEGACY_EMAIL,
                    code_hash,
                    int(time.time()) + 600,
                    "10.97.0.9",
                    time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 3600)
                    ),
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '2')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) "
                "VALUES('registration_enabled', 'true')"
            )
            conn.commit()
        finally:
            conn.close()
        cls.server = MockServer(
            {
                "paths": {
                    "db": cls.legacy_db,
                    "lock": os.path.join(cls.legacy_dir, "register.lock"),
                }
            }
        )

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.stop()
            cls.server = None
        shutil.rmtree(getattr(cls, "legacy_dir", ""), ignore_errors=True)

    def test_01_migration_preserves_data_and_defaults_register(self):
        conn = sqlite3.connect(self.legacy_db)
        try:
            version = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            code_columns = {
                row[1]
                for row in conn.execute("PRAGMA table_info(email_codes)").fetchall()
            }
            purposes = [
                row[0]
                for row in conn.execute(
                    "SELECT purpose FROM email_codes WHERE email = ?",
                    (self.LEGACY_EMAIL,),
                ).fetchall()
            ]
            reg = conn.execute(
                "SELECT email, username FROM registrations WHERE username = 'oldv13user'"
            ).fetchone()
        finally:
            conn.close()
        self.assertEqual(version[0], "4", "schema_version 应升级到 4")
        self.assertIn("purpose", code_columns)
        self.assertEqual(purposes, ["register"], "旧验证码迁移后 purpose 必须默认 register")
        self.assertEqual(reg[0], self.LEGACY_EMAIL)
        # 历史记录在管理员用户列表可见且 email 保留；user_emails 从 registrations.email 回填
        data = self.list_users()
        records = [
            item for item in data["users"] if item.get("username") == "oldv13user"
        ]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].get("email"), self.LEGACY_EMAIL)
        self.assertEqual(records[0].get("source"), "portal")
        conn = sqlite3.connect(self.legacy_db)
        try:
            backfill = conn.execute(
                "SELECT username, email, source FROM user_emails WHERE email = ?",
                (self.LEGACY_EMAIL,),
            ).fetchone()
        finally:
            conn.close()
        self.assertIsNotNone(backfill, "迁移应把 registrations.email 回填到 user_emails")
        self.assertEqual(backfill[0], "oldv13user")
        self.assertEqual(backfill[2], "portal")

    def test_02_old_register_code_cannot_reset_password(self):
        # 迁移仅回填邮箱；补充 mock 系统用户使其可管理（否则 USER_NOT_MANAGEABLE 先返回）
        self.add_mock_user("oldv13user", uid=1200, real_name="旧版用户")
        # 旧码 purpose=register → 重置校验按 purpose=reset 过滤 → EMAIL_CODE_INVALID
        status, _headers, data, raw = self.password_reset(
            self.LEGACY_EMAIL, self.LEGACY_CODE, NEW_STRONG_PW, "10.97.1.1"
        )
        self.assertEqual(
            status, 400, "注册用途旧码不能用于重置，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "EMAIL_CODE_INVALID")
        # 迁移后新发 reset 码仍可用（mock）
        email_data, _raw = self.reset_request_ok(self.LEGACY_EMAIL, "10.97.1.1")
        self.assertRegex(str(email_data.get("debug_code")), r"^\d{6}$")


class PasswordResetRequestTest(MockApiTestCase):
    """SPEC §21.3 reset-request：格式/已注册/启停/冷却/限流。"""

    def test_unregistered_email_404(self):
        email = self.new_email()
        status, headers, data, raw = self.reset_request(email, "10.72.1.1")
        self.assertEqual(status, 404, "未注册邮箱应 404，body=%r" % (raw[:500],))
        self.assert_json_content_type(headers)
        self.assert_error(data, "EMAIL_NOT_FOUND")

    def test_non_school_email_400(self):
        for email in ("someone@qq.com", "someone@gmail.com", "not-an-email"):
            with self.subTest(email=email):
                status, _headers, data, raw = self.reset_request(email, "10.72.1.2")
                self.assertEqual(status, 400, "非学校/非法邮箱应 400，body=%r" % (raw[:500],))
                self.assert_error(data, "INVALID_EMAIL")

    def test_registered_email_200_with_mock_debug_code(self):
        account, email = self.create_account("重置一", "10.72.1.3")
        self.clear_email_codes(email)
        data, raw = self.reset_request_ok(email, "10.72.1.3")
        self.assertEqual(data.get("email"), email)
        self.assertIsInstance(data.get("expires_in"), int)
        self.assertIsInstance(data.get("cooldown"), int)
        debug_code = data.get("debug_code")
        self.assertIsNotNone(debug_code, "mock 模式 reset-request 应返回 debug_code")
        self.assertRegex(str(debug_code), r"^\d{6}$")
        self.assertNotIn(EMAIL_CODE_SECRET, raw.decode("utf-8"))
        # mock-emails.jsonl 记录 purpose=reset；DB 最新码 purpose=reset 且 HMAC 正确
        entries = [item for item in self.mock_emails() if item.get("email") == email]
        self.assertTrue(entries)
        self.assertEqual(entries[-1].get("purpose"), "reset")
        rows = self.query_email_codes(email)
        latest = rows[-1]
        self.assertEqual(latest.get("purpose"), "reset")
        self.assertEqual(latest.get("used"), 0)
        self.assertEqual(
            latest.get("code_hash"),
            self.expected_code_hash(email, str(debug_code)),
        )

    def test_cooldown_60s(self):
        _account, email = self.create_account("重置二", "10.72.1.4")
        self.clear_email_codes(email)
        self.reset_request_ok(email, "10.72.1.4")
        status, headers, data, raw = self.reset_request(email, "10.72.1.4")
        self.assertEqual(status, 429, "60s 冷却内重复 reset-request 应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        retry_after = _header(headers, "Retry-After")
        self.assertIsNotNone(retry_after)
        self.assertGreaterEqual(int(str(retry_after).strip()), 1)

    def test_requires_json_headers(self):
        email = self.new_email()
        status, _headers, data, _raw = self.call(
            "POST", "/api/password/reset-request", body={"email": email},
            headers={"X-Test-Client-IP": "10.72.1.5"},
        )
        self.assertEqual(status, 403, "缺 X-Requested-With 应 403")
        self.assert_error(data, "BAD_REQUEST")


class PasswordResetFlowTest(MockApiTestCase):
    """SPEC §21.3 password/reset：成功/错误/过期/一次性/弱密码/USER_MISSING/不自动解锁。"""

    def test_success_locked_false_and_logs(self):
        account, email = self.create_account("重置成功", "10.73.1.1")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.1.1")[0]["debug_code"])
        data, raw = self.password_reset_ok(
            email, code, NEW_STRONG_PW, "10.73.1.1"
        )
        response_text = raw.decode("utf-8")
        self.assertEqual(data.get("username"), account.get("username"))
        self.assertIs(data.get("locked"), False)
        self.assertNotIn(code, response_text, "响应不得包含验证码")
        self.assertNotIn(NEW_STRONG_PW, response_text, "响应不得包含新密码")
        # 日志只有 password_reset（mask_email/username/locked），无验证码/新密码/完整邮箱
        log = self.server.log_text()
        self.assertIn("password_reset", log)
        self.assertNotIn(code, log, "日志不得出现验证码")
        self.assertNotIn(NEW_STRONG_PW, log, "日志不得出现新密码")
        self.assertNotIn(email, log, "日志不应记录完整邮箱（应掩码）")
        # 一次性：同一码再次重置 → EMAIL_CODE_INVALID（邮箱已注册所以不是 404）
        status, _headers, data2, raw2 = self.password_reset(
            email, code, NEW_STRONG_PW_2, "10.73.1.2"
        )
        self.assertEqual(status, 400, "复用验证码应 400，body=%r" % (raw2[:500],))
        self.assert_error(data2, "EMAIL_CODE_INVALID")
        # DB 中该码 used=1，且 purpose=reset
        rows = self.query_email_codes(email)
        reset_rows = [row for row in rows if row.get("purpose") == "reset"]
        self.assertTrue(reset_rows)
        self.assertTrue(any(int(row.get("used") or 0) == 1 for row in reset_rows))

    def test_wrong_code_then_correct_not_consumed(self):
        account, email = self.create_account("重置正确", "10.73.1.3")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.1.3")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        status, _headers, data, raw = self.password_reset(
            email, wrong, NEW_STRONG_PW, "10.73.1.3"
        )
        self.assertEqual(status, 400, "错误验证码应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_INVALID")
        # 失败不消耗验证码：正确码仍可重置
        data, _raw = self.password_reset_ok(email, code, NEW_STRONG_PW, "10.73.1.3")
        self.assertEqual(data.get("username"), account.get("username"))

    def test_weak_new_password_does_not_consume_code(self):
        account, email = self.create_account("重置弱密", "10.73.1.4")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.1.4")[0]["debug_code"])
        status, _headers, data, raw = self.password_reset(
            email, code, "abc123456", "10.73.1.4"
        )
        self.assertEqual(status, 400, "弱新密码应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "WEAK_PASSWORD")
        # 失败不消耗验证码：换强密码仍可成功
        data, _raw = self.password_reset_ok(email, code, NEW_STRONG_PW, "10.73.1.4")
        self.assertEqual(data.get("username"), account.get("username"))

    def test_too_many_attempts(self):
        _account, email = self.create_account("重试上限", "10.73.2.1")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.2.1")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        error_codes = []
        for _ in range(6):
            status, _headers, data, _raw = self.password_reset(
                email, wrong, NEW_STRONG_PW, "10.73.2.1"
            )
            self.assertEqual(status, 400)
            error_codes.append(data["error"]["code"])
        self.assertEqual(error_codes[0], "EMAIL_CODE_INVALID")
        self.assertIn("EMAIL_TOO_MANY_ATTEMPTS", error_codes[-2:], error_codes)
        status, _headers, data, _raw = self.password_reset(
            email, code, NEW_STRONG_PW, "10.73.2.1"
        )
        self.assertEqual(status, 400)
        self.assert_error(data, "EMAIL_TOO_MANY_ATTEMPTS")

    def test_cross_purpose_binding(self):
        # A) 注册码不能用于重置（用重置另一个已注册邮箱的方式观察 purpose 过滤）
        register_email = self.new_email()
        register_code = str(
            self.send_code_ok(register_email, "10.73.3.1")[0]["debug_code"]
        )
        _account, reset_email = self.create_account("跨用途一", "10.73.3.1")
        self.clear_email_codes(reset_email)
        status, _headers, data, raw = self.password_reset(
            reset_email, register_code, NEW_STRONG_PW, "10.73.3.2"
        )
        self.assertEqual(status, 400, "注册码用于重置应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_INVALID")
        # B) 重置码不能用于注册（为已注册邮箱发 reset 码，拿去注册另一个未注册邮箱）
        reset_code = str(self.reset_request_ok(reset_email, "10.73.3.3")[0]["debug_code"])
        other_email = self.new_email()
        status, _headers, data, raw = self.register(
            "跨用途二", "10.73.3.3", email=other_email, email_code=reset_code
        )
        self.assertEqual(status, 400, "重置码用于注册应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_INVALID")

    def test_user_missing_mapping(self):
        account, email = self.create_account("缺失用户", "10.73.4.1")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.4.1")[0]["debug_code"])
        # 模拟系统账号消失
        self.simulate_missing_system_user(account.get("username"))
        status, _headers, data, raw = self.password_reset(
            email, code, NEW_STRONG_PW, "10.73.4.1"
        )
        self.assertEqual(
            status, 409, "系统账号缺失/不可管理应 409 USER_NOT_MANAGEABLE，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "USER_NOT_MANAGEABLE")

    def test_locked_account_not_auto_unlocked(self):
        account, email = self.create_account("锁定重置", "10.73.5.1")
        record, _list = self.find_registration(username=account.get("username"))
        self.assertIsNotNone(record)
        status, _headers, _data, _raw = self.admin_post(
            "/api/admin/set-locked",
            {"username": account.get("username"), "locked": True},
        )
        self.assertEqual(status, 200)
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.73.5.1")[0]["debug_code"])
        data, _raw = self.password_reset_ok(email, code, NEW_STRONG_PW, "10.73.5.1")
        self.assertIs(data.get("locked"), True, "锁定账号重置后 locked 应为 true（不自动解锁）")
        record2, _list = self.find_registration(username=account.get("username"))
        self.assertEqual(record2.get("os_status"), "locked", "重置不得自动解锁（SPEC §21.5）")


class PasswordResetAttemptsConcurrencyTest(MockApiTestCase):
    """SPEC §21.5：重置验证码 5 次尝试上限必须原子（并发 8 请求不得放大）。"""

    def test_concurrent_wrong_codes_capped(self):
        _account, email = self.create_account("并发重置", "10.74.1.1")
        self.clear_email_codes(email)
        code = str(self.reset_request_ok(email, "10.74.1.1")[0]["debug_code"])
        wrong = "000000" if code != "000000" else "111111"
        results = []
        lock = threading.Lock()

        def attempt(index):
            status, _headers, data, _raw = self.password_reset(
                email, wrong, NEW_STRONG_PW, "10.74.1.%d" % (index + 10)
            )
            error_code = None
            if isinstance(data, dict):
                error_code = (data.get("error") or {}).get("code")
            with lock:
                results.append((status, error_code))

        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(len(results), 8)
        invalid = sum(1 for _s, err in results if err == "EMAIL_CODE_INVALID")
        too_many = sum(1 for _s, err in results if err == "EMAIL_TOO_MANY_ATTEMPTS")
        self.assertLessEqual(
            invalid, EMAIL_MAX_ATTEMPTS - 1,
            "并发重置错误验证码被放行次数超过上限: %r" % (results,),
        )
        self.assertGreaterEqual(too_many, 1, results)
        status, _headers, data, _raw = self.password_reset(
            email, code, NEW_STRONG_PW, "10.74.2.1"
        )
        self.assertEqual(status, 400)
        self.assert_error(data, "EMAIL_TOO_MANY_ATTEMPTS")
        rows = self.query_email_codes(email)
        reset_rows = [row for row in rows if row.get("purpose") == "reset"]
        self.assertTrue(reset_rows)
        self.assertLessEqual(
            max(int(row.get("attempts") or 0) for row in reset_rows),
            EMAIL_MAX_ATTEMPTS,
        )


class PasswordResetTtlTest(MockApiTestCase):
    config_overrides = {"email": {"code_ttl_seconds": 1}}

    def test_expired_reset_code(self):
        email = self.new_email()
        self.insert_registration_row(email, username="expiredreset")
        code = str(self.reset_request_ok(email, "10.75.1.1")[0]["debug_code"])
        time.sleep(1.4)
        status, _headers, data, raw = self.password_reset(
            email, code, NEW_STRONG_PW, "10.75.1.1"
        )
        self.assertEqual(status, 400, "过期重置码应 400，body=%r" % (raw[:500],))
        self.assert_error(data, "EMAIL_CODE_EXPIRED")


class PasswordResetPerEmailDailyTest(MockApiTestCase):
    config_overrides = {
        "email": {
            "resend_cooldown_seconds": 1,
            "max_send_per_email_per_day": 2,
            "max_send_global_per_day": 100,
        }
    }

    def test_per_email_daily_limit(self):
        email = self.new_email()
        self.insert_registration_row(email, username="dailyreset")
        self.reset_request_ok(email, "10.75.2.1")
        time.sleep(1.2)
        self.reset_request_ok(email, "10.75.2.1")
        time.sleep(1.2)
        status, headers, data, raw = self.reset_request(email, "10.75.2.1")
        self.assertEqual(status, 429, "每邮箱每日上限应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        self.assertTrue((_header(headers, "Retry-After") or "").strip().isdigit())


class PasswordResetGlobalDailyTest(MockApiTestCase):
    config_overrides = {"email": {"max_send_global_per_day": 2}}

    def test_global_daily_limit(self):
        for index in range(3):
            email = self.new_email()
            self.insert_registration_row(email, username="globalreset%d" % index)
            if index < 2:
                self.reset_request_ok(email, "10.75.3.%d" % (index + 1))
        email = self.new_email()
        self.insert_registration_row(email, username="globalreset9")
        status, _headers, data, raw = self.reset_request(email, "10.75.3.9")
        self.assertEqual(status, 429, "全局每日上限应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")


class PasswordResetIpRateLimitTest(MockApiTestCase):
    config_overrides = {
        "rate_limits": {"password_reset": {"window_seconds": 60, "max_requests": 2}}
    }

    def test_ip_rate_limited(self):
        ip = "10.76.0.1"
        for index in range(2):
            email = self.new_email()
            self.insert_registration_row(email, username="ipreset%d" % index)
            self.reset_request_ok(email, ip)
        email = self.new_email()
        self.insert_registration_row(email, username="ipreset9")
        status, headers, data, raw = self.reset_request(email, ip)
        self.assertEqual(status, 429, "每 IP password_reset 限流应 429，body=%r" % (raw[:500],))
        self.assert_error(data, "RATE_LIMITED")
        self.assertTrue((_header(headers, "Retry-After") or "").strip().isdigit())



class PasswordResetEnumerationRateLimitTest(MockApiTestCase):
    """L8 回归（SPEC §21.1/§21.3 更新）：reset-request 的 IP 限流必须先于「已注册」检查，
    防止攻击者对未注册邮箱无限速枚举（超过限额返回 429 而不是一直 404）。"""

    config_overrides = {
        "rate_limits": {"password_reset": {"window_seconds": 60, "max_requests": 2}}
    }

    def test_unregistered_enumeration_rate_limited(self):
        ip = "10.78.0.1"
        # 限额内：未注册邮箱仍然 404（信息级别与 send-code 一致）
        for _ in range(2):
            status, _headers, data, raw = self.reset_request(self.new_email(), ip)
            self.assertEqual(
                status, 404, "未注册邮箱应 404，body=%r" % (raw[:500],)
            )
            self.assert_error(data, "EMAIL_NOT_FOUND")
        # 超过 IP 限额后：即使邮箱未注册也必须 429（不能继续拿到 404 枚举）
        status, headers, data, raw = self.reset_request(self.new_email(), ip)
        self.assertEqual(
            status, 429, "未注册邮箱枚举超限应 429，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "RATE_LIMITED")
        retry_after = _header(headers, "Retry-After")
        self.assertIsNotNone(retry_after, "429 应带 Retry-After")
        self.assertGreaterEqual(int(str(retry_after).strip()), 1)
        # 格式校验仍在限流之前：非法/非学校邮箱依旧 400（不消耗/不受限流影响返回码）
        status, _headers, data, raw = self.reset_request("someone@qq.com", ip)
        self.assertEqual(
            status, 400, "格式校验应先于 IP 限流，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "INVALID_EMAIL")

    def test_registered_email_after_limit_also_429(self):
        ip = "10.78.0.2"
        email = self.new_email()
        self.insert_registration_row(email, username="enumreset")
        for _ in range(2):
            self.reset_request(self.new_email(), ip)
        status, _headers, data, raw = self.reset_request(email, ip)
        self.assertEqual(
            status, 429, "超过 IP 限额后已注册邮箱也应先 429，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "RATE_LIMITED")

    def test_other_ip_not_affected(self):
        limited_ip = "10.78.0.3"
        email = self.new_email()
        self.insert_registration_row(email, username="enumreset2")
        for _ in range(3):
            self.reset_request(self.new_email(), limited_ip)
        # 另一 IP 不受影响，已注册邮箱可正常发码
        data, _raw = self.reset_request_ok(email, "10.78.0.4")
        self.assertRegex(str(data.get("debug_code")), r"^\d{6}$")



class MigrationV14ToV4Test(MockApiTestCase):
    """SPEC §22.2：v1.4 旧库（schema_version=3）迁移到 v4，回填 user_emails 且数据保留。"""

    EMAIL_SET = "v14bound@mails.example.edu.cn"

    @classmethod
    def setUpClass(cls):
        cls.legacy_dir = tempfile.mkdtemp(prefix=QA_TMP_PREFIX + "migrate-")
        cls.legacy_db = os.path.join(cls.legacy_dir, "registrations.db")
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn = sqlite3.connect(cls.legacy_db)
        try:
            conn.executescript(
                """
                CREATE TABLE registrations (
                  id           INTEGER PRIMARY KEY AUTOINCREMENT,
                  ip           TEXT    NOT NULL UNIQUE,
                  real_name    TEXT    NOT NULL,
                  pinyin       TEXT    NOT NULL,
                  username     TEXT    NOT NULL UNIQUE,
                  email        TEXT,
                  uid          INTEGER,
                  gid          INTEGER,
                  home         TEXT,
                  workspace    TEXT,
                  status       TEXT    NOT NULL,
                  created_at   TEXT    NOT NULL,
                  updated_at   TEXT    NOT NULL
                );
                CREATE UNIQUE INDEX idx_registrations_email ON registrations(email);
                CREATE TABLE email_codes (
                  id         INTEGER PRIMARY KEY AUTOINCREMENT,
                  email      TEXT NOT NULL,
                  code_hash  TEXT NOT NULL,
                  expires_at INTEGER NOT NULL,
                  used       INTEGER NOT NULL DEFAULT 0,
                  attempts   INTEGER NOT NULL DEFAULT 0,
                  ip         TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  purpose    TEXT NOT NULL DEFAULT 'register'
                );
                CREATE TABLE meta (
                  key   TEXT PRIMARY KEY,
                  value TEXT NOT NULL
                );
                """
            )
            for row in (
                ("10.96.1.1", "旧版甲", "jiubanjia", "v14user", cls.EMAIL_SET,
                 1300, "/home/v14user"),
                ("10.96.1.2", "旧版乙", "jiubanyi", "v14legacy", None,
                 1301, "/home/v14legacy"),
            ):
                conn.execute(
                    "INSERT INTO registrations "
                    "(ip, real_name, pinyin, username, email, uid, gid, home, "
                    " workspace, status, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)",
                    row[0:1] + row[1:2] + row[2:3] + row[3:4] + row[4:5]
                    + (row[5], row[5], row[6], row[6], now_iso, now_iso),
                )
            conn.execute(
                "INSERT INTO email_codes "
                "(email, code_hash, expires_at, used, attempts, ip, created_at, purpose) "
                "VALUES (?, ?, ?, 0, 0, ?, ?, 'reset')",
                (
                    cls.EMAIL_SET,
                    "deadbeef" * 8,
                    int(time.time()) + 600,
                    "10.96.0.9",
                    now_iso,
                ),
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '3')"
            )
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) "
                "VALUES('registration_enabled', 'true')"
            )
            conn.commit()
        finally:
            conn.close()
        cls.server = MockServer(
            {
                "paths": {
                    "db": cls.legacy_db,
                    "lock": os.path.join(cls.legacy_dir, "register.lock"),
                }
            }
        )

    @classmethod
    def tearDownClass(cls):
        server = getattr(cls, "server", None)
        if server is not None:
            server.stop()
            cls.server = None
        shutil.rmtree(getattr(cls, "legacy_dir", ""), ignore_errors=True)

    def test_01_migration_v14_to_v4_backfills_user_emails(self):
        conn = sqlite3.connect(self.legacy_db)
        try:
            version = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()[0]
            rows = conn.execute(
                "SELECT username, email, source FROM user_emails ORDER BY username"
            ).fetchall()
            codes = conn.execute(
                "SELECT email, purpose FROM email_codes"
            ).fetchall()
        finally:
            conn.close()
        self.assertEqual(version, "4")
        self.assertEqual(
            rows, [("v14user", self.EMAIL_SET, "portal")],
            "仅 email 非空的 portal 记录回填 user_emails(source=portal)",
        )
        self.assertEqual(codes, [(self.EMAIL_SET, "reset")], "旧 email_codes 数据应保留")
        # 历史记录在管理员用户列表可见
        data = self.list_users()
        users = {item["username"]: item for item in data["users"]}
        self.assertEqual(users["v14user"].get("email"), self.EMAIL_SET)
        self.assertIsNone(users["v14legacy"].get("email"))

    def test_02_bound_email_uniqueness_after_migration(self):
        # 回填后该邮箱已占用：注册 send-code → 409
        status, _headers, data, raw = self.send_code(self.EMAIL_SET, "10.96.2.1")
        self.assertEqual(
            status, 409, "迁移回填邮箱应阻止重复注册，body=%r" % (raw[:500],)
        )
        self.assert_error(data, "EMAIL_REGISTERED")



if __name__ == "__main__":
    unittest.main(verbosity=2)
