#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §21 忘记密码：production 模式 + 本地 SMTP sink + fake provisioner 集成测试。

目的（Lead 要求）：验证真实 `SocketProvisioner.reset_password` 路径 ——
- reset-request 真实经 smtplib 发出 purpose=reset 邮件（本地 sink 捕获 6 位码）；
- password/reset 成功后 fake provisioner **确实收到 reset_password 请求**，且
  `new_password` 与用户提交一致、通过 `security.validate_password(new_password, username)`；
- provisioner 返回「用户不存在」时映射 409 USER_MISSING，且失败不消耗验证码；
- 响应/日志不含验证码与新密码。

只依赖 stdlib；不联网、不用真实 SMTP 凭据；结束清理两个临时目录、socket 与子进程。
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
    EMAIL_SMTP_PASSWORD,
    EMAIL_SUBJECT,
    EMAIL_TTL_SECONDS,
    NEW_STRONG_PW,
    STRONG_PW,
    MockServer,
    _next_email,
)
from test_email_smtp import SmtpSink  # noqa: E402

CODE_RE = re.compile(r"\b\d{6}\b")


class FakeProvisionerServer(object):
    """最小 provisioner：Unix socket + 换行 JSON，记录收到的请求。"""

    def __init__(self, socket_path):
        self.socket_path = socket_path
        self.requests = []
        self.create_requests = []
        self.reset_requests = []
        self.reset_mode = "ok"  # ok | missing
        self._lock = threading.Lock()
        self._stop = threading.Event()
        if os.path.exists(socket_path):
            os.unlink(socket_path)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(socket_path)
        self._sock.listen(8)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

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

    def _dispatch(self, request):
        with self._lock:
            self.requests.append(request)
        op = request.get("op")
        if op == "ping":
            return {"ok": True}
        if op == "create_user":
            with self._lock:
                self.create_requests.append(request)
            username = request.get("username")
            return {
                "ok": True,
                "username": username,
                "uid": 1001,
                "gid": 1001,
                "home": "/home/" + str(username),
                "workspace": "/home/" + str(username),
                "real_name": request.get("real_name"),
            }
        if op == "user_status":
            users = {}
            for username in request.get("usernames") or []:
                users[username] = {
                    "exists": True,
                    "uid": 1001,
                    "gid": 1001,
                    "home": "/home/" + str(username),
                    "locked": False,
                    "groups": [username],
                    "privileged": False,
                }
            return {"ok": True, "users": users}
        if op == "reset_password":
            with self._lock:
                self.reset_requests.append(request)
                mode = self.reset_mode
            if mode == "missing":
                return {
                    "ok": False,
                    "error": {"code": "INVALID", "message": "用户不存在"},
                }
            return {"ok": True, "username": request.get("username")}
        if op == "set_lock":
            return {
                "ok": True,
                "username": request.get("username"),
                "locked": bool(request.get("locked")),
            }
        if op == "delete_user":
            return {
                "ok": True,
                "username": request.get("username"),
                "deleted": True,
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


class PasswordResetProductionPathTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # macOS AF_UNIX 路径上限 104 字节：使用短目录前缀 + 短 socket 名
        _tag = os.environ.get("QA_RUN_TAG", "").strip()
        cls.workdir = tempfile.mkdtemp(prefix="csqa-" + (_tag + "-" if _tag else ""))
        cls.provisioner_socket = os.path.join(cls.workdir, "p.sock")
        cls.sink = SmtpSink()
        cls.fake_provisioner = FakeProvisionerServer(cls.provisioner_socket)
        cls.server = MockServer(
            {
                "mode": "production",
                "tls": {"enabled": False},
                "provisioner": {
                    "socket": cls.provisioner_socket,
                    "timeout_seconds": 5,
                    "allowed_peer_uid": -1,
                },
                # 本机 peer=127.0.0.1 视为可信代理，用 X-Forwarded-For 模拟不同申请 IP
                "security": {"trusted_proxies": ["127.0.0.1/32"]},
                "email": _email_config(cls.sink.port),
                "rate_limits": {
                    "preview": {"window_seconds": 60, "max_requests": 120},
                    "generate_password": {"window_seconds": 60, "max_requests": 120},
                    "register": {"window_seconds": 600, "max_requests": 50},
                    "admin": {"window_seconds": 60, "max_requests": 60},
                    "announcement": {"window_seconds": 60, "max_requests": 120},
                    "email_send": {"window_seconds": 3600, "max_requests": 100},
                    "password_reset": {"window_seconds": 3600, "max_requests": 100},
                },
            }
        )
        cls._seen_messages = {}

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.stop()
        finally:
            cls.fake_provisioner.stop()
            cls.sink.close()
            shutil.rmtree(cls.workdir, ignore_errors=True)

    # ---- helpers ----

    def _request(self, method, path, body=None, headers=None, timeout=15.0):
        return self.server.request(
            method, path, body=body, headers=headers, timeout=timeout
        )

    def _post_json(self, path, body, ip="10.77.0.1"):
        return self._request(
            "POST",
            path,
            body=body,
            headers={
                "X-Requested-With": "campus-signup",
                "X-Forwarded-For": ip,
            },
        )

    def _clear_email_codes(self, address):
        """测试加速：清除该邮箱验证码记录（规避共享 60s 冷却；不改变被测逻辑）。"""
        db_path = os.path.join(self.server.tmpdir, "registrations.db")
        conn = sqlite3.connect(db_path)
        try:
            conn.execute("DELETE FROM email_codes WHERE email = ?", (address,))
            conn.commit()
        finally:
            conn.close()

    def _next_email_code(self, address, timeout=10.0):
        """从 sink 取该收件人的下一条邮件并解析 6 位验证码。"""
        deadline = time.time() + timeout
        while time.time() < deadline:
            messages = self.sink.wait_for_messages(1, timeout=0.5)
            with self.sink._lock:  # noqa: SLF001 - 测试内部读取
                relevant = [
                    message
                    for message in messages
                    if message.get("rcpt") and message["rcpt"][0] == address
                ]
            seen = self._seen_messages.get(address, 0)
            if len(relevant) > seen:
                self._seen_messages[address] = seen + 1
                parsed = email.parser.BytesParser(
                    policy=email.policy.default
                ).parsebytes(relevant[seen]["data"])
                body_text = parsed.get_content()
                codes = CODE_RE.findall(body_text)
                self.assertTrue(codes, "邮件正文应包含 6 位验证码: %r" % (body_text,))
                return codes[0], parsed
            time.sleep(0.05)
        self.fail("未在 %.1fs 内收到发往 %r 的验证码邮件" % (timeout, address))

    def _register_account(self, name, ip):
        address = _next_email()
        status, _headers, raw = self._post_json(
            "/api/email/send-code", {"email": address}, ip=ip
        )
        self.assertEqual(status, 200, "send-code 应 200，body=%r" % (raw[:600],))
        register_code, _mail = self._next_email_code(address)
        status, _headers, raw = self._post_json(
            "/api/register",
            {
                "name": name,
                "password": STRONG_PW,
                "email": address,
                "email_code": register_code,
            },
            ip=ip,
        )
        self.assertEqual(status, 201, "注册应 201，body=%r" % (raw[:800],))
        account = json.loads(raw.decode("utf-8"))["account"]
        return account, address

    # ---- tests ----

    def test_01_reset_success_calls_provisioner_with_valid_new_password(self):
        account, address = self._register_account("密码生产", "10.77.1.1")
        username = account["username"]
        self._clear_email_codes(address)

        status, _headers, raw = self._post_json(
            "/api/password/reset-request", {"email": address}, ip="10.77.1.1"
        )
        self.assertEqual(status, 200, "reset-request 应 200，body=%r" % (raw[:600],))
        reset_code, mail = self._next_email_code(address)
        # 重置邮件正文应说明重置用途（而非注册）
        body_text = mail.get_content()
        self.assertIn("重置", body_text, "reset 用途邮件正文应说明重置密码")

        status, _headers, raw = self._post_json(
            "/api/password/reset",
            {"email": address, "code": reset_code, "new_password": NEW_STRONG_PW},
            ip="10.77.1.1",
        )
        self.assertEqual(status, 200, "password/reset 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("username"), username)
        self.assertIs(data.get("locked"), False)
        response_text = raw.decode("utf-8")
        self.assertNotIn(reset_code, response_text)
        self.assertNotIn(NEW_STRONG_PW, response_text)

        # fake provisioner 必须收到 reset_password，且新密码与提交一致并满足策略
        self.assertEqual(len(self.fake_provisioner.reset_requests), 1)
        reset_request = self.fake_provisioner.reset_requests[0]
        self.assertEqual(reset_request.get("op"), "reset_password")
        self.assertEqual(reset_request.get("username"), username)
        self.assertEqual(reset_request.get("password"), NEW_STRONG_PW)
        ok, message = app_validate_password(NEW_STRONG_PW, username)
        self.assertTrue(ok, "新密码必须满足策略: %r" % (message,))
        # 日志：password_reset 记录，不含验证码/新密码/完整邮箱
        log = self.server.log_text()
        self.assertIn("password_reset", log)
        self.assertNotIn(reset_code, log)
        self.assertNotIn(NEW_STRONG_PW, log)
        self.assertNotIn(address, log)
        self.assertNotIn(EMAIL_SMTP_PASSWORD, log)

    def test_02_provisioner_user_missing_maps_409_and_keeps_code(self):
        account, address = self._register_account("缺失生产", "10.77.2.1")
        username = account["username"]
        self._clear_email_codes(address)
        status, _headers, raw = self._post_json(
            "/api/password/reset-request", {"email": address}, ip="10.77.2.1"
        )
        self.assertEqual(status, 200, "reset-request 应 200，body=%r" % (raw[:600],))
        reset_code, _mail = self._next_email_code(address)
        reset_count_before = len(self.fake_provisioner.reset_requests)
        # 让 fake provisioner 返回「用户不存在」
        self.fake_provisioner.reset_mode = "missing"
        try:
            status, _headers, raw = self._post_json(
                "/api/password/reset",
                {"email": address, "code": reset_code, "new_password": NEW_STRONG_PW},
                ip="10.77.2.1",
            )
            self.assertEqual(
                status, 409, "系统用户缺失应 409 USER_MISSING，body=%r" % (raw[:600],)
            )
            data = json.loads(raw.decode("utf-8"))
            self.assertEqual(data["error"]["code"], "USER_MISSING")
            self.assertEqual(
                len(self.fake_provisioner.reset_requests), reset_count_before + 1
            )
            self.assertEqual(
                self.fake_provisioner.reset_requests[-1]["username"], username
            )
        finally:
            self.fake_provisioner.reset_mode = "ok"
        # 失败不消耗验证码：provisioner 恢复后同一验证码仍可成功重置
        status, _headers, raw = self._post_json(
            "/api/password/reset",
            {"email": address, "code": reset_code, "new_password": NEW_STRONG_PW},
            ip="10.77.2.1",
        )
        self.assertEqual(
            status, 200, "失败不消耗验证码，重试应成功，body=%r" % (raw[:800],)
        )
        self.assertEqual(
            len(self.fake_provisioner.reset_requests), reset_count_before + 2
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
