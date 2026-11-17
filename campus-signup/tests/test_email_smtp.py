#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SPEC §18.6 本地 SMTP sink 集成测试（真实 smtplib，无需外网/真实凭据）。

做法：
- 用 stdlib socket + threading 起一个最小 SMTP sink（127.0.0.1 随机端口，
  支持 220/HELO/EHLO/MAIL/RCPT/DATA/354/250/QUIT 最小集），捕获原始邮件；
- 用 production 模式（tls.enabled=false，仅本地 HTTP）启动 app/server.py，
  配置 email.smtp.host=127.0.0.1 + sink 端口 + security="none"，验证真实 smtplib 发信；
- 另一台 server 配置指向未监听端口，验证 SMTP 失败 → 502 EMAIL_SEND_FAILED 且不泄露细节。

只依赖 stdlib，不联网、不写真实凭据、结束清理子进程与临时目录。
"""

import email
import email.policy
import email.utils
import json
import os
import re
import socket
import sys
import threading
import time
import unittest

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), PROJECT_ROOT, TESTS_DIR):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from test_api_mock import (  # noqa: E402
    EMAIL_ALLOWED_DOMAINS,
    EMAIL_CODE_SECRET,
    EMAIL_FROM_ADDR,
    EMAIL_FROM_NAME,
    EMAIL_SMTP_PASSWORD,
    EMAIL_SUBJECT,
    EMAIL_TTL_SECONDS,
    ADMIN_TOKEN,
    MockServer,
    STRONG_PW,
    _find_free_port,
    _next_email,
)

CODE_RE = re.compile(r"\b\d{6}\b")


def _smtp_address(command, prefix_length):
    """从 ``MAIL FROM:<a@b> size=123`` 之类的命令中提取 <> 内地址。"""
    rest = command[prefix_length:].strip()
    if "<" in rest and ">" in rest:
        return rest[rest.index("<") + 1 : rest.index(">")].strip()
    return email.utils.parseaddr(rest)[1]


# ---------------------------------------------------------------------------
# 最小 SMTP sink（socket 实现）
# ---------------------------------------------------------------------------

class SmtpSink(object):
    """最小 SMTP 服务器：捕获 MAIL/RCPT/DATA，供 smtplib 客户端投递。"""

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        self.messages = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    # ---- socket 循环 ----

    def _serve(self):
        while not self._stop.is_set():
            try:
                connection, _address = self.sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True
            ).start()

    @staticmethod
    def _send(connection, text):
        try:
            connection.sendall(text.encode("utf-8"))
            return True
        except OSError:
            return False

    def _handle(self, connection):
        envelope = {"mail_from": "", "rcpt": [], "data": b""}
        data_lines = []
        in_data = False
        try:
            connection.settimeout(15.0)
            if not self._send(connection, "220 localhost ESMTP QA-sink\r\n"):
                return
            stream = connection.makefile("rb")
            while True:
                line = stream.readline()
                if not line:
                    break
                if in_data:
                    if line in (b".\r\n", b".\n"):
                        in_data = False
                        envelope["data"] = b"".join(data_lines)
                        with self._lock:
                            self.messages.append(dict(envelope))
                        self._send(connection, "250 OK queued\r\n")
                    else:
                        if line.startswith(b".."):  # dot-unstuffing
                            line = line[1:]
                        data_lines.append(line)
                    continue
                command = line.decode("utf-8", "replace").strip()
                upper = command.upper()
                if upper.startswith("EHLO"):
                    self._send(
                        connection,
                        "250-localhost\r\n250-SIZE 10485760\r\n"
                        "250-8BITMIME\r\n250-SMTPUTF8\r\n250 HELP\r\n",
                    )
                elif upper.startswith("HELO"):
                    self._send(connection, "250 localhost\r\n")
                elif upper.startswith("MAIL FROM:"):
                    envelope["mail_from"] = _smtp_address(command, 10)
                    self._send(connection, "250 OK\r\n")
                elif upper.startswith("RCPT TO:"):
                    address = _smtp_address(command, 8)
                    envelope["rcpt"].append(address)
                    self._send(connection, "250 OK\r\n")
                elif upper == "DATA":
                    in_data = True
                    data_lines = []
                    self._send(connection, "354 End data with <CR><LF>.<CR><LF>\r\n")
                elif upper == "QUIT":
                    self._send(connection, "221 Bye\r\n")
                    break
                elif upper in ("RSET", "NOOP"):
                    self._send(connection, "250 OK\r\n")
                else:
                    self._send(connection, "250 OK\r\n")
        except OSError:
            pass
        finally:
            try:
                connection.close()
            except OSError:
                pass

    # ---- 查询 / 清理 ----

    def wait_for_messages(self, count=1, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if len(self.messages) >= count:
                    return list(self.messages)
            time.sleep(0.05)
        with self._lock:
            return list(self.messages)

    def message_count(self):
        with self._lock:
            return len(self.messages)

    def close(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self._thread.join(timeout=3)


# ---------------------------------------------------------------------------
# server 配置（production 模式 + 本地 SMTP sink）
# ---------------------------------------------------------------------------

def email_config(smtp_host, smtp_port, extra=None):
    config = {
        "enabled": True,
        "allowed_domains": list(EMAIL_ALLOWED_DOMAINS),
        "smtp": {
            "host": smtp_host,
            "port": smtp_port,
            "security": "none",
            # 本地 sink 不实现 AUTH，且测试不写真实凭据：username 留空避免 login()
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
    if extra:
        config.update(extra)
    return config


def production_overrides(smtp_host, smtp_port, email_extra=None):
    return {
        "mode": "production",
        "tls": {"enabled": False},
        "email": email_config(smtp_host, smtp_port, email_extra),
        "rate_limits": {
            "preview": {"window_seconds": 60, "max_requests": 120},
            "generate_password": {"window_seconds": 60, "max_requests": 120},
            "register": {"window_seconds": 600, "max_requests": 50},
            "admin": {"window_seconds": 60, "max_requests": 60},
            "announcement": {"window_seconds": 60, "max_requests": 120},
            "email_send": {"window_seconds": 3600, "max_requests": 100},
        },
    }


class SmtpHarness(object):
    def __init__(self, smtp_host, smtp_port, email_extra=None):
        self.server = MockServer(
            production_overrides(smtp_host, smtp_port, email_extra)
        )

    def send_code(self, address, ip="10.70.0.1"):
        return self.server.request(
            "POST",
            "/api/email/send-code",
            body={"email": address},
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": ip,
            },
            timeout=15.0,
        )

    def stop(self):
        self.server.stop()


# ---------------------------------------------------------------------------
# 用例
# ---------------------------------------------------------------------------

class SmtpDeliveryTest(unittest.TestCase):
    """真实 smtplib → 本地 sink：From/To/Subject/正文 6 位码/无头注入。"""

    @classmethod
    def setUpClass(cls):
        cls.sink = SmtpSink()
        cls.harness = SmtpHarness("127.0.0.1", cls.sink.port)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.harness.stop()
        finally:
            cls.sink.close()

    def test_send_code_delivers_real_email(self):
        address = _next_email()
        status, headers, raw = self.harness.send_code(address)
        self.assertEqual(status, 200, "send-code 应 200，body=%r" % (raw[:800],))
        data = json.loads(raw.decode("utf-8"))
        self.assertIs(data.get("ok"), True)
        self.assertEqual(data.get("email"), address)
        # 生产模式（真实 SMTP）响应不得含验证码，也不返回 mock debug_code
        self.assertNotIn("debug_code", data)
        self.assertIsNone(
            CODE_RE.search(raw.decode("utf-8")), "响应不得包含明文验证码"
        )

        messages = self.sink.wait_for_messages(1)
        self.assertTrue(messages, "SMTP sink 未收到邮件（真实 smtplib 发送失败）")
        message = messages[-1]
        # 信封 From / To
        self.assertEqual(message["mail_from"], EMAIL_FROM_ADDR)
        self.assertEqual(message["rcpt"], [address])
        # 邮件头：From / To / Subject
        parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            message["data"]
        )
        self.assertEqual(
            email.utils.parseaddr(str(parsed["From"]))[1], EMAIL_FROM_ADDR
        )
        self.assertEqual(email.utils.parseaddr(str(parsed["To"]))[1], address)
        self.assertEqual(str(parsed["Subject"]), EMAIL_SUBJECT)
        # 头注入防护：不得出现额外的 Bcc/Cc/自定义注入头
        self.assertIsNone(parsed["Bcc"], "邮件不得包含 Bcc 头")
        self.assertIsNone(parsed["Cc"], "邮件不得包含 Cc 头")
        for header_name, header_value in parsed.items():
            self.assertNotIn("\r", str(header_value))
            self.assertNotIn("\n", str(header_value))
        # 正文：6 位验证码 + 10 分钟有效说明
        body = parsed.get_content()
        codes = CODE_RE.findall(body)
        self.assertEqual(len(codes), 1, "正文应恰好包含一个 6 位验证码: %r" % (body,))
        self.assertRegex(body, r"10\s*分钟", "正文应说明验证码 10 分钟有效")
        self.assertNotIn(EMAIL_SMTP_PASSWORD, body)

    def test_injection_attempts_rejected_before_smtp(self):
        before = self.sink.message_count()
        # email 中含 CRLF / 空格 / 头注入内容 → 400 INVALID_EMAIL，且不触发 SMTP
        for bad_email in (
            "victim@mails.example.edu.cn\r\nBcc: evil@example.com",
            "victim@mails.example.edu.cn\nBcc: evil@example.com",
            "a b@mails.example.edu.cn",
        ):
            with self.subTest(email=repr(bad_email)):
                status, _headers, raw = self.harness.send_code(bad_email)
                self.assertEqual(status, 400, "非法邮箱应 400: %r body=%r" % (bad_email, raw[:500]))
                data = json.loads(raw.decode("utf-8"))
                self.assertEqual(data["error"]["code"], "INVALID_EMAIL")
        # 姓名含 CRLF：注册时姓名校验先拒绝（INVALID_NAME），不会有任何邮件
        body = {
            "name": "张三\r\nBcc: evil@example.com",
            "password": STRONG_PW,
            "email": _next_email(),
            "email_code": "123456",
        }
        status, _headers, raw = self.harness.server.request(
            "POST",
            "/api/register",
            body=body,
            headers={
                "X-Requested-With": "campus-signup",
                "X-Test-Client-IP": "10.70.0.2",
            },
        )
        self.assertEqual(status, 400, "含 CRLF 姓名应 400，body=%r" % (raw[:500],))
        data = json.loads(raw.decode("utf-8"))
        self.assertEqual(data["error"]["code"], "INVALID_NAME")
        time.sleep(0.3)
        self.assertEqual(
            self.sink.message_count(), before, "非法输入不得触发任何 SMTP 投递"
        )

    def test_logs_have_no_smtp_password_or_code(self):
        address = _next_email()
        status, _headers, raw = self.harness.send_code(address)
        self.assertEqual(status, 200, "send-code 应 200")
        messages = self.sink.wait_for_messages(1)
        self.assertTrue(messages)
        parsed = email.parser.BytesParser(policy=email.policy.default).parsebytes(
            messages[-1]["data"]
        )
        code = CODE_RE.findall(parsed.get_content())[0]
        log = self.harness.server.log_text()
        self.assertNotIn(EMAIL_SMTP_PASSWORD, log, "日志不得出现 SMTP 密码")
        self.assertNotIn(code, log, "日志不得出现明文验证码")
        self.assertNotIn(EMAIL_CODE_SECRET, log, "日志不得出现 code_secret")
        self.assertNotIn(ADMIN_TOKEN, log, "日志不得出现 admin token")


class SmtpFailureTest(unittest.TestCase):
    """SMTP 连接失败 → 502 EMAIL_SEND_FAILED，不泄露 SMTP 细节。"""

    @classmethod
    def setUpClass(cls):
        # 先占一个空闲端口再关闭，确保该端口无人监听（连接被拒绝）
        cls.closed_port = _find_free_port()
        # 每邮箱/全局日上限调成 1：验证「发送失败不消耗额度/冷却」
        cls.harness = SmtpHarness(
            "127.0.0.1",
            cls.closed_port,
            email_extra={
                "max_send_per_email_per_day": 1,
                "max_send_global_per_day": 1,
            },
        )

    @classmethod
    def tearDownClass(cls):
        cls.harness.stop()

    def test_failed_send_does_not_consume_quota_or_cooldown(self):
        """SPEC §19.4：SMTP 失败不得消耗 60s 冷却 / 每邮箱日限 / 全局日限。"""
        address = _next_email()
        status1, _h1, raw1 = self.harness.send_code(address)
        self.assertEqual(status1, 502, "首次 SMTP 失败应 502，body=%r" % (raw1[:500],))
        # 立即重试：未被 60s 冷却拦住（仍是 SMTP 失败 502，而不是 429）
        status2, _h2, raw2 = self.harness.send_code(address)
        self.assertEqual(
            status2, 502, "失败发送不应触发冷却（期望 502，实际 %s，body=%r）" % (status2, raw2[:500])
        )
        # 另一邮箱：失败发送也不应消耗全局日限（上限 1）
        status3, _h3, raw3 = self.harness.send_code(_next_email())
        self.assertEqual(
            status3, 502, "失败发送不应消耗全局日限（期望 502，实际 %s，body=%r）" % (status3, raw3[:500])
        )

    def test_smtp_failure_returns_502_generic(self):
        address = _next_email()
        status, _headers, raw = self.harness.send_code(address)
        self.assertEqual(
            status, 502, "SMTP 失败应 502，实际 %s body=%r" % (status, raw[:800])
        )
        data = json.loads(raw.decode("utf-8"))
        self.assertFalse(data.get("ok"))
        self.assertEqual(data["error"]["code"], "EMAIL_SEND_FAILED")
        message = data["error"]["message"]
        self.assertTrue(message.strip())
        self.assertTrue(re.search(r"[\u4e00-\u9fff]", message), "错误信息应为中文")
        # 不泄露 SMTP 主机/端口/底层错误细节
        lowered = message.lower()
        for secret in (
            "127.0.0.1",
            str(self.closed_port),
            "smtp",
            "refused",
            "connection",
            "errno",
            "traceback",
        ):
            self.assertNotIn(secret.lower(), lowered, "错误信息泄露 SMTP 细节: %r" % (message,))
        log = self.harness.server.log_text()
        self.assertNotIn(EMAIL_SMTP_PASSWORD, log, "日志不得出现 SMTP 密码")
        self.assertNotIn(str(self.closed_port), log, "日志不得记录 SMTP 端口")


if __name__ == "__main__":
    unittest.main(verbosity=2)
