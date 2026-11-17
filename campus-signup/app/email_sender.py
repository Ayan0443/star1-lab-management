#!/usr/bin/env python3
"""邮件发送器（SPEC §18 / §19.4）。

- SmtpEmailSender：真实 SMTP（Coremail）。支持 security="ssl"（465 SMTPS）、
  "starttls"（587 等）以及 "plain"（仅本地 SMTP sink 集成测试）。
  TLS 证书校验可配置（生产必须开启）；超时；中文主题/正文；From/To 正确；
  用户输入只进正文，绝不进邮件头（防头注入）；任何异常不泄露 SMTP 凭据。
- MockEmailSender：mock 模式发送器，把 {email, code, created_at} 追加写入
  <paths.db 目录>/mock-emails.jsonl，不连接任何 SMTP。
- build_email_sender(config, mode, db_dir)：按配置/模式构建发送器。

安全约定：SMTP 密码只从 config 读取，绝不写入日志/异常信息/DB/响应。
"""

import json
import os
import re
import smtplib
import ssl
import threading
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

DEFAULT_ALLOWED_DOMAINS = ("mails.example.edu.cn", "example.edu.cn")
DEFAULT_SUBJECT = "【star1 实验室服务器】账号申请验证码"
DEFAULT_SMTP_TIMEOUT = 20.0

MAX_EMAIL_LENGTH = 254
EMAIL_RE = re.compile(r"^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
# 邮件头危险字符（CR/LF/NUL），用于所有进入头部的值
_HEADER_UNSAFE_RE = re.compile(r"[\r\n\x00]")

SSL_SECURITY_VALUES = frozenset({"ssl", "smtps", "ssl_tls"})
STARTTLS_SECURITY_VALUES = frozenset({"starttls", "tls", "starttls_required"})


class EmailSendError(Exception):
    """邮件发送失败。message 固定为通用中文，kind 只用于服务端结构化日志。"""

    def __init__(self, kind="smtp_error"):
        super().__init__("验证码邮件发送失败")
        self.kind = str(kind)


def _utc_iso_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _clean_header_value(value, max_length=512):
    """清理邮件头值：去掉 CR/LF/NUL 等危险字符并限长，防头注入。"""
    if value is None:
        return ""
    text = str(value)
    text = _HEADER_UNSAFE_RE.sub("", text)
    return text[:max_length].strip()


def normalize_allowed_domains(allowed_domains):
    """规范化允许的邮箱域名列表；缺省/非法时回落到 SPEC §18.1 默认域名。"""
    result = []
    if isinstance(allowed_domains, (list, tuple)):
        for item in allowed_domains:
            if not isinstance(item, str):
                continue
            domain = item.strip().lower().lstrip("@")
            if not domain:
                continue
            if _HEADER_UNSAFE_RE.search(domain):
                continue
            if "." not in domain:
                continue
            if domain not in result:
                result.append(domain)
    return result or list(DEFAULT_ALLOWED_DOMAINS)


def normalize_email(raw, allowed_domains=None):
    """校验并规范化邮箱（SPEC §18.5）。

    返回 ``(normalized_email, "")`` 或 ``(None, 中文错误提示)``。
    """
    if not isinstance(raw, str):
        return None, "请输入示例大学邮箱"
    email = raw.strip().lower()
    if not email:
        return None, "请输入示例大学邮箱"
    if len(email) > MAX_EMAIL_LENGTH:
        return None, "邮箱地址过长"
    if _HEADER_UNSAFE_RE.search(email) or not EMAIL_RE.match(email):
        return None, "邮箱格式不正确"
    domains = normalize_allowed_domains(allowed_domains)
    domain = email.rsplit("@", 1)[1]
    if domain not in domains:
        return None, "请使用示例大学邮箱（%s）" % " 或 ".join("@" + item for item in domains)
    return email, ""


def build_code_body(code, ttl_seconds, purpose="register"):
    """固定模板的纯文本验证码邮件正文（用户输入不会进入此处）。"""
    try:
        minutes = max(1, int(ttl_seconds) // 60)
    except (TypeError, ValueError):
        minutes = 10
    if purpose == "reset":
        return (
            "您好！\n\n"
            "您正在重置 star1 实验室服务器账号的登录密码，本次验证码为：\n\n"
            "    %s\n\n"
            "验证码 %d 分钟内有效。\n"
            "如非本人操作，请忽略本邮件，不要向任何人泄露验证码；"
            "如担心账号安全，请联系管理员。\n\n"
            "—— star1 实验室服务器\n" % (code, minutes)
        )
    if purpose == "bind":
        return (
            "您好！\n\n"
            "您正在为 star1 实验室服务器已有账号绑定学校邮箱，本次验证码为：\n\n"
            "    %s\n\n"
            "验证码 %d 分钟内有效。\n"
            "如非本人操作，请忽略本邮件，不要向任何人泄露验证码。\n\n"
            "—— star1 实验室服务器\n" % (code, minutes)
        )
    return (
        "您好！\n\n"
        "您正在申请 star1 实验室服务器账号，本次申请验证码为：\n\n"
        "    %s\n\n"
        "验证码 %d 分钟内有效。\n"
        "如非本人操作，请忽略本邮件，不要向任何人泄露验证码。\n\n"
        "—— star1 实验室服务器\n" % (code, minutes)
    )


class MockEmailSender(object):
    """mock 模式发送器：写 <db 目录>/mock-emails.jsonl，不连 SMTP。"""

    def __init__(self, path):
        self.path = os.path.abspath(path)
        self._lock = threading.Lock()

    def send_code(self, email, code, ttl_seconds=600, purpose="register"):
        record = {
            "email": email,
            "code": code,
            "purpose": purpose,
            "created_at": _utc_iso_now(),
        }
        try:
            with self._lock:
                parent = os.path.dirname(self.path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                fd = os.open(
                    self.path, os.O_CREAT | os.O_APPEND | os.O_WRONLY, 0o600
                )
                with os.fdopen(fd, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            raise EmailSendError("mock_write_failed")
        return True


class SmtpEmailSender(object):
    """真实 SMTP 发送器（线程安全：串行发送，低频）。"""

    def __init__(self, smtp_config, subject=None):
        smtp_config = smtp_config or {}
        self.host = _clean_header_value(smtp_config.get("host") or "", 255)
        self.port = _safe_int(smtp_config.get("port"), 465)
        self.security = (
            _clean_header_value(smtp_config.get("security") or "ssl", 32).lower()
        )
        self.username = _clean_header_value(smtp_config.get("username") or "", 255)
        # 密码原样保存在内存，绝不进入日志/异常/DB/响应
        self._password = str(smtp_config.get("password") or "")
        self.from_name = _clean_header_value(smtp_config.get("from_name") or "", 128)
        self.from_addr = _clean_header_value(
            smtp_config.get("from_addr") or self.username, 255
        )
        self.tls_verify = bool(smtp_config.get("tls_verify", True))
        self.timeout_seconds = _safe_float(
            smtp_config.get("timeout_seconds"), DEFAULT_SMTP_TIMEOUT
        )
        self.subject = _clean_header_value(subject or DEFAULT_SUBJECT, 256)
        self._lock = threading.Lock()

    # -- 对外接口 ----------------------------------------------------------
    def send_code(self, email, code, ttl_seconds=600, purpose="register"):
        if not self.host:
            raise EmailSendError("smtp_host_missing")
        if not self.from_addr or "@" not in self.from_addr:
            raise EmailSendError("smtp_from_missing")
        message = self._build_message(email, code, ttl_seconds, purpose)
        connection = None
        try:
            with self._lock:
                connection = self._connect()
                connection.send_message(message)
        except EmailSendError:
            raise
        except Exception as exc:  # 不泄露 SMTP 主机/账号/凭据等细节
            raise EmailSendError(type(exc).__name__)
        finally:
            if connection is not None:
                try:
                    connection.quit()
                except Exception:
                    try:
                        connection.close()
                    except Exception:
                        pass
        return True

    # -- 内部 --------------------------------------------------------------
    def _build_message(self, email, code, ttl_seconds, purpose="register"):
        message = EmailMessage()
        message["Subject"] = self.subject
        if self.from_name:
            message["From"] = formataddr((self.from_name, self.from_addr))
        else:
            message["From"] = self.from_addr
        # 收件人只可能是已经过严格域名校验的邮箱（无 CR/LF）
        message["To"] = email
        message["Date"] = formatdate(localtime=False)
        message["Message-ID"] = make_msgid(domain="campus-signup.invalid")
        message.set_content(
            build_code_body(code, ttl_seconds, purpose), charset="utf-8"
        )
        return message

    def _ssl_context(self):
        if self.tls_verify:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except (AttributeError, ValueError):  # pragma: no cover - 旧 OpenSSL
            pass
        return context

    def _connect(self):
        timeout = self.timeout_seconds
        security = self.security
        if security in SSL_SECURITY_VALUES:
            connection = smtplib.SMTP_SSL(
                self.host,
                self.port,
                timeout=timeout,
                context=self._ssl_context(),
            )
        elif security in STARTTLS_SECURITY_VALUES:
            connection = smtplib.SMTP(self.host, self.port, timeout=timeout)
            try:
                connection.ehlo()
            except Exception:
                pass
            connection.starttls(context=self._ssl_context())
            connection.ehlo()
        else:  # plain：仅本地 SMTP sink 集成测试
            connection = smtplib.SMTP(self.host, self.port, timeout=timeout)
            try:
                connection.ehlo()
            except Exception:
                pass
        if self.username:
            connection.login(self.username, self._password)
        return connection


def _safe_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value, default):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def build_email_sender(config, mode, db_dir):
    """按模式构建发送器：mock -> MockEmailSender；production -> SmtpEmailSender。"""
    email_config = (config or {}).get("email") or {}
    subject = email_config.get("subject") or DEFAULT_SUBJECT
    if mode == "mock":
        return MockEmailSender(os.path.join(db_dir, "mock-emails.jsonl"))
    return SmtpEmailSender(email_config.get("smtp") or {}, subject)
