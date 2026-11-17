#!/usr/bin/env python3
"""campus-signup Web 服务（SPEC §4/§5/§7/§10/§11/§13）。

启动：
    python3 app/server.py --config /etc/campus-signup/config.json

模式：
    production  HTTPS(8444) 主服务 + HTTP(8082) 301 跳转
    mock        单个 HTTP 明文服务（QA 本地端到端），内置 mock provisioner

约束：仅标准库 + 项目内置 pypinyin；绝不在日志中输出密码/请求体。
"""

import argparse
import fcntl
import hashlib
import hmac
import ipaddress
import json
import math
import os
import pwd
import grp
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import sys
import threading
import time
import traceback
import unicodedata
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import pinyin_util
import security
import email_sender

VERSION = "1.0.0"

# 请求体上限（SPEC §7：统一 8KB）。唯一例外：公告接口（§7.5）允许 1–20000 字符，
# 20000 个汉字 JSON 编码后远超 8KB，因此仅 POST /api/admin/announcement 使用
# MAX_ANNOUNCEMENT_BODY_BYTES（256KB）读取；其余 POST 仍严格 8KB → 413 PAYLOAD_TOO_LARGE。
# 已与 Lead 确认（v1.2 验收：20001 字符仍返回 400 INVALID_REQUEST，由字符数校验拦截）。
MAX_BODY_BYTES = 8 * 1024
MAX_ANNOUNCEMENT_BODY_BYTES = 256 * 1024
MAX_NAME_BYTES = 64
MAX_PASSWORD_BYTES = 128
ANNOUNCEMENT_MIN_CHARS = 1
ANNOUNCEMENT_MAX_CHARS = 20000
MAX_STATUS_USERS = 200
MAX_REGISTER_EXISTS_RETRIES = 50

# ---- SPEC §18 邮箱验证默认值 ------------------------------------------------
EMAIL_CODE_TTL_DEFAULT = 600
EMAIL_RESEND_COOLDOWN_DEFAULT = 60
EMAIL_MAX_VERIFY_ATTEMPTS_DEFAULT = 5
EMAIL_MAX_SEND_PER_EMAIL_PER_DAY_DEFAULT = 10
EMAIL_MAX_SEND_GLOBAL_PER_DAY_DEFAULT = 300
EMAIL_CODE_EXPIRED_RETENTION_SECONDS = 24 * 3600
EMAIL_CODE_CREATED_RETENTION_SECONDS = 30 * 24 * 3600
EMAIL_CODE_RE = re.compile(r"^\d{6}$")
EMAIL_MAX_BYTES = 254

# ---- SPEC §19 连接 / 管理员鉴权加固默认值 -----------------------------------
CONNECTION_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_CONNECTIONS = 64
ADMIN_FAIL_WINDOW_SECONDS = 15 * 60
ADMIN_FAIL_LOCK_THRESHOLD = 10
ADMIN_LOCK_SECONDS = 15 * 60

# SPEC §22.4/§22.6 F11：自助绑定密码校验失败锁定（同 username+IP 窗口内 ≥5 次 → 锁 15 分钟）
BIND_FAIL_WINDOW_SECONDS = 15 * 60
BIND_FAIL_LOCK_THRESHOLD = 5
BIND_LOCK_SECONDS = 15 * 60
BIND_LOCKED_MESSAGE = "用户名或密码错误，或该账号不支持自助操作"

REQUIRED_HEADER_NAME = "X-Requested-With"
REQUIRED_HEADER_VALUE = "campus-signup"

USERNAME_RE = re.compile(r"^[a-z][a-z0-9]{1,31}$")

# SPEC §8.3 保留名单
RESERVED_USERNAMES = frozenset(
    """
    root admin administrator sudo wheel docker signupapp nobody daemon bin sys
    sync games man lp mail news uucp proxy backup list irc gnats systemd sshd
    service support operator
    """.split()
)

# SPEC §22.3 / §6.4：永远不可管理的系统/运维账号（web 与 provisioner 双重保护）
PROTECTED_ACCOUNT_USERNAMES = frozenset(
    {"root", "admin", "signupapp", "ops1", "svc", "nobody"}
)

# SPEC §11 / §19.3：所有响应统一安全头（HSTS 在明文 HTTP 下会被浏览器忽略，无副作用）
SECURITY_HEADERS = (
    (
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
    ("Strict-Transport-Security", "max-age=15552000"),
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
)

STATIC_CONTENT_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
}
STATIC_ALLOWED_EXTENSIONS = frozenset(STATIC_CONTENT_TYPES)

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS registrations (
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
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

# SPEC §18.3 / §21.2 email_codes（schema_version=3：purpose 用途绑定）
EMAIL_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS email_codes (
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
CREATE INDEX IF NOT EXISTS idx_email_codes_email ON email_codes(email);
CREATE INDEX IF NOT EXISTS idx_email_codes_created ON email_codes(created_at);
"""
# 注意：idx_email_codes_purpose 必须等旧库 ALTER 加列之后创建（见 AppContext._init_db）

# SPEC §22.2 user_emails（schema_version=4：现有用户绑定邮箱，一邮箱一账号）
USER_EMAILS_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS user_emails (
  username    TEXT PRIMARY KEY,
  email       TEXT NOT NULL UNIQUE,
  source      TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  created_at  TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_email ON user_emails(email);
"""

GET_ROUTES = frozenset(
    {
        "/healthz",
        "/api/health",
        "/api/preview",
        "/api/announcement",
        "/api/admin/users",
        "/",
        "/admin",
    }
)
POST_ROUTES = frozenset(
    {
        "/api/email/send-code",
        "/api/email/bind-request",
        "/api/email/bind",
        "/api/password/reset-request",
        "/api/password/reset",
        "/api/generate-password",
        "/api/register",
        "/api/admin/reset-ip",
        "/api/admin/set-registration",
        "/api/admin/reset-password",
        "/api/admin/set-locked",
        "/api/admin/bind-email",
        "/api/admin/announcement",
    }
)


# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------


class ConfigError(Exception):
    pass


def utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(event, **fields):
    """结构化日志到 stdout。调用方绝不能传入密码或请求体。"""
    parts = ["event=" + str(event)]
    for key, value in fields.items():
        text = str(value)
        for ch in (" ", "\n", "\r", "\t"):
            if ch in text:
                text = text.replace(ch, "_")
        parts.append("%s=%s" % (key, text))
    print(" ".join(parts), flush=True)


def normalize_ip(text):
    try:
        ip_obj = ipaddress.ip_address(str(text).strip())
    except (ValueError, TypeError):
        return None
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def _parse_networks(entries, field_name):
    networks = []
    if entries is None:
        return networks
    if not isinstance(entries, list):
        raise ConfigError("%s 必须是数组" % field_name)
    for item in entries:
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            raise ConfigError("%s 中存在非法网段: %r" % (field_name, item))
    return networks


def _chunks(items, size):
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _as_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_ssh_login(ctx, username):
    if ctx.ssh_port and ctx.ssh_port != 22:
        return "ssh -p %d %s@%s" % (ctx.ssh_port, username, ctx.ssh_host)
    return "ssh %s@%s" % (username, ctx.ssh_host)


def _build_ssh_login_ipv6(ctx, username):
    if not ctx.ssh_ipv6:
        return ""
    if ctx.ssh_ipv6_port:
        return "ssh -6 -p %d %s@%s" % (ctx.ssh_ipv6_port, username, ctx.ssh_ipv6)
    return "ssh -6 %s@%s" % (username, ctx.ssh_ipv6)


def _contains_control_chars(text):
    """公告等纯文本字段的字符集校验：拒绝控制字符（Cc）与格式字符（Cf，如 U+202E）。

    Cf 不构成 XSS，但可用于显示欺骗（双向文本覆盖），按「不允许其他控制字符」处理。
    \\n / \\t 是唯一允许的控制字符。
    """
    for ch in text:
        if ch in ("\n", "\t"):
            continue
        if unicodedata.category(ch) in ("Cc", "Cf"):
            return True
    return False


def mask_email(email):
    """日志用邮箱掩码（SPEC §19.6）：h***5@mails.example.edu.cn。绝不打印完整邮箱。"""
    if not isinstance(email, str) or "@" not in email:
        return "-"
    local, domain = email.rsplit("@", 1)
    if not local:
        return "-@" + domain
    if len(local) <= 2:
        masked = local[0] + "***"
    else:
        masked = local[0] + "***" + local[-1]
    return masked + "@" + domain


def _iso_from_epoch(epoch_seconds):
    return datetime.fromtimestamp(int(epoch_seconds), timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _epoch_from_iso(text):
    try:
        parsed = datetime.strptime(str(text), "%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError):
        return 0
    return int(parsed.replace(tzinfo=timezone.utc).timestamp())


def _find_unused_email_code(conn, email, purpose="register"):
    """取该邮箱指定用途的最新未使用验证码（§21.2 用途绑定，跨用途不可用）。"""
    return conn.execute(
        "SELECT id, code_hash, expires_at, attempts FROM email_codes "
        "WHERE email = ? AND purpose = ? AND used = 0 "
        "ORDER BY id DESC LIMIT 1",
        (email, purpose),
    ).fetchone()


def verify_email_code(ctx, conn, email, code, purpose="register"):
    """校验邮箱验证码（SPEC §18.4 / §21.3，按 purpose 用途绑定）。

    返回 ``(ok, error_code, message, code_row_id, attempts)``。
    - 错误/不存在/已使用/用途不匹配 → EMAIL_CODE_INVALID
    - 过期 → EMAIL_CODE_EXPIRED
    - 尝试次数达到上限 → EMAIL_TOO_MANY_ATTEMPTS
    仅在匹配成功时返回 code_row_id；调用方在注册/重置成功后将其标记 used=1。

    并发安全（F10）：先用**原子条件 UPDATE** 占用一次尝试名额
    （``attempts = attempts + 1 WHERE used = 0 AND attempts < max``），
    只有 rowcount == 1 的请求才继续做 HMAC 比较；rowcount == 0 说明名额已被
    并发请求抢完或验证码刚被使用。这样并发风暴下最多只有 max_attempts 次错误尝试
    真正比较 HMAC，DB 中 attempts 也不会超过上限。正确匹配时归还该次名额。
    """
    row = _find_unused_email_code(conn, email, purpose)
    if row is None:
        return False, "EMAIL_CODE_INVALID", "验证码无效或已使用，请重新获取", None, 0
    max_attempts = ctx.email_max_verify_attempts
    code_id = int(row["id"])
    attempts = int(row["attempts"] or 0)
    if attempts >= max_attempts:
        return (
            False,
            "EMAIL_TOO_MANY_ATTEMPTS",
            "验证码尝试次数过多，请重新获取验证码",
            None,
            attempts,
        )
    if int(row["expires_at"] or 0) <= int(time.time()):
        return (
            False,
            "EMAIL_CODE_EXPIRED",
            "验证码已过期，请重新获取",
            None,
            attempts,
        )

    # 原子占用一次尝试名额（并发安全的关键步骤）
    claim = conn.execute(
        "UPDATE email_codes SET attempts = attempts + 1 "
        "WHERE id = ? AND used = 0 AND attempts < ?",
        (code_id, max_attempts),
    )
    conn.commit()
    if claim.rowcount != 1:
        # 名额已被并发请求用完，或该验证码刚被成功使用
        current = conn.execute(
            "SELECT used, attempts FROM email_codes WHERE id = ?", (code_id,)
        ).fetchone()
        if current is not None and int(current["used"] or 0) == 1:
            return (
                False,
                "EMAIL_CODE_INVALID",
                "验证码无效或已使用，请重新获取",
                None,
                int(current["attempts"] or 0),
            )
        attempts_now = int(current["attempts"] or 0) if current is not None else max_attempts
        return (
            False,
            "EMAIL_TOO_MANY_ATTEMPTS",
            "验证码尝试次数过多，请重新获取验证码",
            None,
            attempts_now,
        )

    provided = code if isinstance(code, str) else ""
    matched = False
    if EMAIL_CODE_RE.match(provided):
        expected = ctx.code_hash(email, provided)
        stored = str(row["code_hash"] or "")
        try:
            matched = bool(
                stored
                and hmac.compare_digest(
                    expected.encode("utf-8"), stored.encode("utf-8")
                )
            )
        except (TypeError, ValueError):
            matched = False
    if matched:
        # 正确验证码不消耗尝试名额（归还本次占用）
        conn.execute(
            "UPDATE email_codes SET attempts = "
            "CASE WHEN attempts > 0 THEN attempts - 1 ELSE 0 END WHERE id = ?",
            (code_id,),
        )
        conn.commit()
        return True, "", "", code_id, attempts

    current = conn.execute(
        "SELECT attempts FROM email_codes WHERE id = ?", (code_id,)
    ).fetchone()
    attempts_now = int(current["attempts"] or 0) if current is not None else attempts + 1
    if attempts_now >= max_attempts:
        return (
            False,
            "EMAIL_TOO_MANY_ATTEMPTS",
            "验证码尝试次数过多，请重新获取验证码",
            None,
            attempts_now,
        )
    return (
        False,
        "EMAIL_CODE_INVALID",
        "验证码错误（还可尝试 %d 次）" % (max_attempts - attempts_now),
        None,
        attempts_now,
    )


# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            cfg = json.load(handle)
    except OSError as exc:
        raise ConfigError("无法读取配置文件 %s: %s" % (path, exc))
    except ValueError as exc:
        raise ConfigError("配置文件不是合法 JSON: %s" % exc)
    if not isinstance(cfg, dict):
        raise ConfigError("配置文件必须是 JSON 对象")
    mode = cfg.get("mode")
    if mode not in ("production", "mock"):
        raise ConfigError("mode 必须是 production 或 mock")
    if not isinstance(cfg.get("server"), dict):
        raise ConfigError("缺少 server 配置")
    if not isinstance(cfg.get("paths"), dict):
        raise ConfigError("缺少 paths 配置")
    paths = cfg["paths"]
    for key in ("static", "db", "lock"):
        if not isinstance(paths.get(key), str) or not paths.get(key):
            raise ConfigError("缺少 paths.%s" % key)
    return cfg


# ---------------------------------------------------------------------------
# 限流（每 IP 内存滑动窗口）
# ---------------------------------------------------------------------------


class RateLimiter(object):
    # 内存中最多保留的 (bucket, ip) key 数，超出后按最久未用淘汰，防止无界增长
    MAX_KEYS = 10000

    def __init__(self):
        self._lock = threading.Lock()
        self._hits = {}

    def check(self, bucket, key, window_seconds, max_requests):
        """返回 (limited, retry_after)。"""
        now = time.monotonic()
        window = max(1, _as_int(window_seconds, 60))
        limit = max(1, _as_int(max_requests, 60))
        with self._lock:
            if len(self._hits) > self.MAX_KEYS:
                self._purge_stale(now)
            hits = self._hits.get((bucket, key))
            if hits is None:
                hits = deque()
                self._hits[(bucket, key)] = hits
            cutoff = now - window
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= limit:
                retry_after = int(math.ceil(window - (now - hits[0])))
                return True, max(1, retry_after)
            hits.append(now)
            return False, 0

    def _purge_stale(self, now):
        """清理过期 key；若仍超上限则按最近一次命中时间淘汰最旧 key（防内存无界增长）。"""
        for key in list(self._hits.keys()):
            hits = self._hits.get(key)
            if not hits or hits[-1] <= now - 3600:
                self._hits.pop(key, None)
        if len(self._hits) > self.MAX_KEYS:
            # 一次淘汰到一半容量，避免每次请求都触发 O(n log n) 排序
            target = max(1, self.MAX_KEYS // 2)
            ordered = sorted(
                self._hits.items(),
                key=lambda item: item[1][-1] if item[1] else 0.0,
            )
            overflow = len(self._hits) - target
            for key, _hits in ordered[:overflow]:
                self._hits.pop(key, None)


class AdminAuthGuard(object):
    """管理员鉴权失败锁定（SPEC §19.1）。

    同 IP 在 window_seconds 内失败 ≥ max_failures 次 → 封禁 lockout_seconds。
    参数来自 ``security.admin_lockout.{window_seconds,max_failures,lockout_seconds}``
    （默认 900s / 10 次 / 900s）。独立于通用 admin 限流；成功鉴权清零。
    """

    # 内存中最多保留的 IP 数（失败记录 + 锁定记录），防海量失败 IP 造成内存增长
    MAX_IPS = 10000

    def __init__(self, window_seconds=None, max_failures=None, lockout_seconds=None):
        self.window_seconds = max(
            1, _as_int(window_seconds, ADMIN_FAIL_WINDOW_SECONDS)
        )
        self.max_failures = max(1, _as_int(max_failures, ADMIN_FAIL_LOCK_THRESHOLD))
        self.lockout_seconds = max(1, _as_int(lockout_seconds, ADMIN_LOCK_SECONDS))
        self._lock = threading.Lock()
        self._failures = {}
        self._locked_until = {}

    def _prune(self, ip_text, now):
        window_start = now - self.window_seconds
        hits = self._failures.get(ip_text)
        if hits is not None:
            while hits and hits[0] <= window_start:
                hits.popleft()
            if not hits:
                self._failures.pop(ip_text, None)
        locked_until = self._locked_until.get(ip_text)
        if locked_until is not None and locked_until <= now:
            self._locked_until.pop(ip_text, None)

    def _enforce_capacity(self, now):
        """条目超过上限时清理：先清过期，再按最近活动时间淘汰到半容量。"""
        total = len(self._failures) + len(self._locked_until)
        if total <= self.MAX_IPS:
            return
        for ip_text in list(self._locked_until.keys()):
            if self._locked_until[ip_text] <= now:
                self._locked_until.pop(ip_text, None)
        window_start = now - self.window_seconds
        for ip_text in list(self._failures.keys()):
            hits = self._failures.get(ip_text)
            if not hits or hits[-1] <= window_start:
                self._failures.pop(ip_text, None)
        total = len(self._failures) + len(self._locked_until)
        if total <= self.MAX_IPS:
            return
        target = max(1, self.MAX_IPS // 2)
        entries = []
        for ip_text, hits in self._failures.items():
            entries.append((hits[-1] if hits else 0.0, "failure", ip_text))
        for ip_text, until in self._locked_until.items():
            entries.append((until, "locked", ip_text))
        entries.sort()
        for _activity, kind, ip_text in entries[: total - target]:
            if kind == "failure":
                self._failures.pop(ip_text, None)
            else:
                self._locked_until.pop(ip_text, None)

    def is_locked(self, ip_text, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(ip_text, now)
            locked_until = self._locked_until.get(ip_text)
            if locked_until is None:
                return False, 0
            return True, max(1, int(math.ceil(locked_until - now)))

    def record_failure(self, ip_text, now=None):
        """记录一次失败。返回 (fail_count, locked, retry_after)。"""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._prune(ip_text, now)
            self._enforce_capacity(now)
            hits = self._failures.get(ip_text)
            if hits is None:
                hits = deque()
                self._failures[ip_text] = hits
            hits.append(now)
            fail_count = len(hits)
            if fail_count >= self.max_failures:
                self._locked_until[ip_text] = now + self.lockout_seconds
                self._failures.pop(ip_text, None)
                return fail_count, True, self.lockout_seconds
            return fail_count, False, 0

    def record_success(self, ip_text):
        with self._lock:
            self._failures.pop(ip_text, None)
            self._locked_until.pop(ip_text, None)


class BindAuthGuard(object):
    """自助绑定密码校验失败锁定（SPEC §22.4/§22.6 F11）。

    同一 ``(username, ip)`` 在 window_seconds 内密码校验失败 ≥ max_failures 次
    → 锁 lockout_seconds（默认 5 次 / 15 分钟）。锁定期间即使密码正确也拒绝，
    返回统一 INVALID_CREDENTIALS 提示，避免账号枚举。内存 key 有上限。
    """

    MAX_KEYS = 10000

    def __init__(
        self,
        window_seconds=None,
        max_failures=None,
        lockout_seconds=None,
    ):
        self.window_seconds = max(
            1, _as_int(window_seconds, BIND_FAIL_WINDOW_SECONDS)
        )
        self.max_failures = max(1, _as_int(max_failures, BIND_FAIL_LOCK_THRESHOLD))
        self.lockout_seconds = max(1, _as_int(lockout_seconds, BIND_LOCK_SECONDS))
        self._lock = threading.Lock()
        self._failures = {}
        self._locked_until = {}

    def _prune(self, key, now):
        window_start = now - self.window_seconds
        hits = self._failures.get(key)
        if hits is not None:
            while hits and hits[0] <= window_start:
                hits.popleft()
            if not hits:
                self._failures.pop(key, None)
        locked_until = self._locked_until.get(key)
        if locked_until is not None and locked_until <= now:
            self._locked_until.pop(key, None)

    def _enforce_capacity(self, now):
        total = len(self._failures) + len(self._locked_until)
        if total <= self.MAX_KEYS:
            return
        for key in list(self._locked_until.keys()):
            if self._locked_until[key] <= now:
                self._locked_until.pop(key, None)
        window_start = now - self.window_seconds
        for key in list(self._failures.keys()):
            hits = self._failures.get(key)
            if not hits or hits[-1] <= window_start:
                self._failures.pop(key, None)
        total = len(self._failures) + len(self._locked_until)
        if total <= self.MAX_KEYS:
            return
        target = max(1, self.MAX_KEYS // 2)
        entries = []
        for key, hits in self._failures.items():
            entries.append((hits[-1] if hits else 0.0, "failure", key))
        for key, until in self._locked_until.items():
            entries.append((until, "locked", key))
        entries.sort(key=lambda item: item[0])
        for _activity, kind, key in entries[: total - target]:
            if kind == "failure":
                self._failures.pop(key, None)
            else:
                self._locked_until.pop(key, None)

    def is_locked(self, username, ip_text, now=None):
        now = time.monotonic() if now is None else now
        key = (ip_text, username)
        with self._lock:
            self._prune(key, now)
            locked_until = self._locked_until.get(key)
            if locked_until is None:
                return False, 0
            return True, max(1, int(math.ceil(locked_until - now)))

    def record_failure(self, username, ip_text, now=None):
        """记录一次密码校验失败。返回 (fail_count, locked, retry_after)。"""
        now = time.monotonic() if now is None else now
        key = (ip_text, username)
        with self._lock:
            self._prune(key, now)
            self._enforce_capacity(now)
            hits = self._failures.get(key)
            if hits is None:
                hits = deque()
                self._failures[key] = hits
            hits.append(now)
            fail_count = len(hits)
            if fail_count >= self.max_failures:
                self._locked_until[key] = now + self.lockout_seconds
                self._failures.pop(key, None)
                return fail_count, True, self.lockout_seconds
            return fail_count, False, 0

    def record_success(self, username, ip_text):
        key = (ip_text, username)
        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)


# ---------------------------------------------------------------------------
# provisioner 客户端（真实 socket / mock）
# ---------------------------------------------------------------------------


class ProvisionResult(object):
    __slots__ = ("ok", "code", "message", "data")

    def __init__(self, ok, code="", message="", data=None):
        self.ok = ok
        self.code = code
        self.message = message
        self.data = data if isinstance(data, dict) else {}


class SocketProvisioner(object):
    """通过 Unix socket 调用 root provisioner（换行 JSON）。"""

    def __init__(self, socket_path, timeout_seconds):
        self.socket_path = socket_path
        self.timeout_seconds = float(timeout_seconds or 30)

    def _roundtrip(self, request):
        payload = json.dumps(request, ensure_ascii=False).encode("utf-8") + b"\n"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_seconds)
        try:
            sock.connect(self.socket_path)
            sock.sendall(payload)
            chunks = []
            total = 0
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > 65536:
                    raise ValueError("provisioner 响应过长")
                if b"\n" in chunk:
                    break
        finally:
            try:
                sock.close()
            except OSError:
                pass
        line = b"".join(chunks).split(b"\n", 1)[0]
        if not line:
            raise ValueError("provisioner 响应为空")
        return json.loads(line.decode("utf-8"))

    def call(self, request):
        if not self.socket_path:
            return ProvisionResult(False, "INTERNAL", "provisioner 未配置")
        op = request.get("op") if isinstance(request, dict) else "-"
        try:
            response = self._roundtrip(request)
        except socket.timeout:
            log("provisioner_error", op=op, detail="timeout")
            return ProvisionResult(False, "INTERNAL", "provisioner 超时")
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            log("provisioner_error", op=op, detail="unavailable")
            return ProvisionResult(False, "INTERNAL", "provisioner 不可用")
        if not isinstance(response, dict):
            return ProvisionResult(False, "INTERNAL", "provisioner 响应格式错误")
        if response.get("ok"):
            return ProvisionResult(True, data=response)
        error = response.get("error")
        code = "INTERNAL"
        message = "provisioner 错误"
        if isinstance(error, dict):
            if error.get("code") in ("EXISTS", "INVALID", "INTERNAL"):
                code = error["code"]
            if isinstance(error.get("message"), str) and error["message"]:
                message = error["message"]
        log("provisioner_error", op=op, code=code)
        return ProvisionResult(False, code, message)

    def create_user(self, username, real_name, password):
        return self.call(
            {
                "op": "create_user",
                "username": username,
                "real_name": real_name,
                "password": password,
            }
        )

    def user_status(self, usernames):
        return self.call({"op": "user_status", "usernames": list(usernames)})

    def list_users(self):
        """SPEC §22.3：列出系统内 uid>=1000 且 <65000 的普通用户（最多 500）。"""
        return self.call({"op": "list_users"})

    def verify_password(self, username, password):
        """SPEC §22.3：在 root provisioner 内校验当前服务器密码。"""
        return self.call(
            {"op": "verify_password", "username": username, "password": password}
        )

    def reset_password(self, username, password):
        return self.call(
            {"op": "reset_password", "username": username, "password": password}
        )

    def set_lock(self, username, locked):
        return self.call({"op": "set_lock", "username": username, "locked": bool(locked)})


class MockProvisioner(object):
    """mock 模式内置 provisioner：<db 目录>/mock-users/ 下模拟系统用户。"""

    def __init__(self, base_dir):
        self.root = os.path.join(base_dir, "mock-users")
        self.users_file = os.path.join(self.root, "users.json")
        os.makedirs(self.root, exist_ok=True)
        try:
            os.chmod(self.root, 0o750)
        except OSError:
            pass

    def _load(self):
        try:
            with open(self.users_file, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data):
        tmp_path = self.users_file + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=1)
            handle.write("\n")
        os.replace(tmp_path, self.users_file)

    def username_taken(self, username):
        return username in self._load()

    @staticmethod
    def _hash_password(password):
        """mock 专用加盐哈希（仅本地测试数据；不用于生产，生产由 provisioner 校验）。"""
        salt = secrets.token_hex(8)
        digest = hashlib.sha256(("mock:" + salt + ":" + password).encode("utf-8")).hexdigest()
        return "mock-sha256$%s$%s" % (salt, digest)

    @staticmethod
    def _check_password(password, info):
        if not isinstance(info, dict):
            return False
        storage = info.get("password_hash")
        if isinstance(storage, str) and storage.startswith("mock-sha256$"):
            try:
                _kind, salt, expected = storage.split("$", 2)
            except ValueError:
                return False
            digest = hashlib.sha256(
                ("mock:" + salt + ":" + password).encode("utf-8")
            ).hexdigest()
            return hmac.compare_digest(digest, expected)
        # 便于测试直接塞入 users.json 的明文 password 字段（仅 mock）
        plain = info.get("password")
        if isinstance(plain, str):
            return hmac.compare_digest(
                plain.encode("utf-8"), password.encode("utf-8")
            )
        return False

    def _next_uid(self, users):
        next_uid = 2000
        for info in users.values():
            if isinstance(info, dict):
                uid = info.get("uid")
                if isinstance(uid, int) and uid >= next_uid:
                    next_uid = uid + 1
        return next_uid

    def create_user(self, username, real_name, password):
        users = self._load()
        if username in users:
            return ProvisionResult(False, "EXISTS", "用户已存在")
        user_dir = os.path.join(self.root, username)
        if os.path.exists(user_dir):
            return ProvisionResult(False, "EXISTS", "用户已存在")
        uid = self._next_uid(users)
        home = "/home/%s" % username
        try:
            os.makedirs(user_dir, mode=0o750, exist_ok=False)
            os.chmod(user_dir, 0o750)
        except OSError:
            return ProvisionResult(False, "INTERNAL", "provisioner 内部错误")
        users[username] = {
            "uid": uid,
            "gid": uid,
            "home": home,
            "real_name": real_name,
            "locked": False,
            "password_hash": self._hash_password(password),
        }
        try:
            self._save(users)
        except OSError:
            try:
                shutil.rmtree(user_dir)
            except OSError:
                pass
            return ProvisionResult(False, "INTERNAL", "provisioner 内部错误")
        return ProvisionResult(
            True,
            data={
                "ok": True,
                "username": username,
                "uid": uid,
                "gid": uid,
                "home": home,
                "workspace": home,
                "real_name": real_name,
            },
        )

    def user_status(self, usernames):
        users = self._load()
        result = {}
        for username in usernames:
            info = users.get(username)
            if not isinstance(info, dict):
                result[username] = {"exists": False}
                continue
            uid = info.get("uid")
            uid = uid if isinstance(uid, int) else 2000
            home = info.get("home")
            groups = info.get("groups")
            if not isinstance(groups, list) or not groups:
                groups = [username]
            result[username] = {
                "exists": True,
                "uid": uid,
                "gid": info.get("gid", uid),
                "home": home if isinstance(home, str) else "/home/%s" % username,
                "locked": bool(info.get("locked", False)),
                "groups": groups,
                "privileged": bool(info.get("privileged", False)),
            }
        return ProvisionResult(True, data={"ok": True, "users": result})

    def reset_password(self, username, password):
        ok, error = security.validate_password(password, username)
        if not ok:
            return ProvisionResult(False, "INVALID", error)
        users = self._load()
        if username not in users:
            return ProvisionResult(False, "INVALID", "用户不存在")
        users[username]["password_hash"] = self._hash_password(password)
        try:
            self._save(users)
        except OSError:
            return ProvisionResult(False, "INTERNAL", "provisioner 内部错误")
        return ProvisionResult(True, data={"ok": True, "username": username})

    def set_lock(self, username, locked):
        users = self._load()
        if username not in users:
            return ProvisionResult(False, "INVALID", "用户不存在")
        users[username]["locked"] = bool(locked)
        try:
            self._save(users)
        except OSError:
            return ProvisionResult(False, "INTERNAL", "provisioner 内部错误")
        return ProvisionResult(
            True, data={"ok": True, "username": username, "locked": bool(locked)}
        )

    def list_users(self):
        """SPEC §22.3 mock 版 list_users（users.json 中 uid>=1000 的模拟用户）。"""
        users = self._load()
        entries = []
        for username, info in users.items():
            if not isinstance(info, dict):
                continue
            uid = info.get("uid")
            uid = uid if isinstance(uid, int) else 2000
            if uid < 1000 or uid >= 65000:
                continue
            entries.append(
                {
                    "username": username,
                    "uid": uid,
                    "gid": info.get("gid", uid),
                    "home": info.get("home") or ("/home/%s" % username),
                    "shell": "/bin/bash",
                    "real_name": info.get("real_name") or "",
                    "groups": (
                        info.get("groups")
                        if isinstance(info.get("groups"), list)
                        else [username]
                    ),
                    "privileged": bool(info.get("privileged", False)),
                    "locked": bool(info.get("locked", False)),
                }
            )
        entries.sort(key=lambda item: item["uid"])
        return ProvisionResult(True, data={"ok": True, "users": entries})

    def verify_password(self, username, password):
        """SPEC §22.3 mock 版 verify_password（本地测试；不存明文密码）。"""
        users = self._load()
        info = users.get(username)
        if not isinstance(info, dict):
            return ProvisionResult(
                True,
                data={
                    "ok": True,
                    "exists": False,
                    "manageable": False,
                    "locked": False,
                },
            )
        matched = self._check_password(password, info)
        uid = info.get("uid")
        manageable = (
            bool(matched)
            and isinstance(uid, int)
            and uid >= 1000
            and username not in PROTECTED_ACCOUNT_USERNAMES
            and not bool(info.get("privileged", False))
        )
        return ProvisionResult(
            True,
            data={
                "ok": True,
                "exists": True,
                "manageable": manageable,
                "locked": bool(info.get("locked", False)),
            },
        )


# ---------------------------------------------------------------------------
# 应用上下文
# ---------------------------------------------------------------------------


class AppContext(object):
    def __init__(self, cfg):
        self.cfg = cfg
        self.mode = cfg["mode"]
        server_cfg = cfg.get("server") or {}
        self.bind = server_cfg.get("bind") or "0.0.0.0"
        self.public_host = server_cfg.get("public_host") or "127.0.0.1"
        ports = server_cfg.get("ports") or {}
        self.https_port = _as_int(ports.get("https"), 8444)
        self.http_port = _as_int(ports.get("http"), 8082)
        # SPEC §19.2：ThreadingHTTPServer 并发上限（默认 64）
        max_connections = server_cfg.get("max_concurrent_connections")
        if max_connections is None:
            max_connections = server_cfg.get("max_connections")
        if max_connections is None:
            max_connections = cfg.get("max_concurrent_connections")
        if max_connections is None:
            max_connections = cfg.get("max_connections")
        self.max_connections = max(
            1, min(1024, _as_int(max_connections, DEFAULT_MAX_CONNECTIONS))
        )

        tls_cfg = cfg.get("tls") or {}
        self.tls_enabled = bool(tls_cfg.get("enabled"))
        self.tls_cert = tls_cfg.get("cert")
        self.tls_key = tls_cfg.get("key")

        paths = cfg["paths"]
        self.static_dir = os.path.abspath(paths["static"])
        self.db_path = os.path.abspath(paths["db"])
        self.lock_path = os.path.abspath(paths["lock"])

        prov_cfg = cfg.get("provisioner") or {}
        self.provisioner_socket = prov_cfg.get("socket")
        self.provisioner_timeout = float(prov_cfg.get("timeout_seconds") or 30)

        security_cfg = cfg.get("security") or {}
        self.admin_token = security_cfg.get("admin_token") or ""
        self.allowed_client_cidrs = _parse_networks(
            security_cfg.get("allowed_client_cidrs"), "security.allowed_client_cidrs"
        )
        self.trusted_proxies = _parse_networks(
            security_cfg.get("trusted_proxies"), "security.trusted_proxies"
        )
        # SPEC §19.1：默认禁止 ?token=；仅显式开启且来源 127.0.0.1 时例外
        self.allow_query_token = bool(security_cfg.get("allow_query_token"))
        self.admin_allowed_cidrs = _parse_networks(
            security_cfg.get("admin_allowed_cidrs"), "security.admin_allowed_cidrs"
        )
        # SPEC §19.1：admin_lockout 可配置（默认 900s / 10 次 / 900s）
        lockout_cfg = security_cfg.get("admin_lockout") or {}
        if not isinstance(lockout_cfg, dict):
            raise ConfigError("security.admin_lockout 必须是对象")
        self.admin_lockout_window = max(
            1, _as_int(lockout_cfg.get("window_seconds"), ADMIN_FAIL_WINDOW_SECONDS)
        )
        self.admin_lockout_max_failures = max(
            1, _as_int(lockout_cfg.get("max_failures"), ADMIN_FAIL_LOCK_THRESHOLD)
        )
        self.admin_lockout_seconds = max(
            1, _as_int(lockout_cfg.get("lockout_seconds"), ADMIN_LOCK_SECONDS)
        )
        self.admin_guard = AdminAuthGuard(
            self.admin_lockout_window,
            self.admin_lockout_max_failures,
            self.admin_lockout_seconds,
        )
        # SPEC §22.4/§22.6 F11：自助绑定密码校验失败锁定（同 username+IP 5 次/15 分钟）
        bind_lockout_cfg = security_cfg.get("bind_lockout") or {}
        if not isinstance(bind_lockout_cfg, dict):
            raise ConfigError("security.bind_lockout 必须是对象")
        self.bind_guard = BindAuthGuard(
            _as_int(bind_lockout_cfg.get("window_seconds"), BIND_FAIL_WINDOW_SECONDS),
            _as_int(bind_lockout_cfg.get("max_failures"), BIND_FAIL_LOCK_THRESHOLD),
            _as_int(bind_lockout_cfg.get("lockout_seconds"), BIND_LOCK_SECONDS),
        )

        ui_cfg = cfg.get("ui") or {}
        self.server_name = ui_cfg.get("server_name") or ""
        self.site_title = ui_cfg.get("site_title") or ""
        self.ssh_host = ui_cfg.get("ssh_host") or self.public_host
        self.ssh_port = _as_int(ui_cfg.get("ssh_port"), 22)
        self.ssh_ipv6 = ui_cfg.get("ssh_ipv6") or ""
        self.ssh_ipv6_port = _as_int(ui_cfg.get("ssh_ipv6_port"), 2222)
        self.contact = ui_cfg.get("contact") or ""
        self.default_announcement = ui_cfg.get("default_announcement") or ""

        # ---- SPEC §18 邮箱验证配置 ----
        email_cfg = cfg.get("email") or {}
        self.email_cfg = email_cfg
        self.email_enabled = bool(email_cfg.get("enabled"))
        self.allowed_email_domains = email_sender.normalize_allowed_domains(
            email_cfg.get("allowed_domains")
        )
        self.email_code_ttl = max(1, _as_int(email_cfg.get("code_ttl_seconds"), EMAIL_CODE_TTL_DEFAULT))
        self.email_resend_cooldown = max(
            0, _as_int(email_cfg.get("resend_cooldown_seconds"), EMAIL_RESEND_COOLDOWN_DEFAULT)
        )
        self.email_max_verify_attempts = max(
            1, _as_int(email_cfg.get("max_verify_attempts"), EMAIL_MAX_VERIFY_ATTEMPTS_DEFAULT)
        )
        self.email_max_send_per_email_per_day = max(
            1,
            _as_int(
                email_cfg.get("max_send_per_email_per_day"),
                EMAIL_MAX_SEND_PER_EMAIL_PER_DAY_DEFAULT,
            ),
        )
        self.email_max_send_global_per_day = max(
            1,
            _as_int(
                email_cfg.get("max_send_global_per_day"),
                EMAIL_MAX_SEND_GLOBAL_PER_DAY_DEFAULT,
            ),
        )
        secret_raw = email_cfg.get("code_secret")
        if isinstance(secret_raw, str) and secret_raw.strip():
            self.email_code_secret = secret_raw.strip()
        else:
            # 配置缺失时进程内随机密钥（重启后旧码失效，仅用于本地/mock 兜底）
            self.email_code_secret = secrets.token_hex(32)
            log("email_code_secret_fallback", result="generated")

        rate_cfg = cfg.get("rate_limits") or {}
        self.rate_limits = {}
        for name, default in (
            ("preview", (60, 120)),
            ("generate_password", (60, 30)),
            ("register", (600, 20)),
            ("admin", (60, 60)),
            ("announcement", (60, 120)),
            ("email_send", (3600, 20)),
            ("password_reset", (3600, 20)),
            # SPEC §22.4/§22.6 F11：自助绑定（密码校验前）按 IP 限流
            ("bind", (3600, 10)),
        ):
            entry = rate_cfg.get(name) or {}
            self.rate_limits[name] = (
                _as_int(entry.get("window_seconds"), default[0]),
                _as_int(entry.get("max_requests"), default[1]),
            )
        self.rate = RateLimiter()

        self._ensure_directories()
        self._init_db()

        if self.mode == "mock":
            self.provisioner = MockProvisioner(os.path.dirname(self.db_path))
        else:
            self.provisioner = SocketProvisioner(
                self.provisioner_socket, self.provisioner_timeout
            )
        self.email_sender = email_sender.build_email_sender(
            cfg, self.mode, os.path.dirname(self.db_path)
        )

    # -- 目录 / 数据库 ------------------------------------------------------
    def _ensure_directories(self):
        for path in (self.db_path, self.lock_path):
            parent = os.path.dirname(path)
            if parent:
                os.makedirs(parent, exist_ok=True)

    def _init_db(self):
        """建表 + 平滑迁移（schema_version=4，保留历史数据；SPEC §18.3/§21.2/§22.2）。"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.executescript(SCHEMA_SQL)
            conn.executescript(EMAIL_SCHEMA_SQL)
            conn.executescript(USER_EMAILS_SCHEMA_SQL)

            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(registrations)").fetchall()
            }
            if "email" not in columns:
                conn.execute("ALTER TABLE registrations ADD COLUMN email TEXT")
                log("db_migrate", step="add_registrations_email", result="ok")
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_registrations_email "
                "ON registrations(email)"
            )

            code_columns = {
                row[1] for row in conn.execute("PRAGMA table_info(email_codes)").fetchall()
            }
            if "purpose" not in code_columns:
                conn.execute(
                    "ALTER TABLE email_codes ADD COLUMN purpose TEXT NOT NULL "
                    "DEFAULT 'register'"
                )
                log("db_migrate", step="add_email_codes_purpose", result="ok")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_email_codes_purpose "
                "ON email_codes(purpose, email)"
            )

            # SPEC §22.2：从 registrations.email 回填 user_emails(source='portal')
            conn.execute(
                "INSERT OR IGNORE INTO user_emails "
                "(username, email, source, verified_at, created_at) "
                "SELECT username, email, 'portal', COALESCE(updated_at, created_at), "
                "COALESCE(created_at, ?) FROM registrations WHERE email IS NOT NULL",
                (utc_now(),),
            )
            conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_user_emails_email "
                "ON user_emails(email)"
            )

            previous_version = None
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'schema_version'"
            ).fetchone()
            if row is not None:
                previous_version = row[0]
            conn.execute(
                "INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', '4')"
            )
            if previous_version != "4":
                log("db_migrate", step="schema_version", value="4", result="ok")

            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('registration_enabled', 'true')"
            )
            row = conn.execute(
                "SELECT value FROM meta WHERE key = 'announcement'"
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO meta(key, value) VALUES('announcement', ?)",
                    (self.default_announcement,),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO meta(key, value) VALUES('announcement_updated_at', ?)",
                    (utc_now(),),
                )
            conn.commit()
        finally:
            conn.close()

    def connect_db(self):
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def get_meta(conn, key, default=None):
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row is not None else default

    @staticmethod
    def set_meta(conn, key, value):
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)", (key, value)
        )

    @staticmethod
    def registration_enabled_from(conn):
        value = AppContext.get_meta(conn, "registration_enabled", "true")
        return str(value).strip().lower() == "true"

    def registration_enabled(self):
        conn = self.connect_db()
        try:
            return self.registration_enabled_from(conn)
        finally:
            conn.close()

    # -- 客户端 IP ----------------------------------------------------------
    @staticmethod
    def _in_networks(ip_obj, networks):
        for network in networks:
            try:
                if ip_obj in network:
                    return True
            except TypeError:
                continue
        return False

    def resolve_client_ip(self, peer_address, headers):
        peer_ip = normalize_ip(peer_address)
        if peer_ip is None:
            return None
        client_ip = peer_ip
        if self.trusted_proxies and self._in_networks(peer_ip, self.trusted_proxies):
            forwarded = headers.get("X-Forwarded-For")
            if forwarded:
                for part in reversed(str(forwarded).split(",")):
                    candidate = normalize_ip(part)
                    if candidate is None:
                        continue
                    if candidate.is_loopback:
                        continue
                    client_ip = candidate
                    break
        if self.mode == "mock":
            override = headers.get("X-Test-Client-IP")
            if override is not None and str(override).strip():
                candidate = normalize_ip(override)
                if candidate is None:
                    return None
                client_ip = candidate
        return client_ip

    def ip_allowed(self, ip_obj):
        if not self.allowed_client_cidrs:
            return True
        return self._in_networks(ip_obj, self.allowed_client_cidrs)

    def admin_ip_allowed(self, ip_obj):
        """SPEC §19.1：security.admin_allowed_cidrs 限制 /admin 与 /api/admin/*。"""
        if not self.admin_allowed_cidrs:
            return True
        return self._in_networks(ip_obj, self.admin_allowed_cidrs)

    def code_hash(self, email, code):
        """SPEC §18.3：HMAC-SHA256(code_secret, email + ":" + code) 的 hex。"""
        message = ("%s:%s" % (email, code)).encode("utf-8")
        return hmac.new(
            self.email_code_secret.encode("utf-8"), message, hashlib.sha256
        ).hexdigest()

    # -- SPEC §22：邮箱唯一性（registrations.email + user_emails.email 双表） --
    @staticmethod
    def registration_email_owner(conn, email):
        row = conn.execute(
            "SELECT username FROM registrations WHERE email = ? LIMIT 1", (email,)
        ).fetchone()
        return row["username"] if row is not None else None

    @staticmethod
    def user_email_owner(conn, email):
        row = conn.execute(
            "SELECT username FROM user_emails WHERE email = ? LIMIT 1", (email,)
        ).fetchone()
        return row["username"] if row is not None else None

    @classmethod
    def email_owner(cls, conn, email):
        """返回占用该邮箱的 username（两表任一命中），未被占用返回 None。"""
        owner = cls.registration_email_owner(conn, email)
        if owner is not None:
            return owner
        return cls.user_email_owner(conn, email)

    @staticmethod
    def lookup_account_by_email(conn, email):
        """邮箱 → 账号：同时查 registrations.email 与 user_emails.email。

        返回 ``(username, portal_row)``；portal_row 为 registrations 行（可能为 None）。
        """
        row = conn.execute(
            "SELECT * FROM registrations WHERE email = ? LIMIT 1", (email,)
        ).fetchone()
        if row is not None:
            return row["username"], row
        row = conn.execute(
            "SELECT username FROM user_emails WHERE email = ? LIMIT 1", (email,)
        ).fetchone()
        if row is not None:
            return row["username"], None
        return None, None

    @staticmethod
    def username_bound_email(conn, username):
        """该账号当前绑定的邮箱（user_emails 优先，回退 registrations.email）。"""
        row = conn.execute(
            "SELECT email FROM user_emails WHERE username = ?", (username,)
        ).fetchone()
        if row is not None:
            return row["email"]
        row = conn.execute(
            "SELECT email FROM registrations WHERE username = ?", (username,)
        ).fetchone()
        if row is not None:
            return row["email"]
        return None

    # -- 用户名候选 ---------------------------------------------------------
    def system_username_taken(self, username):
        if self.mode == "mock":
            return self.provisioner.username_taken(username)
        try:
            pwd.getpwnam(username)
            return True
        except KeyError:
            pass
        try:
            grp.getgrnam(username)
            return True
        except KeyError:
            pass
        return False

    @staticmethod
    def make_username(base, index):
        if index == 0:
            return base
        return "%s%d" % (base, index)

    def find_available_username(self, conn, base, start_index=0):
        rows = conn.execute("SELECT username FROM registrations").fetchall()
        used = {row["username"] for row in rows}
        indexes = [0]
        indexes.extend(range(2, 1000))
        for index in indexes:
            if index < start_index:
                continue
            username = self.make_username(base, index)
            if len(username) > 32:
                continue
            if not USERNAME_RE.match(username):
                continue
            if username in RESERVED_USERNAMES:
                continue
            if username in used:
                continue
            if self.system_username_taken(username):
                continue
            return index, username
        return None, None


# ---------------------------------------------------------------------------
# HTTP 处理
# ---------------------------------------------------------------------------


class SecurityMixin(object):
    """安全响应头 + 结构化访问日志（所有响应）。"""

    protocol_version = "HTTP/1.0"
    server_version = "campus-signup"

    def setup(self):
        # SPEC §19.2：单连接读/写超时 30s（覆盖慢速攻击；写超时同样生效）
        BaseHTTPRequestHandler.setup(self)
        try:
            self.connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
        except OSError:
            pass

    def version_string(self):
        return "campus-signup"

    def end_headers(self):
        try:
            if not getattr(self, "_security_headers_written", False):
                self._security_headers_written = True
                for name, value in SECURITY_HEADERS:
                    self.send_header(name, value)
                # SPEC §19.3：/admin 与 /api/* 禁止搜索引擎索引
                if getattr(self, "_robots_noindex", False):
                    self.send_header("X-Robots-Tag", "noindex, nofollow")
        except OSError:
            return
        BaseHTTPRequestHandler.end_headers(self)

    def log_request(self, code="-", size="-"):
        duration_ms = 0.0
        started = getattr(self, "_request_started", None)
        if started is not None:
            duration_ms = (time.monotonic() - started) * 1000.0
        log(
            "access",
            ip=getattr(self, "_log_ip", "-"),
            method=getattr(self, "_log_method", "-"),
            path=getattr(self, "_log_path", "-"),
            status=code,
            duration_ms="%.1f" % duration_ms,
        )

    def _begin_request(self, method):
        self._request_started = time.monotonic()
        self._log_method = method
        self._log_ip = self.client_address[0] if self.client_address else "-"
        try:
            self._log_path = urlsplit(self.path).path or "/"
        except ValueError:
            self._log_path = "-"
        self._security_headers_written = False
        self._response_started = False
        self._head_only = method == "HEAD"
        self._robots_noindex = False
        # 防止慢速/挂起客户端长期占用线程
        try:
            self.connection.settimeout(CONNECTION_TIMEOUT_SECONDS)
        except OSError:
            pass

    # -- 基础响应 ----------------------------------------------------------
    def _send_bytes(self, status, data, content_type, extra_headers=None):
        self._response_started = True
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        for name, value in extra_headers or ():
            self.send_header(name, value)
        self.end_headers()
        if not self._head_only:
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, status, payload, extra_headers=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, data, "application/json; charset=utf-8", extra_headers)

    def _send_error(self, status, code, message, extra_headers=None):
        self._send_json(
            status,
            {"ok": False, "error": {"code": code, "message": message}},
            extra_headers,
        )

    def _send_rate_limited(self, retry_after):
        self._send_error(
            429,
            "RATE_LIMITED",
            "请求过于频繁，请稍后再试",
            [("Retry-After", str(int(retry_after)))],
        )


class MainHandler(SecurityMixin, BaseHTTPRequestHandler):
    """主服务（HTTPS 或 mock HTTP）。"""

    # -- HTTP 方法入口 -----------------------------------------------------
    def do_GET(self):
        self._dispatch("GET")

    def do_HEAD(self):
        self._dispatch("HEAD")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._method_not_allowed()

    def do_DELETE(self):
        self._method_not_allowed()

    def do_PATCH(self):
        self._method_not_allowed()

    def do_OPTIONS(self):
        self._method_not_allowed()

    def do_TRACE(self):
        self._method_not_allowed()

    def do_CONNECT(self):
        self._method_not_allowed()

    def _method_not_allowed(self):
        self._begin_request("OTHER")
        self._send_error(
            405, "METHOD_NOT_ALLOWED", "请求方法不被允许", [("Allow", "GET, HEAD, POST")]
        )

    def _dispatch(self, method):
        self._begin_request(method)
        try:
            self._handle(method)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            traceback.print_exc(file=sys.stderr)
            if not getattr(self, "_response_started", False):
                try:
                    self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
                except Exception:
                    pass

    # -- 路由 --------------------------------------------------------------
    def _handle(self, method):
        ctx = self.server.ctx
        try:
            parsed = urlsplit(self.path)
            path = unquote(parsed.path)
            query = parse_qs(parsed.query, keep_blank_values=True)
        except ValueError:
            self._send_error(404, "NOT_FOUND", "页面不存在")
            return

        # SPEC §19.3：/admin 与 /api/* 禁止搜索引擎索引
        if path == "/admin" or path.startswith("/api/"):
            self._robots_noindex = True

        if path == "/healthz":
            if method == "HEAD":
                self._send_error(
                    405, "METHOD_NOT_ALLOWED", "请求方法不被允许", [("Allow", "GET")]
                )
                return
            self._send_json(200, {"ok": True})
            return

        # SPEC §19.2：方法白名单 GET/POST/HEAD，HEAD 仅静态资源
        if method == "HEAD" and not (
            path in ("/", "/admin") or path.startswith("/static/")
        ):
            self._send_error(
                405,
                "METHOD_NOT_ALLOWED",
                "请求方法不被允许",
                [("Allow", "GET, POST")],
            )
            return

        client_ip = ctx.resolve_client_ip(self.client_address[0], self.headers)
        if client_ip is None:
            self._send_error(403, "IP_NOT_ALLOWED", "无法识别客户端 IP")
            return
        self._log_ip = str(client_ip)
        if not ctx.ip_allowed(client_ip):
            self._send_error(403, "IP_NOT_ALLOWED", "当前网络不允许访问")
            return
        # SPEC §19.1：/admin 页面与 /api/admin/* 的 CIDR 白名单
        is_admin_path = path == "/admin" or path.startswith("/api/admin/")
        if is_admin_path and not ctx.admin_ip_allowed(client_ip):
            self._send_error(403, "IP_NOT_ALLOWED", "当前网络不允许访问管理后台")
            return
        self._client_ip = client_ip

        if method in ("GET", "HEAD"):
            if path == "/api/health":
                self._handle_health()
            elif path == "/api/preview":
                self._handle_preview(query)
            elif path == "/api/announcement":
                self._handle_announcement_public(client_ip)
            elif path == "/api/admin/users":
                self._handle_admin_users(client_ip, query)
            elif path == "/":
                self._serve_static_page("index.html")
            elif path == "/admin":
                self._serve_static_page("admin.html")
            elif path.startswith("/static/"):
                self._serve_static_asset(path)
            elif path in POST_ROUTES:
                self._send_error(
                    405, "METHOD_NOT_ALLOWED", "请求方法不被允许", [("Allow", "POST")]
                )
            else:
                self._send_error(404, "NOT_FOUND", "页面不存在")
            return

        # POST
        if path == "/api/email/send-code":
            self._handle_send_code(client_ip)
        elif path == "/api/email/bind-request":
            self._handle_bind_request(client_ip)
        elif path == "/api/email/bind":
            self._handle_bind(client_ip)
        elif path == "/api/password/reset-request":
            self._handle_password_reset_request(client_ip)
        elif path == "/api/password/reset":
            self._handle_password_reset(client_ip)
        elif path == "/api/generate-password":
            self._handle_generate_password(client_ip)
        elif path == "/api/register":
            self._handle_register(client_ip)
        elif path == "/api/admin/reset-ip":
            self._handle_admin_reset_ip(client_ip)
        elif path == "/api/admin/set-registration":
            self._handle_admin_set_registration(client_ip)
        elif path == "/api/admin/reset-password":
            self._handle_admin_reset_password(client_ip)
        elif path == "/api/admin/set-locked":
            self._handle_admin_set_locked(client_ip)
        elif path == "/api/admin/bind-email":
            self._handle_admin_bind_email(client_ip)
        elif path == "/api/admin/announcement":
            self._handle_admin_announcement(client_ip)
        elif path in GET_ROUTES or path.startswith("/static/"):
            self._send_error(
                405, "METHOD_NOT_ALLOWED", "请求方法不被允许", [("Allow", "GET, HEAD")]
            )
        else:
            self._send_error(404, "NOT_FOUND", "页面不存在")

    # -- 请求体 ------------------------------------------------------------
    def _read_json_body(self, max_bytes=MAX_BODY_BYTES):
        media_type = (
            (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        )
        if media_type != "application/json":
            self._send_error(403, "BAD_REQUEST", "请求必须使用 application/json")
            return None
        if (self.headers.get(REQUIRED_HEADER_NAME) or "").strip() != REQUIRED_HEADER_VALUE:
            self._send_error(403, "BAD_REQUEST", "缺少 X-Requested-With 请求头")
            return None
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            length = 0
        else:
            try:
                length = int(raw_length)
            except (TypeError, ValueError):
                self._send_error(400, "INVALID_REQUEST", "Content-Length 无效")
                return None
            if length < 0:
                self._send_error(400, "INVALID_REQUEST", "Content-Length 无效")
                return None
        if length > max_bytes:
            self._send_error(413, "PAYLOAD_TOO_LARGE", "请求体过大")
            return None
        raw = self.rfile.read(length) if length else b""
        if not raw:
            return {}
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            self._send_error(400, "INVALID_JSON", "请求 JSON 格式错误")
            return None
        if not isinstance(payload, dict):
            self._send_error(400, "INVALID_JSON", "请求 JSON 必须为对象")
            return None
        return payload

    # -- 健康检查 / 公告 ---------------------------------------------------
    def _handle_health(self):
        ctx = self.server.ctx
        conn = ctx.connect_db()
        try:
            enabled = ctx.registration_enabled_from(conn)
        finally:
            conn.close()
        self._send_json(
            200,
            {
                "ok": True,
                "version": VERSION,
                "registration_enabled": enabled,
                "server_name": ctx.server_name,
                "site_title": ctx.site_title,
                "contact": ctx.contact,
                "ssh_host": ctx.ssh_host,
                "ssh_port": ctx.ssh_port,
                "ssh_ipv6": ctx.ssh_ipv6,
                "ssh_ipv6_port": ctx.ssh_ipv6_port,
                # SPEC §18.4
                "email_verification_enabled": ctx.email_enabled,
                "allowed_email_domains": list(ctx.allowed_email_domains),
            },
        )

    def _handle_announcement_public(self, client_ip):
        ctx = self.server.ctx
        limited, retry_after = ctx.rate.check(
            "announcement", str(client_ip), *ctx.rate_limits["announcement"]
        )
        if limited:
            self._send_rate_limited(retry_after)
            return
        conn = ctx.connect_db()
        try:
            content = ctx.get_meta(conn, "announcement", "") or ""
            updated_at = ctx.get_meta(conn, "announcement_updated_at", "") or ""
        finally:
            conn.close()
        self._send_json(
            200, {"ok": True, "content": content, "updated_at": updated_at}
        )

    # -- 邮箱验证码（SPEC §18.4 / §19.4） ----------------------------------
    @staticmethod
    def _daily_retry_after(oldest_created_iso, now_ts):
        if not oldest_created_iso:
            return 86400
        elapsed = now_ts - _epoch_from_iso(oldest_created_iso)
        return max(1, int(math.ceil(86400 - max(0, elapsed))))

    def _handle_send_code(self, client_ip):
        """注册邮箱验证码（SPEC §18.4）。"""
        ctx = self.server.ctx
        ip_text = str(client_ip)
        if not ctx.email_enabled:
            self._send_error(409, "EMAIL_DISABLED", "邮箱验证功能已停用，请联系管理员")
            return
        limited, retry_after = ctx.rate.check(
            "email_send", ip_text, *ctx.rate_limits["email_send"]
        )
        if limited:
            log("email_send", ip=ip_text, result="rate_limited", reason="ip")
            self._send_rate_limited(retry_after)
            return
        body = self._read_json_body()
        if body is None:
            return
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return
        self._issue_email_code(client_ip, email, "register")

    # -- SPEC §22：账号可管理性 / 绑定前置校验 ----------------------------
    def _account_manageability(self, username):
        """返回 (state, info)：state ∈ ok/missing/not_manageable/unavailable/invalid。"""
        ctx = self.server.ctx
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            return "invalid", None
        if username in PROTECTED_ACCOUNT_USERNAMES:
            return "not_manageable", None
        result = ctx.provisioner.user_status([username])
        if not result.ok:
            return "unavailable", None
        info = (result.data.get("users") or {}).get(username)
        if not isinstance(info, dict) or not info.get("exists"):
            return "missing", None
        uid = info.get("uid")
        if not isinstance(uid, int) or uid < 1000:
            return "not_manageable", info
        if info.get("privileged"):
            return "not_manageable", info
        return "ok", info

    # -- 忘记密码（SPEC §21 / §22.4）：邮件验证码自助重置 -----------------
    def _handle_password_reset_request(self, client_ip):
        """POST /api/password/reset-request（§21.3 + §22.4 扩展）。

        顺序：body → email 格式（400）→ IP 限流 password_reset（429，L8）
        → 邮箱→账号（registrations.email / user_emails.email，未找到 404）
        → 账号可管理性（不可管理 409 USER_NOT_MANAGEABLE）
        → email.enabled（409）→ 冷却/每日/全局（429）→ purpose=reset 发码。
        """
        ctx = self.server.ctx
        ip_text = str(client_ip)
        body = self._read_json_body()
        if body is None:
            return
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return
        limited, retry_after = ctx.rate.check(
            "password_reset", ip_text, *ctx.rate_limits["password_reset"]
        )
        if limited:
            log("email_send", ip=ip_text, purpose="reset", result="rate_limited",
                reason="ip")
            self._send_rate_limited(retry_after)
            return
        conn = ctx.connect_db()
        try:
            username, _portal_row = ctx.lookup_account_by_email(conn, email)
        finally:
            conn.close()
        if username is None:
            log("email_send", ip=ip_text, email=mask_email(email),
                purpose="reset", result="fail", reason="email_not_found")
            self._send_error(404, "EMAIL_NOT_FOUND", "该邮箱未注册账号")
            return
        state, _info = self._account_manageability(username)
        if state == "unavailable":
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        if state != "ok":
            log("email_send", ip=ip_text, email=mask_email(email),
                purpose="reset", result="fail", reason="user_not_manageable")
            self._send_error(
                409, "USER_NOT_MANAGEABLE", "该账号不支持自助重置密码，请联系管理员"
            )
            return
        if not ctx.email_enabled:
            self._send_error(409, "EMAIL_DISABLED", "邮箱验证功能已停用，请联系管理员")
            return
        self._issue_email_code(client_ip, email, "reset")

    def _handle_password_reset(self, client_ip):
        """POST /api/password/reset（§21.3 + §22.4）：验证码重置密码，不自动解锁。"""
        ctx = self.server.ctx
        ip_text = str(client_ip)
        body = self._read_json_body()
        if body is None:
            return
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return
        limited, retry_after = ctx.rate.check(
            "password_reset", ip_text, *ctx.rate_limits["password_reset"]
        )
        if limited:
            log("password_reset", ip=ip_text, result="rate_limited", reason="ip")
            self._send_rate_limited(retry_after)
            return
        conn = ctx.connect_db()
        try:
            username, _portal_row = ctx.lookup_account_by_email(conn, email)
        finally:
            conn.close()
        if username is None:
            log("password_reset", ip=ip_text, email=mask_email(email),
                result="fail", reason="email_not_found")
            self._send_error(404, "EMAIL_NOT_FOUND", "该邮箱未注册账号")
            return
        state, _info = self._account_manageability(username)
        if state == "unavailable":
            log("password_reset", ip=ip_text, username=username,
                result="fail", reason="provisioner_unavailable")
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        if state != "ok":
            log("password_reset", ip=ip_text, username=username,
                email=mask_email(email), result="fail",
                reason="user_not_manageable")
            self._send_error(
                409, "USER_NOT_MANAGEABLE", "该账号不支持自助重置密码，请联系管理员"
            )
            return
        if not ctx.email_enabled:
            log("password_reset", ip=ip_text, username=username,
                email=mask_email(email), result="fail", reason="email_disabled")
            self._send_error(409, "EMAIL_DISABLED", "邮箱验证功能已停用，请联系管理员")
            return

        conn = ctx.connect_db()
        try:
            verified, code_error, code_message, code_id, attempts = verify_email_code(
                ctx, conn, email, body.get("code"), purpose="reset"
            )
        finally:
            conn.close()
        if not verified:
            log("email_code_fail", ip=ip_text, email=mask_email(email),
                attempts=attempts, reason=code_error, purpose="reset")
            log("password_reset", ip=ip_text, username=username,
                email=mask_email(email), result="fail", reason=code_error)
            self._send_error(400, code_error, code_message)
            return

        new_password = body.get("new_password")
        if not isinstance(new_password, str) or not new_password:
            self._send_error(400, "WEAK_PASSWORD", "请输入新密码")
            return
        if len(new_password.encode("utf-8", "ignore")) > MAX_PASSWORD_BYTES:
            self._send_error(400, "WEAK_PASSWORD", "密码过长")
            return
        pw_ok, pw_error = security.validate_password(new_password, username)
        if not pw_ok:
            log("password_reset", ip=ip_text, username=username,
                email=mask_email(email), result="fail", reason="weak_password")
            self._send_error(400, "WEAK_PASSWORD", pw_error)
            return

        result = ctx.provisioner.reset_password(username, new_password)
        if not result.ok:
            log("password_reset", ip=ip_text, username=username,
                email=mask_email(email), result="fail", reason=result.code)
            if result.code == "INVALID":
                self._send_error(
                    409, "USER_MISSING", "系统账号不存在或不可管理，请联系管理员"
                )
            else:
                self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return

        try:
            conn = ctx.connect_db()
            try:
                conn.execute(
                    "UPDATE email_codes SET used = 1 WHERE id = ?", (code_id,)
                )
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            log("password_reset", ip=ip_text, username=username,
                result="code_mark_fail")

        locked = False
        status_result = ctx.provisioner.user_status([username])
        if status_result.ok:
            info = (status_result.data.get("users") or {}).get(username) or {}
            locked = bool(info.get("locked"))
        else:
            log("password_reset", ip=ip_text, username=username,
                result="status_unknown")
        log("password_reset", ip=ip_text, username=username,
            email=mask_email(email), locked=locked, result="ok")
        self._send_json(200, {"ok": True, "username": username, "locked": locked})

    # -- 现有用户自助绑定邮箱（SPEC §22.4）---------------------------------
    def _bind_precheck(self, client_ip, body):
        """绑定前置校验（bind-request / bind 共用；SPEC §22.4 / §22.6 F11）。

        顺序：username/email 格式 → 邮箱未被任何账号使用（409）
        → **IP 级 rate_limits.bind 限流（429，先于密码校验，防在线爆破与 provisioner DoS）**
        → **同 username+IP 密码失败锁定检查（429）** → provisioner verify_password
        （失败统一 400 INVALID_CREDENTIALS，并累计失败次数，≥5 次锁 15 分钟）
        → 账号已绑定（409）→ email.enabled（409）。返回 (username, email) 或 None。
        """
        ctx = self.server.ctx
        ip_text = str(client_ip)
        username = body.get("username")
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            self._send_error(400, "INVALID_USERNAME", "用户名格式不正确")
            return None
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return None
        conn = ctx.connect_db()
        try:
            owner = ctx.email_owner(conn, email)
        finally:
            conn.close()
        if owner is not None:
            log("email_bind", ip=ip_text, username=username,
                email=mask_email(email), result="fail",
                reason="email_already_bound")
            self._send_error(409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用")
            return None

        # F11-1：IP 级 bind 限流必须在 verify_password 之前（错误密码同样消耗额度）
        limited, retry_after = ctx.rate.check(
            "bind", ip_text, *ctx.rate_limits["bind"]
        )
        if limited:
            log("email_bind", ip=ip_text, username=username,
                result="rate_limited", reason="ip")
            self._send_rate_limited(retry_after)
            return None

        # F11-2：同 username+IP 密码校验失败锁定（5 次/15 分钟），锁定期内即便密码正确也拒绝
        locked, lock_retry = ctx.bind_guard.is_locked(username, ip_text)
        if locked:
            log("email_bind", ip=ip_text, username=username,
                result="rate_limited", reason="bind_locked")
            log("email_bind_locked", ip=ip_text, username=username,
                retry_after=lock_retry)
            self._send_error(
                429,
                "RATE_LIMITED",
                BIND_LOCKED_MESSAGE,
                [("Retry-After", str(int(lock_retry)))],
            )
            return None

        password = body.get("password")
        if (
            not isinstance(password, str)
            or not password
            or len(password.encode("utf-8", "ignore")) > MAX_PASSWORD_BYTES
        ):
            self._send_error(400, "INVALID_CREDENTIALS", BIND_LOCKED_MESSAGE)
            return None
        result = ctx.provisioner.verify_password(username, password)
        if not result.ok:
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return None
        data = result.data if isinstance(result.data, dict) else {}
        if not data.get("manageable"):
            fail_count, just_locked, lock_seconds = ctx.bind_guard.record_failure(
                username, ip_text
            )
            log("email_bind", ip=ip_text, username=username,
                result="fail", reason="invalid_credentials", fails=fail_count)
            if just_locked:
                log("email_bind_locked", ip=ip_text, username=username,
                    retry_after=lock_seconds)
                self._send_error(
                    429,
                    "RATE_LIMITED",
                    BIND_LOCKED_MESSAGE,
                    [("Retry-After", str(int(lock_seconds)))],
                )
            else:
                self._send_error(400, "INVALID_CREDENTIALS", BIND_LOCKED_MESSAGE)
            return None
        ctx.bind_guard.record_success(username, ip_text)

        conn = ctx.connect_db()
        try:
            bound = ctx.username_bound_email(conn, username)
        finally:
            conn.close()
        if bound is not None:
            log("email_bind", ip=ip_text, username=username,
                email=mask_email(email), result="fail",
                reason="account_already_bound")
            self._send_error(409, "EMAIL_ALREADY_BOUND", "该账号已绑定邮箱")
            return None
        if not ctx.email_enabled:
            self._send_error(409, "EMAIL_DISABLED", "邮箱验证功能已停用，请联系管理员")
            return None
        return username, email

    def _handle_bind_request(self, client_ip):
        """POST /api/email/bind-request：密码 + 邮箱验证码绑定已有账号邮箱。"""
        ctx = self.server.ctx
        ip_text = str(client_ip)
        body = self._read_json_body()
        if body is None:
            return
        pre = self._bind_precheck(ip_text, body)
        if pre is None:
            return
        username, email = pre
        self._issue_email_code(client_ip, email, "bind")

    def _handle_bind(self, client_ip):
        """POST /api/email/bind：验证码确认绑定，写 user_emails(source='self')。"""
        ctx = self.server.ctx
        ip_text = str(client_ip)
        body = self._read_json_body()
        if body is None:
            return
        pre = self._bind_precheck(ip_text, body)
        if pre is None:
            return
        username, email = pre
        conn = ctx.connect_db()
        try:
            verified, code_error, code_message, code_id, attempts = verify_email_code(
                ctx, conn, email, body.get("code"), purpose="bind"
            )
        finally:
            conn.close()
        if not verified:
            log("email_code_fail", ip=ip_text, email=mask_email(email),
                attempts=attempts, reason=code_error, purpose="bind")
            log("email_bind", ip=ip_text, username=username,
                result="fail", reason=code_error)
            self._send_error(400, code_error, code_message)
            return

        now = utc_now()
        conn = ctx.connect_db()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            owner = ctx.registration_email_owner(conn, email)
            if owner is None:
                owner = ctx.user_email_owner(conn, email)
            if owner is not None:
                conn.execute("ROLLBACK")
                log("email_bind", ip=ip_text, username=username,
                    email=mask_email(email), result="fail",
                    reason="email_already_bound")
                self._send_error(409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用")
                return
            bound = ctx.username_bound_email(conn, username)
            if bound is not None:
                conn.execute("ROLLBACK")
                log("email_bind", ip=ip_text, username=username,
                    result="fail", reason="account_already_bound")
                self._send_error(409, "EMAIL_ALREADY_BOUND", "该账号已绑定邮箱")
                return
            conn.execute(
                "INSERT INTO user_emails "
                "(username, email, source, verified_at, created_at) "
                "VALUES (?, ?, 'self', ?, ?)",
                (username, email, now, now),
            )
            conn.execute(
                "UPDATE registrations SET email = ?, updated_at = ? "
                "WHERE username = ? AND (email IS NULL OR email = '')",
                (email, now, username),
            )
            conn.execute("UPDATE email_codes SET used = 1 WHERE id = ?", (code_id,))
            conn.execute("COMMIT")
        except sqlite3.IntegrityError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            log("email_bind", ip=ip_text, username=username,
                email=mask_email(email), result="fail",
                reason="email_already_bound")
            self._send_error(409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用")
            return
        except sqlite3.Error:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            log("email_bind", ip=ip_text, username=username, result="fail",
                reason="db_error")
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        finally:
            conn.close()
        log("email_bind", ip=ip_text, username=username,
            email=mask_email(email), result="ok")
        self._send_json(200, {"ok": True, "username": username, "email": email})

    def _issue_email_code(self, client_ip, email, purpose):
        """生成并投递指定用途验证码（注册/重置共享冷却与每日/全局额度）。

        在 BEGIN IMMEDIATE 事务内完成「用途校验 → 冷却 → 每日/全局上限 →
        旧同用途未用码失效 → 写入 HMAC 行」，再在事务外发送邮件；
        发送失败删除该行（不消耗冷却与额度）。
        """
        ctx = self.server.ctx
        ip_text = str(client_ip)
        now_ts = int(time.time())
        code = "%06d" % secrets.randbelow(1000000)
        code_id = None
        conn = ctx.connect_db()
        try:
            conn.isolation_level = None  # 显式事务 + BEGIN IMMEDIATE 保证冷却/限额并发安全
            conn.execute("BEGIN IMMEDIATE")
            owner = ctx.email_owner(conn, email)
            if purpose == "register" and owner is not None:
                conn.execute("ROLLBACK")
                log(
                    "email_send",
                    ip=ip_text,
                    email=mask_email(email),
                    purpose=purpose,
                    result="fail",
                    reason="email_registered",
                )
                self._send_error(409, "EMAIL_REGISTERED", "该邮箱已注册过账号")
                return
            if purpose == "reset" and owner is None:
                conn.execute("ROLLBACK")
                log(
                    "email_send",
                    ip=ip_text,
                    email=mask_email(email),
                    purpose=purpose,
                    result="fail",
                    reason="email_not_found",
                )
                self._send_error(404, "EMAIL_NOT_FOUND", "该邮箱未注册账号")
                return
            if purpose == "bind" and owner is not None:
                conn.execute("ROLLBACK")
                log(
                    "email_send",
                    ip=ip_text,
                    email=mask_email(email),
                    purpose=purpose,
                    result="fail",
                    reason="email_already_bound",
                )
                self._send_error(
                    409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用"
                )
                return

            now_iso = utc_now()
            # 每邮箱 60s 冷却（按 email 统计，不区分 purpose）
            latest = conn.execute(
                "SELECT created_at FROM email_codes WHERE email = ? "
                "ORDER BY id DESC LIMIT 1",
                (email,),
            ).fetchone()
            if latest is not None and ctx.email_resend_cooldown > 0:
                elapsed = now_ts - _epoch_from_iso(latest["created_at"])
                if elapsed < ctx.email_resend_cooldown:
                    retry = max(
                        1, int(math.ceil(ctx.email_resend_cooldown - elapsed))
                    )
                    conn.execute("ROLLBACK")
                    log(
                        "email_send",
                        ip=ip_text,
                        email=mask_email(email),
                        purpose=purpose,
                        result="rate_limited",
                        reason="cooldown",
                    )
                    self._send_error(
                        429,
                        "RATE_LIMITED",
                        "验证码发送过于频繁，请 %d 秒后再试" % retry,
                        [("Retry-After", str(retry))],
                    )
                    return

            # 每邮箱每日上限（共享，不区分 purpose）
            day_cut_iso = _iso_from_epoch(now_ts - 86400)
            per_email = conn.execute(
                "SELECT COUNT(*) AS c, MIN(created_at) AS oldest FROM email_codes "
                "WHERE email = ? AND created_at >= ?",
                (email, day_cut_iso),
            ).fetchone()
            if int(per_email["c"] or 0) >= ctx.email_max_send_per_email_per_day:
                retry = self._daily_retry_after(per_email["oldest"], now_ts)
                conn.execute("ROLLBACK")
                log(
                    "email_send",
                    ip=ip_text,
                    email=mask_email(email),
                    purpose=purpose,
                    result="rate_limited",
                    reason="email_daily",
                )
                self._send_error(
                    429,
                    "RATE_LIMITED",
                    "该邮箱今日验证码发送次数已达上限，请明天再试",
                    [("Retry-After", str(retry))],
                )
                return

            # 全局每日上限（SPEC §19.4）
            global_row = conn.execute(
                "SELECT COUNT(*) AS c, MIN(created_at) AS oldest FROM email_codes "
                "WHERE created_at >= ?",
                (day_cut_iso,),
            ).fetchone()
            if int(global_row["c"] or 0) >= ctx.email_max_send_global_per_day:
                retry = self._daily_retry_after(global_row["oldest"], now_ts)
                conn.execute("ROLLBACK")
                log(
                    "email_send",
                    ip=ip_text,
                    purpose=purpose,
                    result="rate_limited",
                    reason="global_daily",
                )
                self._send_error(
                    429,
                    "RATE_LIMITED",
                    "今日验证码发送总量已达上限，请明天再试",
                    [("Retry-After", str(retry))],
                )
                return

            # 清理：过期超过 24h 或 30 天前的记录（SPEC §18.3）
            conn.execute(
                "DELETE FROM email_codes WHERE expires_at < ? OR created_at < ?",
                (
                    now_ts - EMAIL_CODE_EXPIRED_RETENTION_SECONDS,
                    _iso_from_epoch(now_ts - EMAIL_CODE_CREATED_RETENTION_SECONDS),
                ),
            )
            # 仅最新一条同用途验证码有效：旧未用码立即失效
            conn.execute(
                "UPDATE email_codes SET used = 1 "
                "WHERE email = ? AND purpose = ? AND used = 0",
                (email, purpose),
            )
            cursor = conn.execute(
                "INSERT INTO email_codes "
                "(email, code_hash, expires_at, used, attempts, ip, created_at, purpose) "
                "VALUES (?, ?, ?, 0, 0, ?, ?, ?)",
                (
                    email,
                    ctx.code_hash(email, code),
                    now_ts + ctx.email_code_ttl,
                    ip_text,
                    now_iso,
                    purpose,
                ),
            )
            code_id = cursor.lastrowid
            conn.execute("COMMIT")
        except sqlite3.Error:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            log(
                "email_send",
                ip=ip_text,
                purpose=purpose,
                result="fail",
                reason="db_error",
            )
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        finally:
            conn.close()

        try:
            ctx.email_sender.send_code(
                email, code, ctx.email_code_ttl, purpose=purpose
            )
        except email_sender.EmailSendError as exc:
            # 只记录错误类型，绝不记录 SMTP 主机/账号/密码/验证码
            log(
                "email_send",
                ip=ip_text,
                email=mask_email(email),
                purpose=purpose,
                result="fail",
                kind=exc.kind,
            )
            # 发送失败不消耗冷却/每日/全局额度：删除该 code 行（SPEC §19.4）
            self._delete_email_code(ctx, code_id)
            self._send_error(
                502,
                "EMAIL_SEND_FAILED",
                "验证码邮件发送失败，请稍后重试或联系管理员",
            )
            return
        except Exception as exc:  # 兜底，不泄露细节
            log(
                "email_send",
                ip=ip_text,
                email=mask_email(email),
                purpose=purpose,
                result="fail",
                kind=type(exc).__name__,
            )
            self._delete_email_code(ctx, code_id)
            self._send_error(
                502,
                "EMAIL_SEND_FAILED",
                "验证码邮件发送失败，请稍后重试或联系管理员",
            )
            return

        log(
            "email_send",
            ip=ip_text,
            email=mask_email(email),
            purpose=purpose,
            result="ok",
        )
        payload = {
            "ok": True,
            "email": email,
            "expires_in": ctx.email_code_ttl,
            "cooldown": ctx.email_resend_cooldown,
        }
        if ctx.mode == "mock":
            # SPEC §18.6 / §21：仅 mock 模式返回 debug_code
            payload["debug_code"] = code
        self._send_json(200, payload)


    @staticmethod
    def _delete_email_code(ctx, code_id):
        """删除未成功送达的验证码行：失败不消耗冷却与每日/全局发送额度。"""
        if not code_id:
            return
        try:
            conn = ctx.connect_db()
            try:
                conn.execute("DELETE FROM email_codes WHERE id = ?", (code_id,))
                conn.commit()
            finally:
                conn.close()
        except sqlite3.Error:
            pass

    # -- 预览 --------------------------------------------------------------
    def _handle_preview(self, query):
        ctx = self.server.ctx
        limited, retry_after = ctx.rate.check(
            "preview", str(self._client_ip), *ctx.rate_limits["preview"]
        )
        if limited:
            self._send_rate_limited(retry_after)
            return
        name = (query.get("name") or [""])[0]
        if len(name.encode("utf-8", "ignore")) > MAX_NAME_BYTES:
            self._send_error(400, "INVALID_NAME", "姓名过长")
            return
        normalized, error = pinyin_util.normalize_real_name(name)
        if error:
            self._send_error(400, "INVALID_NAME", error)
            return
        pinyin, pinyin_error = pinyin_util.name_to_pinyin(normalized)
        if pinyin_error:
            self._send_error(400, "INVALID_NAME", pinyin_error)
            return
        conn = ctx.connect_db()
        try:
            index, username = ctx.find_available_username(conn, pinyin)
        finally:
            conn.close()
        if username is None:
            self._send_error(
                409, "USERNAME_EXHAUSTED", "用户名候选已用尽，请联系管理员"
            )
            return
        note = "" if index == 0 else "已有同名账号，将分配 %s" % username
        self._send_json(
            200,
            {
                "ok": True,
                "real_name": normalized,
                "pinyin": pinyin,
                "base_username": pinyin,
                "username": username,
                "duplicate_index": index,
                "available": True,
                "note": note,
            },
        )

    # -- 生成密码 ----------------------------------------------------------
    def _handle_generate_password(self, client_ip):
        ctx = self.server.ctx
        limited, retry_after = ctx.rate.check(
            "generate_password", str(client_ip), *ctx.rate_limits["generate_password"]
        )
        if limited:
            self._send_rate_limited(retry_after)
            return
        body = self._read_json_body()
        if body is None:
            return
        password = security.generate_password(16)
        self._send_json(
            200,
            {
                "ok": True,
                "password": password,
                "length": len(password),
                "strength": security.estimate_strength(password),
            },
        )

    # -- 注册（SPEC §7.4 + §18.4 v1.3） ------------------------------------
    def _handle_register(self, client_ip):
        ctx = self.server.ctx
        ip_text = str(client_ip)
        limited, retry_after = ctx.rate.check(
            "register", ip_text, *ctx.rate_limits["register"]
        )
        if limited:
            self._send_rate_limited(retry_after)
            return
        body = self._read_json_body()
        if body is None:
            return
        # SPEC §19.4 / F-low3：email.enabled=false 视为维护开关，注册也拒绝
        if not ctx.email_enabled:
            self._send_error(409, "EMAIL_DISABLED", "邮箱验证功能已停用，请联系管理员")
            return

        raw_name = body.get("name")
        raw_password = body.get("password")
        # 步骤 1：姓名校验
        if not isinstance(raw_name, str):
            raw_name = ""
        if len(raw_name.encode("utf-8", "ignore")) > MAX_NAME_BYTES:
            self._send_error(400, "INVALID_NAME", "姓名过长")
            return
        normalized, error = pinyin_util.normalize_real_name(raw_name)
        if error:
            self._send_error(400, "INVALID_NAME", error)
            return
        # 步骤 2：密码强度
        if not isinstance(raw_password, str) or not raw_password:
            self._send_error(400, "WEAK_PASSWORD", "请输入密码")
            return
        if len(raw_password.encode("utf-8", "ignore")) > MAX_PASSWORD_BYTES:
            self._send_error(400, "WEAK_PASSWORD", "密码过长")
            return
        ok, error = security.validate_password(raw_password, None)
        if not ok:
            self._send_error(400, "WEAK_PASSWORD", error)
            return

        # 步骤 3：邮箱格式 + 域名
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return

        # 步骤 3.5：邮箱是否已注册（SPEC §18.4 v1.3 定稿顺序：先于验证码校验，409）
        # 注意：响应/日志不回显该邮箱对应账号，避免账号枚举（SPEC §19 最小信息泄露）。
        conn = ctx.connect_db()
        try:
            already = ctx.email_owner(conn, email)
        finally:
            conn.close()
        if already is not None:
            log(
                "register_fail",
                ip=ip_text,
                email=mask_email(email),
                reason="email_registered",
            )
            self._send_error(409, "EMAIL_REGISTERED", "该邮箱已注册过账号")
            return

        pinyin, pinyin_error = pinyin_util.name_to_pinyin(normalized)
        if pinyin_error:
            self._send_error(400, "INVALID_NAME", pinyin_error)
            return

        # 步骤 4：验证码校验（失败不占用 IP / email 名额）
        conn = ctx.connect_db()
        try:
            verified, code_error, code_message, code_id, attempts = verify_email_code(
                ctx, conn, email, body.get("email_code"), purpose="register"
            )
        finally:
            conn.close()
        if not verified:
            log(
                "email_code_fail",
                ip=ip_text,
                email=mask_email(email),
                attempts=attempts,
                reason=code_error,
            )
            log("register_fail", ip=ip_text, email=mask_email(email), reason=code_error)
            self._send_error(400, code_error, code_message)
            return

        # 步骤 5：申请开关 + 来源 IP 限制
        conn = ctx.connect_db()
        try:
            enabled = ctx.registration_enabled_from(conn)
        finally:
            conn.close()
        if not enabled:
            log("register_fail", ip=ip_text, email=mask_email(email), reason="disabled")
            self._send_error(409, "REGISTRATION_DISABLED", "当前暂停新账号申请")
            return
        if not ctx.ip_allowed(client_ip):
            log("register_fail", ip=ip_text, email=mask_email(email), reason="ip_cidr")
            self._send_error(403, "IP_NOT_ALLOWED", "当前网络不允许访问")
            return

        # 步骤 6：全局 flock 覆盖「IP 唯一 → email 唯一 → 用户名 → 建号 → 标记验证码」
        lock_fd = None
        try:
            lock_fd = os.open(ctx.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._register_locked(
                client_ip, normalized, pinyin, raw_password, email, code_id
            )
        finally:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_UN)
                except OSError:
                    pass
                try:
                    os.close(lock_fd)
                except OSError:
                    pass

    def _register_locked(
        self, client_ip, real_name, base_pinyin, password, email, code_id
    ):
        ctx = self.server.ctx
        ip_text = str(client_ip)
        conn = ctx.connect_db()
        try:
            existing = conn.execute(
                "SELECT username FROM registrations WHERE ip = ?", (ip_text,)
            ).fetchone()
            if existing is not None:
                log("register_fail", ip=ip_text, reason="ip_limit")
                self._send_error(
                    409,
                    "IP_LIMIT",
                    "该校园网 IP 已申请过账号（用户名：%s）" % existing["username"],
                )
                return
            email_row = ctx.email_owner(conn, email)
            if email_row is not None:
                log(
                    "register_fail",
                    ip=ip_text,
                    email=mask_email(email),
                    reason="email_registered",
                )
                self._send_error(409, "EMAIL_REGISTERED", "该邮箱已注册过账号")
                return

            next_index = 0
            attempts = 0
            while attempts < MAX_REGISTER_EXISTS_RETRIES:
                index, username = ctx.find_available_username(conn, base_pinyin, next_index)
                if username is None:
                    self._send_error(
                        409, "USERNAME_EXHAUSTED", "用户名候选已用尽，请联系管理员"
                    )
                    return
                # 用户名已确定：补一次「不得包含用户名」校验，避免 provisioner 拒绝后 500
                pw_ok, pw_error = security.validate_password(password, username)
                if not pw_ok:
                    self._send_error(400, "WEAK_PASSWORD", pw_error)
                    return
                now = utc_now()
                try:
                    # 先占位（IP 唯一 + 邮箱双表唯一）：registrations 行 +
                    # user_emails(source='portal')，任何唯一冲突都在建号前失败。
                    cursor = conn.execute(
                        "INSERT INTO registrations "
                        "(ip, real_name, pinyin, username, email, status, "
                        " created_at, updated_at) "
                        "VALUES (?, ?, ?, ?, ?, 'provisioning', ?, ?)",
                        (ip_text, real_name, base_pinyin, username, email, now, now),
                    )
                    row_id = cursor.lastrowid
                    conn.execute(
                        "INSERT INTO user_emails "
                        "(username, email, source, verified_at, created_at) "
                        "VALUES (?, ?, 'portal', ?, ?)",
                        (username, email, now, now),
                    )
                    conn.commit()
                except sqlite3.IntegrityError as exc:
                    conn.rollback()
                    message = str(exc).lower()
                    if "registrations.ip" in message:
                        log("register_fail", ip=ip_text, reason="ip_limit")
                        self._send_error(
                            409,
                            "IP_LIMIT",
                            "该校园网 IP 已申请过账号",
                        )
                        return
                    if "registrations.email" in message or "user_emails.email" in message:
                        log(
                            "register_fail",
                            ip=ip_text,
                            email=mask_email(email),
                            reason="email_registered",
                        )
                        self._send_error(
                            409, "EMAIL_REGISTERED", "该邮箱已注册过账号"
                        )
                        return
                    next_index = 2 if index == 0 else index + 1
                    attempts += 1
                    continue

                result = ctx.provisioner.create_user(username, real_name, password)
                if result.ok:
                    data = result.data
                    uid = data.get("uid")
                    gid = data.get("gid")
                    home = data.get("home") or ("/home/%s" % username)
                    workspace = data.get("workspace") or home
                    conn.execute(
                        "UPDATE registrations SET uid = ?, gid = ?, home = ?, "
                        "workspace = ?, status = 'active', updated_at = ? WHERE id = ?",
                        (uid, gid, home, workspace, utc_now(), row_id),
                    )
                    # SPEC §18.4 步骤 6：注册成功后验证码一次性使用
                    conn.execute(
                        "UPDATE email_codes SET used = 1 WHERE id = ?", (code_id,)
                    )
                    conn.commit()
                    log(
                        "register_ok",
                        ip=ip_text,
                        username=username,
                        uid=uid,
                        email=mask_email(email),
                    )
                    self._send_json(
                        201,
                        {
                            "ok": True,
                            "account": {
                                "username": username,
                                "real_name": real_name,
                                "pinyin": base_pinyin,
                                "email": email,
                                "uid": uid,
                                "gid": gid,
                                "home": home,
                                "workspace": workspace,
                                "ssh_login": _build_ssh_login(ctx, username),
                                "ssh_login_ipv6": _build_ssh_login_ipv6(ctx, username),
                                "created_at": now,
                            },
                        },
                    )
                    return

                # 建号失败：删除 provisioning 行与 user_emails 占位；
                # 验证码保持未使用（不消耗）
                conn.execute("DELETE FROM registrations WHERE id = ?", (row_id,))
                conn.execute(
                    "DELETE FROM user_emails WHERE username = ? AND email = ?",
                    (username, email),
                )
                conn.commit()
                if result.code == "EXISTS":
                    next_index = 2 if index == 0 else index + 1
                    attempts += 1
                    continue
                log(
                    "register_fail",
                    ip=ip_text,
                    username=username,
                    reason="provisioner",
                )
                self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
                return

            self._send_error(
                409, "USERNAME_EXHAUSTED", "用户名候选已用尽，请联系管理员"
            )
        finally:
            conn.close()

    # -- 管理员公共 --------------------------------------------------------
    def _require_admin(self, client_ip, query=None, allow_query_token=False):
        """管理员鉴权（SPEC §7.5 / §19.1）。

        - 失败锁定独立于通用 admin 限流：参数来自 security.admin_lockout
          （默认同 IP 15 分钟失败 ≥10 次 → 封禁 15 分钟）；
        - 生产只接受 X-Admin-Token 头；仅 allow_query_token 配置开启且来源 127.0.0.1
          时允许 ?token=（默认 false）；
        - 常量时间比较；成功鉴权清零失败计数。
        """
        ctx = self.server.ctx
        ip_text = str(client_ip)
        locked, lock_retry = ctx.admin_guard.is_locked(ip_text)
        if locked:
            log("admin_auth_locked", ip=ip_text, retry_after=lock_retry)
            self._send_error(
                403,
                "ADMIN_LOCKED",
                "管理员鉴权失败次数过多，请 %d 秒后再试" % int(lock_retry),
                [("Retry-After", str(int(lock_retry)))],
            )
            return False
        limited, retry_after = ctx.rate.check(
            "admin", ip_text, *ctx.rate_limits["admin"]
        )
        if limited:
            self._send_rate_limited(retry_after)
            return False
        token = self.headers.get("X-Admin-Token") or ""
        if (
            not token
            and allow_query_token
            and query is not None
            and ctx.allow_query_token
            and ip_text == "127.0.0.1"
        ):
            token = (query.get("token") or [""])[0]
        expected = ctx.admin_token or ""
        authorized = False
        if token and expected:
            try:
                authorized = hmac.compare_digest(
                    token.encode("utf-8"), expected.encode("utf-8")
                )
            except (UnicodeEncodeError, TypeError):
                authorized = False
        if not authorized:
            fail_count, just_locked, lock_seconds = ctx.admin_guard.record_failure(
                ip_text
            )
            log("admin_auth_fail", ip=ip_text, count=fail_count)
            if just_locked:
                log("admin_auth_locked", ip=ip_text, retry_after=lock_seconds)
                self._send_error(
                    403,
                    "ADMIN_LOCKED",
                    "管理员鉴权失败次数过多，请 %d 秒后再试" % int(lock_seconds),
                    [("Retry-After", str(int(lock_seconds)))],
                )
            else:
                self._send_error(403, "ADMIN_AUTH", "无权限或 token 错误")
            return False
        ctx.admin_guard.record_success(ip_text)
        return True

    def _lookup_registration(self, conn, record_id):
        return conn.execute(
            "SELECT * FROM registrations WHERE id = ?", (record_id,)
        ).fetchone()

    def _provisioner_user_info(self, username):
        """返回 (info_dict 或 None, ok)。"""
        result = self.server.ctx.provisioner.user_status([username])
        if not result.ok:
            return None, False
        users = result.data.get("users") or {}
        info = users.get(username)
        return (info if isinstance(info, dict) else {"exists": False}), True

    def _read_record_id(self, body):
        record_id = body.get("id")
        if isinstance(record_id, bool) or not isinstance(record_id, int):
            self._send_error(400, "INVALID_REQUEST", "id 必须是整数")
            return None
        return record_id

    # -- 管理员：用户列表（SPEC §22.4）-------------------------------------
    def _portal_row_email(self, conn, username, fallback):
        email = fallback
        if not email:
            row = conn.execute(
                "SELECT email FROM user_emails WHERE username = ?", (username,)
            ).fetchone()
            if row is not None:
                email = row["email"]
        return email

    def _handle_admin_users(self, client_ip, query):
        ctx = self.server.ctx
        if not self._require_admin(client_ip, query, allow_query_token=True):
            return
        list_result = ctx.provisioner.list_users()
        provisioner_ok = bool(list_result.ok)
        system_users = {}
        if provisioner_ok:
            for item in list_result.data.get("users") or []:
                if isinstance(item, dict) and isinstance(item.get("username"), str):
                    system_users[item["username"]] = item
        conn = ctx.connect_db()
        try:
            rows = conn.execute(
                "SELECT id, ip, real_name, username, uid, gid, home, email, "
                "status, created_at FROM registrations ORDER BY id"
            ).fetchall()
            bound_emails = {}
            for row in conn.execute("SELECT username, email FROM user_emails"):
                bound_emails[row["username"]] = row["email"]
        finally:
            conn.close()

        users = []
        seen = set()
        with_emails = 0
        portal_count = 0
        imported_count = 0
        active = locked = missing = 0
        for row in rows:
            username = row["username"]
            seen.add(username)
            system = system_users.get(username)
            if not provisioner_ok:
                os_status = "unknown"
                is_locked = False
                privileged = False
            elif system is None:
                os_status = "missing"
                is_locked = False
                privileged = False
                missing += 1
            else:
                privileged = bool(system.get("privileged"))
                is_locked = bool(system.get("locked"))
                if is_locked:
                    os_status = "locked"
                    locked += 1
                else:
                    os_status = "active"
                    active += 1
            email = row["email"] or bound_emails.get(username)
            if email:
                with_emails += 1
            portal_count += 1
            users.append(
                {
                    "username": username,
                    "real_name": (
                        system.get("real_name")
                        if system and system.get("real_name")
                        else row["real_name"]
                    ),
                    "email": email,
                    "uid": system.get("uid") if system else row["uid"],
                    "gid": system.get("gid") if system else row["gid"],
                    "home": system.get("home") if system else row["home"],
                    "source": "portal",
                    "ip": row["ip"],
                    "registration_id": row["id"],
                    "privileged": privileged,
                    "os_status": os_status,
                    "locked": is_locked,
                }
            )
        if provisioner_ok:
            for username, system in system_users.items():
                if username in seen:
                    continue
                imported_count += 1
                is_locked = bool(system.get("locked"))
                if is_locked:
                    locked += 1
                    os_status = "locked"
                else:
                    active += 1
                    os_status = "active"
                email = bound_emails.get(username)
                if email:
                    with_emails += 1
                users.append(
                    {
                        "username": username,
                        "real_name": system.get("real_name") or "",
                        "email": email,
                        "uid": system.get("uid"),
                        "gid": system.get("gid"),
                        "home": system.get("home"),
                        "source": "imported",
                        "ip": None,
                        "registration_id": None,
                        "privileged": bool(system.get("privileged")),
                        "os_status": os_status,
                        "locked": is_locked,
                    }
                )
        stats = {
            "total": len(users),
            "active": active,
            "locked": locked,
            "missing": missing,
            "with_email": with_emails,
            "portal": portal_count,
            "imported": imported_count,
        }
        self._send_json(200, {"ok": True, "stats": stats, "users": users})

    def _admin_target_state(self, username):
        """管理员操作目标检查：返回 state/info。"""
        return self._account_manageability(username)

    def _send_admin_target_error(self, state, username):
        if state == "unavailable":
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
        elif state == "missing":
            self._send_error(409, "USER_MISSING", "系统用户不存在")
        elif state == "invalid":
            self._send_error(400, "INVALID_REQUEST", "用户名格式不正确")
        else:  # not_manageable
            self._send_error(403, "USER_NOT_MANAGEABLE", "该账号不支持管理操作")

    # -- 管理员：重置 IP ---------------------------------------------------
    def _handle_admin_reset_ip(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body()
        if body is None:
            return
        record_id = self._read_record_id(body)
        if record_id is None:
            return
        conn = ctx.connect_db()
        try:
            row = self._lookup_registration(conn, record_id)
            if row is None:
                self._send_error(404, "NOT_FOUND", "记录不存在")
                return
            conn.execute("DELETE FROM registrations WHERE id = ?", (record_id,))
            conn.commit()
        finally:
            conn.close()
        log("admin_action", action="reset_ip", ip=str(client_ip),
            username=row["username"], result="ok")
        self._send_json(
            200,
            {
                "ok": True,
                "deleted": {
                    "id": row["id"],
                    "ip": row["ip"],
                    "username": row["username"],
                },
            },
        )

    # -- 管理员：开放/暂停申请 ---------------------------------------------
    def _handle_admin_set_registration(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body()
        if body is None:
            return
        enabled = body.get("enabled")
        if not isinstance(enabled, bool):
            self._send_error(400, "INVALID_REQUEST", "enabled 必须是布尔值")
            return
        conn = ctx.connect_db()
        try:
            ctx.set_meta(conn, "registration_enabled", "true" if enabled else "false")
            conn.commit()
        finally:
            conn.close()
        log("admin_action", action="set_registration", ip=str(client_ip),
            enabled=enabled, result="ok")
        self._send_json(200, {"ok": True, "registration_enabled": enabled})

    # -- 管理员：按 username 重置密码 --------------------------------------
    def _handle_admin_reset_password(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body()
        if body is None:
            return
        username = body.get("username")
        state, _info = self._admin_target_state(username)
        if state != "ok":
            self._send_admin_target_error(state, username)
            return
        password = ""
        result = None
        for _attempt in range(3):
            candidate = security.generate_password(16)
            if not security.validate_password(candidate, username)[0]:
                continue
            password = candidate
            result = ctx.provisioner.reset_password(username, password)
            if result.ok or result.code != "INVALID":
                break
        if result is None or not result.ok:
            log("admin_action", action="reset_password", ip=str(client_ip),
                username=username, result="fail")
            if result is not None and result.code == "INVALID":
                self._send_error(409, "USER_MISSING", "系统用户不存在")
            else:
                self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        log("admin_action", action="reset_password", ip=str(client_ip),
            username=username, result="ok")
        self._send_json(
            200, {"ok": True, "username": username, "password": password}
        )

    # -- 管理员：按 username 锁定/解锁 -------------------------------------
    def _handle_admin_set_locked(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body()
        if body is None:
            return
        username = body.get("username")
        locked = body.get("locked")
        if not isinstance(locked, bool):
            self._send_error(400, "INVALID_REQUEST", "locked 必须是布尔值")
            return
        state, _info = self._admin_target_state(username)
        if state != "ok":
            self._send_admin_target_error(state, username)
            return
        result = ctx.provisioner.set_lock(username, locked)
        if not result.ok:
            log("admin_action", action="set_lock", ip=str(client_ip),
                username=username, result="fail")
            if result.code == "INVALID":
                self._send_error(409, "USER_MISSING", "系统用户不存在")
            else:
                self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        log("admin_action", action="set_lock", ip=str(client_ip),
            username=username, locked=bool(locked), result="ok")
        self._send_json(
            200,
            {
                "ok": True,
                "username": username,
                "locked": bool(locked),
            },
        )

    # -- 管理员：按 username 绑定邮箱（无需验证码）------------------------
    def _handle_admin_bind_email(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body()
        if body is None:
            return
        username = body.get("username")
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            self._send_error(400, "INVALID_USERNAME", "用户名格式不正确")
            return
        email, email_error = email_sender.normalize_email(
            body.get("email"), ctx.allowed_email_domains
        )
        if email_error:
            self._send_error(400, "INVALID_EMAIL", email_error)
            return
        state, _info = self._admin_target_state(username)
        if state != "ok":
            self._send_admin_target_error(state, username)
            return
        now = utc_now()
        conn = ctx.connect_db()
        try:
            conn.isolation_level = None
            conn.execute("BEGIN IMMEDIATE")
            owner = ctx.registration_email_owner(conn, email)
            if owner is None:
                owner = ctx.user_email_owner(conn, email)
            if owner is not None:
                conn.execute("ROLLBACK")
                self._send_error(409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用")
                return
            bound = ctx.username_bound_email(conn, username)
            if bound is not None:
                conn.execute("ROLLBACK")
                self._send_error(409, "EMAIL_ALREADY_BOUND", "该账号已绑定邮箱")
                return
            conn.execute(
                "INSERT INTO user_emails "
                "(username, email, source, verified_at, created_at) "
                "VALUES (?, ?, 'admin', ?, ?)",
                (username, email, now, now),
            )
            conn.execute(
                "UPDATE registrations SET email = ?, updated_at = ? "
                "WHERE username = ? AND (email IS NULL OR email = '')",
                (email, now, username),
            )
            conn.execute("COMMIT")
        except sqlite3.IntegrityError:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            log("admin_action", action="bind_email", ip=str(client_ip),
                username=username, email=mask_email(email), result="fail",
                reason="email_already_bound")
            self._send_error(409, "EMAIL_ALREADY_BOUND", "该邮箱已被其他账号使用")
            return
        except sqlite3.Error:
            try:
                conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            log("admin_action", action="bind_email", ip=str(client_ip),
                username=username, result="fail", reason="db_error")
            self._send_error(500, "INTERNAL", "服务器内部错误，请联系管理员")
            return
        finally:
            conn.close()
        log("admin_action", action="bind_email", ip=str(client_ip),
            username=username, email=mask_email(email), result="ok")
        self._send_json(
            200, {"ok": True, "username": username, "email": email}
        )

    # -- 管理员：公告 ------------------------------------------------------
    def _handle_admin_announcement(self, client_ip):
        ctx = self.server.ctx
        if not self._require_admin(client_ip):
            return
        body = self._read_json_body(max_bytes=MAX_ANNOUNCEMENT_BODY_BYTES)
        if body is None:
            return
        content = body.get("content")
        if not isinstance(content, str):
            self._send_error(400, "INVALID_REQUEST", "content 必须是字符串")
            return
        if (
            len(content) < ANNOUNCEMENT_MIN_CHARS
            or len(content) > ANNOUNCEMENT_MAX_CHARS
        ):
            self._send_error(
                400,
                "INVALID_REQUEST",
                "公告长度需为 %d–%d 个字符"
                % (ANNOUNCEMENT_MIN_CHARS, ANNOUNCEMENT_MAX_CHARS),
            )
            return
        if _contains_control_chars(content):
            self._send_error(400, "INVALID_REQUEST", "公告包含不允许的控制字符")
            return
        updated_at = utc_now()
        conn = ctx.connect_db()
        try:
            ctx.set_meta(conn, "announcement", content)
            ctx.set_meta(conn, "announcement_updated_at", updated_at)
            conn.commit()
        finally:
            conn.close()
        log(
            "admin_action",
            action="update_announcement",
            ip=str(client_ip),
            result="ok",
        )
        self._send_json(200, {"ok": True, "updated_at": updated_at})

    # -- 静态文件 ----------------------------------------------------------
    def _serve_static_page(self, filename):
        ctx = self.server.ctx
        path = os.path.join(ctx.static_dir, filename)
        self._send_static_file(path)

    def _serve_static_asset(self, path):
        ctx = self.server.ctx
        relative = path[len("/static/") :]
        if not relative or "\x00" in relative or "\\" in relative:
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        segments = relative.split("/")
        if any(segment in ("", ".", "..") for segment in segments):
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        extension = os.path.splitext(relative)[1].lower()
        if extension not in STATIC_ALLOWED_EXTENSIONS:
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        static_root = os.path.realpath(ctx.static_dir)
        candidate = os.path.realpath(os.path.join(static_root, *segments))
        if candidate != static_root and not candidate.startswith(
            static_root + os.sep
        ):
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        self._send_static_file(candidate)

    def _send_static_file(self, file_path):
        try:
            with open(file_path, "rb") as handle:
                data = handle.read()
        except (OSError, ValueError):
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        if not os.path.isfile(file_path):
            self._send_error(404, "NOT_FOUND", "文件不存在")
            return
        extension = os.path.splitext(file_path)[1].lower()
        content_type = STATIC_CONTENT_TYPES.get(extension, "application/octet-stream")
        self._send_bytes(200, data, content_type)


class RedirectHandler(SecurityMixin, BaseHTTPRequestHandler):
    """HTTP 端口：/healthz 返回 200，其余 301 跳转 HTTPS（SPEC §7）。"""

    def do_GET(self):
        self._redirect("GET")

    def do_HEAD(self):
        self._redirect("HEAD")

    def do_POST(self):
        self._redirect("POST")

    def do_PUT(self):
        self._redirect("PUT")

    def do_DELETE(self):
        self._redirect("DELETE")

    def do_PATCH(self):
        self._redirect("PATCH")

    def do_OPTIONS(self):
        self._redirect("OPTIONS")

    def _redirect(self, method):
        self._begin_request(method)
        ctx = self.server.ctx
        try:
            parsed = urlsplit(self.path)
        except ValueError:
            self._send_error(404, "NOT_FOUND", "页面不存在")
            return
        if parsed.path == "/admin" or parsed.path.startswith("/api/"):
            self._robots_noindex = True
        if parsed.path == "/healthz":
            self._send_bytes(
                200, b'{"ok":true}', "application/json; charset=utf-8"
            )
            return
        host = ctx.public_host
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        default_port = 443
        netloc = host if ctx.https_port == default_port else "%s:%d" % (host, ctx.https_port)
        location = "https://%s%s" % (netloc, parsed.path or "/")
        if parsed.query:
            location += "?" + parsed.query
        self._response_started = True
        self.send_response(301)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


# ---------------------------------------------------------------------------
# 服务器装配 / 主入口
# ---------------------------------------------------------------------------


class CampusHTTPServer(ThreadingHTTPServer):
    """带并发上限的 ThreadingHTTPServer（SPEC §19.2）。"""

    daemon_threads = True
    allow_reuse_address = True
    # 并发突发时由内核 backlog 吸收，避免 accept 队列过浅导致连接被 reset
    request_queue_size = 128

    def __init__(self, server_address, handler_class, ctx, tls_context=None):
        self.ctx = ctx
        self.tls_context = tls_context
        self.max_connections = max(
            1, int(getattr(ctx, "max_connections", DEFAULT_MAX_CONNECTIONS))
        )
        self._active_connections = 0
        self._connection_lock = threading.Lock()
        ThreadingHTTPServer.__init__(self, server_address, handler_class)
        if tls_context is not None:
            self.socket = tls_context.wrap_socket(self.socket, server_side=True)

    def _release_connection(self):
        with self._connection_lock:
            if self._active_connections > 0:
                self._active_connections -= 1

    def process_request(self, request, client_address):
        with self._connection_lock:
            over_limit = self._active_connections >= self.max_connections
            if not over_limit:
                self._active_connections += 1
        if over_limit:
            self._reject_busy(request, client_address)
            return
        try:
            ThreadingHTTPServer.process_request(self, request, client_address)
        except Exception:
            self._release_connection()
            raise

    def process_request_thread(self, request, client_address):
        try:
            ThreadingHTTPServer.process_request_thread(self, request, client_address)
        finally:
            self._release_connection()

    def _reject_busy(self, request, client_address):
        """超过并发上限：立即返回 503 并关闭连接。"""
        body = json.dumps(
            {
                "ok": False,
                "error": {"code": "INTERNAL", "message": "服务器繁忙，请稍后再试"},
            },
            ensure_ascii=False,
        ).encode("utf-8")
        headers = [
            "HTTP/1.0 503 Service Unavailable",
            "Content-Type: application/json; charset=utf-8",
            "Content-Length: %d" % len(body),
            "Cache-Control: no-store",
            "Connection: close",
            "Retry-After: 1",
        ]
        for name, value in SECURITY_HEADERS:
            headers.append("%s: %s" % (name, value))
        payload = ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body
        try:
            request.sendall(payload)
        except OSError:
            pass
        try:
            self.shutdown_request(request)
        except OSError:
            pass
        log(
            "connection_rejected",
            ip=client_address[0] if client_address else "-",
            reason="too_many_connections",
        )

    def handle_error(self, request, client_address):
        # 默认会把 traceback 打到 stderr，可能包含客户端数据；这里只记录摘要
        exc_type = sys.exc_info()[0]
        log(
            "connection_error",
            ip=client_address[0] if client_address else "-",
            error=getattr(exc_type, "__name__", "unknown"),
        )


def build_tls_context(ctx):
    if not ctx.tls_cert or not ctx.tls_key:
        raise ConfigError("TLS 已启用但缺少 tls.cert / tls.key")
    for path in (ctx.tls_cert, ctx.tls_key):
        if not os.path.isfile(path):
            raise ConfigError("TLS 证书/私钥不存在: %s" % path)
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    # SPEC §19.3：禁用压缩，仅启用 ECDHE+AESGCM / CHACHA20 类前向安全套件
    try:
        tls_context.options |= ssl.OP_NO_COMPRESSION
    except (AttributeError, ssl.SSLError):  # pragma: no cover - 旧 OpenSSL
        pass
    try:
        tls_context.set_ciphers(
            "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL:!MD5:!RC4:!DES:!3DES"
        )
    except ssl.SSLError:  # pragma: no cover - 套件名不被支持时回退默认套件
        log("warning", message="tls_ciphers_fallback")
    tls_context.load_cert_chain(certfile=ctx.tls_cert, keyfile=ctx.tls_key)
    return tls_context


def build_servers(ctx):
    servers = []
    if ctx.mode == "mock":
        server = CampusHTTPServer((ctx.bind, ctx.http_port), MainHandler, ctx)
        servers.append(server)
        return servers
    if ctx.tls_enabled:
        tls_context = build_tls_context(ctx)
        servers.append(
            CampusHTTPServer(
                (ctx.bind, ctx.https_port), MainHandler, ctx, tls_context=tls_context
            )
        )
        if ctx.http_port:
            servers.append(
                CampusHTTPServer((ctx.bind, ctx.http_port), RedirectHandler, ctx)
            )
    else:
        log("warning", message="production_mode_without_tls")
        servers.append(
            CampusHTTPServer(
                (ctx.bind, ctx.http_port or ctx.https_port), MainHandler, ctx
            )
        )
    return servers


def _describe_servers(ctx, servers):
    descriptions = []
    for server in servers:
        host, port = server.server_address[0], server.server_address[1]
        scheme = "https" if server.tls_context is not None else "http"
        descriptions.append("%s://%s:%d" % (scheme, host, port))
    return descriptions


def main(argv=None):
    parser = argparse.ArgumentParser(description="campus-signup web service")
    parser.add_argument("--config", required=True, help="配置文件路径")
    args = parser.parse_args(argv)

    try:
        cfg = load_config(args.config)
        ctx = AppContext(cfg)
        servers = build_servers(ctx)
    except ConfigError as exc:
        print("配置错误: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("启动失败: %s" % exc, file=sys.stderr)
        return 1

    stop_event = threading.Event()

    def _handle_signal(_signum, _frame):
        stop_event.set()

    signal.signal(signal.SIGTERM, _handle_signal)
    signal.signal(signal.SIGINT, _handle_signal)

    threads = []
    for server in servers:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        threads.append(thread)
    log(
        "server_start",
        mode=ctx.mode,
        listen=",".join(_describe_servers(ctx, servers)),
    )

    try:
        while not stop_event.wait(0.5):
            if not any(thread.is_alive() for thread in threads):
                break
    finally:
        for server in servers:
            try:
                server.shutdown()
            except Exception:
                pass
        for server in servers:
            try:
                server.server_close()
            except Exception:
                pass
    log("server_stop")
    return 0


if __name__ == "__main__":
    sys.exit(main())
