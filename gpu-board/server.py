#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""star1 GPU 预约台 —— 只读监控 + 预约登记（单文件服务，仅标准库）

复用 campus-signup（/opt/campus-signup）已有的账号与运维体系：
  * 普通用户登录：star1 Linux 账号 + 系统密码，交给 campus-signup 的 root
    provisioner（/run/campus-signup/provision.sock）的 verify_password 校验；
    本服务不接触 /etc/shadow，密码不落库、不写日志。
  * 管理员：复用 campus-signup 的 security.admin_token（+ admin_allowed_cidrs）。
  * 用户列表 / 姓名：复用 provisioner list_users（gECOS 里的中文姓名）。
  * HTTPS：复用 campus-signup 的 TLS 证书。
  * 视觉风格：沿用校园网门户的浅色极简设计（同一组 CSS 变量）。

设计边界（重要）：
  * 只读 nvidia-smi 与 ps，只写自己的 SQLite（会话 / 预约 / 占用采样）。
  * 不杀进程、不改 cgroup、不改任何现有服务，不做任何强制。
  * systemd 侧限制资源：MemoryMax=128M、CPUQuota=5%、Nice=19、IO idle，
    对服务器上其他人的 CPU / 内存实验零影响。

用法：
  python3 server.py --config /etc/star1-gpu-board/config.json
  python3 server.py --mock --no-tls --port 18083 --static ./static --db /tmp/board.db
"""

import argparse
import csv
import hashlib
import hmac
import ipaddress
import json
import os
import pwd
import re
import secrets
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
import traceback
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

VERSION = "1.0.0"
CN_TZ = timezone(timedelta(hours=8))
COOKIE_NAME = "sgb_session"
API_HEADER = "star1-gpu-board"
USERNAME_RE = re.compile(r"^[a-z][a-z0-9]{1,31}$")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")

DEFAULTS = {
    "bind": "0.0.0.0",
    "port": 8083,
    "tls": True,
    "tls_cert": "",
    "tls_key": "",
    "db": "/var/lib/star1-gpu-board/board.db",
    "static": "/opt/star1-gpu-board/static",
    "campus_config": "/etc/campus-signup/config.json",
    "sample_interval": 30,
    "history_interval": 120,
    "retention_days": 60,
    "min_booking_minutes": 30,
    "max_booking_hours": 24,
    "max_booking_days_ahead": 7,
    "max_future_bookings_per_user": 2,
    "login_max_failures": 5,
    "login_lock_seconds": 900,
    "login_ip_max_failures": 20,
    "login_ip_window_seconds": 3600,
    "session_ttl": 43200,
    "admin_session_ttl": 21600,
    "site_title": "star1 GPU 预约台",
    "site_subtitle": "8 × A100-80G · 实时占用、预约与使用统计",
    "contact": "管理员甲 / 管理员乙（见校园网门户公告）",
    "rules_version": "2026-11-17",
}

STATIC_FILES = {
    "index.html": "text/html; charset=utf-8",
    "admin.html": "text/html; charset=utf-8",
    "style.css": "text/css; charset=utf-8",
    "app.js": "application/javascript; charset=utf-8",
    "admin.js": "application/javascript; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}

SECURITY_HEADERS = [
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    ("Referrer-Policy", "no-referrer"),
    (
        "Content-Security-Policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; connect-src 'self'; font-src 'self'; "
        "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    ),
]


def now_ts():
    return int(time.time())


def log(event, **fields):
    parts = [event]
    for key in sorted(fields):
        value = fields[key]
        if value is None:
            continue
        text = str(value).replace("\n", " ").replace("\r", " ")
        if len(text) > 200:
            text = text[:200] + "..."
        parts.append("%s=%s" % (key, text))
    print(" ".join(parts), flush=True)


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
            return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def etime_to_seconds(text):
    text = (text or "").strip()
    if not text:
        return 0
    days = 0
    if "-" in text:
        head, text = text.split("-", 1)
        try:
            days = int(head)
        except ValueError:
            days = 0
    parts = text.split(":")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return days * 86400
    if len(nums) == 3:
        hours, minutes, seconds = nums
    elif len(nums) == 2:
        hours, minutes, seconds = 0, nums[0], nums[1]
    elif len(nums) == 1:
        hours, minutes, seconds = 0, 0, nums[0]
    else:
        return days * 86400
    return days * 86400 + hours * 3600 + minutes * 60 + seconds


def fmt_duration(seconds):
    seconds = int(max(0, seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    if days:
        return "%d天 %02d:%02d" % (days, hours, minutes)
    if hours:
        return "%d:%02d" % (hours, minutes)
    return "%d分钟" % max(1, minutes)


def clamp_int(value, low, high, default):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, number))


def ip_allowed(ip_text, cidrs):
    if not cidrs:
        return True
    try:
        address = ipaddress.ip_address(ip_text)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if address in ipaddress.ip_network(str(cidr), strict=False):
                return True
        except ValueError:
            continue
    return False


# ---------------------------------------------------------------------------
# 数据库
# ---------------------------------------------------------------------------

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token      TEXT PRIMARY KEY,
  role       TEXT NOT NULL,
  username   TEXT,
  real_name  TEXT,
  created_ts INTEGER NOT NULL,
  expires_ts INTEGER NOT NULL,
  ip         TEXT
);
CREATE TABLE IF NOT EXISTS login_fails (
  id       INTEGER PRIMARY KEY AUTOINCREMENT,
  ip       TEXT NOT NULL,
  username TEXT NOT NULL,
  ts       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_fails_ip_ts ON login_fails(ip, ts);
CREATE TABLE IF NOT EXISTS bookings (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  gpu        INTEGER NOT NULL,
  username   TEXT NOT NULL,
  real_name  TEXT,
  start_ts   INTEGER NOT NULL,
  end_ts     INTEGER NOT NULL,
  purpose    TEXT NOT NULL,
  created_ts INTEGER NOT NULL,
  created_by TEXT,
  status     TEXT NOT NULL DEFAULT 'active'
);
CREATE INDEX IF NOT EXISTS idx_bookings_time ON bookings(start_ts, end_ts);
CREATE INDEX IF NOT EXISTS idx_bookings_gpu ON bookings(gpu, start_ts);
CREATE TABLE IF NOT EXISTS api_tokens (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  username     TEXT NOT NULL,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  prefix       TEXT NOT NULL,
  created_ts   INTEGER NOT NULL,
  last_used_ts INTEGER,
  revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(username);
CREATE TABLE IF NOT EXISTS proc_samples (
  ts       INTEGER NOT NULL,
  gpu      INTEGER NOT NULL,
  username TEXT NOT NULL,
  PRIMARY KEY (ts, gpu, username)
);
"""


class Database(object):
    def __init__(self, path):
        self.path = path
        self._local = threading.local()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        conn = self._connect()
        try:
            conn.executescript(SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version', '1')"
            )
            conn.commit()
        finally:
            conn.close()

    def _connect(self):
        conn = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def execute(self, sql, params=()):
        return self.conn().execute(sql, params)

    def query(self, sql, params=()):
        return self.conn().execute(sql, params).fetchall()

    def query_one(self, sql, params=()):
        return self.conn().execute(sql, params).fetchone()


# ---------------------------------------------------------------------------
# campus-signup provisioner 客户端（只用到 ping / list_users / verify_password）
# ---------------------------------------------------------------------------


class Provisioner(object):
    def __init__(self, socket_path, timeout=10.0):
        self.socket_path = socket_path
        self.timeout = timeout

    def call(self, request):
        if not self.socket_path:
            return {"ok": False, "error": {"code": "INTERNAL", "message": "provisioner 未配置"}}
        payload = (json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8")
        sock = None
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
            sock.sendall(payload)
            buffer = b""
            while b"\n" not in buffer:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > 65536:
                    raise ValueError("响应过长")
            line = buffer.split(b"\n", 1)[0]
            if not line:
                raise ValueError("响应为空")
            response = json.loads(line.decode("utf-8"))
            return response if isinstance(response, dict) else {}
        except (OSError, ValueError, UnicodeDecodeError):
            log("provisioner_error", op=str(request.get("op")))
            return {"ok": False, "error": {"code": "INTERNAL", "message": "账号服务暂不可用"}}
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass

    def verify_password(self, username, password):
        return self.call({"op": "verify_password", "username": username, "password": password})

    def list_users(self):
        return self.call({"op": "list_users"})

    def ping(self):
        return self.call({"op": "ping"})


class MockProvisioner(object):
    """本地/离线 mock：只用于开发与自测，生产绝不启用。"""

    USERS = {
        "alice": {"password": "Passw0rd!23", "real_name": "张一", "uid": 1001},
        "bob": {"password": "Passw0rd!23", "real_name": "李二", "uid": 1002},
        "carol": {"password": "Passw0rd!23", "real_name": "王三", "uid": 1003},
        "dave": {"password": "Passw0rd!23", "real_name": "赵四", "uid": 1004},
        "erin": {"password": "Passw0rd!23", "real_name": "孙五", "uid": 1005},
    }

    def verify_password(self, username, password):
        return self.call({"op": "verify_password", "username": username, "password": password})

    def list_users(self):
        return self.call({"op": "list_users"})

    def ping(self):
        return self.call({"op": "ping"})

    def call(self, request):
        op = request.get("op")
        if op == "ping":
            return {"ok": True}
        if op == "list_users":
            users = []
            for name in sorted(self.USERS):
                info = self.USERS[name]
                users.append(
                    {
                        "username": name,
                        "uid": info["uid"],
                        "gid": info["uid"],
                        "home": "/home/%s" % name,
                        "shell": "/bin/bash",
                        "real_name": info["real_name"],
                        "groups": [name],
                        "privileged": False,
                        "locked": False,
                    }
                )
            return {"ok": True, "users": users}
        if op == "verify_password":
            username = str(request.get("username") or "")
            password = str(request.get("password") or "")
            info = self.USERS.get(username)
            if info is None:
                return {"ok": True, "exists": False, "manageable": False, "locked": False}
            matched = hmac.compare_digest(password.encode("utf-8"), info["password"].encode("utf-8"))
            return {"ok": True, "exists": True, "manageable": matched, "locked": False}
        return {"ok": False, "error": {"code": "INVALID", "message": "mock 不支持该操作"}}


# ---------------------------------------------------------------------------
# 用户缓存（姓名 / 状态）
# ---------------------------------------------------------------------------


class UsersCache(object):
    def __init__(self, provisioner, refresh_seconds=600):
        self.provisioner = provisioner
        self.refresh_seconds = refresh_seconds
        self._lock = threading.Lock()
        self._users = {}
        self._last = 0.0
        self._error = None

    def refresh(self, force=False):
        with self._lock:
            if not force and time.time() - self._last < self.refresh_seconds and self._users:
                return
        response = self.provisioner.list_users()
        users = {}
        if response.get("ok") and isinstance(response.get("users"), list):
            for item in response["users"]:
                if not isinstance(item, dict):
                    continue
                username = str(item.get("username") or "").strip()
                if not USERNAME_RE.match(username):
                    continue
                raw_name = str(item.get("real_name") or "").strip()
                gecos_first = raw_name.split(",")[0].strip()
                real_name = "".join(ch for ch in gecos_first if ch.isprintable())[:40]
                users[username] = {
                    "username": username,
                    "real_name": real_name or username,
                    "uid": item.get("uid"),
                    "locked": bool(item.get("locked")),
                    "privileged": bool(item.get("privileged")),
                }
            with self._lock:
                self._users = users
                self._last = time.time()
                self._error = None
            log("users_refreshed", count=len(users))
        else:
            with self._lock:
                self._error = "provisioner 不可用"
            log("users_refresh_failed")
        if not users and not self._users:
            with self._lock:
                self._users = {}

    def get(self, username):
        with self._lock:
            return self._users.get(username)

    def real_name(self, username):
        user = self.get(username)
        return user["real_name"] if user else ""

    def all(self):
        with self._lock:
            return [dict(self._users[name]) for name in sorted(self._users)]


# ---------------------------------------------------------------------------
# GPU 采集
# ---------------------------------------------------------------------------

GPU_FIELDS = "index,uuid,name,memory.used,memory.total,utilization.gpu,temperature.gpu,power.draw"


def run_command(args, timeout=15):
    env = dict(os.environ)
    env["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    return subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, env=env, check=False
    )


class Collector(threading.Thread):
    def __init__(self, app):
        threading.Thread.__init__(self, name="collector", daemon=True)
        self.app = app
        self._lock = threading.Lock()
        self._state = {
            "ts": 0,
            "gpus": [],
            "load": [0.0, 0.0, 0.0],
            "uptime_s": 0,
            "host": socket.gethostname(),
            "error": None,
        }
        self._last_persist = 0
        self._collect_count = 0

    def snapshot(self):
        with self._lock:
            return json.loads(json.dumps(self._state))

    def run(self):
        while not self.app.stopping:
            try:
                self.collect_once()
            except Exception:
                detail = traceback.format_exc(limit=2).replace("\n", " ")[:300]
                log("collector_error", detail=detail)
                with self._lock:
                    self._state["error"] = "采集失败，请查看服务日志"
            time.sleep(self.app.cfg["sample_interval"])

    def collect_once(self):
        started = time.time()
        snapshot = self.read_snapshot() if not self.app.mock else self.mock_snapshot()
        took_ms = int((time.time() - started) * 1000)
        self._collect_count += 1
        if self._collect_count <= 2 or took_ms > 1500:
            log("collect_timing", n=self._collect_count, ms=took_ms)
        snapshot["ts"] = now_ts()
        with self._lock:
            self._state = snapshot
        # 历史采样（按 history_interval 去重写库，用于卡时统计）
        bucket = int(time.time() // self.app.cfg["history_interval"]) * self.app.cfg["history_interval"]
        if bucket != self._last_persist:
            self._last_persist = bucket
            rows = []
            for gpu in snapshot.get("gpus", []):
                users = {p.get("user") for p in gpu.get("procs", []) if p.get("user")}
                for username in users:
                    rows.append((bucket, gpu.get("index"), username))
            if rows:
                try:
                    self.app.db.conn().executemany(
                        "INSERT OR IGNORE INTO proc_samples(ts, gpu, username) VALUES(?,?,?)",
                        rows,
                    )
                except sqlite3.Error:
                    log("persist_error", detail="proc_samples")

    # -- 真实采集 ---------------------------------------------------------
    def read_snapshot(self):
        gpu_proc = run_command(
            ["nvidia-smi", "--query-gpu=" + GPU_FIELDS, "--format=csv,noheader,nounits"]
        )
        if gpu_proc.returncode != 0:
            raise RuntimeError("nvidia-smi 不可用: " + (gpu_proc.stderr or "")[:120])
        gpus = []
        uuid_to_index = {}
        for line in gpu_proc.stdout.strip().splitlines():
            fields = [x.strip() for x in next(csv.reader([line]))]
            if len(fields) < 8:
                continue
            index = clamp_int(fields[0], 0, 64, 0)
            uuid = fields[1]
            uuid_to_index[uuid] = index
            gpus.append(
                {
                    "index": index,
                    "name": fields[2],
                    "mem_used": clamp_int(fields[3], 0, 10 ** 7, 0),
                    "mem_total": clamp_int(fields[4], 0, 10 ** 7, 0),
                    "util": clamp_int(fields[5], 0, 100, 0),
                    "temp": clamp_int(fields[6], -50, 200, 0) if fields[6] != "[N/A]" else None,
                    "power": fields[7] if fields[7] != "[N/A]" else None,
                    "procs": [],
                }
            )
        gpus.sort(key=lambda item: item["index"])
        by_index = {item["index"]: item for item in gpus}
        proc_proc = run_command(
            ["nvidia-smi", "--query-compute-apps=pid,used_memory,gpu_uuid", "--format=csv,noheader,nounits"]
        )
        app_rows = []
        for line in proc_proc.stdout.strip().splitlines():
            fields = [x.strip() for x in next(csv.reader([line]))]
            if len(fields) < 3:
                continue
            pid = clamp_int(fields[0], 0, 10 ** 9, 0)
            index = uuid_to_index.get(fields[2])
            if index is None or index not in by_index or not pid:
                continue
            app_rows.append((pid, index, clamp_int(fields[1], 0, 10 ** 7, 0)))
        self._attach_processes(gpus, by_index, app_rows)
        return {
            "gpus": gpus,
            "load": list(os.getloadavg()),
            "uptime_s": self._uptime(),
            "host": socket.gethostname(),
            "error": None,
        }

    def _attach_processes(self, gpus, by_index, app_rows):
        if not app_rows:
            return
        pids = sorted({row[0] for row in app_rows})
        proc_info = {}
        chunks = [pids[i : i + 40] for i in range(0, len(pids), 40)]
        for chunk in chunks:
            result = run_command(
                ["ps", "-o", "pid=,uid=,etime=,args=", "-p", ",".join(str(p) for p in chunk)]
            )
            if result.returncode != 0:
                continue
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 3)
                if len(parts) < 3:
                    continue
                pid = clamp_int(parts[0], 0, 10 ** 9, 0)
                if not pid:
                    continue
                uid = clamp_int(parts[1], 0, 10 ** 9, 0)
                args_text = parts[3] if len(parts) > 3 else ""
                proc_info[pid] = {
                    "pid": pid,
                    "user": self._username_of(uid),
                    "elapsed": parts[2],
                    "etime_s": etime_to_seconds(parts[2]),
                    "cmd": args_text[:120],
                }
        for pid, index, mem in app_rows:
            info = proc_info.get(pid)
            if not info:
                continue
            gpu = by_index.get(index)
            if not gpu:
                continue
            user = info["user"]
            gpu["procs"].append(
                {
                    "pid": pid,
                    "user": user,
                    "real_name": self.app.users.real_name(user) or user,
                    "elapsed": info["elapsed"],
                    "etime_s": info["etime_s"],
                    "cmd": info["cmd"],
                    "mem": mem,
                }
            )
        for gpu in gpus:
            gpu["procs"].sort(key=lambda item: item["etime_s"], reverse=True)

    @staticmethod
    def _username_of(uid):
        try:
            return pwd.getpwuid(uid).pw_name
        except (KeyError, OSError):
            return str(uid)

    def _uptime(self):
        try:
            with open("/proc/uptime", "r", encoding="utf-8") as handle:
                return int(float(handle.read().split()[0]))
        except (OSError, ValueError):
            return 0

    # -- mock 数据（仅开发/截图用） --------------------------------------
    def mock_snapshot(self):
        seed = int(time.time() // 30)
        gpus = []
        mock_jobs = [
            (0, "alice", "张一", "python -u pre_experiment_thinking.py --input_file data/Advbench.parquet", 51 * 1024, 5 * 3600 + 4 * 60, 98, 59),
            (1, "alice", "张一", "python -u pre_experiment_thinking.py --input_file data/Advbench.parquet", 79 * 1024, 8 * 3600 + 16 * 60, 99, 60),
            (2, "bob", "李二", "python -B -u resume_worker.py --config configs/qwen3vl.yaml", 56 * 1024, 6 * 86400 + 4 * 3600 + 54 * 60, 96, 57),
            (4, "carol", "王三", "python -u train.py --config-name train_prot05_s_a gpu_id=0", 10 * 1024, 26 * 3600, 100, 62),
            (4, "carol", "王三", "python -u train.py --config-name train_prot05_s_repa gpu_id=0", 9 * 1024, 25 * 3600, 100, 62),
            (5, "bob", "李二", "python -m vllm.entrypoints.openai.api_server --model Qwen2.5-72B", 66 * 1024, 5 * 3600 + 50 * 60, 0, 44),
            (6, "alice", "张一", "python -u pre_experiment_thinking.py --input_file data/Advbench.parquet", 54 * 1024, 9 * 3600 + 10 * 60, 96, 59),
            (7, "dave", "赵四", "python -u experiments/information_anchor/interventions.py", 12 * 1024, 10 * 60, 100, 63),
            (7, "carol", "王三", "python -u train_salad_dual_pair.py --scalers runs/probe_01", 21 * 1024, 3 * 3600, 100, 63),
        ]
        by_index = {}
        for index in range(8):
            by_index[index] = {
                "index": index,
                "name": "NVIDIA A100-SXM4-80GB",
                "mem_used": 0,
                "mem_total": 81920,
                "util": 0,
                "temp": 32,
                "power": "58",
                "procs": [],
            }
        for index, user, real_name, cmd, mem, etime_s, util, temp in mock_jobs:
            gpu = by_index[index]
            gpu["mem_used"] += mem
            gpu["util"] = max(gpu["util"], util)
            gpu["temp"] = max(gpu["temp"], temp)
            gpu["procs"].append(
                {
                    "pid": 1000 + index * 10 + len(gpu["procs"]),
                    "user": user,
                    "real_name": real_name,
                    "elapsed": fmt_duration(etime_s),
                    "etime_s": etime_s,
                    "cmd": cmd[:120],
                    "mem": mem,
                }
            )
        for index, gpu in by_index.items():
            if gpu["mem_used"] == 0:
                gpu["util"] = 0
            else:
                gpu["util"] = max(0, min(100, gpu["util"] + ((seed + index) % 3) - 1))
            gpus.append(gpu)
        gpus.sort(key=lambda item: item["index"])
        return {
            "gpus": gpus,
            "load": [24.7, 25.7, 26.3],
            "uptime_s": 25 * 86400 + 15 * 3600,
            "host": "star1",
            "error": None,
        }


# ---------------------------------------------------------------------------
# 应用
# ---------------------------------------------------------------------------


class App(object):
    def __init__(self, cfg, mock=False):
        self.cfg = cfg
        self.mock = mock
        self.stopping = False
        self.db = Database(cfg["db"])
        self.campus = {} if mock else (load_json(cfg.get("campus_config")) or {})
        self.mock_admin_token = "mock-admin-token"
        if mock:
            self.provisioner = MockProvisioner()
        else:
            prov_cfg = self.campus.get("provisioner") or {}
            self.provisioner = Provisioner(
                prov_cfg.get("socket"), timeout=min(15.0, float(prov_cfg.get("timeout_seconds") or 15))
            )
        self.users = UsersCache(self.provisioner)
        self.collector = Collector(self)
        self.booking_lock = threading.Lock()
        self.tls = bool(cfg.get("tls")) and not mock
        self.tls_cert = ""
        self.tls_key = ""
        self.admin_allowed_cidrs = []
        self._load_campus_security()

    def _load_campus_security(self):
        campus = self.campus if not self.mock else {}
        tls_cfg = campus.get("tls") or {}
        if self.tls:
            self.tls_cert = self.cfg.get("tls_cert") or tls_cfg.get("cert") or ""
            self.tls_key = self.cfg.get("tls_key") or tls_cfg.get("key") or ""
        security = campus.get("security") or {}
        self.admin_allowed_cidrs = security.get("admin_allowed_cidrs") or []

    def admin_token(self):
        if self.mock:
            return self.mock_admin_token
        # 每次管理员登录时重新读取，便于门户轮换 token 后无需重启本服务
        campus = load_json(self.cfg.get("campus_config")) or {}
        return str((campus.get("security") or {}).get("admin_token") or "")

    def admin_cidrs(self):
        if self.mock:
            return ["127.0.0.1/32", "10.0.0.0/8", "::1/128"]
        campus = load_json(self.cfg.get("campus_config")) or {}
        return (campus.get("security") or {}).get("admin_allowed_cidrs") or []

    # -- 会话 -----------------------------------------------------------
    def create_session(self, role, username, real_name, ttl, ip):
        token = secrets.token_urlsafe(32)
        ts = now_ts()
        self.db.execute(
            "INSERT INTO sessions(token, role, username, real_name, created_ts, expires_ts, ip)"
            " VALUES(?,?,?,?,?,?,?)",
            (token, role, username or "", real_name or "", ts, ts + int(ttl), ip or ""),
        )
        return token

    def get_session(self, token):
        if not token:
            return None
        row = self.db.query_one(
            "SELECT role, username, real_name, expires_ts FROM sessions WHERE token=?",
            (token,),
        )
        if not row:
            return None
        if row["expires_ts"] <= now_ts():
            self.db.execute("DELETE FROM sessions WHERE token=?", (token,))
            return None
        return {
            "role": row["role"],
            "username": row["username"],
            "real_name": row["real_name"],
            "via": "session",
        }

    def delete_session(self, token):
        if token:
            self.db.execute("DELETE FROM sessions WHERE token=?", (token,))

    # -- 登录限流 -------------------------------------------------------
    def login_failure_state(self, ip, username):
        ts = now_ts()
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM login_fails WHERE ip=? AND username=? AND ts>?",
            (ip, username, ts - int(self.cfg["login_lock_seconds"])),
        )
        if row and row["n"] >= int(self.cfg["login_max_failures"]):
            return "user"
        row = self.db.query_one(
            "SELECT COUNT(*) AS n FROM login_fails WHERE ip=? AND ts>?",
            (ip, ts - int(self.cfg["login_ip_window_seconds"])),
        )
        if row and row["n"] >= int(self.cfg["login_ip_max_failures"]):
            return "ip"
        return None

    def record_login_failure(self, ip, username):
        self.db.execute(
            "INSERT INTO login_fails(ip, username, ts) VALUES(?,?,?)", (ip, username, now_ts())
        )

    def clear_login_failures(self, ip, username):
        self.db.execute("DELETE FROM login_fails WHERE ip=? AND username=?", (ip, username))

    # -- 预约 -----------------------------------------------------------
    def bookings_between(self, start_ts, end_ts, include_cancelled=False):
        sql = (
            "SELECT id, gpu, username, real_name, start_ts, end_ts, purpose, created_ts,"
            " created_by, status FROM bookings WHERE end_ts>? AND start_ts<?"
        )
        params = [start_ts, end_ts]
        if not include_cancelled:
            sql += " AND status='active'"
        sql += " ORDER BY start_ts, gpu"
        return [dict(row) for row in self.db.query(sql, params)]

    def overlapping_bookings(self, gpu, start_ts, end_ts, status="active", username=None):
        sql = (
            "SELECT id, gpu, username, start_ts, end_ts FROM bookings"
            " WHERE status=? AND start_ts<? AND end_ts>?"
        )
        params = [status, end_ts, start_ts]
        if gpu is not None:
            sql += " AND gpu=?"
            params.append(gpu)
        if username is not None:
            sql += " AND username=?"
            params.append(username)
        sql += " ORDER BY start_ts"
        return [dict(row) for row in self.db.query(sql, params)]

    def create_booking(self, actor_username, actor_role, username, gpu, start_ts, end_ts, purpose):
        """返回 (ok, payload)。所有检查在 booking_lock 内完成，避免并发抢同一时段。"""
        cfg = self.cfg
        if not USERNAME_RE.match(username):
            return False, ("INVALID_USERNAME", "用户名不合法")
        if not self.users.all():
            return False, ("USERS_UNAVAILABLE", "用户列表暂不可用，请稍后再试（provisioner 未就绪）")
        user = self.users.get(username)
        if not user:
            return False, ("USER_MISSING", "该账号不在可预约用户列表中")
        if user.get("locked"):
            return False, ("USER_LOCKED", "该账号已被锁定，无法预约")
        if user.get("privileged"):
            return False, ("USER_PRIVILEGED", "该账号为特权账号，请勿用于预约")
        ts = now_ts()
        min_seconds = int(cfg["min_booking_minutes"]) * 60
        max_seconds = int(cfg["max_booking_hours"]) * 3600
        if not isinstance(start_ts, int) or not isinstance(end_ts, int):
            return False, ("INVALID_TIME", "时间格式不正确")
        if end_ts <= start_ts:
            return False, ("INVALID_TIME", "结束时间必须晚于开始时间")
        duration = end_ts - start_ts
        if duration < min_seconds:
            return False, ("INVALID_TIME", "预约时长至少 %d 分钟" % int(cfg["min_booking_minutes"]))
        if duration > max_seconds:
            return False, ("INVALID_TIME", "单次预约不能超过 %d 小时" % int(cfg["max_booking_hours"]))
        if start_ts < ts - 300:
            return False, ("INVALID_TIME", "开始时间不能早于当前时间")
        if start_ts > ts + int(cfg["max_booking_days_ahead"]) * 86400:
            return False, ("INVALID_TIME", "最多提前 %d 天预约" % int(cfg["max_booking_days_ahead"]))
        purpose = (purpose or "").strip()
        if not purpose:
            return False, ("INVALID_PURPOSE", "请填写用途")
        if len(purpose) > 120 or CONTROL_RE.search(purpose):
            return False, ("INVALID_PURPOSE", "用途最多 120 个字符，且不能包含控制字符")
        if gpu not in (None, -1):
            try:
                gpu = int(gpu)
            except (TypeError, ValueError):
                return False, ("INVALID_GPU", "显卡编号不合法")
            if gpu < 0 or gpu > 31:
                return False, ("INVALID_GPU", "显卡编号不合法")
        with self.booking_lock:
            # 同一用户此时段不能重复预约（不同卡也不行）
            own = self.overlapping_bookings(None, start_ts, end_ts, username=username)
            if own:
                return False, ("DUPLICATE", "你在该时段已有预约（GPU %d）" % own[0]["gpu"])
            future = self.db.query_one(
                "SELECT COUNT(*) AS n FROM bookings WHERE status='active' AND username=?"
                " AND end_ts>?",
                (username, ts),
            )
            if future and future["n"] >= int(cfg["max_future_bookings_per_user"]):
                return False, (
                    "TOO_MANY_BOOKINGS",
                    "你已有 %d 个未结束的预约，请先取消再约" % int(cfg["max_future_bookings_per_user"]),
                )
            target_gpu = None
            if gpu in (None, -1):
                # 自动分配：优先当前空闲且该时段未被预约的卡
                snapshot = self.collector.snapshot()
                busy = {
                    item["index"]
                    for item in snapshot.get("gpus", [])
                    if item.get("procs") or item.get("util")
                }
                candidates = list(range(len(snapshot.get("gpus", [])) or 8))
                candidates.sort(key=lambda idx: (idx in busy, idx))
                for idx in candidates:
                    if not self.overlapping_bookings(idx, start_ts, end_ts):
                        target_gpu = idx
                        break
                if target_gpu is None:
                    return False, ("NO_FREE_GPU", "该时段没有空闲显卡，请换一个时间段")
            else:
                target_gpu = gpu
                conflicts = self.overlapping_bookings(target_gpu, start_ts, end_ts)
                if conflicts:
                    first = conflicts[0]
                    return False, (
                        "TIME_CONFLICT",
                        "GPU %d 在该时段已被预约（%s，%s）"
                        % (target_gpu, fmt_duration_short(first["start_ts"], first["end_ts"]), first["username"]),
                    )
            real_name = user.get("real_name") or username
            cursor = self.db.execute(
                "INSERT INTO bookings(gpu, username, real_name, start_ts, end_ts, purpose,"
                " created_ts, created_by, status) VALUES(?,?,?,?,?,?,?,?, 'active')",
                (target_gpu, username, real_name, start_ts, end_ts, purpose, ts, actor_username),
            )
            booking_id = cursor.lastrowid
            log(
                "booking_created",
                id=booking_id,
                gpu=target_gpu,
                user=username,
                by=actor_username,
                start=start_ts,
                end=end_ts,
            )
            return True, {
                "id": booking_id,
                "gpu": target_gpu,
                "username": username,
                "real_name": real_name,
                "start_ts": start_ts,
                "end_ts": end_ts,
                "purpose": purpose,
                "status": "active",
            }

    def cancel_booking(self, booking_id, actor_username, actor_role):
        with self.booking_lock:
            row = self.db.query_one("SELECT * FROM bookings WHERE id=?", (booking_id,))
            if not row:
                return False, ("NOT_FOUND", "预约不存在")
            if row["status"] != "active":
                return False, ("NOT_ACTIVE", "该预约已取消或已结束")
            if actor_role != "admin" and row["username"] != actor_username:
                return False, ("FORBIDDEN", "只能取消自己的预约")
            self.db.execute("UPDATE bookings SET status='cancelled' WHERE id=?", (booking_id,))
            log("booking_cancelled", id=booking_id, user=row["username"], by=actor_username)
            return True, {"id": booking_id, "status": "cancelled"}

    # -- API token（给 agent / MCP 用） --------------------------------
    def create_api_token(self, username, name):
        rows = self.db.query(
            "SELECT COUNT(*) AS n FROM api_tokens WHERE username=? AND revoked=0",
            (username,),
        )
        if rows and rows[0]["n"] >= 8:
            return None, ("TOO_MANY_TOKENS", "每人最多保留 8 个有效 token，请先撤销旧的")
        token = "sgb_" + secrets.token_urlsafe(30)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        cursor = self.db.execute(
            "INSERT INTO api_tokens(username, name, token_hash, prefix, created_ts)"
            " VALUES(?,?,?,?,?)",
            (username, name, token_hash, token[:12], now_ts()),
        )
        log("token_created", user=username, token_id=cursor.lastrowid, name=name)
        return {
            "id": cursor.lastrowid,
            "username": username,
            "name": name,
            "token": token,
            "prefix": token[:12],
            "created_ts": now_ts(),
        }, None

    def list_api_tokens(self, username):
        rows = self.db.query(
            "SELECT id, name, prefix, created_ts, last_used_ts FROM api_tokens"
            " WHERE username=? AND revoked=0 ORDER BY id DESC",
            (username,),
        )
        return [dict(row) for row in rows]

    def revoke_api_token(self, username, token_id):
        cursor = self.db.execute(
            "UPDATE api_tokens SET revoked=1 WHERE id=? AND username=? AND revoked=0",
            (token_id, username),
        )
        if cursor.rowcount:
            log("token_revoked", user=username, token_id=token_id)
            return True
        return False

    def auth_api_token(self, token):
        if not token or not token.startswith("sgb_") or len(token) > 80:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        row = self.db.query_one(
            "SELECT id, username, last_used_ts FROM api_tokens WHERE token_hash=? AND revoked=0",
            (digest,),
        )
        if not row:
            return None
        ts = now_ts()
        if not row["last_used_ts"] or ts - row["last_used_ts"] > 60:
            self.db.execute("UPDATE api_tokens SET last_used_ts=? WHERE id=?", (ts, row["id"]))
        user = self.users.get(row["username"]) or {}
        return {
            "role": "user",
            "username": row["username"],
            "real_name": user.get("real_name") or row["username"],
            "via": "token",
        }

    # -- 后台维护 -------------------------------------------------------
    def start_background(self):
        self.collector.start()
        threading.Thread(target=self._maintenance_loop, name="maintenance", daemon=True).start()
        threading.Thread(target=self._users_loop, name="users", daemon=True).start()

    def _users_loop(self):
        self.users.refresh(force=True)
        while not self.stopping:
            time.sleep(60)
            try:
                self.users.refresh()
            except Exception:
                log("users_loop_error")

    def _maintenance_loop(self):
        while not self.stopping:
            try:
                ts = now_ts()
                self.db.execute("DELETE FROM sessions WHERE expires_ts<=?", (ts,))
                self.db.execute("DELETE FROM login_fails WHERE ts<?", (ts - 7 * 86400,))
                self.db.execute(
                    "DELETE FROM proc_samples WHERE ts<?",
                    (ts - int(self.cfg["retention_days"]) * 86400,),
                )
            except sqlite3.Error:
                log("maintenance_error")
            time.sleep(1800)


def fmt_duration_short(start_ts, end_ts):
    def hm(ts_value):
        return datetime.fromtimestamp(ts_value, CN_TZ).strftime("%H:%M")

    return "%s-%s" % (hm(start_ts), hm(end_ts))


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------

class BoardServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, app):
        self.app = app
        if ":" in address[0]:
            self.address_family = socket.AF_INET6
        ThreadingHTTPServer.__init__(self, address, handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "star1-gpu-board/" + VERSION
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        # 访问日志交给显式事件日志，避免噪音
        return

    # -- 工具 -----------------------------------------------------------
    @property
    def app(self):
        return self.server.app

    def client_ip(self):
        try:
            return self.client_address[0]
        except (IndexError, TypeError):
            return ""

    def _session_token(self):
        cookie = self.headers.get("Cookie") or ""
        match = re.search(r"(?:^|;\s*)" + COOKIE_NAME + r"=([A-Za-z0-9_\-]+)", cookie)
        return match.group(1) if match else None

    def _session(self):
        return self.app.get_session(self._session_token())

    def _send(self, code, body, content_type="application/json; charset=utf-8", headers=None):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in SECURITY_HEADERS:
            self.send_header(key, value)
        for key, value in headers or []:
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def send_json(self, code, payload, headers=None):
        self._send(
            code,
            json.dumps(payload, ensure_ascii=False),
            "application/json; charset=utf-8",
            headers=headers,
        )

    def error(self, message, http_status=400, error_code=None):
        self.send_json(
            http_status,
            {"ok": False, "error": {"code": error_code or ("HTTP_%d" % http_status), "message": message}},
        )

    def read_json_body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if length <= 0 or length > 16384:
            return None
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def set_cookie(self, token, max_age):
        flags = "Path=/; Max-Age=%d; HttpOnly; SameSite=Lax" % int(max_age)
        if self.app.tls:
            flags += "; Secure"
        self._cookies = getattr(self, "_cookies", [])
        self._cookies.append(("%s=%s; %s" % (COOKIE_NAME, token, flags)))
        return self._cookies

    def cookie_headers(self):
        cookies = getattr(self, "_cookies", None)
        if not cookies:
            return []
        return [("Set-Cookie", cookie) for cookie in cookies]

    def clear_cookie(self):
        self._cookies = []
        flags = "Path=/; Max-Age=0; HttpOnly; SameSite=Lax"
        if self.app.tls:
            flags += "; Secure"
        self._cookies.append(("%s=deleted; %s" % (COOKIE_NAME, flags)))

    # -- 路由 -----------------------------------------------------------
    def do_GET(self):
        self._cookies = []
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if path == "/":
                return self.serve_static("index.html")
            if path == "/admin":
                return self.serve_static("admin.html")
            if path.startswith("/static/"):
                return self.serve_static(path[len("/static/"):])
            if path == "/healthz":
                return self.send_json(200, {"ok": True, "version": VERSION, "ts": now_ts()})
            if path == "/api/state":
                return self.send_json(200, self.build_state())
            if path == "/api/me":
                session = self._auth()
                return self.send_json(200, {"ok": True, "me": session})
            if path == "/api/usage":
                query = parse_qs(parsed.query)
                days = clamp_int((query.get("days") or ["7"])[0], 1, 90, 7)
                return self.send_json(200, self.build_usage(days))
            if path == "/api/tokens":
                session = self._require_cookie_session()
                if session is None:
                    return
                return self.send_json(
                    200, {"ok": True, "tokens": self.app.list_api_tokens(session["username"])}
                )
            if path == "/api/admin/overview":
                session = self._require_admin()
                if session is None:
                    return
                query = parse_qs(parsed.query)
                days = clamp_int((query.get("days") or ["30"])[0], 1, 90, 30)
                return self.send_json(200, self.build_admin_overview(days))
            if path == "/api/admin/users":
                session = self._require_admin()
                if session is None:
                    return
                self.app.users.refresh(force=True)
                return self.send_json(
                    200, {"ok": True, "users": self.app.users.all(), "ts": now_ts()}
                )
            return self.error("页面不存在", 404, error_code="NOT_FOUND")
        except Exception:
            log("handler_error", detail=traceback.format_exc(limit=2).replace("\n", " ")[:300])
            return self.error("服务器内部错误", 500, error_code="INTERNAL")

    def do_POST(self):
        self._cookies = []
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            if (self.headers.get("X-Requested-With") or "") != API_HEADER:
                return self.error("请求缺少必要标记", 403, error_code="BAD_REQUEST")
            content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip()
            if content_type != "application/json":
                return self.error("请求格式不正确", 403, error_code="BAD_REQUEST")
            if path == "/api/login":
                return self.handle_login()
            if path == "/api/logout":
                return self.handle_logout()
            if path == "/api/tokens":
                return self.handle_create_token()
            if path == "/api/tokens/revoke":
                return self.handle_revoke_token()
            if path == "/api/bookings":
                return self.handle_create_booking()
            if path == "/api/bookings/cancel":
                return self.handle_cancel_booking()
            if path == "/api/admin/login":
                return self.handle_admin_login()
            if path == "/api/admin/bookings":
                return self.handle_admin_create_booking()
            if path == "/api/admin/cancel":
                return self.handle_admin_cancel()
            return self.error("接口不存在", 404, error_code="NOT_FOUND")
        except Exception:
            log("handler_error", detail=traceback.format_exc(limit=2).replace("\n", " ")[:300])
            return self.error("服务器内部错误", 500, error_code="INTERNAL")

    # -- 静态文件 -------------------------------------------------------
    def serve_static(self, name):
        if name not in STATIC_FILES:
            return self.error("页面不存在", 404, error_code="NOT_FOUND")
        base = os.path.realpath(self.app.cfg["static"])
        target = os.path.realpath(os.path.join(base, name))
        if not target.startswith(base + os.sep):
            return self.error("页面不存在", 404, error_code="NOT_FOUND")
        try:
            with open(target, "rb") as handle:
                body = handle.read()
        except OSError:
            return self.error("页面不存在", 404, error_code="NOT_FOUND")
        self._send(200, body, STATIC_FILES[name], headers=[("Cache-Control", "no-cache")])

    # -- 业务数据 -------------------------------------------------------
    def build_state(self):
        app = self.app
        snapshot = app.collector.snapshot()
        ts = now_ts()
        bookings = app.bookings_between(ts - 6 * 3600, ts + 36 * 3600)
        by_gpu = {}
        for booking in bookings:
            by_gpu.setdefault(booking["gpu"], []).append(booking)
        summary = {"free": 0, "busy": 0, "reserved": 0, "unregistered": 0, "conflict": 0}
        for gpu in snapshot.get("gpus", []):
            procs = gpu.get("procs") or []
            current = None
            upcoming = None
            for booking in by_gpu.get(gpu["index"], []):
                if booking["start_ts"] <= ts < booking["end_ts"]:
                    current = booking
                elif booking["start_ts"] > ts and (upcoming is None or booking["start_ts"] < upcoming["start_ts"]):
                    upcoming = booking
            for booking in (current, upcoming):
                if booking:
                    booking["time_label"] = fmt_duration_short(booking["start_ts"], booking["end_ts"])
            gpu["booking"] = current
            gpu["next_booking"] = upcoming
            gpu["unregistered"] = bool(procs) and current is None
            gpu["conflict"] = bool(
                current
                and procs
                and all(proc.get("user") != current["username"] for proc in procs)
            )
            gpu["reserved_only"] = bool(current) and not procs
            if procs:
                summary["busy"] += 1
            elif current:
                summary["reserved"] += 1
            else:
                summary["free"] += 1
            if gpu["unregistered"]:
                summary["unregistered"] += 1
            if gpu["conflict"]:
                summary["conflict"] += 1
        session = self._auth()
        return {
            "ok": True,
            "ts": ts,
            "version": VERSION,
            "host": snapshot.get("host") or "",
            "load": snapshot.get("load") or [],
            "uptime_s": snapshot.get("uptime_s") or 0,
            "error": snapshot.get("error"),
            "gpus": snapshot.get("gpus", []),
            "bookings": bookings,
            "summary": summary,
            "me": session,
            "site_title": app.cfg["site_title"],
            "site_subtitle": app.cfg["site_subtitle"],
            "contact": app.cfg["contact"],
            "limits": {
                "min_minutes": int(app.cfg["min_booking_minutes"]),
                "max_hours": int(app.cfg["max_booking_hours"]),
                "max_days_ahead": int(app.cfg["max_booking_days_ahead"]),
                "max_future_bookings": int(app.cfg["max_future_bookings_per_user"]),
            },
        }

    def build_usage(self, days):
        app = self.app
        since = now_ts() - days * 86400
        rows = app.db.query(
            "SELECT username, COUNT(*) AS n FROM proc_samples WHERE ts>=? GROUP BY username",
            (since,),
        )
        interval = int(app.cfg["history_interval"])
        total = 0.0
        users = []
        for row in rows:
            hours = float(row["n"]) * interval / 3600.0
            total += hours
            users.append(
                {
                    "username": row["username"],
                    "real_name": app.users.real_name(row["username"]) or row["username"],
                    "hours": round(hours, 1),
                }
            )
        users.sort(key=lambda item: item["hours"], reverse=True)
        for item in users:
            item["percent"] = round(item["hours"] / total * 100, 1) if total else 0.0
        return {
            "ok": True,
            "days": days,
            "interval_seconds": interval,
            "total_hours": round(total, 1),
            "users": users,
            "ts": now_ts(),
        }

    def build_admin_overview(self, days):
        ts = now_ts()
        bookings = self.app.bookings_between(ts - 86400, ts + 7 * 86400)
        usage = self.build_usage(days)
        sessions = self.app.db.query_one(
            "SELECT COUNT(*) AS n FROM sessions WHERE expires_ts>?", (ts,)
        )
        return {
            "ok": True,
            "ts": ts,
            "bookings": bookings,
            "usage": usage,
            "active_sessions": sessions["n"] if sessions else 0,
            "users": self.app.users.all(),
        }

    # -- 登录 / 退出 ----------------------------------------------------
    def handle_login(self):
        app = self.app
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        username = str(body.get("username") or "").strip().lower()
        password = str(body.get("password") or "")
        ip = self.client_ip()
        if not USERNAME_RE.match(username) or not password or len(password) > 256:
            return self.error("用户名或密码错误", 401, error_code="INVALID_CREDENTIALS")
        locked = app.login_failure_state(ip, username)
        if locked:
            return self.error("尝试次数过多，请 15 分钟后再试", 429, error_code="RATE_LIMITED")
        response = app.provisioner.verify_password(username, password)
        if not response.get("ok"):
            return self.error("账号服务暂不可用，请稍后再试", 503, error_code="PROVISIONER_UNAVAILABLE")
        manageable = bool(response.get("manageable"))
        locked_account = bool(response.get("locked"))
        if not manageable:
            app.record_login_failure(ip, username)
            log("login_failed", user=username, ip=ip)
            return self.error("用户名或密码错误，或账号不可用", 401, error_code="INVALID_CREDENTIALS")
        if locked_account:
            return self.error("该账号已被锁定，请联系管理员", 403, error_code="USER_LOCKED")
        app.clear_login_failures(ip, username)
        user = app.users.get(username)
        real_name = (user or {}).get("real_name") or username
        ttl = int(app.cfg["session_ttl"])
        token = app.create_session("user", username, real_name, ttl, ip)
        log("login_ok", user=username, ip=ip)
        self.set_cookie(token, ttl)
        return self.send_json(
            200,
            {"ok": True, "me": {"role": "user", "username": username, "real_name": real_name, "via": "session"}},
            headers=self.cookie_headers(),
        )

    def _cookie_flags(self, max_age):
        flags = "Path=/; Max-Age=%d; HttpOnly; SameSite=Lax" % int(max_age)
        if self.app.tls:
            flags += "; Secure"
        return flags

    def handle_logout(self):
        session = self._session()
        if session:
            log("logout", user=session.get("username") or session.get("role"))
        self.app.delete_session(self._session_token())
        self.clear_cookie()
        return self.send_json(200, {"ok": True}, headers=self.cookie_headers())

    def handle_admin_login(self):
        app = self.app
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        token = str(body.get("token") or "")
        ip = self.client_ip()
        cidrs = app.admin_cidrs()
        if not ip_allowed(ip, cidrs):
            log("admin_login_denied_cidr", ip=ip)
            return self.error("当前网络不允许管理员登录", 403, error_code="FORBIDDEN")
        locked = app.login_failure_state(ip, "__admin__")
        if locked:
            return self.error("尝试次数过多，请 15 分钟后再试", 429, error_code="RATE_LIMITED")
        expected = app.admin_token()
        if not expected:
            return self.error("管理员口令未配置", 503, error_code="ADMIN_DISABLED")
        if not hmac.compare_digest(token.encode("utf-8"), expected.encode("utf-8")):
            app.record_login_failure(ip, "__admin__")
            log("admin_login_failed", ip=ip)
            return self.error("管理员口令错误", 401, error_code="INVALID_CREDENTIALS")
        ttl = int(app.cfg["admin_session_ttl"])
        session_token = app.create_session("admin", "admin", "管理员", ttl, ip)
        log("admin_login_ok", ip=ip)
        self.set_cookie(session_token, ttl)
        return self.send_json(
            200,
            {"ok": True, "me": {"role": "admin", "username": "admin", "real_name": "管理员"}},
            headers=self.cookie_headers(),
        )

    def _auth(self):
        """优先 Cookie 会话；其次 Authorization: Bearer <api token>。"""
        session = self._session()
        if session is not None:
            return session
        header = self.headers.get("Authorization") or ""
        if header.lower().startswith("bearer "):
            token = header[7:].strip()
            return self.app.auth_api_token(token)
        return None

    def _require_session(self):
        session = self._auth()
        if session is None:
            self.error("请先登录（或提供有效的 Bearer token）", 401, error_code="UNAUTHORIZED")
            return None
        return session

    def _require_cookie_session(self):
        """token 管理只允许浏览器 Cookie 会话，避免被盗 token 自我续期。"""
        session = self._session()
        if session is None:
            self.error("请先在网页登录", 401, error_code="UNAUTHORIZED")
            return None
        return session

    def _require_admin(self):
        session = self._session()
        if session is None:
            self.error("请先登录", 401, error_code="UNAUTHORIZED")
            return None
        if session.get("role") != "admin":
            self.error("需要管理员权限", 403, error_code="FORBIDDEN")
            return None
        return session

    # -- token 管理 -----------------------------------------------------
    def handle_create_token(self):
        session = self._require_cookie_session()
        if session is None:
            return
        if session.get("role") != "user":
            return self.error("管理员请使用门户 token，不在此创建", 403, error_code="FORBIDDEN")
        body = self.read_json_body()
        if body is None:
            body = {}
        name = str(body.get("name") or "agent").strip()
        name = "".join(ch for ch in name if ch.isprintable())[:40]
        if not name:
            name = "agent"
        token_info, error = self.app.create_api_token(session["username"], name)
        if error:
            code, message = error
            return self.error(message, 400, error_code=code)
        return self.send_json(
            200,
            {
                "ok": True,
                "token": token_info["token"],
                "id": token_info["id"],
                "name": token_info["name"],
                "prefix": token_info["prefix"],
                "created_ts": token_info["created_ts"],
            },
        )

    def handle_revoke_token(self):
        session = self._require_cookie_session()
        if session is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        try:
            token_id = int(body.get("id"))
        except (TypeError, ValueError):
            return self.error("token 编号不合法", 400, error_code="BAD_REQUEST")
        if not self.app.revoke_api_token(session["username"], token_id):
            return self.error("token 不存在或已撤销", 404, error_code="NOT_FOUND")
        return self.send_json(200, {"ok": True, "id": token_id})

    # -- 预约接口 -------------------------------------------------------
    def _parse_booking_body(self, body):
        start_ts = body.get("start")
        end_ts = body.get("end")
        try:
            start_ts = int(float(start_ts))
            end_ts = int(float(end_ts))
        except (TypeError, ValueError):
            return None
        gpu = body.get("gpu", -1)
        try:
            gpu = int(gpu)
        except (TypeError, ValueError):
            gpu = -1
        purpose = str(body.get("purpose") or "")
        return gpu, start_ts, end_ts, purpose

    def handle_create_booking(self):
        session = self._require_session()
        if session is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        parsed = self._parse_booking_body(body)
        if parsed is None:
            return self.error("时间格式不正确", 400, error_code="INVALID_TIME")
        gpu, start_ts, end_ts, purpose = parsed
        ok, payload = self.app.create_booking(
            session.get("username") or "",
            session.get("role") or "user",
            session.get("username") or "",
            gpu,
            start_ts,
            end_ts,
            purpose,
        )
        if not ok:
            code, message = payload
            status = 409 if code == "TIME_CONFLICT" else (503 if code == "USERS_UNAVAILABLE" else 400)
            return self.error(message, status, error_code=code)
        return self.send_json(200, {"ok": True, "booking": payload})

    def handle_cancel_booking(self):
        session = self._require_session()
        if session is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        try:
            booking_id = int(body.get("id"))
        except (TypeError, ValueError):
            return self.error("预约编号不合法", 400, error_code="BAD_REQUEST")
        ok, payload = self.app.cancel_booking(
            booking_id, session.get("username") or "", session.get("role") or "user"
        )
        if not ok:
            code, message = payload
            return self.error(message, 404 if code == "NOT_FOUND" else 400, error_code=code)
        return self.send_json(200, {"ok": True, "booking": payload})

    def handle_admin_create_booking(self):
        session = self._require_admin()
        if session is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        username = str(body.get("username") or "").strip().lower()
        parsed = self._parse_booking_body(body)
        if parsed is None:
            return self.error("时间格式不正确", 400, error_code="INVALID_TIME")
        gpu, start_ts, end_ts, purpose = parsed
        ok, payload = self.app.create_booking(
            "admin", "admin", username, gpu, start_ts, end_ts, purpose
        )
        if not ok:
            code, message = payload
            return self.error(message, 409 if code == "TIME_CONFLICT" else 400, error_code=code)
        return self.send_json(200, {"ok": True, "booking": payload})

    def handle_admin_cancel(self):
        session = self._require_admin()
        if session is None:
            return
        body = self.read_json_body()
        if body is None:
            return self.error("请求格式不正确", 400, error_code="BAD_REQUEST")
        try:
            booking_id = int(body.get("id"))
        except (TypeError, ValueError):
            return self.error("预约编号不合法", 400, error_code="BAD_REQUEST")
        ok, payload = self.app.cancel_booking(booking_id, "admin", "admin")
        if not ok:
            code, message = payload
            return self.error(message, 404 if code == "NOT_FOUND" else 400, error_code=code)
        return self.send_json(200, {"ok": True, "booking": payload})


# ---------------------------------------------------------------------------
# 启动
# ---------------------------------------------------------------------------


def load_config(path, overrides):
    cfg = dict(DEFAULTS)
    if path:
        data = load_json(path)
        if data:
            for key, value in data.items():
                cfg[key] = value
    for key, value in overrides.items():
        if value is not None:
            cfg[key] = value
    return cfg


def main(argv=None):
    parser = argparse.ArgumentParser(description="star1 GPU 预约台")
    parser.add_argument("--config", help="配置文件路径（默认 /etc/star1-gpu-board/config.json）")
    parser.add_argument("--db")
    parser.add_argument("--static")
    parser.add_argument("--port", type=int)
    parser.add_argument("--bind")
    parser.add_argument("--no-tls", action="store_true")
    parser.add_argument("--mock", action="store_true", help="mock 模式（离线自测/截图）")
    args = parser.parse_args(argv)

    overrides = {
        "db": args.db,
        "static": args.static,
        "port": args.port,
        "bind": args.bind,
    }
    if args.no_tls or args.mock:
        overrides["tls"] = False
    cfg = load_config(args.config, overrides)
    if args.mock:
        cfg["db"] = args.db or "/tmp/star1-gpu-board-mock.db"
        cfg["static"] = args.static or os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    app = App(cfg, mock=args.mock)
    app.start_background()
    # 预热：等第一次 GPU 采样完成再开始监听，避免打开页面先看到空状态
    warmup_deadline = time.time() + 15
    while time.time() < warmup_deadline:
        if app.collector.snapshot().get("gpus"):
            break
        time.sleep(0.1)

    bind = cfg["bind"]
    port = int(cfg["port"])
    httpd = BoardServer((bind, port), Handler, app)
    scheme = "https" if app.tls else "http"
    if app.tls:
        if not app.tls_cert or not app.tls_key:
            print("TLS 已启用但未配置证书路径", file=sys.stderr)
            return 2
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(app.tls_cert, app.tls_key)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    host = socket.gethostname()
    print(
        "star1-gpu-board %s listening on %s://%s:%d/ (host=%s, db=%s)"
        % (VERSION, scheme, bind, port, host, cfg["db"]),
        flush=True,
    )
    if args.mock:
        print("mock 模式：用户 alice/bob/carol/dave/erin，密码 Passw0rd!23；管理员口令 mock-admin-token", flush=True)
    try:
        httpd.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        app.stopping = True
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
