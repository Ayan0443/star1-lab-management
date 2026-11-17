#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""star1 GPU 预约台 —— MCP 服务（stdio，仅标准库）

给使用 Claude Code / Codex / DSH 等 agent 的同学用。agent 通过本 MCP 服务可以：
  * 查看 8 张卡的实时占用情况（谁在用、跑多久、有没有预约）
  * 预约 / 取消 / 查询自己的预约，并等待预约生效
  * 在预约生效期间，用 gpu_run 在指定卡上运行实验（自动设置 CUDA_VISIBLE_DEVICES）
  * 查看近 N 天每人卡时统计

配置（环境变量或 token 文件，任选其一）：
  GPU_BOARD_URL         看板地址，默认 https://127.0.0.1:8083
  GPU_BOARD_TOKEN       在网页登录后「Agent 接入」里生成的 token（sgb_...）
  GPU_BOARD_TOKEN_FILE  token 文件路径，默认 ~/.config/star1-gpu/token
  GPU_BOARD_TLS_VERIFY  1=校验证书；默认 0（看板用自签名证书）
  GPU_BOARD_RUN         auto/1/0，是否允许 gpu_run 在本机执行命令（默认 auto：仅当本机就是 star1 时启用）

本服务只通过看板 HTTPS API 读写预约数据；gpu_run 只会在本机（star1）执行你给的命令，
行为与你在 star1 终端里手动运行一致。
"""

import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

SERVER_NAME = "star1-gpu"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18")
DEFAULT_PROTOCOL = "2024-11-05"
CN_TZ = timezone(timedelta(hours=8))

INSTRUCTIONS = (
    "这是 star1 实验室 GPU 预约台（8 × A100-80G）。使用 GPU 的流程：\n"
    "1. gpu_status 查看实时占用；\n"
    "2. gpu_book 预约（gpu 传 auto 或卡号，start 支持 ISO8601 或 now+30m，duration_minutes 默认 120，purpose 必填）；\n"
    "3. gpu_wait 等到预约生效（或 gpu_book 之后先用 gpu_bookings 确认）；\n"
    "4. gpu_run 在预约的卡上运行实验命令（自动设置 CUDA_VISIBLE_DEVICES；长任务用 background=true）；\n"
    "5. 结束或不用时 gpu_cancel 取消预约。\n"
    "公约：先预约后使用；单次预约不超过 24 小时；每人最多保留 2 个未结束预约；禁止 kill 他人进程。"
)

RULES_TEXT = """star1 GPU 使用公约（摘要）
1. 先登记后占用：使用整卡前先预约；共享小任务用 CUDA_VISIBLE_DEVICES 指定卡并限制显存。
2. 限时：单次预约不超过 24 小时；长任务按 checkpoint 分段，并提前预约所需时段。
3. 对号入座：按预约的卡号运行任务；临时调整先取消或修改预约。
4. 禁止：kill 他人进程、未经沟通强占多卡、预约后长时间不跑（连续 30 分钟利用率 < 5% 视为空闲）。
5. 共享：一张 80G 卡可同时跑多个小实验，请自行限制显存；大任务优先整卡。
6. 优先级：论文 deadline / 全组共享任务可联系管理员协调，普通实验按预约顺序。
7. 争议：以预约记录为准；无法解决时联系管理员。"""


def log(*parts):
    print("[mcp]", *parts, file=sys.stderr, flush=True)


class BoardError(Exception):
    def __init__(self, message, code="ERROR"):
        Exception.__init__(self, message)
        self.code = code


# ---------------------------------------------------------------------------
# 看板 HTTP 客户端
# ---------------------------------------------------------------------------


class BoardClient(object):
    def __init__(self, base_url, token, verify_tls, timeout=20):
        self.base_url = (base_url or "https://127.0.0.1:8083").rstrip("/")
        self.token = token or ""
        self.timeout = timeout
        self.context = ssl.create_default_context()
        if not verify_tls:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def call(self, method, path, payload=None, need_auth=False):
        if need_auth and not self.token:
            raise BoardError(
                "未配置 GPU_BOARD_TOKEN：请先在网页登录，在「Agent 接入」里生成 token，"
                "写入环境变量 GPU_BOARD_TOKEN 或 ~/.config/star1-gpu/token",
                code="NO_TOKEN",
            )
        data = None
        headers = {"Accept": "application/json", "X-Requested-With": "star1-gpu-board"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=self.timeout, context=self.context)
            body = response.read().decode("utf-8")
            return json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = {}
            info = parsed.get("error") if isinstance(parsed, dict) else None
            if isinstance(info, dict):
                raise BoardError(info.get("message") or ("HTTP %d" % error.code), code=info.get("code") or "HTTP_ERROR")
            raise BoardError("看板返回 HTTP %d" % error.code, code="HTTP_%d" % error.code)
        except (urllib.error.URLError, OSError) as error:
            raise BoardError("无法连接看板 %s：%s" % (self.base_url, error), code="CONNECTION")


# ---------------------------------------------------------------------------
# 时间工具
# ---------------------------------------------------------------------------

RELATIVE_RE = re.compile(r"^(?:now)?([+-])(\d+)([smhd])$", re.IGNORECASE)


def parse_time(value, base=None, what="时间"):
    if base is None:
        base = datetime.now(CN_TZ)
    text = ("" if value is None else str(value)).strip()
    if not text or text.lower() == "now":
        return int(base.timestamp())
    match = RELATIVE_RE.match(text)
    if match:
        sign, amount, unit = match.groups()
        seconds = int(amount) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit.lower()]
        return int(base.timestamp()) + (seconds if sign == "+" else -seconds)
    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso)
    except ValueError:
        raise BoardError("无法解析%s：%r（支持 2026-11-18T09:00:00+08:00、now、now+30m 等）" % (what, value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=CN_TZ)
    return int(parsed.timestamp())


def fmt_cn(epoch_seconds):
    return datetime.fromtimestamp(int(epoch_seconds), CN_TZ).strftime("%Y-%m-%d %H:%M")


def fmt_elapsed(seconds):
    seconds = max(0, int(seconds or 0))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return "%d天%d小时" % (days, hours)
    if hours:
        return "%d小时%d分" % (hours, minutes)
    return "%d分钟" % max(1, minutes)


# ---------------------------------------------------------------------------
# MCP 服务
# ---------------------------------------------------------------------------


class GpuBoardMcp(object):
    def __init__(self):
        self.base_url = os.environ.get("GPU_BOARD_URL") or "https://127.0.0.1:8083"
        self.verify_tls = os.environ.get("GPU_BOARD_TLS_VERIFY", "0").strip() not in ("0", "false", "no")
        try:
            timeout = float(os.environ.get("GPU_BOARD_TIMEOUT") or 20)
        except ValueError:
            timeout = 20
        self.client = BoardClient(self.base_url, self._load_token(), self.verify_tls, timeout)
        self.run_mode = (os.environ.get("GPU_BOARD_RUN") or "auto").strip().lower()

    @staticmethod
    def _load_token():
        token = (os.environ.get("GPU_BOARD_TOKEN") or "").strip()
        if token:
            return token
        path = os.environ.get("GPU_BOARD_TOKEN_FILE") or os.path.expanduser("~/.config/star1-gpu/token")
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read().strip()
        except OSError:
            return ""

    # -- 基础数据 -------------------------------------------------------
    def state(self):
        return self.client.call("GET", "/api/state")

    def me(self):
        try:
            return self.client.call("GET", "/api/me").get("me")
        except BoardError:
            raise

    def active_booking(self):
        me = self.me()
        if not me:
            raise BoardError("token 无效或未配置，无法确认身份", code="NO_IDENTITY")
        state = self.state()
        now = int(time.time())
        rows = [
            booking
            for booking in state.get("bookings") or []
            if booking.get("username") == me.get("username")
            and booking.get("status") == "active"
            and booking.get("start_ts", 0) <= now < booking.get("end_ts", 0)
        ]
        rows.sort(key=lambda item: item.get("start_ts", 0))
        return me, state, (rows[0] if rows else None)

    def require_token(self):
        if not self.client.token:
            raise BoardError(
                "未配置 GPU_BOARD_TOKEN：请先在网页登录，在「Agent 接入」里生成 token，"
                "写入环境变量 GPU_BOARD_TOKEN 或 ~/.config/star1-gpu/token",
                code="NO_TOKEN",
            )

    # -- 工具实现 -------------------------------------------------------
    def tool_status(self, args):
        state = self.state()
        me = None
        try:
            me = self.me()
        except BoardError:
            me = None
        now = int(time.time())
        gpus = []
        for gpu in state.get("gpus") or []:
            procs = []
            for proc in gpu.get("procs") or []:
                procs.append(
                    {
                        "user": proc.get("user"),
                        "real_name": proc.get("real_name"),
                        "elapsed": fmt_elapsed(proc.get("etime_s")),
                        "mem_gib": round((proc.get("mem") or 0) / 1024.0, 1),
                        "cmd": proc.get("cmd"),
                    }
                )
            current = gpu.get("booking")
            upcoming = gpu.get("next_booking")
            gpus.append(
                {
                    "gpu": gpu.get("index"),
                    "util_percent": gpu.get("util"),
                    "mem_used_gib": round((gpu.get("mem_used") or 0) / 1024.0, 1),
                    "mem_total_gib": round((gpu.get("mem_total") or 0) / 1024.0, 1),
                    "temp_c": gpu.get("temp"),
                    "status": (
                        "conflict" if gpu.get("conflict")
                        else "unregistered" if gpu.get("unregistered")
                        else "busy" if procs
                        else "reserved" if current
                        else "free"
                    ),
                    "procs": procs,
                    "current_booking": self._booking_brief(current),
                    "next_booking": self._booking_brief(upcoming),
                }
            )
        return {
            "ok": True,
            "now": fmt_cn(now),
            "host": state.get("host"),
            "load": [round(float(value), 1) for value in (state.get("load") or [])],
            "summary": state.get("summary"),
            "gpus": gpus,
            "me": me,
            "bookings_window": [
                self._booking_brief(booking)
                for booking in (state.get("bookings") or [])
            ],
        }

    @staticmethod
    def _booking_brief(booking):
        if not booking:
            return None
        return {
            "id": booking.get("id"),
            "gpu": booking.get("gpu"),
            "username": booking.get("username"),
            "real_name": booking.get("real_name"),
            "start": fmt_cn(booking.get("start_ts")),
            "end": fmt_cn(booking.get("end_ts")),
            "purpose": booking.get("purpose"),
        }

    def tool_bookings(self, args):
        state = self.state()
        me = None
        try:
            me = self.me()
        except BoardError:
            me = None
        scope = str(args.get("scope") or "mine").lower()
        hours = max(1, min(168, int(args.get("hours") or 24)))
        now = int(time.time())
        rows = []
        for booking in state.get("bookings") or []:
            if booking.get("end_ts", 0) < now or booking.get("start_ts", 0) > now + hours * 3600:
                continue
            if scope == "mine" and (not me or booking.get("username") != me.get("username")):
                continue
            rows.append(self._booking_brief(booking))
        return {"ok": True, "scope": scope, "hours": hours, "bookings": rows}

    def tool_book(self, args):
        self.require_token()
        me = self.me()
        if not me:
            raise BoardError("token 无效或已撤销", code="NO_IDENTITY")
        purpose = str(args.get("purpose") or "").strip()
        if not purpose:
            raise BoardError("purpose 必填：请说明用途，例如「训练 xxx 模型」", code="INVALID_PURPOSE")
        now = int(time.time())
        start_ts = parse_time(args.get("start"), what="开始时间")
        if args.get("end") not in (None, ""):
            end_ts = parse_time(args.get("end"), what="结束时间")
        else:
            try:
                duration = int(args.get("duration_minutes") or 120)
            except (TypeError, ValueError):
                duration = 120
            duration = max(1, duration)
            end_ts = start_ts + duration * 60
        gpu = args.get("gpu", "auto")
        if isinstance(gpu, str):
            gpu_text = gpu.strip().lower()
            gpu_value = -1 if gpu_text in ("auto", "", "-1") else int(gpu_text)
        else:
            gpu_value = int(gpu)
        response = self.client.call(
            "POST",
            "/api/bookings",
            {"gpu": gpu_value, "start": start_ts, "end": end_ts, "purpose": purpose},
            need_auth=True,
        )
        booking = response.get("booking") or {}
        return {
            "ok": True,
            "booking": self._booking_brief(
                {
                    "id": booking.get("id"),
                    "gpu": booking.get("gpu"),
                    "username": booking.get("username"),
                    "real_name": booking.get("real_name"),
                    "start_ts": booking.get("start_ts"),
                    "end_ts": booking.get("end_ts"),
                    "purpose": booking.get("purpose"),
                }
            ),
            "note": "预约已创建。若开始时间在未来，请用 gpu_wait 等待生效后再运行实验。",
        }

    def tool_cancel(self, args):
        self.require_token()
        try:
            booking_id = int(args.get("booking_id"))
        except (TypeError, ValueError):
            raise BoardError("booking_id 必填且必须是整数", code="INVALID_ARGUMENT")
        response = self.client.call(
            "POST", "/api/bookings/cancel", {"id": booking_id}, need_auth=True
        )
        return {"ok": True, "booking": response.get("booking")}

    def tool_wait(self, args):
        self.require_token()
        try:
            booking_id = int(args.get("booking_id"))
        except (TypeError, ValueError):
            raise BoardError("booking_id 必填且必须是整数", code="INVALID_ARGUMENT")
        timeout_seconds = max(5, min(3600, int(args.get("timeout_seconds") or 300)))
        deadline = time.time() + timeout_seconds
        me = self.me()
        while True:
            state = self.state()
            now = int(time.time())
            for booking in state.get("bookings") or []:
                if booking.get("id") != booking_id:
                    continue
                if booking.get("start_ts", 0) <= now < booking.get("end_ts", 0):
                    return {
                        "ok": True,
                        "active": True,
                        "booking": self._booking_brief(booking),
                        "note": "预约已生效，现在可以用 gpu_run 在 GPU %d 上运行实验。" % booking.get("gpu"),
                    }
            if time.time() >= deadline:
                wait_minutes = max(1, timeout_seconds // 60)
                raise BoardError(
                    "等待超时：预约 #%s 在 %d 分钟内未生效（可能还没到开始时间）。可稍后重试 gpu_wait。"
                    % (booking_id, wait_minutes),
                    code="TIMEOUT",
                )
            time.sleep(5)

    def tool_usage(self, args):
        days = max(1, min(90, int(args.get("days") or 7)))
        return self.client.call("GET", "/api/usage?days=%d" % days)

    def tool_rules(self, args):
        return {"ok": True, "rules": RULES_TEXT}

    def tool_run(self, args):
        command = str(args.get("command") or "").strip()
        if not command:
            raise BoardError("command 必填，例如 \"python train.py --config xxx\"", code="INVALID_ARGUMENT")
        self.require_token()
        me, state, booking = self.active_booking()
        if booking is None:
            raise BoardError(
                "当前没有生效中的预约，不能在 GPU 上运行实验。请先 gpu_book 预约，并用 gpu_wait 等到生效。",
                code="NO_ACTIVE_BOOKING",
            )
        if self.run_mode in ("0", "false", "no"):
            raise BoardError("gpu_run 已被禁用（GPU_BOARD_RUN=0）", code="RUN_DISABLED")
        board_host = state.get("host") or ""
        local_host = socket.gethostname()
        if self.run_mode != "1" and board_host and board_host != local_host:
            raise BoardError(
                "当前 MCP 客户端不在看板主机 %s 上（本机 %s）。gpu_run 只能在 star1 上执行；"
                "请在 star1 的 shell/agent 里启动本 MCP 服务（或设置 GPU_BOARD_RUN=1 强制）。"
                % (board_host, local_host),
                code="WRONG_HOST",
            )
        gpu = booking.get("gpu")
        cwd = args.get("cwd") or None
        if cwd and not os.path.isdir(cwd):
            raise BoardError("cwd 不存在：%s" % cwd, code="INVALID_CWD")
        try:
            timeout_seconds = int(args.get("timeout_seconds") or 120)
        except (TypeError, ValueError):
            timeout_seconds = 120
        timeout_seconds = max(1, min(1800, timeout_seconds))
        background = bool(args.get("background"))
        env = dict(os.environ)
        env["CUDA_VISIBLE_DEVICES"] = str(gpu)
        env["STAR1_GPU_BOARD_GPU"] = str(gpu)
        env["STAR1_GPU_BOARD_BOOKING"] = str(booking.get("id"))
        if background:
            log_dir = os.path.expanduser("~/.local/state/star1-gpu/runs")
            os.makedirs(log_dir, exist_ok=True)
            stamp = datetime.now(CN_TZ).strftime("%Y%m%d-%H%M%S")
            log_path = os.path.join(log_dir, "%s-gpu%s.log" % (stamp, gpu))
            handle = open(log_path, "wb")
            process = subprocess.Popen(
                command,
                shell=True,
                cwd=cwd,
                env=env,
                stdout=handle,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            handle.close()
            return {
                "ok": True,
                "background": True,
                "gpu": gpu,
                "booking_id": booking.get("id"),
                "pid": process.pid,
                "log": log_path,
                "note": "后台任务已启动；用 tail -f %s 查看输出。" % log_path,
            }
        try:
            completed = subprocess.run(
                command,
                shell=True,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            raise BoardError(
                "命令超过 %d 秒未结束。长任务请用 background=true 以后台方式启动。" % timeout_seconds,
                code="TIMEOUT",
            )
        stdout = (completed.stdout or "")[-20000:]
        stderr = (completed.stderr or "")[-8000:]
        return {
            "ok": completed.returncode == 0,
            "gpu": gpu,
            "booking_id": booking.get("id"),
            "exit_code": completed.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

    # -- MCP 协议 -------------------------------------------------------
    def tool_definitions(self):
        return [
            {
                "name": "gpu_status",
                "description": "查看 star1 的 8 张 A100 实时状态：每张卡的利用率、显存、当前进程（谁在用、跑了多久、在跑什么）、预约情况，以及空闲/占用汇总。开始任何 GPU 工作前先调用它。",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
            {
                "name": "gpu_bookings",
                "description": "查看预约列表（默认只看自己的）。scope=mine|all，hours 表示未来多少小时（1-168，默认 24）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "scope": {"type": "string", "enum": ["mine", "all"], "default": "mine"},
                        "hours": {"type": "integer", "minimum": 1, "maximum": 168, "default": 24},
                    },
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_book",
                "description": "预约 GPU。gpu 可以是卡号（0-7）或 \"auto\"（自动挑空闲卡）；start 支持 ISO8601（如 2026-11-18T09:00:00+08:00）或相对时间（now、now+30m、+2h）；不传 end 时用 duration_minutes（默认 120，最多 1440）；purpose 必填。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "gpu": {"type": ["integer", "string"], "default": "auto", "description": "卡号 0-7 或 auto"},
                        "start": {"type": "string", "default": "now", "description": "ISO8601 或 now / now+30m / +2h"},
                        "duration_minutes": {"type": "integer", "minimum": 1, "maximum": 1440, "default": 120},
                        "end": {"type": "string", "description": "可替代 duration_minutes 的结束时间"},
                        "purpose": {"type": "string", "description": "用途，例如：训练 xxx 模型"},
                    },
                    "required": ["purpose"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_cancel",
                "description": "取消自己的预约（booking_id 来自 gpu_book / gpu_bookings）。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"booking_id": {"type": "integer"}},
                    "required": ["booking_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_wait",
                "description": "阻塞等待指定预约生效（到达开始时间），默认最多等 300 秒。返回后即可用 gpu_run 跑实验。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "booking_id": {"type": "integer"},
                        "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 3600, "default": 300},
                    },
                    "required": ["booking_id"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_run",
                "description": "在「当前生效预约」对应的 GPU 上运行一条 shell 命令（自动设置 CUDA_VISIBLE_DEVICES）。仅当本 MCP 服务运行在 star1 上时可用；长任务用 background=true（返回 pid 和日志路径）。没有生效中的预约会报错。",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "shell 命令，例如 python train.py --config cfg.yaml"},
                        "cwd": {"type": "string", "description": "工作目录（默认继承）"},
                        "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 1800, "default": 120},
                        "background": {"type": "boolean", "default": False},
                    },
                    "required": ["command"],
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_usage",
                "description": "查看近 N 天每人 GPU 卡时统计（默认 7 天，最多 90 天），用于判断谁用得多、何时该让卡。",
                "inputSchema": {
                    "type": "object",
                    "properties": {"days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 7}},
                    "additionalProperties": False,
                },
            },
            {
                "name": "gpu_rules",
                "description": "返回 star1 GPU 使用公约（摘要），做任何预约/运行前请遵守。",
                "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
            },
        ]

    def dispatch_tool(self, name, arguments):
        handlers = {
            "gpu_status": self.tool_status,
            "gpu_bookings": self.tool_bookings,
            "gpu_book": self.tool_book,
            "gpu_cancel": self.tool_cancel,
            "gpu_wait": self.tool_wait,
            "gpu_run": self.tool_run,
            "gpu_usage": self.tool_usage,
            "gpu_rules": self.tool_rules,
        }
        handler = handlers.get(name)
        if handler is None:
            raise BoardError("未知工具：%s" % name, code="UNKNOWN_TOOL")
        if not isinstance(arguments, dict):
            arguments = {}
        return handler(arguments)

    @staticmethod
    def _text(payload):
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def handle_request(self, message):
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        method = message.get("method")
        request_id = message.get("id")
        is_notification = "id" not in message
        if is_notification:
            return None  # 通知不需要响应（initialize 之前的 notifications/initialized 等）
        if method == "initialize":
            requested = (message.get("params") or {}).get("protocolVersion") or ""
            version = requested if requested in PROTOCOL_VERSIONS else DEFAULT_PROTOCOL
            return {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "instructions": INSTRUCTIONS,
                },
            }
        if method == "ping":
            return {"jsonrpc": "2.0", "id": request_id, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": self.tool_definitions()}}
        if method == "tools/call":
            params = message.get("params") or {}
            name = params.get("name")
            arguments = params.get("arguments") or {}
            try:
                result = self.dispatch_tool(name, arguments)
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": self._text(result)}],
                        "isError": False,
                    },
                }
            except BoardError as error:
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [
                            {
                                "type": "text",
                                "text": json.dumps(
                                    {"ok": False, "error": {"code": error.code, "message": str(error)}},
                                    ensure_ascii=False,
                                    indent=2,
                                ),
                            }
                        ],
                        "isError": True,
                    },
                }
            except Exception as error:  # 兜底，避免 MCP 进程崩溃
                log("tool_error", name=name, detail=repr(error)[:300])
                return {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "content": [{"type": "text", "text": "工具执行失败：%s" % error}],
                        "isError": True,
                    },
                }
        if method == "resources/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"resources": []}}
        if method == "prompts/list":
            return {"jsonrpc": "2.0", "id": request_id, "result": {"prompts": []}}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "Method not found: %s" % method},
        }

    def serve(self):
        log("server=%s version=%s board=%s token=%s" % (
            SERVER_NAME, SERVER_VERSION, self.client.base_url, "yes" if self.client.token else "no"
        ))
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                message = json.loads(line)
            except ValueError:
                self._send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
                continue
            if isinstance(message, list):
                responses = [self.handle_request(item) for item in message]
                responses = [item for item in responses if item]
                if responses:
                    self._send(responses)
                continue
            response = self.handle_request(message)
            if response is not None:
                self._send(response)

    @staticmethod
    def _send(payload):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()


def main():
    try:
        server = GpuBoardMcp()
    except Exception as error:
        log("启动失败：%s" % error)
        return 2
    try:
        server.serve()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
