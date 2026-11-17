#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""star1 GPU 预约台 —— MCP 服务端到端测试。

流程：
  1. 启动 mock 看板（--mock）；
  2. 用 alice 登录并生成 API token；
  3. 以 stdio 启动 mcp_server.py，模拟 MCP 客户端发送 JSON-RPC：
     initialize / tools/list / gpu_status / gpu_book / gpu_bookings /
     gpu_wait / gpu_run / gpu_cancel / gpu_usage / 未知工具；
  4. 校验结果并退出。

用法：python3 tests/test_mcp.py
"""

import http.cookiejar
import json
import os
import queue
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

PASS = 0
FAIL = 0
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print("PASS  %s" % name)
    else:
        FAIL += 1
        print("FAIL  %s  %s" % (name, str(detail)[:400]))


def free_port():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_http(url, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    return False


class HttpClient(object):
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method, path, payload=None, headers=None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request_headers = {"X-Requested-With": "star1-gpu-board"}
        request_headers.update(headers or {})
        if payload is not None:
            request_headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.base + path, data=data, headers=request_headers, method=method)
        try:
            with self.opener.open(request, timeout=10) as response:
                body = response.read().decode("utf-8")
                return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", "replace")
            try:
                return error.code, json.loads(body)
            except ValueError:
                return error.code, {"raw": body}


class McpProcess(object):
    def __init__(self, env):
        self.process = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "mcp_server.py")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=True,
            bufsize=1,
        )
        self.counter = 0
        self.lines = queue.Queue()
        self.stderr_lines = []
        threading.Thread(target=self._pump, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump(self):
        for line in self.process.stdout:
            self.lines.put(line)

    def _pump_err(self):
        for line in self.process.stderr:
            self.stderr_lines.append(line.rstrip("\n"))

    def request(self, method, params=None, timeout=30):
        self.counter += 1
        request_id = self.counter
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
        self.process.stdin.flush()
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self.lines.get(timeout=1)
            except queue.Empty:
                continue
            try:
                response = json.loads(line)
            except ValueError:
                continue
            if response.get("id") == request_id:
                return response
        raise RuntimeError("等待 MCP 响应超时：%s %s" % (method, params))

    def notify(self, method, params=None):
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self.process.stdin.write(json.dumps(message, ensure_ascii=False) + "\n")
        self.process.stdin.flush()

    def call_tool(self, name, arguments=None, timeout=60):
        response = self.request("tools/call", {"name": name, "arguments": arguments or {}}, timeout=timeout)
        result = response.get("result") or {}
        text = ""
        for item in result.get("content") or []:
            if item.get("type") == "text":
                text += item.get("text") or ""
        payload = None
        try:
            payload = json.loads(text)
        except ValueError:
            payload = {"raw": text}
        return result.get("isError"), payload, text

    def close(self):
        try:
            self.process.stdin.close()
        except OSError:
            pass
        try:
            self.process.terminate()
            self.process.wait(timeout=5)
        except Exception:
            try:
                self.process.kill()
            except Exception:
                pass


def main():
    port = free_port()
    workdir = tempfile.mkdtemp(prefix="star1-gpu-mcp-test-")
    db_path = os.path.join(workdir, "board.db")
    base = "http://127.0.0.1:%d" % port
    board = subprocess.Popen(
        [
            sys.executable,
            os.path.join(ROOT, "server.py"),
            "--mock",
            "--no-tls",
            "--port",
            str(port),
            "--static",
            os.path.join(ROOT, "static"),
            "--db",
            db_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        check("mock 看板启动", wait_http(base + "/healthz", 20), "port=%d" % port)
        http = HttpClient(base)
        status, data = http.call("POST", "/api/login", {"username": "alice", "password": "Passw0rd!23"})
        check("alice 登录（生成 token 用）", status == 200, data)
        status, data = http.call("POST", "/api/tokens", {"name": "MCP 测试"})
        token = data.get("token") or ""
        check("生成 MCP 用 token", status == 200 and token.startswith("sgb_"), data)
        status, data = http.call("GET", "/api/me")
        username = (data.get("me") or {}).get("username")

        env = dict(os.environ)
        env.update(
            {
                "GPU_BOARD_URL": base,
                "GPU_BOARD_TOKEN": token,
                "GPU_BOARD_TLS_VERIFY": "0",
                "GPU_BOARD_RUN": "1",
            }
        )
        mcp = McpProcess(env)
        try:
            response = mcp.request(
                "initialize",
                {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "1"}},
            )
            result = response.get("result") or {}
            check(
                "MCP initialize",
                result.get("serverInfo", {}).get("name") == "star1-gpu"
                and result.get("protocolVersion") == "2024-11-05",
                response,
            )
            mcp.notify("notifications/initialized")

            response = mcp.request("tools/list")
            tools = (response.get("result") or {}).get("tools") or []
            names = {tool.get("name") for tool in tools}
            expected = {
                "gpu_status",
                "gpu_bookings",
                "gpu_book",
                "gpu_cancel",
                "gpu_wait",
                "gpu_run",
                "gpu_usage",
                "gpu_rules",
            }
            check("tools/list 包含 8 个工具", expected.issubset(names), names)

            is_error, payload, text = mcp.call_tool("gpu_status")
            check(
                "gpu_status 返回 8 张卡",
                not is_error and len(payload.get("gpus") or []) == 8,
                text[:300],
            )
            check("gpu_status 识别当前用户", payload.get("me", {}).get("username") == username, payload.get("me"))
            free_gpu = 3

            is_error, payload, text = mcp.call_tool(
                "gpu_book",
                {
                    "gpu": free_gpu,
                    "start": "-60s",
                    "duration_minutes": 120,
                    "purpose": "MCP 端到端测试",
                },
            )
            booking = payload.get("booking") or {}
            booking_id = booking.get("id")
            check(
                "gpu_book 创建预约",
                not is_error and booking_id and booking.get("gpu") == free_gpu,
                text[:400],
            )

            is_error, payload, text = mcp.call_tool("gpu_bookings", {"scope": "mine", "hours": 24})
            ids = [item.get("id") for item in payload.get("bookings") or []]
            check("gpu_bookings 返回自己的预约", not is_error and booking_id in ids, text[:300])

            is_error, payload, text = mcp.call_tool(
                "gpu_wait", {"booking_id": booking_id, "timeout_seconds": 10}
            )
            check("gpu_wait 立即生效", not is_error and payload.get("active") is True, text[:300])

            is_error, payload, text = mcp.call_tool(
                "gpu_run",
                {"command": "echo CUDA=$CUDA_VISIBLE_DEVICES; exit 0", "timeout_seconds": 10},
            )
            check(
                "gpu_run 在预约卡上执行",
                not is_error
                and payload.get("exit_code") == 0
                and ("CUDA=%s" % free_gpu) in (payload.get("stdout") or "")
                and payload.get("gpu") == free_gpu,
                text[:400],
            )

            is_error, payload, text = mcp.call_tool("gpu_rules")
            check("gpu_rules 返回公约", not is_error and "先登记后占用" in (payload.get("rules") or ""), text[:200])

            is_error, payload, text = mcp.call_tool("gpu_usage", {"days": 7})
            check("gpu_usage 返回总量", not is_error and "total_hours" in payload, text[:200])

            is_error, payload, text = mcp.call_tool("gpu_cancel", {"booking_id": booking_id})
            check("gpu_cancel 取消预约", not is_error and payload.get("ok") is True, text[:300])

            is_error, payload, text = mcp.call_tool("this_tool_does_not_exist")
            check("未知工具返回 isError", is_error is True, text[:200])

            is_error, payload, text = mcp.call_tool(
                "gpu_run", {"command": "echo should-not-run", "timeout_seconds": 5}
            )
            check("无生效预约时 gpu_run 被拒绝", is_error is True, text[:200])

            response = mcp.request("tools/call", {"name": "gpu_status", "arguments": {}})
            check("未知协议方法处理", isinstance(response.get("result"), dict), response)
        finally:
            mcp.close()
            for line in mcp.stderr_lines[-5:]:
                print("  [mcp stderr] %s" % line)
    finally:
        board.terminate()
        try:
            board.wait(timeout=5)
        except subprocess.TimeoutExpired:
            board.kill()
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n结果：%d 通过，%d 失败" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
