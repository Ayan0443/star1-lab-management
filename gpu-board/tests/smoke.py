#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""star1 GPU 预约台 —— 接口冒烟测试（配合 --mock 模式运行）。

用法：
    python3 server.py --mock --no-tls --port 18083 --static ./static --db /tmp/board-mock.db &
    python3 tests/smoke.py --port 18083
"""

import argparse
import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.request

PASS = 0
FAIL = 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print("PASS  %s" % name)
    else:
        FAIL += 1
        print("FAIL  %s  %s" % (name, detail))


class Client(object):
    def __init__(self, base):
        self.base = base
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar), urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        )

    def call(self, method, path, payload=None, headers=None):
        url = self.base + path
        data = None
        request_headers = dict(headers or {})
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        if method == "POST":
            request_headers.setdefault("X-Requested-With", "star1-gpu-board")
        request = urllib.request.Request(url, data=data, headers=request_headers, method=method)
        try:
            response = self.opener.open(request, timeout=10)
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8")
            try:
                parsed = json.loads(body)
            except ValueError:
                parsed = {"raw": body}
            return error.code, parsed

    def get(self, path):
        return self.call("GET", path)

    def post(self, path, payload):
        return self.call("POST", path, payload)

    def bearer(self, method, path, token, payload=None):
        headers = {"Authorization": "Bearer " + token}
        return self.call(method, path, payload, headers=headers)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18083)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    base = "http://%s:%d" % (args.host, args.port)
    client = Client(base)

    status, data = client.get("/healthz")
    check("healthz", status == 200 and data.get("ok") is True, str(data))

    status, state = client.get("/api/state")
    check("state 返回 8 张卡", status == 200 and len(state.get("gpus") or []) == 8)
    check("state 含 summary", isinstance(state.get("summary"), dict))
    check("state 含 me=null", state.get("me") is None)

    status, data = client.get("/api/usage?days=7")
    check("usage 接口", status == 200 and data.get("ok") is True)

    status, data = client.post("/api/login", {"username": "alice", "password": "wrong-password"})
    check("错误密码被拒绝", status == 401 and data.get("ok") is False, str(data))

    status, data = client.post("/api/login", {"username": "alice", "password": "Passw0rd!23"})
    check("正确密码登录成功", status == 200 and data.get("me", {}).get("username") == "alice", str(data))
    check("登录返回中文姓名", data.get("me", {}).get("real_name") == "张一", str(data))

    status, data = client.get("/api/me")
    check("me 返回 alice", status == 200 and data.get("me", {}).get("username") == "alice")

    # ---- API token（供 agent / MCP 使用）----
    token_client = Client(base)  # 不带 Cookie，确保测试的是 Bearer token 本身
    status, data = client.post("/api/tokens", {"name": "冒烟测试"})
    token = data.get("token") or ""
    token_id = data.get("id")
    check("生成 api token", status == 200 and token.startswith("sgb_") and token_id, str(data)[:200])

    status, data = client.get("/api/tokens")
    check(
        "token 列表包含新 token",
        status == 200 and any(item.get("id") == token_id for item in data.get("tokens") or []),
        str(data)[:200],
    )

    status, data = token_client.bearer("GET", "/api/me", token)
    check("Bearer token 识别用户", status == 200 and data.get("me", {}).get("username") == "alice", str(data))

    now = int(time.time())
    status, data = token_client.bearer(
        "POST",
        "/api/bookings",
        token,
        {"gpu": 5, "start": now + 1800, "end": now + 5400, "purpose": "token 冒烟预约"},
    )
    token_booking_id = (data.get("booking") or {}).get("id")
    check("Bearer token 可预约", status == 200 and token_booking_id, str(data)[:200])
    if token_booking_id:
        status, data = token_client.bearer("POST", "/api/bookings/cancel", token, {"id": token_booking_id})
        check("Bearer token 可取消预约", status == 200 and data.get("ok") is True, str(data)[:200])

    status, data = client.post("/api/tokens/revoke", {"id": token_id})
    check("撤销 api token", status == 200 and data.get("ok") is True, str(data)[:200])
    status, data = token_client.bearer("GET", "/api/me", token)
    check("撤销后 token 失效", status == 200 and data.get("me") is None, str(data))

    start = now + 3600
    end = start + 7200
    status, data = client.post(
        "/api/bookings", {"gpu": -1, "start": start, "end": end, "purpose": "冒烟测试任务"}
    )
    booking = data.get("booking") or {}
    booking_id = booking.get("id")
    check("自动分配预约成功", status == 200 and data.get("ok") is True, str(data))
    check("自动分配返回卡号", isinstance(booking.get("gpu"), int) and 0 <= booking["gpu"] <= 7, str(booking))

    status, data = client.post(
        "/api/bookings", {"gpu": -1, "start": start + 60, "end": end, "purpose": "重复预约"}
    )
    check("同一时段重复预约被拒绝", status == 400 and data.get("ok") is False, str(data))

    status, data = client.post(
        "/api/bookings", {"gpu": -1, "start": start, "end": start + 60, "purpose": "太短"}
    )
    check("过短预约被拒绝", status == 400, str(data))

    status, state = client.get("/api/state")
    found = [item for item in state.get("bookings", []) if item.get("id") == booking_id]
    check("state 中包含新预约", len(found) == 1, str(found[:1]))

    status, data = client.post("/api/bookings/cancel", {"id": booking_id})
    check("取消自己的预约", status == 200 and data.get("ok") is True, str(data))

    status, data = client.post("/api/bookings/cancel", {"id": booking_id})
    check("重复取消被拒绝", status == 400, str(data))

    # 管理员
    admin = Client(base)
    status, data = admin.post("/api/admin/login", {"token": "wrong-token"})
    check("错误管理员口令被拒绝", status == 401, str(data))

    status, data = admin.post("/api/admin/login", {"token": "mock-admin-token"})
    check("管理员登录成功", status == 200 and data.get("me", {}).get("role") == "admin", str(data))

    status, data = admin.get("/api/admin/overview?days=30")
    check("管理员 overview", status == 200 and data.get("ok") is True and "users" in data, str(data)[:200])
    check("管理员可见用户列表", len(data.get("users") or []) == 5, str(len(data.get("users") or [])))

    status, data = admin.post(
        "/api/admin/bookings",
        {"username": "bob", "gpu": 2, "start": now + 7200, "end": now + 10800, "purpose": "管理员代约"},
    )
    admin_booking_id = (data.get("booking") or {}).get("id")
    check("管理员代约成功", status == 200 and admin_booking_id, str(data))

    status, data = admin.post("/api/admin/cancel", {"id": admin_booking_id})
    check("管理员取消预约", status == 200 and data.get("ok") is True, str(data))

    status, data = admin.get("/api/admin/users")
    check("管理员用户列表接口", status == 200 and len(data.get("users") or []) == 5, str(data)[:200])

    # 权限边界
    status, data = client.get("/api/admin/overview")
    check("普通用户不能访问管理员接口", status == 403, str(data))

    status, data = client.post("/api/login", {"username": "alice", "password": "Passw0rd!23"})
    status, data = client.post("/api/logout", {})
    check("退出登录", status == 200 and data.get("ok") is True, str(data))
    status, data = client.get("/api/me")
    check("退出后 me 为空", data.get("me") is None)

    # 未登录不能预约
    status, data = client.post(
        "/api/bookings", {"gpu": 0, "start": now + 20000, "end": now + 21000, "purpose": "未登录"}
    )
    check("未登录预约被拒绝", status == 401, str(data))

    # CSRF 头缺失
    status, data = client.call("POST", "/api/login", {"username": "alice", "password": "Passw0rd!23"}, headers={"X-Requested-With": ""})
    check("缺少 X-Requested-With 被拒绝", status == 403, str(data))

    print("\n结果：%d 通过，%d 失败" % (PASS, FAIL))
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
