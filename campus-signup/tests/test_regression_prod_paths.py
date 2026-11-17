#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""生产路径回归测试（不启动真实 socket / 不需要 root）。

背景（security_review.md F1/F2/F4）：
- F1（已修复历史）：delete-user 缺 uid 防御（v1.2）；**v1.5 §22 起删除用户功能彻底禁用**：
  provisioner dispatch 对 delete_user 一律返回 INVALID「删除用户功能已禁用」且不调用 userdel；
  web 侧 /api/admin/delete-user 路由已移除（见 test_api_mock）。
- F2：provisioner `_send` 在连接断开（BrokenPipe/Reset）时不得抛异常导致 root 服务退出，
  应返回 False 由调用方结束该连接。
- F4：限流器 `RateLimiter` 的 (bucket, ip) key 必须有硬上限并执行淘汰，防止大量不同
  客户端 IP 造成内存无界增长（F5 的公告 Cf 字符校验在 test_api_mock 的公告用例中回归）。

本文件用 fake 依赖（no real socket / no root / no real provisioner）锁定上述契约，
属于 mock 模式黑盒测试覆盖不到的生产分支。
只依赖 stdlib，Python 3.9 兼容。
"""

import json
import os
import sys
import unittest

sys.dont_write_bytecode = True

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP_DIR = os.path.join(PROJECT_ROOT, "app")
for _path in (os.path.join(PROJECT_ROOT, "vendor", "site-packages"), APP_DIR, PROJECT_ROOT):
    if _path not in sys.path:
        sys.path.insert(0, _path)

if not os.path.isfile(os.path.join(APP_DIR, "server.py")):
    raise unittest.SkipTest("app/server.py 尚未实现（等待 backend 完成）")
if not os.path.isfile(os.path.join(APP_DIR, "provisioner.py")):
    raise unittest.SkipTest("app/provisioner.py 尚未实现（等待 backend 完成）")

import provisioner as provisioner_module  # noqa: E402  (app/provisioner.py)
import server  # noqa: E402  (app/server.py)


# ---------------------------------------------------------------------------
# Fake 依赖（只实现 handler 分支用到的接口）
# ---------------------------------------------------------------------------

class FakeCursor(object):
    def __init__(self, row=None):
        self._row = row

    def fetchone(self):
        return self._row


class FakeConn(object):
    """记录 SQL 的假 SQLite 连接。"""

    def __init__(self, select_row=None):
        self.select_row = select_row
        self.executed = []
        self.committed = False
        self.closed = False

    def execute(self, sql, params=()):
        self.executed.append((sql, tuple(params or ())))
        if sql.lstrip().upper().startswith("SELECT"):
            return FakeCursor(self.select_row)
        return FakeCursor(None)

    def commit(self):
        self.committed = True

    def close(self):
        self.closed = True


class FakeCtx(object):
    def __init__(self, prov, row):
        self.provisioner = prov
        self.row = row
        self.connections = []

    def connect_db(self):
        conn = FakeConn(self.row)
        self.connections.append(conn)
        return conn


class FakeProductionProvisioner(object):
    """模拟「修复前」的 SocketProvisioner：expected_uid=None → int(None) TypeError。

    F1 回归要求：handler 在系统用户缺失时不得把 None 传进来（否则旧缺陷复现）。
    """

    def __init__(self, deleted=True):
        self.deleted = deleted
        self.calls = []

    def delete_user(self, username, expected_uid):
        if expected_uid is None:
            raise TypeError(
                "int() argument must be a string, a bytes-like object or a number, "
                "not 'NoneType'"
            )
        self.calls.append((username, expected_uid))
        return server.ProvisionResult(
            True,
            data={"ok": True, "username": username, "deleted": self.deleted},
        )


class FakeServer(object):
    def __init__(self, ctx):
        self.ctx = ctx


def make_handler(ctx, body, user_info):
    """构造一个只初始化了 `_handle_admin_delete_user` 所需依赖的 MainHandler。"""
    handler = object.__new__(server.MainHandler)
    handler.server = FakeServer(ctx)
    sent = {"json": [], "errors": []}
    handler._require_admin = lambda client_ip, *args, **kwargs: True
    handler._read_json_body = lambda max_bytes=server.MAX_BODY_BYTES: body
    handler._read_record_id = lambda body_obj: body_obj.get("id")
    handler._provisioner_user_info = lambda username: (user_info, True)
    handler._send_json = lambda status, payload, extra_headers=None: sent["json"].append(
        (status, payload)
    )
    handler._send_error = lambda status, code, message, extra_headers=None: sent[
        "errors"
    ].append((status, code))
    return handler, sent


class DeleteUserDisabledRegressionTest(unittest.TestCase):
    """SPEC §22.1/§22.3/§22.7：删除用户功能彻底禁用（不调用 userdel，数据/家目录不受影响）。"""

    def test_dispatch_delete_user_disabled_without_subprocess(self):
        calls = []

        def _record_and_fail(*args, **kwargs):
            calls.append(args)
            raise AssertionError("delete_user 已禁用，不得调用任何子进程（userdel）")

        original_run_command = provisioner_module.run_command
        provisioner_module.run_command = _record_and_fail
        try:
            response = provisioner_module.dispatch(
                {
                    "op": "delete_user",
                    "username": "zhangsan",
                    "expected_uid": 1030,
                },
                {"timeout_seconds": 10},
            )
        finally:
            provisioner_module.run_command = original_run_command
        self.assertIsInstance(response, dict)
        self.assertFalse(response.get("ok"), "delete_user 必须被拒绝: %r" % (response,))
        error = response.get("error") or {}
        self.assertEqual(error.get("code"), "INVALID")
        self.assertIn("删除用户功能已禁用", error.get("message", ""))
        self.assertEqual(calls, [], "delete_user 不得调用 userdel/任何子进程")

    def test_dispatch_other_ops_still_work(self):
        response = provisioner_module.dispatch({"op": "ping"}, {})
        self.assertTrue(response.get("ok"))


class F2ProvisionerConnectionRobustnessRegressionTest(unittest.TestCase):
    """F2 回归：连接断开/异常时 provisioner 不得抛异常退出（_send 返回 False）。"""

    def setUp(self):
        self._orig_prov_log = provisioner_module.log
        provisioner_module.log = lambda *args, **kwargs: None

    def tearDown(self):
        provisioner_module.log = self._orig_prov_log

    def test_send_broken_pipe_returns_false_without_raising(self):
        class BrokenConnection(object):
            def sendall(self, data):
                raise BrokenPipeError("peer closed")

        instance = object.__new__(provisioner_module.ProvisionerServer)
        ok = provisioner_module.ProvisionerServer._send(
            instance, BrokenConnection(), {"ok": True}
        )
        self.assertIs(ok, False, "连接已断开时 _send 应返回 False 而不是抛异常")

    def test_send_reset_connection_returns_false_without_raising(self):
        class ResetConnection(object):
            def sendall(self, data):
                raise ConnectionResetError("peer reset")

        instance = object.__new__(provisioner_module.ProvisionerServer)
        ok = provisioner_module.ProvisionerServer._send(
            instance, ResetConnection(), {"ok": True}
        )
        self.assertIs(ok, False)

    def test_send_falls_back_for_unserializable_payload(self):
        """payload 含不可 JSON 序列化对象时返回 INTERNAL 错误行，不得抛异常。"""
        class RecordingConnection(object):
            def __init__(self):
                self.sent = []

            def sendall(self, data):
                self.sent.append(data)

        connection = RecordingConnection()
        instance = object.__new__(provisioner_module.ProvisionerServer)
        ok = provisioner_module.ProvisionerServer._send(
            instance, connection, {"ok": True, "bad": object()}
        )
        self.assertIs(ok, True)
        self.assertEqual(len(connection.sent), 1)
        payload = json.loads(connection.sent[0].decode("utf-8"))
        self.assertFalse(payload.get("ok"))
        self.assertEqual(payload["error"]["code"], "INTERNAL")


class F4RateLimiterMemoryBoundRegressionTest(unittest.TestCase):
    """F4 回归：大量不同客户端 IP 不得使限流器内存无界增长（必须有硬上限）。"""

    def test_rate_limiter_keys_are_bounded(self):
        limit = int(getattr(server.RateLimiter, "MAX_KEYS", 10000))
        self.assertGreater(limit, 0, "RateLimiter 必须定义 key 上限")
        limiter = server.RateLimiter()
        # 生成 limit + 200 个互不相同的客户端 IP，每个只请求一次
        for index in range(limit + 200):
            ip = "10.%d.%d.%d" % (
                (index >> 16) & 0xFF,
                (index >> 8) & 0xFF,
                index & 0xFF,
            )
            limited, _retry_after = limiter.check("preview", ip, 60, 1000)
            self.assertFalse(limited, "单 key 首次请求不应被限流")
        # 共插入 limit + 200 个不同 key；若无上限，字典会保留全部 key。
        # 有上限时中途必然触发淘汰，最终 key 数 < limit。
        self.assertLessEqual(
            len(limiter._hits),
            limit,
            "限流器 key 数必须有界（实测 %d，上限 %d）" % (len(limiter._hits), limit),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
