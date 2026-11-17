#!/usr/bin/env python3
"""root 特权助手（SPEC §6）。

只通过 Unix domain socket 暴露少量运维操作：
    ping / create_user
    user_status / reset_password / set_lock / delete_user   （SPEC §6.4）

安全要点：
* 只接受 SO_PEERCRED 中 uid == provisioner.allowed_peer_uid 的连接；
* 换行分隔 JSON，单行 <= 64KB；
* 所有参数再次严格校验；密码只经 stdin 传给 chpasswd，绝不进入 argv / 日志；
* 保护名单与 uid<1000 的账号永远拒绝管理操作。

启动：python3 app/provisioner.py --config /etc/campus-signup/config.json
"""

import argparse
import grp
import hmac
import json
import os
import pwd
import re
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

try:  # SPEC §22.3 verify_password 需要 crypt；Python 3.13 起移除，服务器 3.12 可用
    import crypt as _crypt
except ImportError:  # pragma: no cover - 仅在无 crypt 的解释器上
    _crypt = None

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
if _APP_DIR not in sys.path:
    sys.path.insert(0, _APP_DIR)

import pinyin_util
import security

USERNAME_RE = re.compile(r"^[a-z][a-z0-9]{1,31}$")
MAX_LINE_BYTES = 64 * 1024
MAX_STATUS_USERS = 200
# SPEC §22.3：管理后台纳入 uid>=1000 且 <65000 的普通用户，最多 500 个
MIN_MANAGED_UID = 1000
MAX_MANAGED_UID = 65000
MAX_LIST_USERS = 500
COMMAND_TIMEOUT = 15.0

# 子进程使用的固定 PATH（SPEC §6.3）
CHILD_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

# 永远拒绝管理操作的保护名单（SPEC §6.4 + §8.3 保留名单）
PROTECTED_USERNAMES = frozenset(
    {
        "root",
        "admin",
        "signupapp",
        "ops1",
        "svc",
        "nobody",
        "admin",
        "administrator",
        "sudo",
        "wheel",
        "docker",
        "daemon",
        "bin",
        "sys",
        "sync",
        "games",
        "man",
        "lp",
        "mail",
        "news",
        "uucp",
        "proxy",
        "backup",
        "list",
        "irc",
        "gnats",
        "systemd",
        "sshd",
        "service",
        "support",
        "operator",
    }
)

# 特权组：目标用户属于其中任何一个都拒绝管理操作/创建校验
PRIVILEGED_GROUPS = frozenset(
    {"sudo", "wheel", "docker", "adm", "root", "lxd", "disk", "kvm", "libvirt"}
)

_STOP_EVENT = threading.Event()


def log(event, **fields):
    """输出结构化日志到 stdout（journald），调用方绝不能传入密码。"""
    parts = ["event=" + str(event)]
    for key, value in fields.items():
        text = str(value).replace("\n", " ").replace("\r", " ").replace(" ", "_")
        parts.append("%s=%s" % (key, text))
    print(" ".join(parts), flush=True)


class ProvisionError(Exception):
    """内部错误：code 为协议错误码（INVALID/EXISTS/INTERNAL）。"""

    def __init__(self, code, message, detail=""):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        cfg = json.load(handle)
    if not isinstance(cfg, dict):
        raise SystemExit("配置文件格式错误：必须是 JSON 对象")
    return cfg


def _child_env():
    env = dict(os.environ)
    env["PATH"] = CHILD_PATH
    env["LC_ALL"] = "C"
    env.pop("PYTHONPATH", None)
    return env


def run_command(args, timeout=COMMAND_TIMEOUT, stdin_text=None):
    """以 list 参数运行子进程（禁止 shell=True），返回 CompletedProcess。"""
    if not isinstance(args, (list, tuple)) or not args:
        raise ProvisionError("INTERNAL", "内部错误")
    limit = max(1.0, min(COMMAND_TIMEOUT, float(timeout)))
    try:
        return subprocess.run(
            list(args),
            input=stdin_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=limit,
            env=_child_env(),
            check=False,
        )
    except FileNotFoundError:
        log("command_missing", command=args[0])
        raise ProvisionError("INTERNAL", "内部错误", detail="命令不存在: %s" % args[0])
    except subprocess.TimeoutExpired:
        log("command_timeout", command=args[0])
        raise ProvisionError("INTERNAL", "内部错误", detail="命令超时: %s" % args[0])
    except OSError as exc:
        raise ProvisionError("INTERNAL", "内部错误", detail=str(exc))


def _remaining(deadline):
    return max(0.0, deadline - time.monotonic())


def _run_with_deadline(args, deadline, stdin_text=None):
    remaining = _remaining(deadline)
    if remaining <= 1.0:
        raise ProvisionError("INTERNAL", "内部错误", detail="操作超时")
    return run_command(args, timeout=min(COMMAND_TIMEOUT, remaining), stdin_text=stdin_text)


# ---------------------------------------------------------------------------
# 基础查询
# ---------------------------------------------------------------------------


def getent_has(kind, name):
    """getent <kind> <name> 是否存在；返回 True/False/None(无法判断)。"""
    getent = shutil.which("getent", path=CHILD_PATH)
    if not getent:
        return None
    try:
        proc = run_command([getent, kind, name], timeout=10.0)
    except ProvisionError:
        return None
    if proc.returncode == 0:
        return True
    if proc.returncode in (1, 2):
        return False
    return None


def username_exists(username):
    """系统里是否已有该用户名/用户组（getent + pwd/grp 双保险）。"""
    if getent_has("passwd", username):
        return True
    if getent_has("group", username):
        return True
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


def get_pw_entry(username):
    try:
        return pwd.getpwnam(username)
    except KeyError:
        return None


def read_shadow_passwords():
    """读取 /etc/shadow 的 {用户名: 密码字段}；不可读返回 None。"""
    entries = {}
    try:
        with open("/etc/shadow", "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.rstrip("\n")
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) >= 2:
                    entries[parts[0]] = parts[1]
    except OSError:
        return None
    return entries


def passwd_status_flag(username):
    """`passwd -S` 的第二个字段（P/L/NP），失败返回 None。"""
    try:
        proc = run_command(["passwd", "-S", username], timeout=10.0)
    except ProvisionError:
        return None
    if proc.returncode != 0:
        return None
    parts = proc.stdout.split()
    return parts[1] if len(parts) >= 2 else None


def is_user_locked(username, shadow_map=None):
    if shadow_map is None:
        shadow_map = read_shadow_passwords()
    if shadow_map is not None and username in shadow_map:
        field = shadow_map[username]
        return field.startswith("!") or field.startswith("*")
    flag = passwd_status_flag(username)
    return flag == "L"


def user_group_names(pw_entry):
    """主组 + 附加组名字列表。"""
    names = []
    try:
        names.append(grp.getgrgid(pw_entry.pw_gid).gr_name)
    except KeyError:
        pass
    try:
        for entry in grp.getgrall():
            if pw_entry.pw_name in entry.gr_mem and entry.gr_name not in names:
                names.append(entry.gr_name)
    except OSError:  # pragma: no cover - NSS 异常
        pass
    return names


def has_privileged_group(group_names):
    return bool(PRIVILEGED_GROUPS.intersection(group_names))


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------


def validate_username(username):
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise ProvisionError("INVALID", "用户名不合法")


def validate_real_name(real_name):
    normalized, error = pinyin_util.normalize_real_name(real_name)
    if error or not normalized:
        raise ProvisionError("INVALID", error or "姓名不合法")
    return normalized


def validate_password(password, username):
    ok, error = security.validate_password(password, username)
    if not ok:
        raise ProvisionError("INVALID", error or "密码不合法")
    if any(ch in password for ch in (":", "\n", "\r", " ", "\t", "\x00")):
        raise ProvisionError("INVALID", "密码包含不允许的字符")
    return password


def _expect_string(value, field_name, max_len=4096):
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise ProvisionError("INVALID", "%s 不合法" % field_name)
    return value


def _expect_bool(value, field_name):
    if not isinstance(value, bool):
        raise ProvisionError("INVALID", "%s 必须是布尔值" % field_name)
    return value


def _expect_int(value, field_name):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProvisionError("INVALID", "%s 必须是整数" % field_name)
    return value


def ensure_managed_user(username):
    """管理操作的通用安全检查：存在、uid>=1000、非保护名单、非特权组。"""
    validate_username(username)
    if username in PROTECTED_USERNAMES:
        raise ProvisionError("INVALID", "该账号受保护，禁止操作")
    pw_entry = get_pw_entry(username)
    if pw_entry is None:
        raise ProvisionError("INVALID", "用户不存在")
    if pw_entry.pw_uid < 1000:
        raise ProvisionError("INVALID", "该账号为系统账号，禁止操作")
    groups = user_group_names(pw_entry)
    if has_privileged_group(groups):
        raise ProvisionError("INVALID", "该账号属于特权组，禁止操作")
    return pw_entry, groups


# ---------------------------------------------------------------------------
# 操作实现
# ---------------------------------------------------------------------------


def _remove_user_best_effort(username):
    try:
        if get_pw_entry(username) is not None:
            proc = run_command(["userdel", "--remove", username], timeout=COMMAND_TIMEOUT)
            if proc.returncode != 0:
                log(
                    "rollback_failed",
                    username=username,
                    returncode=proc.returncode,
                )
                return False
            return True
    except ProvisionError:
        log("rollback_failed", username=username)
    return False


def _verify_created_user(username, pw_entry, home):
    if not os.path.isdir(home):
        raise ProvisionError("INTERNAL", "内部错误", detail="家目录不存在: %s" % home)
    stat_info = os.stat(home)
    if stat_info.st_uid != pw_entry.pw_uid or stat_info.st_gid != pw_entry.pw_gid:
        try:
            os.chown(home, pw_entry.pw_uid, pw_entry.pw_gid)
        except OSError as exc:
            raise ProvisionError("INTERNAL", "内部错误", detail="家目录属主修正失败: %s" % exc)
        stat_info = os.stat(home)
    if not os.path.isdir(home):
        raise ProvisionError("INTERNAL", "内部错误", detail="家目录不是目录")
    if (stat_info.st_mode & 0o777) != 0o750:
        raise ProvisionError("INTERNAL", "内部错误", detail="家目录权限不是 0750")
    if stat_info.st_uid != pw_entry.pw_uid or stat_info.st_gid != pw_entry.pw_gid:
        raise ProvisionError("INTERNAL", "内部错误", detail="家目录属主不正确")
    flag = passwd_status_flag(username)
    if flag != "P":
        raise ProvisionError("INTERNAL", "内部错误", detail="密码状态异常: %s" % flag)
    groups = user_group_names(pw_entry)
    if has_privileged_group(groups):
        raise ProvisionError("INTERNAL", "内部错误", detail="用户属于特权组")


def op_create_user(request, config):
    deadline = time.monotonic() + float(config.get("timeout_seconds", 30))
    username = _expect_string(request.get("username"), "用户名", 64)
    real_name = _expect_string(request.get("real_name"), "姓名", 256)
    password = _expect_string(request.get("password"), "密码", 256)

    validate_username(username)
    normalized_name = validate_real_name(real_name)
    validate_password(password, username)

    if username_exists(username):
        raise ProvisionError("EXISTS", "用户或用户组已存在")

    home_path = "/home/%s" % username
    created = False
    try:
        proc = _run_with_deadline(
            [
                "useradd",
                "--create-home",
                "--user-group",
                "--shell",
                "/bin/bash",
                "--comment",
                normalized_name,
                "--",
                username,
            ],
            deadline,
        )
        if proc.returncode != 0:
            # useradd 可能已部分创建用户/同名组，尽力清理后再返回 INTERNAL
            _remove_user_best_effort(username)
            raise ProvisionError(
                "INTERNAL",
                "内部错误",
                detail="useradd failed rc=%s stderr=%s"
                % (proc.returncode, (proc.stderr or "").strip()[:300]),
            )
        created = True

        # 密码只经 stdin 交给 chpasswd，绝不出现在 argv
        proc = _run_with_deadline(
            ["chpasswd"], deadline, stdin_text="%s:%s\n" % (username, password)
        )
        if proc.returncode != 0:
            raise ProvisionError(
                "INTERNAL",
                "内部错误",
                detail="chpasswd failed rc=%s stderr=%s"
                % (proc.returncode, (proc.stderr or "").strip()[:300]),
            )

        pw_entry = get_pw_entry(username)
        if pw_entry is None:
            raise ProvisionError("INTERNAL", "内部错误", detail="useradd 后仍找不到用户")
        home = pw_entry.pw_dir or home_path
        home_path = home
        if not os.path.isdir(home):
            raise ProvisionError("INTERNAL", "内部错误", detail="useradd 未创建家目录")
        try:
            os.chmod(home, 0o750)
        except OSError as exc:
            raise ProvisionError("INTERNAL", "内部错误", detail="chmod 失败: %s" % exc)
        _verify_created_user(username, pw_entry, home)
    except Exception:
        if created:
            _remove_user_best_effort(username)
        raise

    log("create_user", username=username, uid=pw_entry.pw_uid, result="ok")
    return {
        "ok": True,
        "username": username,
        "uid": pw_entry.pw_uid,
        "gid": pw_entry.pw_gid,
        "home": home_path,
        "workspace": home_path,
        "real_name": normalized_name,
    }


def op_user_status(request):
    usernames = request.get("usernames")
    if not isinstance(usernames, list) or not usernames:
        raise ProvisionError("INVALID", "usernames 必须是非空数组")
    if len(usernames) > MAX_STATUS_USERS:
        raise ProvisionError("INVALID", "单次最多查询 %d 个用户名" % MAX_STATUS_USERS)
    for username in usernames:
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ProvisionError("INVALID", "用户名不合法")

    shadow_map = read_shadow_passwords()
    users = {}
    # 去重但保持稳定顺序
    for username in usernames:
        if username in users:
            continue
        pw_entry = get_pw_entry(username)
        if pw_entry is None:
            users[username] = {"exists": False}
            continue
        groups = user_group_names(pw_entry)
        users[username] = {
            "exists": True,
            "uid": pw_entry.pw_uid,
            "gid": pw_entry.pw_gid,
            "home": pw_entry.pw_dir,
            "locked": is_user_locked(username, shadow_map),
            "groups": groups,
            "privileged": has_privileged_group(groups),
        }
    return {"ok": True, "users": users}


def _is_manageable_password_account(username, pw_entry):
    """SPEC §22.3 / §6.4：uid>=1000、非保护名单、非特权组的普通账号才可管理。"""
    if username in PROTECTED_USERNAMES:
        return False
    if pw_entry.pw_uid < MIN_MANAGED_UID:
        return False
    if has_privileged_group(user_group_names(pw_entry)):
        return False
    return True


def op_list_users(request):
    """SPEC §22.3：列出 uid>=1000 且 <65000 的普通用户（最多 500）。

    字段：username/uid/gid/home/shell/real_name(gECOS)/groups/privileged/locked。
    """
    shadow_map = read_shadow_passwords()
    entries = []
    for pw_entry in pwd.getpwall():
        uid = pw_entry.pw_uid
        if uid < MIN_MANAGED_UID or uid >= MAX_MANAGED_UID:
            continue
        groups = user_group_names(pw_entry)
        entries.append(
            {
                "username": pw_entry.pw_name,
                "uid": uid,
                "gid": pw_entry.pw_gid,
                "home": pw_entry.pw_dir,
                "shell": pw_entry.pw_shell,
                "real_name": pw_entry.pw_gecos or "",
                "groups": groups,
                "privileged": has_privileged_group(groups),
                "locked": is_user_locked(pw_entry.pw_name, shadow_map),
            }
        )
        if len(entries) >= MAX_LIST_USERS:
            break
    entries.sort(key=lambda item: item["uid"])
    return {"ok": True, "users": entries}


def op_verify_password(request, config):
    """SPEC §22.3：校验指定用户当前服务器密码（crypt + 常量时间比较）。

    返回 ``{ok, exists, manageable, locked}``；不存在/不可管理时 manageable=false，
    调用方统一提示 INVALID_CREDENTIALS，避免账号枚举。绝不记录密码。
    """
    deadline = time.monotonic() + float(config.get("timeout_seconds", 30))
    username = _expect_string(request.get("username"), "用户名", 64)
    password = _expect_string(request.get("password"), "密码", 256)
    validate_username(username)

    pw_entry = get_pw_entry(username)
    if pw_entry is None:
        return {"ok": True, "exists": False, "manageable": False, "locked": False}
    manageable = _is_manageable_password_account(username, pw_entry)
    shadow_map = read_shadow_passwords()
    locked = is_user_locked(username, shadow_map)
    stored_hash = ""
    if shadow_map is not None:
        stored_hash = shadow_map.get(username, "") or ""
    # 锁定账号的 shadow 字段形如 "!$y$..."；去掉前导 ! 后再校验哈希
    candidate_hash = stored_hash.lstrip("!")
    matched = False
    if _crypt is None or not candidate_hash or candidate_hash.startswith("*"):
        matched = False
    elif _remaining(deadline) <= 0:
        raise ProvisionError("INTERNAL", "内部错误", detail="密码校验超时")
    else:
        try:
            computed = _crypt.crypt(password, candidate_hash)
        except (ValueError, OSError):
            computed = None
        if computed:
            matched = hmac.compare_digest(
                str(computed).encode("utf-8"), candidate_hash.encode("utf-8")
            )
    log(
        "verify_password",
        username=username,
        manageable=manageable,
        matched=matched,
        result="ok",
    )
    return {
        "ok": True,
        "exists": True,
        "manageable": bool(manageable and matched),
        "locked": locked,
    }


def op_reset_password(request, config):
    deadline = time.monotonic() + float(config.get("timeout_seconds", 30))
    username = _expect_string(request.get("username"), "用户名", 64)
    password = _expect_string(request.get("password"), "密码", 256)
    validate_username(username)
    validate_password(password, username)
    pw_entry, _groups = ensure_managed_user(username)

    locked_before = is_user_locked(username, read_shadow_passwords())
    proc = _run_with_deadline(
        ["chpasswd"], deadline, stdin_text="%s:%s\n" % (username, password)
    )
    if proc.returncode != 0:
        raise ProvisionError(
            "INTERNAL",
            "内部错误",
            detail="chpasswd failed rc=%s stderr=%s"
            % (proc.returncode, (proc.stderr or "").strip()[:300]),
        )
    # chpasswd 会清除 shadow 中的 ! 前缀；保持原有锁定状态不变
    if locked_before:
        proc = _run_with_deadline(["usermod", "--lock", username], deadline)
        if proc.returncode != 0:
            raise ProvisionError("INTERNAL", "内部错误", detail="重新锁定失败")
        if not is_user_locked(username, read_shadow_passwords()):
            raise ProvisionError("INTERNAL", "内部错误", detail="重新锁定校验失败")
    else:
        flag = passwd_status_flag(username)
        if flag == "L":
            raise ProvisionError("INTERNAL", "内部错误", detail="密码更新后状态异常")

    log("reset_password", username=username, uid=pw_entry.pw_uid, result="ok")
    return {"ok": True, "username": username}


def op_set_lock(request, config):
    deadline = time.monotonic() + float(config.get("timeout_seconds", 30))
    username = _expect_string(request.get("username"), "用户名", 64)
    locked = _expect_bool(request.get("locked"), "locked")
    validate_username(username)
    pw_entry, _groups = ensure_managed_user(username)

    cmd = "usermod"
    proc = _run_with_deadline([cmd, "--lock" if locked else "--unlock", username], deadline)
    if proc.returncode != 0:
        raise ProvisionError(
            "INTERNAL",
            "内部错误",
            detail="usermod failed rc=%s stderr=%s"
            % (proc.returncode, (proc.stderr or "").strip()[:300]),
        )
    actual = is_user_locked(username, read_shadow_passwords())
    if actual != locked:
        raise ProvisionError("INTERNAL", "内部错误", detail="锁定状态校验失败")

    log("set_lock", username=username, uid=pw_entry.pw_uid, locked=locked, result="ok")
    return {"ok": True, "username": username, "locked": locked}


def dispatch(request, config):
    if not isinstance(request, dict):
        return {
            "ok": False,
            "error": {"code": "INVALID", "message": "请求必须是 JSON 对象"},
        }
    op = request.get("op")
    if not isinstance(op, str):
        return {"ok": False, "error": {"code": "INVALID", "message": "缺少 op 字段"}}

    # SPEC §22.3 / §22.6：彻底禁用删除用户（web 路由已移除，这里双重禁用）
    if op == "delete_user":
        log("delete_user", result="disabled")
        return {
            "ok": False,
            "error": {"code": "INVALID", "message": "删除用户功能已禁用"},
        }

    try:
        if op == "ping":
            return {"ok": True}
        if op == "create_user":
            return op_create_user(request, config)
        if op == "user_status":
            return op_user_status(request)
        if op == "list_users":
            return op_list_users(request)
        if op == "verify_password":
            return op_verify_password(request, config)
        if op == "reset_password":
            return op_reset_password(request, config)
        if op == "set_lock":
            return op_set_lock(request, config)
        return {"ok": False, "error": {"code": "INVALID", "message": "未知操作"}}
    except ProvisionError as exc:
        if exc.code == "INTERNAL":
            log("operation_failed", op=op, detail=exc.detail or exc.message)
        return {
            "ok": False,
            "error": {"code": exc.code, "message": exc.message},
        }
    except Exception as exc:  # pragma: no cover - 兜底，绝不泄露细节
        log("operation_crashed", op=op, detail=repr(exc)[:300])
        return {
            "ok": False,
            "error": {"code": "INTERNAL", "message": "服务器内部错误"},
        }


# ---------------------------------------------------------------------------
# Unix socket 服务
# ---------------------------------------------------------------------------


def peer_uid(connection):
    """Linux SO_PEERCRED -> uid；不可用返回 None。"""
    option = getattr(socket, "SO_PEERCRED", None)
    if option is None:
        return None
    try:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, option, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return uid
    except OSError:
        return None


class ProvisionerServer(object):
    def __init__(self, socket_path, allowed_peer_uid, timeout_seconds, group_name):
        self.socket_path = socket_path
        self.allowed_peer_uid = allowed_peer_uid
        self.timeout_seconds = timeout_seconds
        self.group_name = group_name
        self.config = {"timeout_seconds": timeout_seconds}
        self.sock = None

    def setup(self):
        parent = os.path.dirname(self.socket_path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        try:
            gid = grp.getgrnam(self.group_name).gr_gid
        except KeyError:
            raise SystemExit("找不到用户组 %s，无法设置 socket 属组" % self.group_name)
        old_umask = os.umask(0o077)
        try:
            try:
                os.unlink(self.socket_path)
            except FileNotFoundError:
                pass
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.bind(self.socket_path)
            self.sock.listen(16)
            os.chmod(self.socket_path, 0o660)
            try:
                os.chown(self.socket_path, -1, gid)
            except PermissionError:
                raise SystemExit("无法把 socket 属组改为 %s（需要 root）" % self.group_name)
        finally:
            os.umask(old_umask)

    def cleanup(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        except OSError:
            pass
        log("stop", socket=self.socket_path)

    def _send(self, connection, payload):
        """发送一行 JSON；返回 False 表示连接已断开（绝不向调用方抛异常）。"""
        try:
            data = json.dumps(
                payload, ensure_ascii=False, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError):
            data = json.dumps(
                {
                    "ok": False,
                    "error": {"code": "INTERNAL", "message": "服务器内部错误"},
                },
                ensure_ascii=False,
            ).encode("utf-8")
        try:
            connection.sendall(data + b"\n")
            return True
        except OSError as exc:  # BrokenPipeError / ConnectionResetError 等
            log("send_failed", detail=type(exc).__name__)
            return False

    @staticmethod
    def _invalid_payload(message):
        return {"ok": False, "error": {"code": "INVALID", "message": message}}

    def handle_connection(self, connection):
        """处理单个连接；任何异常只影响该连接，绝不能退出 root 服务。"""
        try:
            uid = peer_uid(connection)
            if uid is None or uid != self.allowed_peer_uid:
                log("peer_rejected", peer_uid=("unknown" if uid is None else uid))
                return
            try:
                connection.settimeout(float(self.timeout_seconds) + 5.0)
            except OSError:
                pass
            buffer = b""
            while not _STOP_EVENT.is_set():
                try:
                    chunk = connection.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                if len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
                    self._send(connection, self._invalid_payload("请求过长"))
                    return
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    if not line.strip():
                        continue
                    if len(line) > MAX_LINE_BYTES:
                        if not self._send(connection, self._invalid_payload("请求过长")):
                            return
                        continue
                    try:
                        request = json.loads(line.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError):
                        if not self._send(
                            connection, self._invalid_payload("请求 JSON 格式错误")
                        ):
                            return
                        continue
                    try:
                        response = dispatch(request, self.config)
                    except Exception as exc:  # 兜底：单条请求异常不退出服务
                        log("dispatch_crashed", detail=type(exc).__name__)
                        response = {
                            "ok": False,
                            "error": {"code": "INTERNAL", "message": "服务器内部错误"},
                        }
                    if not self._send(connection, response):
                        return
        except Exception as exc:  # 连接级兜底（如 SO_PEERCRED/结构异常）
            log("connection_failed", detail=type(exc).__name__)

    def serve_forever(self):
        self.sock.settimeout(0.5)
        while not _STOP_EVENT.is_set():
            try:
                connection, _addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if _STOP_EVENT.is_set() or self.sock is None:
                    break
                # 单次 accept 失败（EMFILE/连接中断等）不应退出 root 服务
                log("accept_failed", detail=type(exc).__name__)
                time.sleep(0.1)
                continue
            try:
                self.handle_connection(connection)
            except Exception as exc:  # noqa: BLE001 - 单连接故障续命
                log("connection_failed", detail=type(exc).__name__)
            finally:
                try:
                    connection.close()
                except OSError:
                    pass


def _install_signal_handlers():
    def _handle(_signum, _frame):
        _STOP_EVENT.set()

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)


def main(argv=None):
    parser = argparse.ArgumentParser(description="campus-signup root provisioner")
    parser.add_argument("--config", required=True, help="配置文件路径")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    prov_config = config.get("provisioner") or {}
    socket_path = prov_config.get("socket")
    if not isinstance(socket_path, str) or not socket_path:
        raise SystemExit("配置缺少 provisioner.socket")
    try:
        allowed_peer_uid = int(prov_config.get("allowed_peer_uid"))
    except (TypeError, ValueError):
        raise SystemExit("配置 provisioner.allowed_peer_uid 必须是整数")
    try:
        timeout_seconds = float(prov_config.get("timeout_seconds", 30))
    except (TypeError, ValueError):
        raise SystemExit("配置 provisioner.timeout_seconds 必须是数字")
    group_name = prov_config.get("group") or "signupapp"

    _install_signal_handlers()
    server = ProvisionerServer(
        socket_path, allowed_peer_uid, timeout_seconds, group_name
    )
    try:
        server.setup()
    except SystemExit:
        raise
    except OSError as exc:
        raise SystemExit("无法监听 %s: %s" % (socket_path, exc))
    log(
        "start",
        socket=socket_path,
        allowed_peer_uid=allowed_peer_uid,
    )
    try:
        server.serve_forever()
    finally:
        server.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
