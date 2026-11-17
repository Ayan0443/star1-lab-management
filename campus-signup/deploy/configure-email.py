#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""向 /etc/campus-signup/config.json 注入/更新邮箱验证与 SMTP 配置（需 root）。

凭据通过 stdin 传 JSON，避免出现在命令行/Shell 历史/仓库中：
    sudo python3 deploy/configure-email.py --config /etc/campus-signup/config.json <<'JSON'
    {
      "enabled": true,
      "allowed_domains": ["mails.example.edu.cn", "example.edu.cn"],
      "subject": "【star1 实验室服务器】账号申请验证码",
      "smtp": {
        "host": "mails.example.edu.cn",
        "port": 465,
        "security": "ssl",
        "username": "huagd25@mails.example.edu.cn",
        "password": "***",
        "from_addr": "huagd25@mails.example.edu.cn",
        "from_name": "star1 实验室服务器",
        "tls_verify": true
      }
    }
    JSON
    sudo systemctl restart campus-signup-web

查看当前非敏感配置：
    sudo python3 deploy/configure-email.py --show

安全说明：
* 只接受白名单字段（enabled/allowed_domains/subject/code_ttl_seconds/resend_cooldown_seconds/
  max_verify_attempts/max_send_per_email_per_day/smtp{host,port,security,username,password,
  from_name,from_addr,tls_verify,timeout_seconds}）；
* 若配置缺少 code_secret 会自动生成 64 位 hex 随机密钥；
* 输出/日志只打印非敏感字段，绝不打印 SMTP 密码；
* 写入后文件属主 root:signupapp、权限 0640，原子替换。
"""

import argparse
import grp
import json
import os
import pathlib
import secrets
import sys
import tempfile

DEFAULT_CONFIG = "/etc/campus-signup/config.json"
GROUP = "signupapp"

TOP_KEYS = {
    "enabled",
    "allowed_domains",
    "subject",
    "code_ttl_seconds",
    "resend_cooldown_seconds",
    "max_verify_attempts",
    "max_send_per_email_per_day",
    "max_send_global_per_day",
    "smtp",
}
SMTP_KEYS = {
    "host",
    "port",
    "security",
    "username",
    "password",
    "from_name",
    "from_addr",
    "tls_verify",
    "timeout_seconds",
}


def die(msg):
    print("[configure-email][ERROR] " + msg, file=sys.stderr)
    sys.exit(1)


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError) as exc:
        die("无法读取配置 %s: %s" % (path, exc))
    if not isinstance(data, dict):
        die("配置文件必须是 JSON 对象")
    return data


def validate(payload):
    if not isinstance(payload, dict):
        die("stdin 必须是 JSON 对象")
    unknown = set(payload) - TOP_KEYS
    if unknown:
        die("不支持的字段: %s" % ", ".join(sorted(unknown)))
    email = payload
    if "enabled" in email and not isinstance(email["enabled"], bool):
        die("enabled 必须是布尔值")
    if "allowed_domains" in email:
        domains = email["allowed_domains"]
        if not isinstance(domains, list) or not domains or not all(
            isinstance(d, str) and d and " " not in d for d in domains
        ):
            die("allowed_domains 必须是非空字符串数组")
    if "subject" in email and not isinstance(email["subject"], str):
        die("subject 必须是字符串")
    for key in ("code_ttl_seconds", "resend_cooldown_seconds", "max_verify_attempts",
                "max_send_per_email_per_day"):
        if key in email and (not isinstance(email[key], int) or email[key] <= 0):
            die("%s 必须是正整数" % key)
    smtp = email.get("smtp")
    if smtp is not None:
        if not isinstance(smtp, dict):
            die("smtp 必须是对象")
        unknown = set(smtp) - SMTP_KEYS
        if unknown:
            die("smtp 不支持的字段: %s" % ", ".join(sorted(unknown)))
        if "port" in smtp and (not isinstance(smtp["port"], int) or not 1 <= smtp["port"] <= 65535):
            die("smtp.port 必须是 1-65535 的整数")
        if "security" in smtp and smtp["security"] not in ("ssl", "starttls", "none"):
            die("smtp.security 只能是 ssl/starttls/none")
        for key in ("host", "username", "password", "from_addr", "from_name"):
            if key in smtp and not isinstance(smtp[key], str):
                die("smtp.%s 必须是字符串" % key)
            if key in smtp and ("\n" in smtp[key] or "\r" in smtp[key]):
                die("smtp.%s 不能包含换行" % key)
        if "tls_verify" in smtp and not isinstance(smtp["tls_verify"], bool):
            die("smtp.tls_verify 必须是布尔值")


def write_config(path, cfg):
    path = pathlib.Path(path)
    directory = str(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".config.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(cfg, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o640)
        try:
            gid = grp.getgrnam(GROUP).gr_gid
            os.chown(tmp, 0, gid)
        except KeyError:
            os.chown(tmp, 0, 0)
            print("[configure-email][WARN] 找不到组 %s，文件保持 root:root 0640" % GROUP,
                  file=sys.stderr)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="配置 campus-signup 邮箱验证 / SMTP")
    parser.add_argument("--config", default=DEFAULT_CONFIG, help="配置文件路径")
    parser.add_argument("--show", action="store_true", help="只显示非敏感配置")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        die("请用 root 运行（sudo）")

    cfg = load(args.config)
    email = cfg.get("email") or {}
    if args.show:
        smtp = email.get("smtp") or {}
        print(json.dumps({
            "enabled": email.get("enabled"),
            "allowed_domains": email.get("allowed_domains"),
            "subject": email.get("subject"),
            "smtp": {
                "host": smtp.get("host"),
                "port": smtp.get("port"),
                "security": smtp.get("security"),
                "username": smtp.get("username"),
                "from_addr": smtp.get("from_addr"),
                "tls_verify": smtp.get("tls_verify"),
                "password_configured": bool(smtp.get("password")),
            },
            "code_secret_configured": bool(email.get("code_secret")),
        }, ensure_ascii=False, indent=2))
        return 0

    raw = sys.stdin.read().strip()
    if not raw:
        die("请通过 stdin 提供 JSON 配置")
    try:
        payload = json.loads(raw)
    except ValueError as exc:
        die("stdin 不是合法 JSON: %s" % exc)
    validate(payload)

    if not isinstance(cfg.get("email"), dict):
        cfg["email"] = {}
    target = cfg["email"]
    for key, value in payload.items():
        if key == "smtp":
            smtp = target.get("smtp") if isinstance(target.get("smtp"), dict) else {}
            smtp.update(value)
            target["smtp"] = smtp
        else:
            target[key] = value
    if not target.get("code_secret"):
        target["code_secret"] = secrets.token_hex(32)
    write_config(args.config, cfg)

    smtp = target.get("smtp") or {}
    print("[configure-email] 已写入 %s" % args.config)
    print("  enabled=%s allowed_domains=%s" % (target.get("enabled"), target.get("allowed_domains")))
    print("  smtp=%s:%s security=%s username=%s from=%s tls_verify=%s password=%s" % (
        smtp.get("host"), smtp.get("port"), smtp.get("security"), smtp.get("username"),
        smtp.get("from_addr"), smtp.get("tls_verify"),
        "已设置" if smtp.get("password") else "未设置"))
    print("  code_secret=%s" % ("已设置" if target.get("code_secret") else "未设置"))
    print("提示：修改后请重启服务：sudo systemctl restart campus-signup-web")
    return 0


if __name__ == "__main__":
    sys.exit(main())
