#!/usr/bin/env bash
# campus-signup 卸载脚本（root）
#   sudo bash deploy/uninstall.sh           # 停服务、删代码，保留配置与数据库
#   sudo bash deploy/uninstall.sh --purge   # 另外删除配置、数据库与 signupapp 系统账号
# 注意：自助创建的普通用户账号不会被自动删除，如需删除请手工 userdel -r <用户名>。
set -euo pipefail

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

[ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo bash deploy/uninstall.sh" >&2; exit 1; }

systemctl disable --now campus-signup-web.service campus-signup-provisioner.service 2>/dev/null || true
rm -f /etc/systemd/system/campus-signup-web.service /etc/systemd/system/campus-signup-provisioner.service
systemctl daemon-reload 2>/dev/null || true
rm -f /etc/tmpfiles.d/campus-signup.conf
rm -rf /run/campus-signup
rm -rf /opt/campus-signup

if [ "$PURGE" -eq 1 ]; then
  read -r -p "确认删除 /etc/campus-signup、/var/lib/campus-signup 以及 signupapp 系统账号？[y/N] " ans
  if [ "${ans:-N}" = "y" ] || [ "${ans:-N}" = "Y" ]; then
    rm -rf /etc/campus-signup /var/lib/campus-signup
    userdel signupapp 2>/dev/null || true
    groupdel signupapp 2>/dev/null || true
    echo "已完全清理（自助创建的普通用户未删除）"
  else
    echo "已取消 purge，保留配置与数据库"
  fi
else
  echo "已卸载服务与代码；保留 /etc/campus-signup 与 /var/lib/campus-signup（--purge 可删除）"
fi

echo "提示：自助创建的普通用户仍在 /etc/passwd 中，可执行 sudo userdel -r <用户名> 逐个清理。"
