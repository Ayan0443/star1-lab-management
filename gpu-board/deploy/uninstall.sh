#!/usr/bin/env bash
# star1 GPU 预约台 —— 卸载脚本（在 star1 上以 root 运行）
#
#   sudo bash deploy/uninstall.sh          # 交互确认
#   sudo bash deploy/uninstall.sh --yes    # 不询问
#
# 只删除本服务自己的文件；不会影响 campus-signup、GPU 进程或其他服务。
set -euo pipefail

APP_DIR=/opt/star1-gpu-board
DATA_DIR=/var/lib/star1-gpu-board
CONF_DIR=/etc/star1-gpu-board
UNIT_PATH=/etc/systemd/system/star1-gpu-board.service

log() { printf '[uninstall] %s\n' "$*"; }
die() { printf '[uninstall] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo bash deploy/uninstall.sh"

# 安全校验：只允许删除固定路径
for path in "$APP_DIR" "$DATA_DIR" "$CONF_DIR"; do
  case "$path" in
    /opt/star1-gpu-board|/var/lib/star1-gpu-board|/etc/star1-gpu-board) ;;
    *) die "意外的路径，拒绝删除：$path" ;;
  esac
done

if [[ "${1:-}" != "--yes" ]]; then
  printf '将删除 %s、%s、%s 以及服务单元，确认？[y/N] ' "$APP_DIR" "$DATA_DIR" "$CONF_DIR"
  read -r answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { log "已取消"; exit 0; }
fi

systemctl disable --now star1-gpu-board.service 2>/dev/null || true
rm -f "$UNIT_PATH"
systemctl daemon-reload
rm -rf "$APP_DIR" "$DATA_DIR" "$CONF_DIR"
log "已删除服务、程序、数据与配置。"
