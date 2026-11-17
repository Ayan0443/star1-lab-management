#!/usr/bin/env bash
# star1 GPU 预约台 —— 安装 / 升级脚本（在 star1 上以 root 运行）
#
#   sudo bash deploy/install.sh
#
# 复用 campus-signup 的账号体系（signupapp 账号 + provisioner + admin token + TLS 证书），
# 不改动、不重启 campus-signup 的任何服务。
set -euo pipefail

APP_DIR=/opt/star1-gpu-board
DATA_DIR=/var/lib/star1-gpu-board
CONF_DIR=/etc/star1-gpu-board
UNIT_PATH=/etc/systemd/system/star1-gpu-board.service
SVC_USER=signupapp
SVC_GROUP=signupapp
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "请用 root 运行：sudo bash deploy/install.sh"

# ---- 前置检查 -------------------------------------------------------------
getent passwd "$SVC_USER" >/dev/null || die "找不到 $SVC_USER 账号（需要先安装 campus-signup）"
getent group "$SVC_GROUP" >/dev/null || die "找不到 $SVC_GROUP 组"
[[ -f /etc/campus-signup/config.json ]] || die "找不到 /etc/campus-signup/config.json"
[[ -f "$PROJECT_ROOT/server.py" ]] || die "找不到 $PROJECT_ROOT/server.py"
[[ -d "$PROJECT_ROOT/static" ]] || die "找不到 $PROJECT_ROOT/static"

runuser -u "$SVC_USER" -- /usr/bin/python3 - <<'PY' || die "signupapp 账号读不到 campus-signup 配置 / TLS 证书 / provisioner socket"
import json, os
cfg = json.load(open("/etc/campus-signup/config.json"))
tls = cfg.get("tls") or {}
assert os.access("/etc/campus-signup/config.json", os.R_OK)
if tls.get("enabled"):
    assert os.access(tls["cert"], os.R_OK), "cert not readable"
    assert os.access(tls["key"], os.R_OK), "key not readable"
sock = (cfg.get("provisioner") or {}).get("socket")
assert sock and os.path.exists(sock), "provisioner socket missing"
PY

if ! command -v nvidia-smi >/dev/null 2>&1; then
  die "找不到 nvidia-smi（本服务只适用于 GPU 服务器）"
fi

# ---- 目录与文件 -----------------------------------------------------------
log "安装到 $APP_DIR"
install -d -m 0755 "$APP_DIR"
install -m 0644 "$PROJECT_ROOT/server.py" "$APP_DIR/server.py"
install -m 0644 "$PROJECT_ROOT/mcp_server.py" "$APP_DIR/mcp_server.py"
install -d -m 0755 "$APP_DIR/static"
for name in index.html admin.html style.css app.js admin.js favicon.svg; do
  [[ -f "$PROJECT_ROOT/static/$name" ]] || die "缺少 static/$name"
  install -m 0644 "$PROJECT_ROOT/static/$name" "$APP_DIR/static/$name"
done
if [[ -f "$PROJECT_ROOT/README.md" ]]; then
  install -m 0644 "$PROJECT_ROOT/README.md" "$APP_DIR/README.md"
fi

install -d -m 0755 "$CONF_DIR"
if [[ ! -f "$CONF_DIR/config.json" ]]; then
  install -m 0644 "$PROJECT_ROOT/deploy/config.example.json" "$CONF_DIR/config.json"
  log "写入默认配置 $CONF_DIR/config.json"
else
  log "保留已有配置 $CONF_DIR/config.json"
fi

install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$DATA_DIR"

install -m 0644 "$PROJECT_ROOT/deploy/star1-gpu-board.service" "$UNIT_PATH"

# ---- 启动 -----------------------------------------------------------------
systemctl daemon-reload
systemctl enable star1-gpu-board.service >/dev/null
systemctl restart star1-gpu-board.service

# ---- 健康检查 -------------------------------------------------------------
PORT="$(/usr/bin/python3 -c "import json;print(int(json.load(open('$CONF_DIR/config.json')).get('port',8083)))")"
TLS="$(/usr/bin/python3 -c "import json;print('1' if json.load(open('$CONF_DIR/config.json')).get('tls',True) else '0')")"
if [[ "$TLS" == "1" ]]; then
  URL="https://127.0.0.1:${PORT}/healthz"
  CURL_OPTS=(-k -s)
else
  URL="http://127.0.0.1:${PORT}/healthz"
  CURL_OPTS=(-s)
fi
ok=0
for _ in $(seq 1 20); do
  if curl "${CURL_OPTS[@]}" --max-time 3 "$URL" | grep -q '"ok": *true'; then
    ok=1
    break
  fi
  sleep 1
done

if [[ "$ok" != "1" ]]; then
  systemctl --no-pager status star1-gpu-board.service || true
  journalctl -u star1-gpu-board.service -n 30 --no-pager || true
  die "健康检查失败：$URL"
fi

log "服务已启动：$URL"
log "systemd 状态："
systemctl --no-pager --lines=0 status star1-gpu-board.service | sed 's/^/  /' || true
log "资源占用（systemd 统计）："
systemctl show star1-gpu-board.service -p MemoryCurrent -p MemoryMax -p CPUQuotaPerSecUSec 2>/dev/null | sed 's/^/  /'
log "完成。访问 https://<服务器IP>:${PORT}/ ，管理员入口 /admin 。"
