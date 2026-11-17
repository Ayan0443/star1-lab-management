#!/usr/bin/env bash
# campus-signup 安装/升级脚本（在 star1 上以 root 运行）
# 用法：
#   tar xzf campus-signup-*.tar.gz -C /tmp/campus-signup-pkg
#   cd /tmp/campus-signup-pkg && sudo bash deploy/install.sh
set -euo pipefail

PKG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="/opt/campus-signup"
ETC_DIR="/etc/campus-signup"
TLS_DIR="$ETC_DIR/tls"
DATA_DIR="/var/lib/campus-signup"
SVC_USER="signupapp"
SVC_GROUP="signupapp"

log()  { printf '[install] %s\n' "$*"; }
die()  { printf '[install][ERROR] %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "请用 root 运行：sudo bash deploy/install.sh"
for c in python3 openssl curl systemctl useradd groupadd getent ss systemd-tmpfiles; do
  command -v "$c" >/dev/null 2>&1 || die "缺少命令：$c"
done
[ -f "$PKG_DIR/deploy/config.example.json" ] || die "包不完整：缺少 deploy/config.example.json（请在解包后的项目根目录执行）"
[ -f "$PKG_DIR/app/server.py" ] || die "包不完整：缺少 app/server.py"

HTTPS_PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["server"]["ports"]["https"])' "$PKG_DIR/deploy/config.example.json")"
HTTP_PORT="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1],encoding="utf-8"))["server"]["ports"]["http"])' "$PKG_DIR/deploy/config.example.json")"

log "1/8 检查/创建服务账号 $SVC_USER"
if ! getent group "$SVC_GROUP" >/dev/null; then
  groupadd --system "$SVC_GROUP"; log "  创建组 $SVC_GROUP"
fi
if ! getent passwd "$SVC_USER" >/dev/null; then
  useradd --system --gid "$SVC_GROUP" --home-dir /nonexistent --no-create-home \
          --shell /usr/sbin/nologin "$SVC_USER"
  log "  创建用户 $SVC_USER"
fi
SVC_UID="$(id -u "$SVC_USER")"

log "2/8 安装代码到 $APP_DIR"
install -d -m 0755 -o root -g root "$APP_DIR"
rm -rf "$APP_DIR/app" "$APP_DIR/static" "$APP_DIR/vendor"
cp -a "$PKG_DIR/app" "$PKG_DIR/static" "$PKG_DIR/vendor" "$APP_DIR/"
install -d -m 0755 -o root -g root "$APP_DIR/deploy"
install -m 0755 "$PKG_DIR/deploy/configure-email.py" "$APP_DIR/deploy/configure-email.py"
find "$APP_DIR" -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
chown -R root:root "$APP_DIR"
chmod -R a+rX,go-w "$APP_DIR"

log "3/8 数据/配置目录权限"
install -d -m 0750 -o root -g "$SVC_GROUP" "$ETC_DIR" "$TLS_DIR"
install -d -m 0750 -o "$SVC_USER" -g "$SVC_GROUP" "$DATA_DIR"

log "4/8 生成/迁移配置"
CONFIG_OUT="$(python3 - "$PKG_DIR/deploy/config.example.json" "$PKG_DIR/deploy/announcement.default.txt" "$ETC_DIR/config.json" "$SVC_UID" <<'PY'
import json, pathlib, secrets, sys
tpl_path, ann_path, cfg_path, uid = sys.argv[1:5]
tpl = json.loads(pathlib.Path(tpl_path).read_text(encoding="utf-8"))
ann = pathlib.Path(ann_path).read_text(encoding="utf-8")
p = pathlib.Path(cfg_path)
new_token = False
if p.exists():
    cfg = json.loads(p.read_text(encoding="utf-8"))
else:
    cfg = {}
    new_token = True

def merge(dst, src):
    for k, v in src.items():
        if k not in dst:
            dst[k] = v
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            merge(dst[k], v)

merge(cfg, tpl)
tok = cfg.get("security", {}).get("admin_token", "")
if not tok or tok.startswith("<") or tok.startswith("__"):
    cfg.setdefault("security", {})["admin_token"] = secrets.token_urlsafe(32)
    new_token = True
cfg.setdefault("provisioner", {})["allowed_peer_uid"] = int(uid)
if not cfg.get("ui", {}).get("default_announcement"):
    cfg.setdefault("ui", {})["default_announcement"] = ann
if not cfg.get("email", {}).get("code_secret"):
    cfg.setdefault("email", {})["code_secret"] = secrets.token_hex(32)
p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print("NEW_TOKEN" if new_token else "TOKEN_KEPT")
PY
)" || die "配置生成失败"
chown root:"$SVC_GROUP" "$ETC_DIR/config.json"
chmod 0640 "$ETC_DIR/config.json"
log "  $CONFIG_OUT"

log "5/8 自签名 TLS 证书"
if [ ! -f "$TLS_DIR/server.crt" ] || [ ! -f "$TLS_DIR/server.key" ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
    -subj "/CN=10.0.0.10" \
    -addext "subjectAltName=IP:10.0.0.10,IP:127.0.0.1,DNS:localhost" \
    -keyout "$TLS_DIR/server.key" -out "$TLS_DIR/server.crt" >/dev/null 2>&1 \
    || die "openssl 生成证书失败"
  log "  已生成自签名证书（浏览器首次访问需手动信任一次）"
else
  log "  已存在证书，保留"
fi
chown root:"$SVC_GROUP" "$TLS_DIR/server.key" "$TLS_DIR/server.crt"
chmod 0640 "$TLS_DIR/server.key"
chmod 0644 "$TLS_DIR/server.crt"
chmod 0750 "$TLS_DIR"

log "6/8 安装 systemd / tmpfiles 配置"
install -m 0644 "$PKG_DIR/deploy/campus-signup.tmpfiles.conf" /etc/tmpfiles.d/campus-signup.conf
systemd-tmpfiles --create /etc/tmpfiles.d/campus-signup.conf
install -m 0644 "$PKG_DIR/deploy/campus-signup-provisioner.service" /etc/systemd/system/campus-signup-provisioner.service
install -m 0644 "$PKG_DIR/deploy/campus-signup-web.service" /etc/systemd/system/campus-signup-web.service
systemctl daemon-reload
systemctl enable campus-signup-provisioner.service campus-signup-web.service >/dev/null 2>&1

log "7/8 启动服务"
for p in "$HTTPS_PORT" "$HTTP_PORT"; do
  if ss -tln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$p$"; then
    if ! systemctl is-active --quiet campus-signup-web.service; then
      die "端口 $p 已被其他进程占用，请先释放（ss -tlnp | grep :$p）"
    fi
  fi
done
systemctl restart campus-signup-provisioner.service
for _ in $(seq 1 50); do [ -S /run/campus-signup/provision.sock ] && break; sleep 0.2; done
if [ ! -S /run/campus-signup/provision.sock ]; then
  journalctl -u campus-signup-provisioner -n 40 --no-pager 2>/dev/null || true
  die "provisioner socket 未就绪"
fi
systemctl restart campus-signup-web.service

log "8/8 健康检查"
BIND_HOST="$(python3 -c 'import json;print(json.load(open("/etc/campus-signup/config.json",encoding="utf-8"))["server"]["bind"])')"
HEALTH_HOST="$BIND_HOST"
[ "$BIND_HOST" = "0.0.0.0" ] && HEALTH_HOST="127.0.0.1"
ok=0
for _ in $(seq 1 40); do
  if curl -ks --max-time 2 "https://${HEALTH_HOST}:${HTTPS_PORT}/healthz" 2>/dev/null | grep -q '"ok"'; then ok=1; break; fi
  sleep 0.5
done
if [ "$ok" -ne 1 ]; then
  echo '--- provisioner 日志 ---'; journalctl -u campus-signup-provisioner -n 40 --no-pager 2>/dev/null || true
  echo '--- web 日志 ---';        journalctl -u campus-signup-web -n 60 --no-pager 2>/dev/null || true
  systemctl --no-pager --lines=10 status campus-signup-provisioner.service campus-signup-web.service 2>/dev/null || true
  die "健康检查失败"
fi

TOKEN_SHOW="$(python3 -c 'import json;print(json.load(open("/etc/campus-signup/config.json",encoding="utf-8"))["security"]["admin_token"])')"
echo
echo "========================= 安装完成 ========================="
echo " 校内访问（HTTPS）: https://10.0.0.10:${HTTPS_PORT}/"
echo " 校内访问（HTTP） : http://10.0.0.10:${HTTP_PORT}/   （自动跳转 HTTPS）"
echo " 管理后台         : https://10.0.0.10:${HTTPS_PORT}/admin"
echo " 管理员 token     : ${TOKEN_SHOW}"
echo " 邮箱验证         : $(python3 -c 'import json;c=json.load(open("/etc/campus-signup/config.json"))["email"];print("enabled" if c.get("enabled") else "disabled", "| smtp:", c.get("smtp",{}).get("host",""), "| 发件:", c.get("smtp",{}).get("from_addr") or "未配置")')"
echo "   （SMTP 账号密码需另行注入：sudo python3 /opt/campus-signup/deploy/configure-email.py）"
echo " 安全加固         : bind=${BIND_HOST} | admin CIDR=$(python3 -c 'import json;print(",".join(json.load(open("/etc/campus-signup/config.json"))["security"].get("admin_allowed_cidrs") or ["不限"]))') | query_token=$(python3 -c 'import json;print("允许(仅本机)" if json.load(open("/etc/campus-signup/config.json"))["security"].get("allow_query_token") else "禁用")')"
echo "                    （已写入 ${ETC_DIR}/config.json，权限 0640 root:${SVC_GROUP}）"
echo " 服务状态         : systemctl status campus-signup-web campus-signup-provisioner"
echo " 查看日志         : journalctl -u campus-signup-web -f"
echo "============================================================"
