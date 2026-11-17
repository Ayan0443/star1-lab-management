#!/usr/bin/env bash
# 在本机（macOS）打包，供上传到 star1 安装
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-/tmp/campus-signup-$(date +%Y%m%d-%H%M%S).tar.gz}"

cd "$ROOT"
COPYFILE_DISABLE=1 tar --no-mac-metadata --exclude='__pycache__' --exclude='*.pyc' \
    --exclude='.DS_Store' -czf "$OUT" app static vendor deploy

echo "package : $OUT"
echo "size    : $(du -h "$OUT" | cut -f1)"
if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$OUT"; else sha256sum "$OUT"; fi
echo
echo "安装："
echo "  scp $OUT 10.0.0.10:/tmp/campus-signup-pkg.tar.gz"
echo "  ssh 10.0.0.10 'rm -rf /tmp/campus-signup-pkg && mkdir -p /tmp/campus-signup-pkg && tar xzf /tmp/campus-signup-pkg.tar.gz -C /tmp/campus-signup-pkg && sudo bash /tmp/campus-signup-pkg/deploy/install.sh'"
