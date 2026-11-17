#!/usr/bin/env bash
# 一键运行 campus-signup 全部本地测试（单元测试 + mock 模式端到端黑盒测试）。
#
# 用法：
#   ./tests/run_all.sh                 # 用默认 python3
#   PYTHON=/usr/bin/python3 ./tests/run_all.sh
#
# 行为：
#   - 在项目根目录执行 `python3 -m unittest discover -s tests -v`；
#   - app/ 关键文件缺失时直接退出 2（不把「跳过」误报成通过）；
#   - 结束后终止残留 server 子进程临时目录并清理 /tmp/campus-signup-qa-*；
#   - 不生成 __pycache__（PYTHONDONTWRITEBYTECODE=1）。

set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "错误：找不到 Python 解释器：$PYTHON" >&2
    exit 1
fi

export PYTHONDONTWRITEBYTECODE=1
# 本次测试 run 的唯一 tag：并发跑测试时只清理自己产生的临时目录/进程
export QA_RUN_TAG="$$"

cleanup() {
    # 兜底清理：正常情况下每个 mock server 的 tearDownClass 已清理自身临时目录。
    local dir
    local tmp_root="${TMPDIR:-/tmp}"
    tmp_root="${tmp_root%/}"
    # 若测试进程被中断，可能有遗留 server 子进程；只匹配本项目 QA 临时配置路径
    if command -v pkill >/dev/null 2>&1; then
        pkill -f "campus-signup/app/server.py --config ${tmp_root}/campus-signup-qa-${QA_RUN_TAG}-" 2>/dev/null || true
        pkill -f "campus-signup/app/server.py --config ${tmp_root}/csqa-${QA_RUN_TAG}-" 2>/dev/null || true
    fi
    for dir in "${tmp_root}"/campus-signup-qa-"${QA_RUN_TAG}"-* "${tmp_root}"/csqa-"${QA_RUN_TAG}"-*; do
        if [ -e "$dir" ]; then
            rm -rf -- "$dir"
        fi
    done
}
trap cleanup EXIT INT TERM

# 跑测试遗留的 app/server.py 子进程：由测试自身 terminate；此处仅提示，不强杀。
missing_app=0
for file in app/server.py app/pinyin_util.py app/security.py; do
    if [ ! -f "$file" ]; then
        echo "错误：缺少 $file，后端尚未就绪，测试无法执行。" >&2
        missing_app=1
    fi
done
if [ "$missing_app" -ne 0 ]; then
    echo "（等 backend 完成后重试；task-3 仍为等待执行状态）" >&2
    exit 2
fi

for file in static/index.html static/admin.html static/app.js static/admin.js; do
    if [ ! -f "$file" ]; then
        echo "警告：缺少 $file，静态页面相关测试预计失败（等待 frontend 完成）。" >&2
    fi
done

echo "==> 项目根：$ROOT"
echo "==> Python：$PYTHON ($("$PYTHON" --version 2>&1))"
echo "==> 运行：$PYTHON -m unittest discover -s tests -v"
echo

"$PYTHON" -m unittest discover -s tests -v
status=$?

cleanup
trap - EXIT INT TERM

if [ "$status" -eq 0 ]; then
    echo
    echo "==> 全部测试通过"
else
    echo
    echo "==> 测试失败（退出码 ${status}）" >&2
fi
exit "$status"
