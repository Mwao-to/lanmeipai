#!/data/data/com.termux/files/usr/bin/bash
# ══════════════════════════════════════════════════════════════
# fetch-apk.sh — 拉取 lanmeipai 最新成功 CI 构建的 arm64 正式版 APK
# 用法:
#   fetch-apk.sh          直接取当前最新成功构建
#   fetch-apk.sh 600      先等 CI 完成(最多600秒,每15秒轮询),再取
# 流程: 最新成功 run → artifact(lanmeipai-arm64-apk) → 签名直链
#       → aria2c 16连接×32分段下载 → 解压 → ~/o/binsys.apk
# ══════════════════════════════════════════════════════════════
set -euo pipefail

REPO="Mwao-to/lanmeipai"
OUT="$HOME/o/binsys.apk"
TMP="$HOME/o/.apk-tmp.$$"
TOKEN="$(cat "$HOME/.gh_token")"
AUTH=(-H "Authorization: token $TOKEN")

py() { python3 -c "$1"; }

# ── 可选:等待最新 CI 运行结束 ──
if [ $# -ge 1 ]; then
    echo "⏳ 等待 CI 构建完成(最多 ${1}s)..."
    deadline=$(( $(date +%s) + $1 ))
    while :; do
        read -r status conclusion < <(curl -s "${AUTH[@]}" \
            "https://api.github.com/repos/$REPO/actions/runs?per_page=1" | py '
import sys, json
r = json.load(sys.stdin)["workflow_runs"][0]
print(r["status"], r.get("conclusion") or "-")')
        case "$status:$conclusion" in
            completed:success) echo "✓ CI 构建成功"; break ;;
            completed:*)       echo "‼️ CI 构建失败($conclusion)"; exit 1 ;;
        esac
        [ "$(date +%s)" -ge "$deadline" ] && { echo "‼️ 等待超时"; exit 1; }
        sleep 15
    done
fi

# ── 取最新成功 run 的 artifact ──
echo "→ 查询最新成功构建..."
read -r run_id run_name < <(curl -s "${AUTH[@]}" \
    "https://api.github.com/repos/$REPO/actions/runs?per_page=20&status=success" | py '
import sys, json
for r in json.load(sys.stdin)["workflow_runs"]:
    print(r["id"], r["display_title"].replace(" ", "_")); break')

ART_JSON=$(curl -s "${AUTH[@]}" \
    "https://api.github.com/repos/$REPO/actions/runs/$run_id/artifacts")
read -r art_id art_size art_expired < <(printf '%s' "$ART_JSON" | py '
import sys, json
a = json.load(sys.stdin)["artifacts"][0]
print(a["id"], a["size_in_bytes"], a["expired"])')
[ "$art_expired" = "False" ] || { echo "‼️ artifact 已过期,请重新触发构建"; exit 1; }
echo "→ run #$run_id ($run_name) artifact=$art_id ($(numfmt --to=iec $art_size 2>/dev/null || echo ${art_size}B))"

# ── 捕获签名直链(api.github.com 会 302 到带签名的对象存储) ──
SURL=$(curl -s -o /dev/null -w '%{redirect_url}' "${AUTH[@]}" \
    "https://api.github.com/repos/$REPO/actions/artifacts/$art_id/zip")
[ -n "$SURL" ] || { echo "‼️ 未获取到下载直链"; exit 1; }

# ── aria2 多线程下载(16连接×32分段,wget 不支持多线程故用 aria2c) ──
mkdir -p "$TMP"
aria2c -x16 -s32 -k1M --file-allocation=none -d "$TMP" -o artifact.zip "$SURL" 2>&1 | tail -4

# ── 解压并就位 ──
APK_NAME=$(unzip -l "$TMP/artifact.zip" | grep -o '[^ ]*\.apk$' | head -1)
unzip -o -q "$TMP/artifact.zip" -d "$TMP"
mkdir -p "$HOME/o"
mv "$TMP/$APK_NAME" "$OUT"
rm -rf "$TMP"
echo "════════════════════════════════════"
echo "✓ $OUT ($(numfmt --to=iec "$(stat -c%s "$OUT")"))"
sha256sum "$OUT" | cut -c1-16 | sed 's/^/  sha256: /'
