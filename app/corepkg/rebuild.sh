#!/data/data/com.termux/files/usr/bin/bash
# 本地重新生成 main_app.c 并重打包 sdist(修改 src/main_app.py 后执行)
set -e
cd "$(dirname "$0")"
rm -f src/main_app.c
cython -3 --directive language_level=3 \
    src/main_app.py -o src/main_app.c
rm -rf dist wyapp_core.egg-info build
python3 setup.py sdist -q
echo "✓ dist/wyapp_core-1.0.tar.gz 已更新(含最新 main_app.c),提交后 CI 自动编译"
