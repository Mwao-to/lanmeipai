#!/usr/bin/env python3
"""GitHub 清理:删旧工作流运行(连带产物)、旧Release及旧tag,只留最新"""
import json, time, sys, urllib.request

TOKEN = open('/data/data/com.termux/files/home/.gh_token').read().strip()
REPO = 'Mwao-to/lanmeipai'
KEEP_RUN = 32751436709        # v3.67最新成功构建
KEEP_RELEASE = 375394476      # v3.66(现存最新Release)
BASE = f'https://api.github.com/repos/{REPO}'

def req(method, path):
    r = urllib.request.Request(BASE + path, method=method, headers={
        'Authorization': f'token {TOKEN}', 'Accept': 'application/vnd.github+json',
        'User-Agent': 'cleanup-script'})
    try:
        with urllib.request.urlopen(r) as resp:
            body = resp.read()
            return resp.status, json.loads(body) if body else None
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]

# ── 1) 删除旧工作流运行 ──
runs, page = [], 1
while True:
    st, d = req('GET', f'/actions/runs?per_page=100&page={page}')
    if st != 200 or not d.get('workflow_runs'): break
    runs += [r['id'] for r in d['workflow_runs']]
    if len(d['workflow_runs']) < 100: break
    page += 1
old = [i for i in runs if i != KEEP_RUN]
print(f'工作流运行共{len(runs)}个,删除{len(old)}个旧运行(保留{KEEP_RUN})')
ok = fail = 0
for i, rid in enumerate(old, 1):
    st, _ = req('DELETE', f'/actions/runs/{rid}')
    ok += st in (204, 404); fail += st not in (204, 404)
    if st not in (204, 404): print(f'  ✗ run {rid}: HTTP {st}')
    if i % 20 == 0: print(f'  进度 {i}/{len(old)}')
    time.sleep(0.4)
print(f'✓ 运行删除完成: 成功/已消失 {ok}, 失败 {fail}')

# ── 2) 删除旧Release并收集其tag ──
st, rels = req('GET', '/releases?per_page=100')
rels = [r for r in rels if r['id'] != KEEP_RELEASE]
print(f'Release共{len(rels)+1}个,删除{len(rels)}个旧Release(保留v3.66)')
old_tags = []
for i, r in enumerate(rels, 1):
    st, _ = req('DELETE', f'/releases/{r["id"]}')
    if st == 204:
        old_tags.append(r['tag_name'])
    else:
        print(f'  ✗ release {r["tag_name"]}: HTTP {st}')
    if i % 10 == 0: print(f'  进度 {i}/{len(rels)}')
    time.sleep(0.3)
print(f'✓ Release删除完成')

# ── 3) 删除旧tag(git refs) ──
print(f'删除{len(old_tags)}个旧tag: {old_tags[:3]}...{old_tags[-1] if old_tags else ""}')
for tag in old_tags:
    st, _ = req('DELETE', f'/git/refs/tags/{tag}')
    if st not in (204, 422): print(f'  ⚠ tag {tag}: HTTP {st}')   # 422=不存在
    time.sleep(0.3)
print('✓ tag清理完成')
