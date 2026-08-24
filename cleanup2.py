#!/usr/bin/env python3
"""GitHub清理v2:keep-alive长连接+超时+幂等续跑。用法: cleanup2.py [runs|releases|tags|all]"""
import http.client, json, sys, time

TOKEN = open('/data/data/com.termux/files/home/.gh_token').read().strip()
REPO = 'Mwao-to/lanmeipai'
KEEP_RUN = 32751436709
KEEP_RELEASE_TAG = 'v3.66'
HOST = 'api.github.com'

conn = http.client.HTTPSConnection(HOST, timeout=30)

def req(method, path):
    """返回(status, json或None);自动重连一次"""
    global conn
    for attempt in (1, 2):
        try:
            conn.request(method, path, headers={'Authorization': 'token ' + TOKEN,
                         'User-Agent': 'cleanup', 'Accept': 'application/vnd.github+json'})
            r = conn.getresponse(); body = r.read()
            return r.status, json.loads(body) if body and r.status != 204 else None
        except Exception as e:
            try: conn.close()
            except Exception: pass
            conn = http.client.HTTPSConnection(HOST, timeout=30)
            if attempt == 2: print(f'  ⚠ {method} {path}: {e}', flush=True)
            time.sleep(1)
    return 0, None

def paged(path):
    out, page = [], 1
    while True:
        sep = '&' if '?' in path else '?'
        st, d = req('GET', f'{path}{sep}per_page=100&page={page}')
        if st != 200 or not d: break
        items = d.get('workflow_runs') if isinstance(d, dict) else d   # releases响应是纯数组
        if st != 200 or not items: break
        out += items
        if len(items) < 100: break
        page += 1
    return out

phase = sys.argv[1] if len(sys.argv) > 1 else 'all'
t0 = time.time()

if phase in ('runs', 'all'):
    runs = paged('/repos/Mwao-to/lanmeipai/actions/runs')
    old = [r['id'] for r in runs if r['id'] != KEEP_RUN]
    print(f'[runs] 共{len(runs)},待删{len(old)}', flush=True)
    for i, rid in enumerate(old, 1):
        st, _ = req('DELETE', f'/repos/Mwao-to/lanmeipai/actions/runs/{rid}')
        if i % 10 == 0 or i == len(old): print(f'  runs {i}/{len(old)} ({st})', flush=True)
        time.sleep(0.25)

if phase in ('releases', 'all'):
    rels = paged('/repos/Mwao-to/lanmeipai/releases')
    old = [r for r in rels if r['tag_name'] != KEEP_RELEASE_TAG]
    print(f'[releases] 共{len(rels)},待删{len(old)}', flush=True)
    n = 0
    for i, r in enumerate(old, 1):
        st, _ = req('DELETE', f'/repos/Mwao-to/lanmeipai/releases/{r["id"]}')
        if st == 204:
            n += 1
            req('DELETE', f'/repos/Mwao-to/lanmeipai/git/refs/tags/{r["tag_name"]}')   # 连带删tag(422=无此tag忽略)
        if i % 10 == 0 or i == len(old): print(f'  releases {i}/{len(old)} 已删{n}', flush=True)
        time.sleep(0.25)

print(f'═══ 完成 耗时{time.time()-t0:.0f}s ═══', flush=True)
