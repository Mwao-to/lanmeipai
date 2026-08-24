#!/usr/bin/env python3
"""v3.86 单一数据源同步:index.html(明文,可编辑) → main_app.py EMBEDDED_ENC(密文)
每次修改 index.html 后必须运行;自动做编译校验+解密回读哈希比对。"""
import base64, hashlib, re, sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from crypt_html import enc_b64, dec_b64

HTML = 'app/htmlsrc/index.html'
PY = 'app/corepkg/src/main_app.py'

html = open(HTML, encoding='utf-8').read()
assert "'''" not in html
enc = enc_b64(html)
assert dec_b64(enc) == html, '往返自检失败'
py = open(PY, encoding='utf-8').read()
py2, n = re.subn(r"EMBEDDED_ENC = '[^']*'", "EMBEDDED_ENC = '" + enc + "'", py, count=1)
assert n == 1, '未找到 EMBEDDED_ENC'
compile(py2, PY, 'exec')
open(PY, 'w', encoding='utf-8').write(py2)
print(f'✓ 已同步 {HTML} → EMBEDDED_ENC({len(enc)}B64) | sha256:{hashlib.sha256(html.encode()).hexdigest()[:16]}')
