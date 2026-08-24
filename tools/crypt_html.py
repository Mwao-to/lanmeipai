#!/usr/bin/env python3
"""v3.86 HTML 静态加密工具(与 MainActivity.java / main_app.py 内嵌解密器同构)
算法: keystream[i] = SHA256(KEY || u32be(block_idx)), 明文按 32B 块异或
用途: assets/index.html → index.bin (APK内不再有明文); EMBEDDED_HTML → 密文b64 (dex内不再有明文)
"""
import base64, hashlib, sys

# 密钥拆4段存放(与 Java 端 HK[] / Python 端 _EMB_KEY 拼接结果一致,32字节)
KEY = bytes.fromhex(
    '9f3ac1e2' '5d84bb07' '21ce6a49' 'f0183d76'
    'ab52de90' '47c31f68' 'd9b024af' '6e1c8533'
)

def stream_xor(data: bytes) -> bytes:
    out = bytearray(len(data))
    i = counter = 0
    while i < len(data):
        h = hashlib.sha256(KEY + counter.to_bytes(4, 'big')).digest()
        n = min(32, len(data) - i)
        for j in range(n):
            out[i + j] = data[i + j] ^ h[j]
        i += n; counter += 1
    return bytes(out)

def enc_file(src, dst):
    data = open(src, 'rb').read()
    assert b'</html>' in data[-64:], '输入不是完整HTML'
    open(dst, 'wb').write(stream_xor(data))
    print(f'✓ {src} → {dst} ({len(data)}B → {len(data)}B)')

def dec_file(src, dst=None):
    data = stream_xor(open(src, 'rb').read())
    if dst: open(dst, 'wb').write(data)
    else: sys.stdout.write(data.decode('utf-8'))
    return data

def enc_b64(html_text: str) -> str:
    return base64.b64encode(stream_xor(html_text.encode('utf-8'))).decode('ascii')

def dec_b64(b64str: str) -> str:
    return stream_xor(base64.b64decode(b64str)).decode('utf-8')

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'enc': enc_file(sys.argv[2], sys.argv[3])
    elif cmd == 'dec': dec_file(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
    else: print('用法: crypt_html.py enc|dec <in> [out]')
