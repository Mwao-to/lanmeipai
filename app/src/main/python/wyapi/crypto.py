# -*- coding: utf-8 -*-
"""
crypto.py — 纯 Python 加密实现（零外部依赖，Android 上无需编译任何 C 扩展）

逐行移植自原版 lx-music-mobile 的:
  src/utils/musicSdk/wy/utils/crypto.js
  + android 原生 AES.java / RSA.java 的实际行为

关键结论(从原生代码反推,与原版 JS 命名不同):
  * AES_MODE.CBC_128_PKCS7Padding = 'AES/CBC/PKCS7Padding'  → AES-128-CBC + PKCS7
  * AES_MODE.ECB_128_NoPadding = 'AES'  → Cipher.getInstance("AES") 在 Android 上
    默认是 AES/ECB/PKCS5Padding,所以 eapi/linuxapi 实际用的是 **PKCS7 填充**
    (名字叫 NoPadding,实现是带填充的!)
  * RSA/ECB/NoPadding:输入必须是 128 字节(JS 层先补零),输出 128 字节密文
"""
from __future__ import annotations

import base64
import hashlib
import json
import random
import string

# ---------------------------------------------------------------- GF(2^8)

def _gf_mul(a: int, b: int) -> int:
    """GF(2^8) 乘法,不可约多项式 x^8+x^4+x^3+x+1 (0x11B)。"""
    res = 0
    while b:
        if b & 1:
            res ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return res & 0xFF


def _gf_pow(base: int, exp: int) -> int:
    result = 1
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


# ---------------------------------------------------------------- S-box

def _gen_sbox() -> list:
    sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else _gf_pow(i, 254)  # a^254 = a^-1
        s = inv
        s ^= ((inv << 1) | (inv >> 7)) & 0xFF
        s ^= ((inv << 2) | (inv >> 6)) & 0xFF
        s ^= ((inv << 3) | (inv >> 5)) & 0xFF
        s ^= ((inv << 4) | (inv >> 4)) & 0xFF
        s ^= 0x63
        sbox[i] = s & 0xFF
    return sbox


SBOX = _gen_sbox()
SBOX_INV = [0] * 256
for _i, _v in enumerate(SBOX):
    SBOX_INV[_v] = _i

# MixColumns 查表
M2 = [_gf_mul(x, 2) for x in range(256)]
M3 = [_gf_mul(x, 3) for x in range(256)]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# 行移位后的索引映射 (AES-128, 列主序)
_SHIFT_ROWS_IDX = (0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11)
_INV_SHIFT_ROWS_IDX = (0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3)


# ---------------------------------------------------------------- AES 核心

def _expand_key(key: bytes) -> list:
    """AES-128 密钥扩展,返回 11 个 16 字节轮密钥。"""
    w = [list(key[4 * i:4 * i + 4]) for i in range(4)]
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]          # RotWord
            temp = [SBOX[b] for b in temp]      # SubWord
            temp[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    return [bytes(sum((w[r * 4 + c] for c in range(4)), [])) for r in range(11)]


class AES:
    """AES-128 块加密(纯 Python,查表加速)。"""

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError('AES-128 requires 16-byte key')
        self.rk = _expand_key(key)

    def encrypt_block(self, block: bytes) -> bytes:
        s = [block[i] ^ self.rk[0][i] for i in range(16)]
        for rnd in range(1, 10):
            s = [SBOX[b] for b in s]                     # SubBytes
            s = [s[i] for i in _SHIFT_ROWS_IDX]          # ShiftRows
            # MixColumns
            ns = [0] * 16
            for c in range(4):
                i = c * 4
                a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
                ns[i] = M2[a0] ^ M3[a1] ^ a2 ^ a3
                ns[i + 1] = a0 ^ M2[a1] ^ M3[a2] ^ a3
                ns[i + 2] = a0 ^ a1 ^ M2[a2] ^ M3[a3]
                ns[i + 3] = M3[a0] ^ a1 ^ a2 ^ M2[a3]
            s = ns
            s = [s[i] ^ self.rk[rnd][i] for i in range(16)]
        s = [SBOX[b] for b in s]
        s = [s[i] for i in _SHIFT_ROWS_IDX]
        s = [s[i] ^ self.rk[10][i] for i in range(16)]
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = [block[i] ^ self.rk[10][i] for i in range(16)]
        for rnd in range(9, 0, -1):
            s = [SBOX_INV[b] for b in s]
            s = [s[i] for i in _INV_SHIFT_ROWS_IDX]
            s = [s[i] ^ self.rk[rnd][i] for i in range(16)]
            # InvMixColumns
            ns = [0] * 16
            for c in range(4):
                i = c * 4
                a0, a1, a2, a3 = s[i], s[i + 1], s[i + 2], s[i + 3]
                ns[i] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
                ns[i + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
                ns[i + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
                ns[i + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
            s = ns
        s = [SBOX_INV[b] for b in s]
        s = [s[i] for i in _INV_SHIFT_ROWS_IDX]
        s = [s[i] ^ self.rk[0][i] for i in range(16)]
        return bytes(s)


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError('invalid pkcs7 padding')
    return data[:-pad_len]


# ---------------------------------------------------------------- 模式封装

def aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes, pad: bool = True) -> bytes:
    a = AES(key)
    if pad:
        data = pkcs7_pad(data)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = bytes(x ^ y for x, y in zip(data[i:i + 16], prev))
        enc = a.encrypt_block(blk)
        out += enc
        prev = enc
    return bytes(out)


def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes, unpad: bool = True) -> bytes:
    a = AES(key)
    prev = iv
    out = bytearray()
    for i in range(0, len(data), 16):
        blk = data[i:i + 16]
        dec = a.decrypt_block(blk)
        out += bytes(x ^ y for x, y in zip(dec, prev))
        prev = blk
    res = bytes(out)
    return pkcs7_unpad(res) if unpad else res


def aes_ecb_encrypt(data: bytes, key: bytes, pad: bool = True) -> bytes:
    a = AES(key)
    if pad:
        data = pkcs7_pad(data)
    return b''.join(a.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def aes_ecb_decrypt(data: bytes, key: bytes, unpad: bool = True) -> bytes:
    a = AES(key)
    res = b''.join(a.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))
    return pkcs7_unpad(res) if unpad else res


# ---------------------------------------------------------------- RSA (纯 Python)

def der_read_tlv(data: bytes, pos: int = 0):
    """极简 DER 读取器,返回 (tag, value_bytes, next_pos)。"""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(data[pos:pos + n], 'big')
        pos += n
    value = data[pos:pos + length]
    return tag, value, pos + length


def parse_spki_public_key(pem: str):
    """解析 X.509 SubjectPublicKeyInfo PEM,返回 (n, e)。"""
    b64 = ''.join(pem.strip().split('\n')[1:-1])
    der = base64.b64decode(b64)
    _, spki, _ = der_read_tlv(der)                      # SEQUENCE
    _, _, pos = der_read_tlv(spki)                      # SEQUENCE(alg)
    _, bit_string, _ = der_read_tlv(spki, pos)          # BIT STRING
    rsa_der = bit_string[1:]                            # 跳过 0x00 unused bits
    _, rsa_seq, _ = der_read_tlv(rsa_der)
    _, n_bytes, pos2 = der_read_tlv(rsa_seq)
    _, e_bytes, _ = der_read_tlv(rsa_seq, pos2)
    return int.from_bytes(n_bytes, 'big'), int.from_bytes(e_bytes, 'big')


def rsa_nopadding_encrypt(data: bytes, n: int, e: int) -> bytes:
    """RSA/ECB/NoPadding:输入必须是 modulus 等长(1024-bit → 128 字节)。"""
    if len(data) != 128:
        raise ValueError(f'RSA NoPadding requires 128-byte input, got {len(data)}')
    m = int.from_bytes(data, 'big')
    c = pow(m, e, n)
    return c.to_bytes(128, 'big')


# ---------------------------------------------------------------- 网易云密钥常量

NETEASE_PRESET_KEY = b'0CoJUm6Qyw8W8jud'
NETEASE_IV = b'0102030405060708'
NETEASE_LINUXAPI_KEY = b'rFgB&h#%2?^eDg:Q'
NETEASE_EAPI_KEY = b'e82ckenh8dichen8'
NETEASE_PUBLIC_KEY = (
    '-----BEGIN PUBLIC KEY-----\n'
    'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ3'
    '7BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvakl'
    'V8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44o'
    'ncaTWz7OBGLbCiK45wIDAQAB\n'
    '-----END PUBLIC KEY-----'
)

# 缓存解析结果
_NETEASE_RSA_KEY = None


def _netease_rsa_key():
    global _NETEASE_RSA_KEY
    if _NETEASE_RSA_KEY is None:
        _NETEASE_RSA_KEY = parse_spki_public_key(NETEASE_PUBLIC_KEY)
    return _NETEASE_RSA_KEY


def _json_dumps(obj) -> str:
    """与 JS JSON.stringify 一致:无空格、不转义非 ASCII。"""
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'))


# ---------------------------------------------------------------- weapi / eapi / linuxapi

def weapi(obj) -> dict:
    """网易云 weapi 加密。与 crypto.js 完全一致(含随机 16 位数字 secretKey)。"""
    text = _json_dumps(obj)
    secret_key = ''.join(random.choices(string.digits, k=16)).encode()
    # 内层: AES-CBC-PKCS7(base64(text), presetKey, iv)
    inner = aes_cbc_encrypt(text.encode(), NETEASE_PRESET_KEY, NETEASE_IV)
    inner_b64 = base64.b64encode(inner)
    # 外层: AES-CBC-PKCS7(内层结果, secretKey, iv)
    params = base64.b64encode(aes_cbc_encrypt(inner_b64, secret_key, NETEASE_IV)).decode()
    # encSecKey: RSA-NoPadding(反转 secretKey 并补零到 128 字节) 的 hex
    reversed_key = secret_key[::-1]
    padded = b'\x00' * (128 - len(reversed_key)) + reversed_key
    n, e = _netease_rsa_key()
    enc_sec_key = rsa_nopadding_encrypt(padded, n, e).hex()
    return {'params': params, 'encSecKey': enc_sec_key}


def linuxapi(obj) -> dict:
    """网易云 linuxapi 加密。eparams = hex(大写)(AES-ECB-PKCS7(text))"""
    text = _json_dumps(obj)
    enc = aes_ecb_encrypt(text.encode(), NETEASE_LINUXAPI_KEY)
    return {'eparams': enc.hex().upper()}


def eapi(url: str, obj) -> dict:
    """网易云 eapi 加密。params = hex(大写)(AES-ECB-PKCS7(data))"""
    text = _json_dumps(obj) if isinstance(obj, dict) else str(obj)
    message = f'nobody{url}use{text}md5forencrypt'
    digest = hashlib.md5(message.encode()).hexdigest()
    data = f'{url}-36cd479b6b5-{text}-36cd479b6b5-{digest}'
    enc = aes_ecb_encrypt(data.encode(), NETEASE_EAPI_KEY)
    return {'params': enc.hex().upper()}


def eapi_decrypt(params_hex: str) -> str:
    """eapi 响应解密(hex → AES-ECB 解密)。"""
    raw = bytes.fromhex(params_hex)
    return aes_ecb_decrypt(raw, NETEASE_EAPI_KEY).decode()


# ---------------------------------------------------------------- 通用哈希

def md5(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def sha1(text: str) -> str:
    return hashlib.sha1(text.encode()).hexdigest()


def md5_hex_digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()
