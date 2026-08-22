# -*- coding: utf-8 -*-
"""网易云下载器单文件版:全部后端逻辑 + 内嵌 HTML 界面(供 Chaquopy 打包,零文件系统依赖)"""

# ════════ wyapi/log.py ════════
# -*- coding: utf-8 -*-
"""log.py — 轻量日志(写文件 + 可选控制台)"""

import os
import threading
import time

_LOG_DIR = None
_level = 'info'
_lock = threading.Lock()
_console = True

LEVELS = {'debug': 10, 'info': 20, 'warn': 30, 'error': 40}


def init(log_dir, console = True):
    global _LOG_DIR, _console
    _LOG_DIR = log_dir
    _console = console
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)


class _Logger:
    def __init__(self, name):
        self.name = name

    def _write(self, lv, msg):
        if LEVELS.get(lv, 20) < LEVELS.get(_level, 20):
            return
        line = f'[{time.strftime("%H:%M:%S")}][{lv.upper()}][{self.name}] {msg}'
        if _console:
            try:
                print(line, flush=True)
            except Exception:
                pass
        if _LOG_DIR:
            try:
                with _lock:
                    with open(os.path.join(_LOG_DIR, 'app.log'), 'a', encoding='utf-8') as f:
                        f.write(f'[{time.strftime("%Y-%m-%d %H:%M:%S")}] {line}\n')
            except Exception:
                pass

    def debug(self, msg): self._write('debug', str(msg))
    def info(self, msg): self._write('info', str(msg))
    def warn(self, msg): self._write('warn', str(msg))
    def error(self, msg): self._write('error', str(msg))


_loggers = {}


def get_logger(name) :
    if name not in _loggers:
        _loggers[name] = _Logger(name)
    return _loggers[name]

# ════════ wyapi/crypto.py ════════
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

import base64
import hashlib
import json
import random
import string

# ---------------------------------------------------------------- GF(2^8)

def _gf_mul(a, b) :
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


def _gf_pow(base, exp) :
    result = 1
    while exp:
        if exp & 1:
            result = _gf_mul(result, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return result


# ---------------------------------------------------------------- S-box

def _gen_sbox() :
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

def _expand_key(key) :
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

    def __init__(self, key):
        if len(key) != 16:
            raise ValueError('AES-128 requires 16-byte key')
        self.rk = _expand_key(key)

    def encrypt_block(self, block) :
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

    def decrypt_block(self, block) :
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


def pkcs7_pad(data, block_size = 16) :
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data) :
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError('invalid pkcs7 padding')
    return data[:-pad_len]


# ---------------------------------------------------------------- 模式封装

def aes_cbc_encrypt(data, key, iv, pad = True) :
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


def aes_cbc_decrypt(data, key, iv, unpad = True) :
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


def aes_ecb_encrypt(data, key, pad = True) :
    a = AES(key)
    if pad:
        data = pkcs7_pad(data)
    return b''.join(a.encrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))


def aes_ecb_decrypt(data, key, unpad = True) :
    a = AES(key)
    res = b''.join(a.decrypt_block(data[i:i + 16]) for i in range(0, len(data), 16))
    return pkcs7_unpad(res) if unpad else res


# ---------------------------------------------------------------- RSA (纯 Python)

def der_read_tlv(data, pos = 0):
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


def parse_spki_public_key(pem):
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


def rsa_nopadding_encrypt(data, n, e) :
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


def _json_dumps(obj) :
    """与 JS JSON.stringify 一致:无空格、不转义非 ASCII。"""
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':'))


# ---------------------------------------------------------------- weapi / eapi / linuxapi

def weapi(obj) :
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


def linuxapi(obj) :
    """网易云 linuxapi 加密。eparams = hex(大写)(AES-ECB-PKCS7(text))"""
    text = _json_dumps(obj)
    enc = aes_ecb_encrypt(text.encode(), NETEASE_LINUXAPI_KEY)
    return {'eparams': enc.hex().upper()}


def eapi(url, obj) :
    """网易云 eapi 加密。params = hex(大写)(AES-ECB-PKCS7(data))"""
    text = _json_dumps(obj) if isinstance(obj, dict) else str(obj)
    message = f'nobody{url}use{text}md5forencrypt'
    digest = hashlib.md5(message.encode()).hexdigest()
    data = f'{url}-36cd479b6b5-{text}-36cd479b6b5-{digest}'
    enc = aes_ecb_encrypt(data.encode(), NETEASE_EAPI_KEY)
    return {'params': enc.hex().upper()}


def eapi_decrypt(params_hex) :
    """eapi 响应解密(hex → AES-ECB 解密)。"""
    raw = bytes.fromhex(params_hex)
    return aes_ecb_decrypt(raw, NETEASE_EAPI_KEY).decode()


# ---------------------------------------------------------------- 通用哈希

def md5(text) :
    return hashlib.md5(text.encode()).hexdigest()


def sha1(text) :
    return hashlib.sha1(text.encode()).hexdigest()


def md5_hex_digest(data) :
    return hashlib.md5(data).hexdigest()

# ════════ wyapi/text.py ════════
# -*- coding: utf-8 -*-
"""
text.py — 文本/格式化工具(移植自原版 src/utils/index.js 相关函数)
"""


def size_formate(size) :
    """字节数 → 人类可读,如 3.5 MB"""
    if size is None:
        return ''
    size = float(size)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    return f'{size:.2f} {units[i]}'


def format_play_time(seconds) :
    """秒 → mm:ss"""
    if seconds is None:
        return '00:00'
    seconds = int(seconds)
    m = seconds // 60
    s = seconds % 60
    return f'{m:02d}:{s:02d}'


def date_format(timestamp_ms, fmt = 'YYYY-MM-DD') :
    """毫秒时间戳 → 日期字符串。支持 YYYY MM DD HH mm ss 占位符"""
    import time
    ts = timestamp_ms / 1000 if timestamp_ms > 1e11 else timestamp_ms
    t = time.localtime(ts)
    mapping = {
        'YYYY': f'{t.tm_year:04d}',
        'MM': f'{t.tm_mon:02d}',
        'DD': f'{t.tm_mday:02d}',
        'HH': f'{t.tm_hour:02d}',
        'mm': f'{t.tm_min:02d}',
        'ss': f'{t.tm_sec:02d}',
    }
    out = fmt
    for k, v in mapping.items():
        out = out.replace(k, v)
    return out


def format_play_count(count) :
    """播放量 → 万/亿"""
    try:
        count = int(count)
    except (TypeError, ValueError):
        return ''
    if count >= 100000000:
        return f'{count / 100000000:.1f}亿'
    if count >= 10000:
        return f'{count / 10000:.1f}万'
    return str(count)


def decode_name(name) :
    """URL 解码(容错)"""
    from urllib.parse import unquote
    try:
        return unquote(name)
    except Exception:
        return name


# ---------------------------------------------------------------- 简繁转换(内置精简映射)

_S2T = {
    '说': '說', '听': '聽', '乐': '樂', '网': '網', '云': '雲', '歌': '歌', '词': '詞',
    '专': '專', '辑': '輯', '艺': '藝', '人': '人', '单': '單', '曲': '曲', '频': '頻',
    '视': '視', '播': '播', '放': '放', '列': '列', '表': '表', '下': '下', '载': '載',
    '设': '設', '置': '置', '搜': '搜', '索': '索', '热': '熱', '榜': '榜', '评': '評',
    '论': '論', '喜': '喜', '欢': '歡', '关': '關', '于': '於', '进': '進', '入': '入',
    '历': '歷', '史': '史', '缓': '緩', '存': '存', '同': '同', '步': '步', '静': '靜',
    '态': '態', '版': '版', '权': '權', '开': '開', '发': '發', '者': '者', '组': '組',
    '件': '件', '离': '離', '线': '線', '浏': '瀏', '览': '覽', '窗': '窗', '口': '口',
    '按': '按', '钮': '鈕', '图': '圖', '片': '片', '标': '標', '题': '題', '信': '信',
    '息': '息', '数': '數', '据': '據', '库': '庫', '无': '無', '损': '損', '质': '質',
    '量': '量', '声': '聲', '音': '音', '画': '畫', '面': '面', '颜': '顏', '色': '色',
    '亮': '亮', '度': '度', '字': '字', '体': '體', '大': '大', '小': '小', '应': '應',
    '用': '用', '程': '程', '序': '序', '退': '退', '出': '出', '启': '啟', '动': '動',
    '内': '內', '外': '外', '部': '部', '存': '存', '储': '儲', '路': '路', '径': '徑',
    '错': '錯', '误': '誤', '提': '提', '示': '示', '确': '確', '认': '認', '取': '取',
    '消': '消', '删': '刪', '除': '除', '添': '添', '加': '加', '改': '改', '名': '名',
    '新': '新', '建': '建', '文': '文', '件': '件', '夹': '夾', '目': '目', '录': '錄',
    '个': '個', '这': '這', '那': '那', '里': '裡', '边': '邊', '东': '東', '西': '西',
    '南': '南', '北': '北', '上': '上', '下': '下', '左': '左', '右': '右', '前': '前',
    '后': '後', '间': '間', '时': '時', '间': '間', '为': '為', '与': '與', '和': '和',
    '及': '及', '或': '或', '并': '並', '且': '且', '但': '但', '是': '是', '不': '不',
    '能': '能', '可': '可', '以': '以', '会': '會', '将': '將', '就': '就', '都': '都',
    '还': '還', '很': '很', '最': '最', '更': '更', '从': '從', '到': '到', '在': '在',
    '对': '對', '于': '於', '被': '被', '把': '把', '让': '讓', '给': '給', '使': '使',
    '用': '用', '通': '通', '过': '過', '经': '經', '过': '過', '因': '因', '此': '此',
    '如': '如', '果': '果', '则': '則', '虽': '雖', '然': '然', '仍': '仍', '然': '然',
    '已': '已', '经': '經', '正': '正', '在': '在', '现': '現', '实': '實', '验': '驗',
    '证': '證', '明': '明', '写': '寫', '读': '讀', '看': '看', '见': '見', '问': '問',
    '题': '題', '答': '答', '案': '案', '知': '知', '道': '道', '想': '想', '法': '法',
}


def to_traditional(text) :
    """简体 → 繁体(内置常用映射)"""
    return ''.join(_S2T.get(ch, ch) for ch in text)


def to_simplified(text) :
    """繁体 → 简体(反转映射)"""
    _T2S = {v: k for k, v in _S2T.items()}
    return ''.join(_T2S.get(ch, ch) for ch in text)

# ════════ wyapi/base.py ════════
# -*- coding: utf-8 -*-
"""base.py — 音源抽象基类

与原版 src/utils/musicSdk/* 的接口对齐:
  musicSearch / search / songList / leaderboard / hotSearch / lyric / getMusicUrl / comment
"""

from abc import ABC, abstractmethod
from typing import Any


class MusicSource(ABC):
    id = ''          # 音源标识: wy / kw / kg / tx / mg
    name = ''        # 显示名: 网易 / 酷我 / 酷狗 / QQ / 咪咕
    limit = 30
    # 支持的音质(从高到低)
    qualitys = ['hires', 'flac', '320k', '128k']

    # ---------------- 搜索 ----------------
    @abstractmethod
    def search(self, keyword, page = 1, limit = None) :
        """返回 {list, total, allPage, limit, source}"""
        ...

    # ---------------- 歌单 ----------------
    @abstractmethod
    def songlist_detail(self, list_id, page = 1, limit = None) :
        """返回 {list, total, page, limit, source, info}"""
        ...

    # ---------------- 排行榜 ----------------
    @abstractmethod
    def leaderboard(self) :
        """返回 {list: [{id, name, bangid}], source}"""
        ...

    # ---------------- 热搜 ----------------
    @abstractmethod
    def hot_search(self) :
        """返回 [词1, 词2, ...]"""
        ...

    # ---------------- 歌词 ----------------
    @abstractmethod
    def lyric(self, song) :
        """返回 {lyric, tlyric, rlyric, lxlyric}"""
        ...

    # ---------------- 播放链接 ----------------
    @abstractmethod
    def get_music_url(self, song, quality) :
        """返回可直接播放的 URL"""
        ...

    # ---------------- 附加 ----------------
    def pic_url(self, song) :
        """封面图 URL(可覆盖)"""
        return song.get('img') or ''

    def song_detail_page_url(self, song) :
        return ''

    # ---------------- 工具 ----------------
    def _format_interval(self, ms) :
        if not ms:
            return '00:00'
        return format_play_time(ms / 1000 if ms > 10000 else ms)


# ---------------------------------------------------------------- 歌曲数据结构

def make_song(
    source,
    songmid,
    name,
    singer,
    img = '',
    interval = '',
    album_name = '',
    album_id = '',
    types = None,
    meta = None,
) :
    """统一歌曲对象(与原版 handleResult 输出结构一致)"""
    return {
        'source': source,
        'songmid': songmid,
        'name': name,
        'singer': singer,
        'img': img,
        'interval': interval,
        'albumName': album_name,
        'albumId': album_id,
        'types': types or [],
        'typeUrl': {},
        'meta': meta or {},
    }

# ════════ wyapi/net.py ════════
# -*- coding: utf-8 -*-
"""
net.py — 网络层
- requests + 超时 + 自动重试 + 统一 UA
- 所有请求可被全局取消标记中断
- 对比原版 RN 的 httpFetch:增加指数退避重试、连接复用、gzip 自动解压
"""

import threading

import requests


logger = get_logger('net')

DEFAULT_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
    '(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54'
)

_session = requests.Session()
_session.headers.update({'User-Agent': DEFAULT_UA})
_session.trust_env = False  # 不读系统代理,避免 Android 上误走代理

# 全局取消标记(应用退出时置位)
_cancel_flag = threading.Event()

# cookie 预热: 部分接口需要先访问站点主页建立会话 cookie
_warm_ups = {}
_warm_lock = threading.Lock()


def warm_up(host_url):
    """首次请求某站点前先访问主页,建立会话 cookie(幂等,带缓存)"""
    with _warm_lock:
        if _warm_ups.get(host_url):
            return
        _warm_ups[host_url] = True
    try:
        _session.get(host_url, timeout=10)
    except Exception:
        pass  # 预热失败不致命,后续请求仍会尝试


# 简单内存缓存: url -> (headers, body_bytes)
_cache = {}
_cache_lock = threading.Lock()
CACHE_MAX = 128


def set_cancel():
    _cancel_flag.set()


def clear_cancel():
    _cancel_flag.clear()


def _check_cancel():
    if _cancel_flag.is_set():
        raise requests.RequestException('request cancelled')


class HttpError(Exception):
    def __init__(self, message, status_code = 0):
        super().__init__(message)
        self.status_code = status_code


def http_fetch(
    url,
    method = 'get',
    params = None,
    data = None,
    form = None,
    json_body = None,
    headers = None,
    timeout = 15.0,
    retry = 3,
    use_cache = False,
) :
    """统一 HTTP 请求。
    返回 {'status_code', 'body'(解析后的 JSON 或原始 bytes), 'headers', 'url'}
    form: application/x-www-form-urlencoded (与原版 httpFetch 的 form 一致)
    data: 原始 body bytes/str
    """
    hdrs = dict(headers or {})
    hdrs.setdefault('User-Agent', DEFAULT_UA)

    cache_key = None
    if use_cache and method == 'get':
        cache_key = url
        with _cache_lock:
            if cache_key in _cache:
                h, b = _cache[cache_key]
                return _parse_response(b, h, url)

    last_err = None
    for attempt in range(retry):
        _check_cancel()
        try:
            resp = _session.request(
                method,
                url,
                params=params,
                data=form if form is not None else data,
                json=json_body,
                headers=hdrs,
                timeout=timeout,
            )
        except requests.RequestException as e:
            last_err = e
            if attempt < retry - 1:
                _sleep(0.3 * (2 ** attempt))
                continue
            raise HttpError(f'网络请求失败: {url} ({e.__class__.__name__})') from e

        if resp.status_code >= 500 and attempt < retry - 1:
            last_err = HttpError(f'服务器错误 {resp.status_code}', resp.status_code)
            _sleep(0.3 * (2 ** attempt))
            continue

        body_bytes = resp.content
        if cache_key is not None:
            with _cache_lock:
                if len(_cache) >= CACHE_MAX:
                    _cache.clear()
                _cache[cache_key] = (resp.headers, body_bytes)
        return _parse_response(body_bytes, resp.headers, url, resp.status_code)

    raise HttpError(f'请求失败: {url}', getattr(last_err, 'status_code', 0))


def _parse_response(body_bytes, headers, url, status_code = 200) :
    result = {
        'status_code': status_code,
        'headers': headers,
        'url': url,
        'body': body_bytes,
    }
    # 尝试解析 JSON
    try:
        result['body'] = body_bytes.decode('utf-8')
        import json as _json
        result['body'] = _json.loads(result['body'])
    except (UnicodeDecodeError, ValueError):
        # 保留原始 bytes
        result['body'] = body_bytes
    return result


def _sleep(sec):
    import time
    for _ in range(int(sec * 10)):
        if _cancel_flag.is_set():
            break
        time.sleep(0.1)

# ════════ wyapi/toubiec.py ════════
# -*- coding: utf-8 -*-
"""
toubiec.py — 第三方网易云解析服务封装
后端: https://nextmusic.toubiec.cn (前端 https://wyapi.toubiec.cn/)
用于官方接口取不到播放链接的 VIP / 无版权歌曲。

流程(与网页前端一致):
  1. POST /api/ip 获取本机出口 IP(缓存 5 分钟,防滥用校验)
  2. POST /api/getSongUrl {id, level, timestamp, ip}  → {code, data:{url}}
  3. POST /api/getSongLyric {id, timestamp, ip}       → {code, data:{lrc,tlyric,yrc}}
"""

import threading
import time

import requests

BASE = 'https://nextmusic.toubiec.cn'
REFERER = 'https://wyapi.toubiec.cn/'
UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
      '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

# 音质 → 第三方接口 level
LEVEL_MAP = {
    '128k': 'standard',
    '320k': 'exhigh',
    'flac': 'lossless',
    'hires': 'hires',
    'master': 'jymaster',
}

_ip_cache = {'ip': '', 'ts': 0.0}
_lock = threading.Lock()


def _get_ip() :
    """获取本机出口 IP(接口防滥用参数),缓存 5 分钟"""
    with _lock:
        if _ip_cache['ip'] and time.time() - _ip_cache['ts'] < 300:
            return _ip_cache['ip']
    try:
        r = requests.post(f'{BASE}/api/ip',
                          json={'timestamp': int(time.time() * 1000)},
                          headers={'User-Agent': UA}, timeout=10)
        ip = r.json()['data']['ip']
        with _lock:
            _ip_cache['ip'] = ip
            _ip_cache['ts'] = time.time()
        return ip
    except Exception:
        return ''  # 拿不到 IP 也照发,部分情况下仍可用


def _post(path, payload) :
    payload['timestamp'] = int(time.time() * 1000)
    ip = _get_ip()
    if ip:
        payload['ip'] = ip
    resp = requests.post(
        f'{BASE}{path}',
        json=payload,
        headers={
            'User-Agent': UA,
            'Content-Type': 'application/json',
            'Referer': REFERER,
            'Origin': 'https://wyapi.toubiec.cn',
        },
        timeout=20,
    )
    return resp.json()


def get_song_url(song_id, quality = '320k', max_retry = 2) :
    """第三方解析播放直链。失败抛 RuntimeError。

    策略:
      - 429 限流:按响应 retryAfter 等待后重试
      - 404/无 url:尝试降级到 standard 档(共享账号各档位可用性不同)
      - 账号轮换导致偶发失败,整体重试 max_retry 次
    """
    level = LEVEL_MAP.get(quality, 'exhigh')
    levels = [level] if level == 'standard' else [level, 'standard']
    last_err = None
    for attempt in range(max_retry + 1):
        for lv in levels:
            try:
                data = _post('/api/getSongUrl', {'id': str(song_id), 'level': lv})
            except Exception as e:
                last_err = e
                time.sleep(1)
                continue
            if data.get('code') == 429:
                d = data.get('data') or {}
                wait = float(d.get('retryAfter') or 5)
                last_err = RuntimeError(data.get('message') or f'请求频率过快,{int(wait)}秒后重试')
                time.sleep(min(wait, 15))
                continue
            if data.get('code') == 404:
                last_err = RuntimeError(data.get('message') or '未找到(可能限流或账号无权限)')
                time.sleep(1)
                continue
            if data.get('code') != 200:
                raise RuntimeError(data.get('message') or f'解析失败(code={data.get("code")})')
            url = ((data.get('data') or {}).get('url') or '').replace('`', '').strip()
            if not url:
                last_err = RuntimeError('第三方解析未返回链接(该歌曲可能不可用)')
                continue
            return url
    raise RuntimeError(f'第三方解析失败: {last_err}')


def _yrc_json_to_lrc(raw) :
    """网易云逐字歌词转标准LRC,失败返回空串。
    兼容两种格式:
      1. 整体 JSON 数组 [{t,c}, ...]
      2. 逐行 NDJSON(每行一个 {t,c} 对象,行即歌词行)
    """
    import json as _json
    try:
        obj = _json.loads(raw)
        arr = obj if isinstance(obj, list) else [obj]
        if not isinstance(obj, (list, dict)):
            return ''
    except Exception:
        # 逐行 NDJSON:任一行解析失败即视为无效
        arr = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = _json.loads(line)
            except Exception:
                return ''
            if not isinstance(item, dict):
                return ''
            arr.append(item)
    out = []
    for item in arr:
        if not isinstance(item, dict):
            continue
        txt = ''.join((c.get('tx') or '') for c in (item.get('c') or []) if isinstance(c, dict))
        txt = txt.replace('/', ' ').strip()
        if not txt:
            continue
        sec = (item.get('t') or 0) / 1000.0
        m = int(sec // 60)
        out.append(f'[{m:02d}:{sec - m * 60:05.2f}]{txt}')
    return '\n'.join(out)


def _clean_lrc(raw) :
    """清洗歌词字段:逐字JSON转标准LRC;无法解析的JSON视为无效返回空串。"""
    raw = (raw or '').strip()
    if raw.startswith('{'):
        converted = _yrc_json_to_lrc(raw)
        return converted          # 转换失败返回空串,避免前端显示乱码
    return raw


def get_lyric(song_id, max_retry = 2) :
    """第三方解析歌词。返回 {lrc, tlyric, yrc}(可能为空串)。失败抛 RuntimeError。"""
    last_err = None
    for attempt in range(max_retry + 1):
        try:
            data = _post('/api/getSongLyric', {'id': str(song_id)})
        except Exception as e:
            last_err = e
            time.sleep(1)
            continue
        if data.get('code') == 429:
            last_err = RuntimeError(data.get('message') or '请求频率过快,稍后再试')
            time.sleep(3)
            continue
        if data.get('code') != 200:
            raise RuntimeError(data.get('message') or f'歌词解析失败(code={data.get("code")})')
        d = data.get('data') or {}
        return {
            'lyric': _clean_lrc(d.get('lrc')),
            'tlyric': _clean_lrc(d.get('tlyric')),
            'yrc': d.get('yrc') or '',
        }
    raise RuntimeError(f'第三方歌词解析失败: {last_err}')

# toubiec 模块命名空间兼容层(单文件版):server 段沿用原版 `toubiec.get_song_url()` /
# `toubiec.get_lyric()` 的模块式调用,缺失此对象会导致 VIP/无版权歌曲兜底解析
# 静默失效(NameError 被 except Exception 吞掉)。
import types as _types

toubiec = _types.SimpleNamespace(get_song_url=get_song_url, get_lyric=get_lyric)

# ════════ wyapi/wy.py ════════
# -*- coding: utf-8 -*-
"""
wy.py — 网易云音源(完整移植)

逐行对照原版:
  src/utils/musicSdk/wy/{musicSearch,songList,lyric,leaderboard,hotSearch,api-cookie,musicInfo}.js
  + utils/{index,crypto}.js

改进(IO/策略优化):
  * 搜索失败自动重试(指数退避,最多 3 次,与原版一致)
  * 歌词获取失败 200ms 重试(与原版一致)
  * 响应缓存: 热搜/排行榜 30 分钟缓存,减少无效请求
"""

import re
import threading
import time


# 独立服务:不再依赖 lxmusic.config。网易云 Cookie(可选,用于解锁 VIP/无版权歌曲)可从环境变量 WY_COOKIE 传入
_WY_COOKIE = ''


def set_wy_cookie(cookie):
    global _WY_COOKIE
    _WY_COOKIE = (cookie or '').strip()


def get_wy_cookie() :
    return _WY_COOKIE

UA_PC = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
         '(KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.54')
UA_OLD = ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
          '(KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36')

_EAPI_BATCH_URL = 'https://interface.music.163.com/eapi/batch'


def _wy_warm():
    """网易云会话 cookie 预热(幂等)"""
    warm_up('https://music.163.com/')


class _Cache:
    """带过期时间的简单缓存"""

    def __init__(self, ttl):
        self.ttl = ttl
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            item = self._data.get(key)
            if item and item[0] + self.ttl > time.time():
                return item[1]
        return None

    def set(self, key, value):
        with self._lock:
            self._data[key] = (time.time(), value)


def eapi_request(url, data) :
    """eapi 批量接口请求(与原版 utils/index.js eapiRequest 一致)
    改进: 首次请求前预热 music.163.com 会话 cookie + 带 Referer(反爬必需)
    """
    warm_up('https://music.163.com/')
    resp = http_fetch(
        _EAPI_BATCH_URL,
        method='post',
        headers={'User-Agent': UA_PC, 'origin': 'https://music.163.com',
                 'Referer': 'https://music.163.com/'},
        form=eapi(url, data),
        retry=2,
    )
    return resp


class WYSource(MusicSource):
    id = 'wy'
    name = '网易云'
    qualitys = ['hires', 'flac', '320k', '128k']

    _hot_cache = _Cache(1800)
    _leaderboard_cache = _Cache(1800)

    # ---------------- 搜索 ----------------
    def search(self, keyword, page = 1, limit = None, retry_num = 0) :
        limit = limit or self.limit
        try:
            resp = eapi_request('/api/search/song/list/page', {
                'keyword': keyword,
                'needCorrect': '1',
                'channel': 'typing',
                'offset': limit * (page - 1),
                'scene': 'normal',
                'total': page == 1,
                'limit': limit,
            })
        except Exception as e:
            return self._retry_search(keyword, page, limit, retry_num, e)
        body = resp['body']
        if not isinstance(body, dict) or body.get('code') != 200:
            return self._retry_search(keyword, page, limit, retry_num, None)
        raw = body.get('data', {}).get('resources') or []
        song_list = self._handle_result(raw)
        if song_list is None:
            return self._retry_search(keyword, page, limit, retry_num, None)
        total = max(body.get('data', {}).get('totalCount') or 0, len(song_list))
        return {
            'list': song_list,
            'total': total,
            'allPage': (total + limit - 1) // limit if total else 0,
            'limit': limit,
            'source': self.id,
        }

    def _retry_search(self, keyword, page, limit, retry_num, err):
        if retry_num >= 3:
            raise RuntimeError(f'搜索失败: {err or "响应码无效"}') from err
        time.sleep(0.3 * (2 ** retry_num))
        return self.search(keyword, page, limit, retry_num + 1)

    @staticmethod
    def _get_singer(singers) :
        return '、'.join(s.get('name', '') for s in (singers or []))

    @staticmethod
    def _handle_result(raw_list) :
        if not raw_list:
            return []
        result = []
        for item in raw_list:
            info = item.get('baseInfo', {}).get('simpleSongData')
            if not info:
                continue
            types, _types = [], {}
            for quality, label in (('hr', 'hires'), ('sq', 'flac'), ('h', '320k'), ('m', '128k'), ('l', '128k')):
                q = info.get(quality)
                if q and q.get('size') and label not in _types:
                    _types[label] = {'size': size_formate(q['size'])}
                    types.append({'type': label, 'size': _types[label]['size']})
            types.reverse()
            ar = info.get('ar') or []
            al = info.get('al') or {}
            result.append(make_song(
                source='wy',
                songmid=str(info.get('id', '')),
                name=info.get('name', ''),
                singer=WYSource._get_singer(ar),
                img=al.get('picUrl') or '',
                interval=format_play_time((info.get('dt') or 0) / 1000),
                album_name=al.get('name') or '',
                album_id=str(al.get('id') or ''),
                types=types,
                meta={
                    'songId': info.get('id'),
                    'albumName': al.get('name'),
                    'albumId': al.get('id'),
                    'picUrl': al.get('picUrl'),
                    'qualitys': types,
                    'fee': info.get('fee'),
                    'noCopyrightRcmd': info.get('noCopyrightRcmd'),
                    'mv': info.get('mv'),
                },
            ))
        return result

    # ---------------- 歌单 ----------------
    def songlist_detail(self, list_id, page = 1, limit = None) :
        limit = limit or 100000
        list_id, cookie = self._resolve_list_id(list_id)
        _wy_warm()
        resp = http_fetch(
            'https://music.163.com/weapi/v3/playlist/detail',
            method='post',
            headers={
                'User-Agent': UA_PC,
                'origin': 'https://music.163.com',
                'Referer': 'https://music.163.com',
                'cookie': cookie,
            },
            form=weapi({'id': list_id, 'n': limit, 's': 8, 'csrf_token': ''}),
            retry=3,
        )
        body = resp['body']
        if resp['status_code'] != 200 or body.get('code') != 200:
            raise RuntimeError(body.get('message') or '歌单获取失败')
        playlist = body.get('playlist') or {}
        track_ids = playlist.get('trackIds') or []
        if not track_ids:
            return {'list': [], 'page': 1, 'limit': limit, 'total': 0, 'source': self.id,
                    'info': {'name': playlist.get('name', ''), 'play_count': format_play_count(playlist.get('playCount'))}}
        # 拉取歌曲详情
        ids = [str(t['id']) for t in track_ids]
        song_list = self._get_song_details(ids)
        return {
            'list': song_list,
            'page': page,
            'limit': limit,
            'total': len(song_list),
            'source': self.id,
            'info': {
                'name': playlist.get('name', ''),
                'picUrl': playlist.get('coverImgUrl') or '',
                'play_count': format_play_count(playlist.get('playCount')),
                'creator': (playlist.get('creator') or {}).get('nickname', ''),
            },
        }

    _LIST_LINK_RXP = re.compile(r'^.+(?:\?|&)id=(\d+)(?:&.*$|#.*$|$)')
    _LIST_LINK_RXP2 = re.compile(r'^.+/playlist/(\d+)/\d+/.+$')

    def _resolve_list_id(self, raw_id):
        cookie = ''
        if '###' in raw_id:
            raw_id, token = raw_id.split('###', 1)
            cookie = f'MUSIC_U={token}'
        if re.search(r'[?&:/]', raw_id):
            m = self._LIST_LINK_RXP.match(raw_id) or self._LIST_LINK_RXP2.match(raw_id)
            if m:
                raw_id = m.group(1)
            else:
                # 通过重定向解析
                resp = http_fetch(raw_id, retry=2)
                url = resp.get('url', raw_id)
                m = self._LIST_LINK_RXP.match(url) or self._LIST_LINK_RXP2.match(url)
                raw_id = m.group(1) if m else raw_id
        return raw_id, cookie

    def _get_song_details(self, ids, batch = 100) :
        """批量获取歌曲详情(weapi/v3/song/detail)"""
        result = []
        for i in range(0, len(ids), batch):
            chunk = ids[i:i + batch]
            _wy_warm()
            # 注意: f-string 表达式内不能有反斜杠(Python < 3.12),用普通拼接
            c_json = '[' + ','.join('{"id":' + x + '}' for x in chunk) + ']'
            ids_json = '[' + ','.join(chunk) + ']'
            resp = http_fetch(
                'https://music.163.com/weapi/v3/song/detail',
                method='post',
                headers={'User-Agent': UA_OLD, 'Referer': 'https://music.163.com', 'origin': 'https://music.163.com'},
                form=weapi({'c': c_json, 'ids': ids_json}),
                retry=3,
            )
            body = resp['body']
            if body.get('code') != 200:
                continue
            for s in body.get('songs') or []:
                ar = s.get('ar') or []
                al = s.get('al') or {}
                types, _types = [], {}
                for quality, label in (('hr', 'hires'), ('sq', 'flac'), ('h', '320k'), ('m', '128k'), ('l', '128k')):
                    q = s.get(quality)
                    if q and q.get('size') and label not in _types:
                        _types[label] = {'size': size_formate(q['size'])}
                        types.append({'type': label, 'size': _types[label]['size']})
                types.reverse()
                result.append(make_song(
                    source='wy',
                    songmid=str(s.get('id', '')),
                    name=s.get('name', ''),
                    singer=self._get_singer(ar),
                    img=al.get('picUrl') or '',
                    interval=format_play_time((s.get('dt') or 0) / 1000),
                    album_name=al.get('name') or '',
                    album_id=str(al.get('id') or ''),
                    types=types,
                    meta={'songId': s.get('id'), 'fee': s.get('fee'), 'noCopyrightRcmd': s.get('noCopyrightRcmd')},
                ))
        return result

    # ---------------- 排行榜 ----------------
    _TOP_LIST = [
        ('19723756', '飙升榜'), ('3779629', '新歌榜'), ('2884035', '原创榜'), ('3778678', '热歌榜'),
        ('991319590', '说唱榜'), ('71384707', '古典榜'), ('1978921795', '电音榜'), ('5453912201', '黑胶VIP爱听榜'),
        ('71385702', 'ACG榜'), ('745956260', '韩语榜'), ('10520166', '国电榜'), ('180106', 'UK排行榜周榜'),
        ('60198', '美国Billboard榜'), ('3812895', 'Beatport全球电子舞曲榜'), ('21845217', 'KTV唛榜'),
        ('60131', '日本Oricon榜'), ('2809513713', '欧美热歌榜'), ('2809577409', '欧美新歌榜'),
        ('27135204', '法国NRJ周榜'), ('3001835560', 'ACG动画榜'), ('3001795926', 'ACG游戏榜'),
        ('3001890046', 'ACG VOCALOID榜'), ('3112516681', '中国新乡村音乐排行榜'), ('5059644681', '日语榜'),
        ('5059633707', '摇滚榜'), ('5059642708', '国风榜'), ('5338990334', '潜力爆款榜'), ('5059661515', '民谣榜'),
        ('6688069460', '听歌识曲榜'), ('6723173524', '网络热歌榜'), ('6732051320', '俄语榜'), ('6732014811', '越南语榜'),
        ('6886768100', '中文DJ榜'), ('6939992364', '俄罗斯top hit流行音乐榜'), ('7095271308', '泰语榜'),
        ('7356827205', 'BEAT排行榜'), ('7775163417', '赏音榜'), ('7785123708', '黑胶VIP新歌榜'),
        ('7785066739', '黑胶VIP热歌榜'), ('7785091694', '黑胶VIP爱搜榜'),
    ]

    def leaderboard(self) :
        cached = self._leaderboard_cache.get('list')
        if cached:
            return cached
        result = {
            'source': self.id,
            'list': [{'id': f'wy__{bid}', 'name': name, 'bangid': bid} for bid, name in self._TOP_LIST],
        }
        self._leaderboard_cache.set('list', result)
        return result

    def leaderboard_detail(self, bangid, limit = 100) :
        _wy_warm()
        resp = http_fetch(
            'https://music.163.com/weapi/v3/playlist/detail',
            method='post',
            headers={'User-Agent': UA_PC, 'origin': 'https://music.163.com', 'Referer': 'https://music.163.com'},
            form=weapi({'id': bangid, 'n': limit, 's': 8, 'csrf_token': ''}),
            retry=3,
        )
        body = resp['body']
        playlist = body.get('playlist') or {}
        ids = [str(t['id']) for t in (playlist.get('trackIds') or [])]
        song_list = self._get_song_details(ids) if ids else []
        return {
            'list': song_list,
            'total': len(song_list),
            'source': self.id,
            'info': {'name': playlist.get('name', ''), 'picUrl': playlist.get('coverImgUrl') or ''},
        }

    # ---------------- 热搜 ----------------
    def hot_search(self) :
        cached = self._hot_cache.get('list')
        if cached:
            return cached
        resp = eapi_request('/api/search/chart/detail', {'id': 'HOT_SEARCH_SONG#@#'})
        body = resp['body']
        if resp['status_code'] != 200 or not isinstance(body, dict) or body.get('code') != 200:
            raise RuntimeError('获取热搜词失败')
        items = body.get('data', {}).get('itemList') or []
        result = [i.get('searchWord', '') for i in items]
        self._hot_cache.set('list', result)
        return result

    # ---------------- 歌词 ----------------
    def lyric(self, song) :
        songmid = song.get('songmid') or (song.get('meta') or {}).get('songId')
        last_err = None
        for attempt in range(3):
            try:
                _wy_warm()
                resp = http_fetch(
                    'https://interface3.music.163.com/eapi/song/lyric/v1',
                    method='post',
                    headers={'User-Agent': UA_OLD, 'origin': 'https://music.163.com'},
                    form=eapi('/api/song/lyric/v1', {
                        'id': songmid, 'cp': False, 'tv': 0, 'lv': 0, 'rv': 0,
                        'kv': 0, 'yv': 0, 'ytv': 0, 'yrv': 0,
                    }),
                    retry=2,
                )
                body = resp['body']
                if resp['status_code'] != 200 or not isinstance(body, dict) or body.get('code') != 200:
                    raise RuntimeError('获取歌词响应码无效')
                if body.get('lrc', {}).get('lyric'):
                    return parse_netease_lyric(body)
                return {'lyric': '', 'tlyric': '', 'rlyric': '', 'lxlyric': ''}
            except Exception as e:
                last_err = e
                if attempt < 2:
                    time.sleep(0.2)
        raise RuntimeError(f'获取歌词失败: {last_err}')

    # ---------------- 播放链接 ----------------
    def get_music_url(self, song, quality) :
        song_id = song.get('songmid') or (song.get('meta') or {}).get('songId')
        cookie = get_wy_cookie()
        level_map = {
            '128k': ('standard', 'aac'),
            '320k': ('exhigh', 'aac'),
            'flac': ('lossless', 'aac'),
            'hires': ('hires', 'flac'),
            'master': ('jymaster', 'flac'),
        }
        level, encode_type = level_map.get(quality, ('exhigh', 'aac'))
        csrf = re.search(r'_csrf=([^(;|$)]+)', cookie)
        _wy_warm()
        resp = http_fetch(
            'https://music.163.com/weapi/song/enhance/player/url/v1',
            method='post',
            headers={
                'User-Agent': UA_PC,
                'origin': 'https://music.163.com',
                'Referer': 'https://music.163.com',
                'cookie': cookie,
            },
            form=weapi({
                'ids': f'[{song_id}]',
                'level': level,
                'encodeType': encode_type,
                'csrf_token': csrf.group(1) if csrf else '',
            }),
            retry=3,
        )
        body = resp['body']
        if resp['status_code'] != 200 or not isinstance(body, dict) or body.get('code') != 200:
            raise RuntimeError('Cookie 请求失败')
        data = body['data'][0]
        url = data.get('url')
        if not url:
            # 无版权推荐歌曲回退(与原版 api-cookie.js 一致)
            fallback_id = self._get_no_copyright_song_id(song)
            if fallback_id and str(fallback_id) != str(song_id):
                fallback_song = dict(song, songmid=str(fallback_id))
                fallback_song.setdefault('meta', {})['songId'] = fallback_id
                return self.get_music_url(fallback_song, quality)
            if data.get('fee') in (1, 4):
                raise RuntimeError('VIP 歌曲或无版权,无法通过 Cookie 获取')
            raise RuntimeError('未能获取到播放链接')
        return url

    def get_mv_url(self, mvid, r = 1080) :
        """网易云官方 MV 播放直链(weapi song/enhance/play/mv/url)。
        优先请求指定清晰度,无则逐级降级 1080→720→480。"""
        cookie = get_wy_cookie()
        csrf = re.search(r'_csrf=([^(;|$)]+)', cookie)
        _wy_warm()
        for ratio in (r, 720, 480):
            try:
                resp = http_fetch(
                    'https://music.163.com/weapi/song/enhance/play/mv/url',
                    method='post',
                    headers={
                        'User-Agent': UA_PC,
                        'origin': 'https://music.163.com',
                        'Referer': 'https://music.163.com',
                        'cookie': cookie,
                    },
                    form=weapi({
                        'id': str(mvid),
                        'r': str(ratio),
                        'csrf_token': csrf.group(1) if csrf else '',
                    }),
                    retry=2,
                )
                body = resp['body']
                if resp['status_code'] == 200 and isinstance(body, dict) and body.get('code') == 200:
                    url = (body.get('data') or {}).get('url')
                    if url:
                        return url
            except Exception:
                continue
        raise RuntimeError('未能获取到 MV 播放链接')

    @staticmethod
    def _get_no_copyright_song_id(song):
        ncr = song.get('noCopyrightRcmd') or (song.get('meta') or {}).get('noCopyrightRcmd')
        if not ncr:
            return None
        return ncr.get('songId') or ncr.get('id') or (ncr.get('song') or {}).get('id')

    # ---------------- 其他 ----------------
    def pic_url(self, song) :
        return (song.get('meta') or {}).get('picUrl') or song.get('img') or ''

    def song_detail_page_url(self, song) :
        return f'https://music.163.com/#/song?id={song.get("songmid")}'


# ---------------------------------------------------------------- 歌词解析(移植 parseTools)

def _ms_format(time_ms) :
    if time_ms is None:
        return ''
    ms = time_ms % 1000
    time_ms //= 1000
    m = time_ms // 60
    s = time_ms % 60
    return f'[{m:02d}:{s:02d}.{ms}]'


_LINE_TIME_RXP = re.compile(r'^\[(\d+),\d+\]')
_WORD_TIME_RXP = re.compile(r'\((\d+),(\d+),\d+\)')
_WORD_TIME_ALL_RXP = re.compile(r'(\(\d+,\d+,\d+\))')
_INFO_RXP = re.compile(r'^{"')


def _parse_lyric(lines) :
    lxlrc_lines, lrc_lines = [], []
    for line in lines:
        line = line.strip()
        m = _LINE_TIME_RXP.match(line)
        if not m:
            if line.startswith('[offset'):
                lxlrc_lines.append(line)
                lrc_lines.append(line)
            continue
        start_ms = int(m.group(1))
        start_str = _ms_format(start_ms)
        if not start_str:
            continue
        words = _LINE_TIME_RXP.sub('', line)
        lrc_lines.append(f'{start_str}{_WORD_TIME_ALL_RXP.sub("", words)}')
        times = _WORD_TIME_ALL_RXP.findall(words)
        if not times:
            continue
        new_times = []
        for t in times:
            m2 = _WORD_TIME_RXP.search(t)
            new_times.append(f'<{max(int(m2.group(1)) - start_ms, 0)},{m2.group(2)}>')
        word_arr = _WORD_TIME_RXP.split(words)
        word_arr = word_arr[1::2]
        lxlrc_lines.append(f'{start_str}{"".join(f"{t}{w}" for t, w in zip(new_times, word_arr))}')
    return '\n'.join(lrc_lines), '\n'.join(lxlrc_lines)


def _parse_header_info(text) :
    if not text:
        return []
    text = text.strip().replace('\r', '')
    lines = text.split('\n')
    out = []
    for line in lines:
        if not _INFO_RXP.match(line):
            out.append(line)
            continue
        try:
            import json
            info = json.loads(line)
            tag = _ms_format(info.get('t'))
            out.append(f'{tag}{"".join(c.get("tx", "") for c in info.get("c", []))}' if tag else '')
        except Exception:
            out.append('')
    return out


def _get_intv(interval) :
    if not interval:
        return 0
    if '.' not in interval:
        interval += '.0'
    parts = re.split(r':|\.', interval)
    while len(parts) < 3:
        parts.insert(0, '0')
    m, s, ms = parts
    return int(m) * 3600000 + int(s) * 1000 + int(ms)


def _fix_time_tag(lrc, target_lrc) :
    lrc_lines = lrc.split('\n')
    target_lines = target_lrc.split('\n')
    time_rxp = re.compile(r'^\[([\d:.]+)\]')
    temp, new_lrc = [], []
    for line in target_lines:
        m = time_rxp.match(line)
        if not m:
            continue
        words = time_rxp.sub('', line)
        if not words.strip():
            continue
        t1 = _get_intv(m.group(1))
        while lrc_lines:
            lrc_line = lrc_lines.pop(0)
            m2 = time_rxp.match(lrc_line)
            if not m2:
                continue
            t2 = _get_intv(m2.group(1))
            if abs(t1 - t2) < 100:
                new_line = time_rxp.sub(m2.group(0), line).strip()
                if new_line:
                    new_lrc.append(new_line)
                break
            temp.append(lrc_line)
        lrc_lines = temp + lrc_lines
        temp = []
    return '\n'.join(new_lrc)


def parse_netease_lyric(body) :
    """解析网易云歌词响应(含 yrc 逐字歌词 → lxlyric)"""
    info = {'lyric': '', 'tlyric': '', 'rlyric': '', 'lxlyric': ''}
    ylrc = (body.get('yrc') or {}).get('lyric')
    ytlrc = (body.get('ytlrc') or {}).get('lyric')
    yrlrc = (body.get('yromalrc') or {}).get('lyric')
    lrc = (body.get('lrc') or {}).get('lyric')
    tlrc = (body.get('tlyric') or {}).get('lyric')
    rlrc = (body.get('romalrc') or {}).get('lyric')

    # fixTimeLabel(与原版一致)
    if lrc:
        new_lrc = re.sub(r'\[(\d{2}:\d{2}):(\d{2})]', r'[\1.\2]', lrc)
        new_tlrc = re.sub(r'\[(\d{2}:\d{2}):(\d{2})]', r'[\1.\2]', tlrc or '')
        if new_lrc != lrc or new_tlrc != (tlrc or ''):
            lrc = new_lrc
            tlrc = new_tlrc
            if rlrc:
                rlrc = re.sub(r'\[(\d{2}:\d{2}):(\d{2,3})]', r'[\1.\2]', rlrc)
                rlrc = re.sub(r'\[(\d{2}:\d{2}\.\d{2})0]', r'[\1]', rlrc)

    if ylrc:
        lines = _parse_header_info(ylrc)
        if lines:
            lyric, lxlyric = _parse_lyric(lines)
            if ytlrc:
                tlines = _parse_header_info(ytlrc)
                if tlines:
                    info['tlyric'] = _fix_time_tag(lyric, '\n'.join(tlines))
            if yrlrc:
                rlines = _parse_header_info(yrlrc)
                if rlines:
                    info['rlyric'] = _fix_time_tag(lyric, '\n'.join(rlines))
            time_rxp = re.compile(r'^\[[\d:.]+\]')
            headers = '\n'.join(l for l in lines if time_rxp.match(l))
            info['lyric'] = f'{headers}\n{lyric}' if headers else lyric
            info['lxlyric'] = lxlyric
            return info
    if lrc:
        lines = _parse_header_info(lrc)
        if lines:
            info['lyric'] = '\n'.join(lines)
    if tlrc:
        lines = _parse_header_info(tlrc)
        if lines:
            info['tlyric'] = '\n'.join(lines)
    if rlrc:
        lines = _parse_header_info(rlrc)
        if lines:
            info['rlyric'] = '\n'.join(lines)
    return info

# ════════ wyapi/__init__ 胶水 ════════
wy = WYSource()

# ════════ server.py 主体 ════════
# -*- coding: utf-8 -*-
"""
网易云音乐 Web 播放服务(独立版)
从 LX-Pro-Music-Python 抽取网易云音源,提供搜索 + 播放的本地 Web 服务,端口 5000

启动:
    python3 server.py            # 监听 0.0.0.0:5000
    WY_COOKIE='MUSIC_U=xxx' python3 server.py   # 可选:带网易云登录 Cookie 解锁 VIP 歌曲
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import requests
from flask import Flask, Response, jsonify, request, send_from_directory
from urllib.parse import quote as _url_quote

# 是否启用第三方解析兑底(官方取不到链接时,如 VIP/无版权歌曲)
TOUBIEC_ENABLED = os.environ.get('TOUBIEC_ENABLED', '1') != '0'

app = Flask(__name__)   # 单文件版:无静态目录


@app.after_request
def _no_cache(resp):
    """禁用页面缓存,保证刷新即拿到最新版本(旧缓存页会导致热歌点击误触发搜索等历史行为)"""
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

# 搜索缓存:songmid -> song dict(供 /api/url 按 id 取歌)
_song_cache = {}
_SONG_CACHE_MAX = 2000

# 播放链接缓存:songmid|quality -> (url, via, ts),TTL 10 分钟(第三方接口有限流)
_url_cache = {}
_URL_CACHE_TTL = 600
_URL_CACHE_MAX = 500
import time as _time

QUALITY_LABELS = {'hires': 'Hi-Res', 'flac': 'FLAC', '320k': '320k', '128k': '128k'}


def _cache_songs(song_list):
    for s in song_list:
        if len(_song_cache) >= _SONG_CACHE_MAX:
            _song_cache.clear()
        _song_cache[s['songmid']] = s


@app.get('/')
def index():
    return EMBEDDED_HTML   # 内嵌界面


@app.get('/api/search')
def api_search():
    keyword = (request.args.get('keyword') or '').strip()
    if not keyword:
        return jsonify({'code': 400, 'message': '缺少 keyword 参数'})
    page = max(int(request.args.get('page', 1) or 1), 1)
    limit = min(int(request.args.get('limit', 20) or 20), 50)
    try:
        res = wy.search(keyword, page, limit)
    except Exception as e:
        return jsonify({'code': 500, 'message': str(e)})
    _cache_songs(res['list'])
    return jsonify({
        'code': 200,
        'data': {
            'list': res['list'],
            'total': res.get('total', 0),
            'page': page,
            'limit': limit,
            'allPage': res.get('allPage', 0),
        },
    })


@app.get('/api/url')
def api_url():
    songmid = (request.args.get('songmid') or '').strip()
    quality = (request.args.get('quality') or '320k').strip()
    if not songmid:
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'})
    if quality not in QUALITY_LABELS:
        quality = '320k'
    song, err = _get_song_obj(songmid)
    if err:
        return jsonify({'code': 400, 'message': err})
    url, via, err = _resolve_music_url(song, songmid, quality)
    if err:
        return jsonify({'code': 500, 'message': err})
    return jsonify({'code': 200, 'data': {'url': url, 'quality': quality, 'via': via}})


def _get_song_obj(songmid):
    """从缓存取歌曲对象;无缓存则用最小对象兑底。返回 (song, error)。"""
    song = _song_cache.get(songmid)
    if song is not None:
        return song, None
    try:
        song_id = int(songmid)
    except ValueError:
        return None, 'songmid 无效'
    return {
        'source': 'wy', 'songmid': songmid, 'name': '', 'singer': '',
        'img': '', 'interval': '', 'albumName': '', 'albumId': '',
        'types': [], 'typeUrl': {},
        'meta': {'songId': song_id},
    }, None


def _resolve_music_url(song, songmid, quality):
    """官方优先取直链,失败走第三方兑底(带限流缓存)。返回 (url, via, error)。"""
    try:
        return wy.get_music_url(song, quality), 'netease', None
    except Exception as e1:
        if not TOUBIEC_ENABLED:
            return None, '', str(e1)
        # 第三方解析(带缓存,避免触发限流)
        cache_key = f'{songmid}|{quality}'
        hit = _url_cache.get(cache_key)
        if hit and hit[2] + _URL_CACHE_TTL > _time.time():
            return hit[0], hit[1], None
        try:
            url = toubiec.get_song_url(songmid, quality)
            if len(_url_cache) >= _URL_CACHE_MAX:
                _url_cache.clear()
            _url_cache[cache_key] = (url, 'toubiec', _time.time())
            return url, 'toubiec', None
        except Exception as e2:
            return None, '', f'官方失败: {e1}; 第三方失败: {e2}'


def _cd_header(filename, ctype) :
    """构建下载响应头:双文件名(ASCII 回退 + RFC 5987 中文)兼容所有浏览器,
    部分安卓浏览器/WebView 不认 filename*,会回退按 MIME 命名导致后缀错误。"""
    base, dot, ext = filename.rpartition('.')
    ascii_base = re.sub(r'[^A-Za-z0-9._ -]', '', base).strip(' -_.') or 'download'
    ascii_name = f"{ascii_base}.{ext}" if dot else ascii_base
    return {
        'Content-Disposition': f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{_url_quote(filename)}",
        'Content-Type': ctype,
        'Cache-Control': 'no-store',
    }


@app.get('/api/download')
def api_download():
    """流式代理下载:同源请求 + Content-Disposition 强制浏览器以 歌名-歌手.mp3/flac 保存,
    避免直链跨域导致文件被命名为 .mpga 等错误后缀。"""
    songmid = (request.args.get('songmid') or '').strip()
    quality = (request.args.get('quality') or '320k').strip()
    if not songmid:
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'}), 400
    if quality not in QUALITY_LABELS:
        quality = '320k'
    song, err = _get_song_obj(songmid)
    if err:
        return jsonify({'code': 400, 'message': err}), 400
    # 文件名基础:歌名-歌手(过滤非法字符,扩展名待嗅探后确定)
    safe = lambda s: re.sub(r'[\\/:*?"<>|]', '_', (s or '').strip()) or '未知'
    base = f"{safe(song.get('name'))}-{safe(song.get('singer'))}"
    req_ext = 'flac' if quality == 'flac' else 'mp3'
    url, _, err = _resolve_music_url(song, songmid, quality)
    if err:
        return jsonify({'code': 500, 'message': err}), 502
    try:
        upstream = requests.get(url, stream=True, timeout=(10, 60),
                                headers={'User-Agent': 'Mozilla/5.0'})
    except Exception as e:
        return jsonify({'code': 502, 'message': f'拉取音频失败: {e}'}), 502
    if upstream.status_code != 200:
        upstream.close()
        return jsonify({'code': 502, 'message': f'直链响应异常({upstream.status_code})'}), 502

    # 预读首个数据块用于嗅探真实容器格式
    it = upstream.iter_content(chunk_size=64 * 1024)
    first = b''
    try:
        first = next(it)
    except StopIteration:
        pass

    def _sniff(head, fallback):
        """根据文件头嗅探真实音频格式,返回 (扩展名, MIME)。"""
        if head[:4] == b'fLaC':
            return 'flac', 'audio/flac'
        if len(head) >= 8 and head[4:8] == b'ftyp':
            return 'm4a', 'audio/mp4'          # MP4/M4A 容器(部分歌曲 AAC 源)
        if head[:2] in (b'\xff\xf1', b'\xff\xf9'):
            return 'aac', 'audio/aac'          # ADTS AAC 裸流
        if head[:3] == b'ID3':
            return 'mp3', 'audio/mpeg'
        if len(head) > 1 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0 and (head[1] & 0x06):
            return 'mp3', 'audio/mpeg'         # MPEG 帧同步(层位非 00)
        return fallback, ('audio/mpeg' if fallback == 'mp3' else 'audio/flac')

    ext, ctype = _sniff(first, req_ext)
    filename = f"{base}.{ext}"

    # info=1:仅探测真实格式即返回,不传输音频体(前端用于让提示后缀与实际文件一致)
    if request.args.get('info'):
        upstream.close()
        return jsonify({'code': 200, 'data': {'ext': ext, 'ctype': ctype, 'filename': filename}})

    def gen():
        try:
            if first:
                yield first
            for chunk in it:
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    headers = _cd_header(filename, ctype)
    if 'Content-Length' in upstream.headers:
        headers['Content-Length'] = upstream.headers['Content-Length']
    return Response(gen(), headers=headers)


@app.get('/api/lyric')
def api_lyric():
    songmid = (request.args.get('songmid') or '').strip()
    if not songmid:
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'})
    song = _song_cache.get(songmid)
    if song is None:
        try:
            song_id = int(songmid)
        except ValueError:
            return jsonify({'code': 400, 'message': 'songmid 无效'})
        song = {'songmid': songmid, 'meta': {'songId': song_id}}
    data, via, lerr = _fetch_lyric(song, songmid)
    if data is None:
        if not TOUBIEC_ENABLED:
            return jsonify({'code': 500, 'message': lerr or '官方接口失败'}), 500
        return jsonify({'code': 500, 'message': f'官方失败: {lerr}; 第三方无有效歌词'}), 500
    return jsonify({'code': 200, 'data': data, 'via': via})


def _fetch_lyric(song, songmid):
    """歌词获取策略:官方优先,第三方仅兜底。返回 (data, via, error)。"""
    official_err = None
    try:
        data = wy.lyric(song)
    except Exception as e1:
        official_err = str(e1)
        data = None
    if data and (data.get('lyric') or '').strip():
        return data, 'netease', None
    if TOUBIEC_ENABLED:
        try:
            td = toubiec.get_lyric(songmid)
            tlrc = ((td or {}).get('lyric') or '').strip()
            if tlrc and not tlrc.startswith('{'):
                return td, 'toubiec', None
        except Exception:
            pass
    if data is not None:
        return data, 'netease', None
    return None, '', official_err or '官方接口失败'


@app.get('/api/download-lyric')
def api_download_lyric():
    """歌词文件下载:同源请求 + Content-Disposition 强制浏览器以 歌名-歌手.lrc 保存,
    避免前端 Blob 下载被浏览器按 MIME 改成 .txt 等错误后缀。"""
    songmid = (request.args.get('songmid') or '').strip()
    if not songmid:
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'}), 400
    song, err = _get_song_obj(songmid)
    if err:
        return jsonify({'code': 400, 'message': err}), 400
    data, _, lerr = _fetch_lyric(song, songmid)
    lrc = ((data or {}).get('lyric') or '').strip()
    if not lrc:
        return jsonify({'code': 404, 'message': lerr or '暂无歌词'}), 404
    content = lrc
    tlyric = ((data or {}).get('tlyric') or '').strip()
    if tlyric:
        content += '\n\n' + tlyric
    safe = lambda s: re.sub(r'[\\/:*?"<>|]', '_', (s or '').strip()) or '未知'
    filename = f"{safe(song.get('name'))}-{safe(song.get('singer'))}.lrc"
    # octet-stream 强制下载:防止浏览器按 text/plain 渲染并改名为 .txt
    return Response(content, headers=_cd_header(filename, 'application/octet-stream'))


def _resolve_mvid(song, songmid):
    """从官方歌曲对象解析 MV id(搜索数据 meta.mv 字段)。0/缺失 → None。"""
    mv = (song.get('meta') or {}).get('mv')
    try:
        mvid = int(mv)
    except (TypeError, ValueError):
        return None
    return mvid if mvid > 0 else None


@app.get('/api/mv/check')
def api_mv_check():
    """检查歌曲是否有官方 MV。"""
    songmid = (request.args.get('songmid') or '').strip()
    if not songmid:
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'}), 400
    song, err = _get_song_obj(songmid)
    if err:
        return jsonify({'code': 400, 'message': err}), 400
    mvid = _resolve_mvid(song, songmid)
    return jsonify({'code': 200, 'data': {'hasMv': bool(mvid), 'mvid': mvid}})


@app.get('/api/mv/url')
def api_mv_url():
    """官方接口解析 MV 视频直链(自动降级 1080→720→480)。"""
    mvid = (request.args.get('mvid') or '').strip()
    if not mvid:
        return jsonify({'code': 400, 'message': '缺少 mvid 参数'}), 400
    try:
        url = wy.get_mv_url(mvid)
    except Exception as e:
        return jsonify({'code': 502, 'message': f'MV 解析失败: {e}'}), 502
    return jsonify({'code': 200, 'data': {'url': url}})


@app.get('/api/download-mv')
def api_download_mv():
    """MV 流式代理下载:同源 + Content-Disposition 强制 歌名-歌手-MV.mp4 保存。"""
    mvid = (request.args.get('mvid') or '').strip()
    name = (request.args.get('name') or '').strip()
    singer = (request.args.get('singer') or '').strip()
    if not mvid:
        return jsonify({'code': 400, 'message': '缺少 mvid 参数'}), 400
    try:
        url = wy.get_mv_url(mvid)
    except Exception as e:
        return jsonify({'code': 502, 'message': f'MV 解析失败: {e}'}), 502
    try:
        upstream = requests.get(url, stream=True, timeout=(10, 60),
                                headers={'User-Agent': 'Mozilla/5.0'})
    except Exception as e:
        return jsonify({'code': 502, 'message': f'拉取 MV 失败: {e}'}), 502
    if upstream.status_code != 200:
        upstream.close()
        return jsonify({'code': 502, 'message': f'MV 直链响应异常({upstream.status_code})'}), 502

    def gen():
        try:
            for chunk in upstream.iter_content(chunk_size=64 * 1024):
                if chunk:
                    yield chunk
        finally:
            upstream.close()

    safe = lambda s: re.sub(r'[\\/:*?"<>|]', '_', (s or '').strip()) or '未知'
    filename = f"{safe(name)}-{safe(singer)}-MV.mp4"
    headers = _cd_header(filename, 'application/octet-stream')
    if 'Content-Length' in upstream.headers:
        headers['Content-Length'] = upstream.headers['Content-Length']
    return Response(gen(), headers=headers)



@app.get('/api/hot')
def api_hot():
    try:
        words = wy.hot_search()
    except Exception as e:
        return jsonify({'code': 500, 'message': str(e)})
    return jsonify({'code': 200, 'data': words})


@app.get('/api/songlist')
def api_songlist():
    """按歌单 id 取歌曲列表,方便播放收藏歌单 / 热门歌单"""
    list_id = (request.args.get('id') or '').strip()
    if not list_id:
        return jsonify({'code': 400, 'message': '缺少 id 参数'})
    limit_arg = request.args.get('limit')
    try:
        limit = min(max(int(limit_arg), 1), 500) if limit_arg else None
    except ValueError:
        limit = None
    try:
        res = wy.songlist_detail(list_id, 1, limit)
    except Exception as e:
        return jsonify({'code': 500, 'message': str(e)})
    if limit:
        # 榜单接口会返回全部 trackIds,这里截取前 limit 首
        res['list'] = (res.get('list') or [])[:limit]
        res['total'] = len(res['list'])
    _cache_songs(res['list'])
    return jsonify({'code': 200, 'data': res})


@app.get('/api/songdetail')
def api_song_detail():
    """按单曲 ID 官方解析歌曲详情(搜索框单曲链接直连),结构与搜索结果一致"""
    songmid = (request.args.get('songmid') or '').strip()
    if not songmid.isdigit():
        return jsonify({'code': 400, 'message': '缺少 songmid 参数'})
    try:
        lst = wy._get_song_details([songmid])
    except Exception as e:
        return jsonify({'code': 500, 'message': str(e)})
    if not lst:
        return jsonify({'code': 404, 'message': '未找到该歌曲'})
    _cache_songs(lst)
    return jsonify({'code': 200, 'data': {'list': lst}})


@app.post('/api/cookie')
def api_set_cookie():
    """设置网易云 Cookie(如 MUSIC_U=xxx),可选"""
    body = request.get_json(silent=True) or {}
    cookie = body.get('cookie') or request.form.get('cookie') or ''
    set_wy_cookie(cookie)
    return jsonify({'code': 200, 'message': 'Cookie 已设置', 'has_cookie': bool(cookie)})


if __name__ == '__main__':
    cookie = os.environ.get('WY_COOKIE', '')
    if cookie:
        set_wy_cookie(cookie)
    print('网易云 Web 播放服务启动: http://localhost:5000')
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)


def start():
    """桌面/服务器模式入口(监听 HTTP 端口)。App 内无端口架构不再调用此函数,
    改由 handle_api() 桥接分发;保留以兼容 wy-web-server 独立部署场景。"""
    cookie = os.environ.get('WY_COOKIE', '')
    if cookie:
        set_wy_cookie(cookie)
    print('网易云下载器 Web 服务启动: http://127.0.0.1:5000')
    app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)


def get_html():
    """供 Java 层调用:把界面 HTML 渲染进 WebView(无端口架构,无需等服务启动)。"""
    return EMBEDDED_HTML


def _ensure_init():
    """桥接模式一次性初始化(幂等)。"""
    global _BRIDGE_INITED
    if _BRIDGE_INITED:
        return
    cookie = os.environ.get('WY_COOKIE', '')
    if cookie:
        set_wy_cookie(cookie)
    _BRIDGE_INITED = True


_BRIDGE_INITED = False


def handle_api(path):
    """JS 桥接入口(无端口模式核心):WebView 页面经 AndroidBridge 直达此处,
    用 Flask test client 在进程内分发到既有路由 —— 零网络开销、零端口监听、
    路由逻辑零改动。每次调用独立 client,天然线程安全,可并发。
    返回 JSON 字符串 {"status": <http状态码>, "body": "<路由原始响应>"}"""
    _ensure_init()
    r = app.test_client(use_cookies=False).open(path, method='GET')
    body = r.get_data(as_text=True)
    # 404 兜底:未匹配路由返回的是 HTML 错误页,包装成 JSON 供前端统一解析
    if r.status_code == 404 and not body.lstrip().startswith('{'):
        body = json.dumps({'code': 404, 'message': '接口不存在'})
    return json.dumps({'status': r.status_code, 'body': body})

# ════════ 内嵌界面 index.html ════════
EMBEDDED_HTML = r'''<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>网易云-播放/下载器</title>
<style>
  /* ============ VS Code 主题变量 ============ */
  :root {
    --bg: #1e1e1e;            /* 编辑器背景 */
    --bg-panel: #252526;      /* 面板背景 */
    --bg-hover: #2a2d2e;      /* 悬停 */
    --bg-active: #c20c0c;     /* 选中行背景(与搜索按钮同色 网易云红) */
    --bg-input: #3c3c3c;
    --border: #3c3c3c;
    --text: #cccccc;
    --text-bright: #ffffff;
    --muted: #858585;
    --accent: #c20c0c;        /* 网易云红 */
    --accent-hover: #ec4141;
    --green: #89d185;
    --red: #f48771;
    --yellow: #cca700;
    --selection: #264f78;
    --mono: "Consolas","Menlo","DejaVu Sans Mono",monospace;
    --radius: 4px;
    /* ====== 毛玻璃统一参数 ====== */
    --glass-alpha: .5;           /* 面板/控件背景不透明度 50% */
    --bgcover-blur: 48px;        /* 全局封面背景模糊强度(约70%档):单层渲染,GPU 缓存一次 */
  }
  * { box-sizing:border-box; margin:0; padding:0; -webkit-tap-highlight-color:transparent; outline:none; }
  body {
    background:var(--bg); color:var(--text);
    font-family:-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",system-ui,sans-serif;
    font-size:14px;
    min-height:100vh;
    padding-bottom:130px;
  }

  /* ============ 全局封面底层背景(单层预模糊,替代逐元素 backdrop-filter,大幅降低合成开销) ============ */
  #bgCover {
    position:fixed; inset:-80px; z-index:-1;
    background:center/cover no-repeat #1e1e1e;
    filter:blur(var(--bgcover-blur)) brightness(.5) saturate(150%);
    transform:translateZ(0);        /* 提升为独立合成层:滚动时零重绘 */
    pointer-events:none;
  }
  ::selection { background:var(--selection); color:var(--text-bright); }
  ::-webkit-scrollbar { width:8px; height:8px; }
  ::-webkit-scrollbar-thumb { background:#424242; border-radius:4px; }
  ::-webkit-scrollbar-thumb:hover { background:#4f4f4f; }
  ::-webkit-scrollbar-track { background:transparent; }

  .container { max-width:960px; margin:0 auto; padding:16px 18px; }

  /* ============ 顶栏 ============ */
  header { padding-bottom:14px; border-bottom:1px solid var(--border); margin-bottom:14px; }
  h1 { font-size:16px; font-weight:600; color:var(--text-bright); letter-spacing:.3px; }
  h1 .sub { display:block; font-size:10.5px; color:var(--muted); font-weight:400; margin-top:2px; font-family:var(--mono); }

  /* ============ 搜索栏(只保留输入框+按钮) ============ */
  .search-bar { display:flex; gap:8px; margin-bottom:12px; }
  .search-bar input {
    flex:1; padding:8px 13px; border-radius:var(--radius);
    border:1px solid var(--border); background:rgba(60,60,60,var(--glass-alpha)); color:var(--text-bright);
    font-size:13px; outline:none; transition:border-color .15s, box-shadow .15s;
    font-family:var(--mono);
  }
  .search-bar input:focus { border-color:var(--accent); box-shadow:0 0 0 1px var(--accent); }
  .search-bar input::placeholder { color:var(--muted); }
  .btn {
    padding:8px 18px; border-radius:var(--radius); border:none; cursor:pointer;
    background:var(--accent); color:#fff; font-size:13px; font-weight:500;
    transition:background .15s; user-select:none; white-space:nowrap;
  }
  .btn:hover { background:var(--accent-hover); }  .btn:active { transform:translateY(1px); }

  /* ============ 网易云热门歌曲(15首) ============ */
  .hot { margin-bottom:12px; }
  .hot-title {
    font-size:11px; color:var(--muted); margin-bottom:7px;
    font-family:var(--mono); letter-spacing:1px; display:flex; align-items:center; gap:6px;
  }
  .hot-title::after { content:""; flex:1; height:1px; background:var(--border); }
  .hot-list { display:flex; flex-wrap:wrap; gap:5px; }
  .chip {
    color:var(--muted); font-size:11px; text-decoration:none; padding:3px 9px;
    border:1px solid var(--border); border-radius:11px; cursor:pointer;
    transition:all .15s; background:rgba(60,60,60,var(--glass-alpha)); font-family:inherit;
    max-width:200px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;
  }
  .chip:hover { color:var(--accent-hover); border-color:var(--accent); background:rgba(194,12,12,.25); }
  .chip .n { color:var(--accent-hover); margin-right:3px; font-family:var(--mono); font-size:10px; }

  /* ============ 双栏布局:左歌词 / 右搜索结果(等权重) ============ */
  .dash {
    display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:14px; align-items:start;
  }
  .panel {
    background:rgba(37,37,38,var(--glass-alpha)); border:1px solid var(--border); border-radius:var(--radius);
    padding:8px; min-height:200px; max-height:64vh; overflow-y:auto;
    font-size:10px;               /* 字体缩小约 2 倍,防挤压穿插 */
    scrollbar-width:none;         /* Firefox 隐藏滚动条 */
    -ms-overflow-style:none;      /* IE/旧 Edge 隐藏滚动条 */
  }
  /* WebKit 内核隐藏面板滚动条(仍可触摸/滚轮滚动) */
  .panel::-webkit-scrollbar { width:0; height:0; display:none; }
  /* 列表标题(位于列表外上方、热门歌曲之下,带圆角) */
  .dash > .col { display:flex; flex-direction:column; min-width:0; }
  .panel-title {
    font-size:10.5px; color:var(--muted); font-family:var(--mono); letter-spacing:1px;
    margin-bottom:6px; display:flex; align-items:center; gap:6px;
    background:rgba(37,37,38,var(--glass-alpha)); padding:5px 10px;
    border-radius:var(--radius);           /* 标题圆角与列表一致 */
    width:100%; height:27px; box-sizing:border-box;   /* 两栏标题等宽等高,与列表 1:1 权重对齐 */
    white-space:nowrap; overflow:hidden;   /* 强制单行:标题永不换行(不用跑马灯),超出部分裁切 */
  }
  .panel-title::after { content:""; flex:1; height:1px; background:var(--border); min-width:6px; }   /* 线条吸收挤压 */
  /* 歌词同步校准控件(标题栏右侧) */
  .calib { margin-left:auto; display:inline-flex; align-items:center; gap:4px; flex-shrink:0; }   /* 校准控件永不縮水 */
  .calib button {
    width:16px; height:16px; border-radius:3px; border:1px solid var(--border);
    background:transparent; color:var(--muted); cursor:pointer;
    font-size:10px; line-height:1; padding:0; font-family:var(--mono);
  }
  .calib button:hover { color:var(--text-bright); border-color:var(--accent); }
  #calVal { font-family:var(--mono); font-size:9px; color:var(--muted); min-width:26px; text-align:center; cursor:pointer; }
  #calVal:hover { color:var(--text-bright); }
  .panel .empty { color:#4d4d4d; text-align:center; padding:30px 0; font-family:var(--mono); font-size:9.5px; }

  /* ---- 左侧歌词 ---- */
  .lyrics div {
    color:var(--muted); transition:color .2s, transform .2s; padding:1px 5px; border-radius:3px;
    font-size:10px; line-height:1.75; word-break:break-all;
  }
  .lyrics div.active {
    color:var(--text-bright); transform:translateX(4px);
    background:linear-gradient(90deg, rgba(194,12,12,.18), transparent);
    border-left:2px solid var(--accent);
  }

  /* ---- 右侧搜索结果 ---- */
  .meta { color:var(--muted); font-size:9.5px; margin-bottom:5px; font-family:var(--mono); }
  .song { display:flex; align-items:center; gap:6px; padding:7px 6px; border-radius:3px; cursor:pointer; border-left:2px solid transparent; transition:background .1s; }
  .song:hover { background:var(--bg-hover); }
  .song.playing { background:linear-gradient(90deg, rgba(194,12,12,.23), transparent); border-left-color:var(--accent); }
  .song.playing .name { color:var(--text-bright); }
  .song .idx { width:13px; min-width:13px; text-align:center; color:var(--muted); font-size:10px; flex-shrink:0; font-family:var(--mono); }
  .song.playing .idx { color:#fff; opacity:.92; }
  .song .info { flex:1; min-width:0; white-space:nowrap; overflow:hidden; }
  .song .track { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; will-change:transform; }
  .song .name { font-size:10px; color:var(--text); font-weight:500; }
  .song .singer { font-size:10px; color:var(--muted); }
  /* 内容超宽时横向滚动(跑马灯),两端停顿便于阅读 */
  .song .track.marquee { animation:songMarquee var(--dur,8s) ease-in-out infinite alternate; }
  @keyframes songMarquee {
    0%, 12%    { transform:translateX(0); }
    88%, 100%  { transform:translateX(calc(var(--dist, 0px) * -1)); }
  }


  /* ============ 底部播放器(圆角卡片,极简) ============ */
  .player { position:fixed; left:0; right:0; bottom:0; z-index:100; display:flex; justify-content:center; padding:0 14px 14px; pointer-events:none; }
  .player-card {
    pointer-events:auto; width:100%; max-width:680px;
    background:rgba(37,37,38,var(--glass-alpha));
    border:1px solid var(--border); border-radius:16px;
    padding:10px 14px; display:flex; align-items:center; gap:12px;
    box-shadow:0 8px 30px rgba(0,0,0,.55);
  }
  .play-btn {
    width:40px; height:40px; border-radius:50%; border:none; cursor:pointer;
    background:var(--accent); color:#fff; flex-shrink:0;
    display:flex; align-items:center; justify-content:center;
    transition:background .15s, transform .1s;
  }
  .play-btn:hover { background:var(--accent-hover); }
  .play-btn:active { transform:scale(.92); }
  .play-btn svg { width:18px; height:18px; fill:#fff; }
  .p-info { flex:1; min-width:0; }
  .p-name { font-size:13.5px; color:var(--text-bright); overflow:hidden; }
  .p-artist { font-size:11.5px; color:var(--muted); margin-top:2px; overflow:hidden; }
  /* 播放器跑马灯轨道:歌名+VIP标签(或歌手)作为整体来回滚动,不再被挤掉 */
  .p-track { display:inline-flex; align-items:center; gap:6px; white-space:nowrap; will-change:transform; padding-right:16px; }
  .p-track.marquee { animation:songMarquee var(--dur,8s) ease-in-out infinite alternate; }
  .p-name .tag3rd { color:#ffd700; font-size:10px; border:1px solid #6b5b00; border-radius:3px; padding:0 5px; font-family:var(--mono); flex-shrink:0; }
  .p-progress { display:flex; align-items:center; gap:8px; flex-shrink:0; width:42%; min-width:120px; cursor:pointer; }
  .p-bar { flex:1; height:4px; background:#3c3c3c; border-radius:2px; overflow:hidden; }
  .p-fill { height:100%; width:0%; background:var(--accent); border-radius:2px; transition:width .2s linear; position:relative; }
  .p-fill::after { content:""; position:absolute; right:-4px; top:50%; width:9px; height:9px; margin-top:-4.5px; border-radius:50%; background:var(--accent-hover); box-shadow:0 0 6px rgba(236,65,65,.8); }
  .p-time { font-family:var(--mono); font-size:10.5px; color:var(--muted); white-space:nowrap; }

  /* ============ 下载标签按钮 + 居中弹窗 ============ */
  .dl-tag {
    flex-shrink:0; cursor:pointer; font-family:var(--mono);
    font-size:10.5px; color:var(--accent-hover); background:transparent;
    border:1px solid var(--border); border-radius:11px;
    width:44px; padding:3px 0; text-align:center;   /* 统一固定尺寸:MV/下载标签完全一致 */
    transition:all .15s; user-select:none;
    box-sizing:border-box; line-height:1.4;
  }
  .dl-tag:hover { border-color:var(--accent); background:rgba(194,12,12,.08); }
  .dl-tag:active { transform:translateY(1px); }
  /* MV 弹窗视频播放器(严格限制在弹窗内) */
  #mvModal .modal-box { width:min(340px, 88vw); }
  .modal-box video {
    display:block; width:100%; max-width:100%; max-height:48vh;
    border-radius:8px; background:#000; margin-bottom:2px;
    object-fit:contain;
  }

  .modal-mask {
    position:fixed; inset:0; z-index:1000; display:none;
    align-items:center; justify-content:center;
    background:rgba(0,0,0,.55); backdrop-filter:blur(2px);
  }
  .modal-mask.show { display:flex; }
  .modal-box {
    position:relative; width:min(300px, 84vw);
    background:rgba(37,37,38,var(--glass-alpha)); border:1px solid var(--border); border-radius:12px;   /* 背景透明度与列表一致 */
    padding:20px 24px 24px; box-shadow:0 12px 40px rgba(0,0,0,.6);
    display:flex; flex-direction:column; align-items:center;
    animation:popIn .16s ease-out;
  }
  @keyframes popIn { from { opacity:0; transform:scale(.92); } to { opacity:1; transform:none; } }
  .modal-x {
    position:absolute; top:8px; right:10px; background:none; border:none;
    color:var(--muted); font-size:17px; line-height:1; cursor:pointer; padding:2px 4px;
  }
  .modal-x:hover { color:var(--text-bright); }
  .modal-title { color:var(--text-bright); font-size:13.5px; letter-spacing:.5px; margin-bottom:14px; }
  #dlSongName { display:inline-block; vertical-align:bottom; max-width:min(210px,58vw); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }   /* 单行显示,过长省略号截断 */
  .modal-btn {
    width:100%; max-width:210px; padding:9px 0; margin-top:10px;
    border-radius:var(--radius); border:none; cursor:pointer;
    background:rgba(60,60,60,var(--glass-alpha)); color:#fff; font-size:13px; font-weight:500;   /* 与下载歌词按钮配色一致 */
    box-shadow:0 3px 10px rgba(0,0,0,.5), inset 0 1px 0 rgba(255,255,255,.12);   /* 阴影+顶部高光:与弹窗同透明度也能看出按钮层次 */
    transition:background .15s, box-shadow .15s;
  }
  .modal-btn:hover { background:rgba(74,74,74,var(--glass-alpha)); box-shadow:0 4px 14px rgba(0,0,0,.6), inset 0 1px 0 rgba(255,255,255,.18); }
  .modal-btn:active { transform:translateY(1px); }

  /* (启动引导浮层样式已移除:改用 toast 提示) */
  /* ============ Toast 通知(VS Code 风格) ============ */
  #toasts { position:fixed; right:16px; bottom:105px; z-index:999; display:flex; flex-direction:column; gap:8px; width:320px; max-width:80vw; }
  .toast {
    display:flex; align-items:flex-start; gap:10px;
    background:#333333; border:1px solid #424242; border-left:3px solid var(--accent);
    color:var(--text); border-radius:var(--radius); padding:10px 12px;
    font-size:12.5px; line-height:1.5; word-break:break-all;
    box-shadow:0 4px 14px rgba(0,0,0,.45);
    animation:toastIn .18s ease-out;
  }
  .toast.info { border-left-color:var(--accent); }
  .toast.success { border-left-color:var(--green); }
  .toast.warn { border-left-color:var(--yellow); }
  .toast.error { border-left-color:var(--red); }
  .toast .toast-icon { font-size:15px; line-height:1.2; flex-shrink:0; }
  .toast.info .toast-icon { color:var(--accent-hover); }
  .toast.success .toast-icon { color:var(--green); }
  .toast.warn .toast-icon { color:var(--yellow); }
  .toast.error .toast-icon { color:var(--red); }
  .toast .toast-msg { flex:1; min-width:0; white-space:pre-line; }
  .toast .toast-close { background:none; border:none; color:var(--muted); cursor:pointer; font-size:15px; padding:0 2px; line-height:1; flex-shrink:0; }
  .toast .toast-close:hover { color:var(--text-bright); }
  .toast.hide { opacity:0; transform:translateX(20px); transition:all .25s; }
  @keyframes toastIn { from { opacity:0; transform:translateX(30px); } to { opacity:1; transform:none; } }

  /* ============ 迷你下载任务面板(固定在页面顶部最右,与标题「网易云-播放/下载器」同排;
     可收缩;进度到 100% 显示「即将完成」;无进行中任务时短暂展示后自动消失) ============ */
  #dlPanel {
    position:fixed; top:10px; right:12px; z-index:998;
    width:212px; max-width:56vw;
    background:rgba(24,16,17,.94); border:1px solid rgba(236,65,65,.35); border-radius:8px;
    box-shadow:0 6px 18px rgba(0,0,0,.45); overflow:hidden;
    animation:toastIn .18s ease-out;
  }
  #dlPanel.hidden { display:none; }
  .dl-head {
    display:flex; align-items:center; gap:6px; padding:5px 9px;
    cursor:pointer; user-select:none;
    background:rgba(194,12,12,.2); color:#fff; font-size:10.5px;
    font-family:var(--mono); letter-spacing:.5px;
  }
  .dl-head:hover { background:rgba(194,12,12,.32); }
  .dl-head .dl-arrow { margin-left:auto; transition:transform .22s; font-size:9px; }
  #dlPanel.collapsed .dl-arrow { transform:rotate(-90deg); }
  #dlPanel.collapsed .dl-list { display:none; }
  .dl-list { max-height:168px; overflow-y:auto; overscroll-behavior:contain; }
  .dl-item { padding:5px 9px; border-top:1px solid rgba(255,255,255,.05); cursor:pointer; }
  .dl-item .nm { display:flex; justify-content:space-between; align-items:center; gap:8px; margin-bottom:3px; font-size:10.5px; color:var(--text); }
  .dl-item .dl-nm { flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .dl-item .pc { flex-shrink:0; font-size:9.5px; color:var(--accent-hover); font-family:var(--mono); }
  .dl-item.done .pc { color:var(--green); }
  .dl-item.fail .pc { color:var(--red); }
  .dl-item.sys .pc { color:var(--yellow); }
  .dl-bar { height:3px; border-radius:2px; background:rgba(255,255,255,.08); overflow:hidden; }
  .dl-bar i { display:block; height:100%; width:0%; border-radius:2px;
    background:linear-gradient(90deg,var(--accent),var(--accent-hover)); transition:width .35s ease-out; }
  .dl-item.done .dl-bar i { background:var(--green); }
  .dl-item.fail .dl-bar i { background:var(--red); }
  .dl-path {
    margin-top:4px; font-size:9px; font-family:var(--mono); color:var(--muted);
    word-break:break-all; line-height:1.4;
  }

  .loading { color:var(--muted); text-align:center; padding:30px 0; font-family:var(--mono); font-size:10px; }
  .loading::after { content:"…"; animation:dots 1s steps(4) infinite; }
  @keyframes dots { 0%{content:""} 25%{content:"."} 50%{content:".."} 75%{content:"..."} }
  .err { color:var(--red); text-align:center; padding:18px; font-size:11px; }

  /* ====== PC 大屏适配:容器加宽、字号微调 ====== */
  @media (min-width:1024px) {
    .container { max-width:1180px; padding:22px 28px; }
    body { font-size:15px; }
    .panel { max-height:70vh; font-size:11.5px; }
    .lyrics div { font-size:11.5px; }
    .song .idx, .song .name, .song .singer { font-size:11.5px; }
  }

  @media (max-width:600px) {
    .p-progress { width:34%; min-width:88px; }
    .player-card { padding:9px 12px; gap:9px; }
    .play-btn { width:36px; height:36px; }
  }
</style>
</head>
<body>
<!-- 全局封面底层背景:播放时加载歌曲专辑封面,重度模糊成毛玻璃氛围层 -->
<div id="bgCover"></div>
<div class="container">
  <header>
    <h1>网易云-播放/下载器
      <span class="sub">NETEASE MUSIC · by:binsys蓝莓派</span>
    </h1>
  </header>

  <div class="search-bar">
    <input id="kw" autocomplete="off" enterkeyhint="search" placeholder="搜索歌曲/歌手/专辑 或粘贴歌单链接/ID" onkeydown="if(event.key==='Enter')doSearch(1)">
    <button class="btn" onclick="doSearch(1)">搜索</button>
  </div>

  <div class="hot">
    <div class="hot-title">🔥 网易云热门歌曲</div>
    <div class="hot-list" id="hotList"><span class="loading">加载中</span></div>
  </div>

  <!-- 双栏:左歌词 / 右搜索结果,标题在列表外上方 -->
  <div class="dash">
    <div class="col">
      <h3 class="panel-title">歌词 LYRICS <span class="calib" title="微调歌词与歌声的同步偏差,按歌曲自动记忆">
        <button id="calMinus" type="button">−</button><span id="calVal" title="当前校准偏移(点击复位为0)">+0.0</span><button id="calPlus" type="button">+</button>
      </span></h3>
      <div class="panel lyrics" id="lyrics">
        <div class="empty" id="lyricsEmpty">≽^⚈⩊⚈^≼</div>
        <div id="lyricsBody"></div>
      </div>
    </div>
    <div class="col">
      <h3 class="panel-title">列表 PLAYLIST <span class="calib"><button id="mqToggle" type="button" title="搜索结果跑马灯 开/关">⇄</button><button id="srcToggle" type="button" title="切换 歌单/单曲 数据" style="display:none">♫</button></span></h3>
      <div class="panel" id="resultPanel">
        <div class="empty" id="resultEmpty">ᕙ(  •̀ ᗜ •́  )ᕗ</div>
        <div id="resultBody"></div>
      </div>
    </div>
  </div>
</div>

<div class="player">
  <div class="player-card">
    <button class="play-btn" id="btnPlay" onclick="togglePlay()" title="播放/暂停"></button>
    <div class="p-info">
      <div class="p-name" id="nowName"><div class="p-track">未播放</div></div>
      <div class="p-artist" id="nowArtist"><div class="p-track"></div></div>
    </div>
    <div class="p-progress" id="progWrap" onclick="seek(event)">
      <div class="p-bar"><div class="p-fill" id="progFill"></div></div>
      <span class="p-time" id="nowTime">00:00 / 00:00</span>
    </div>
    <button class="dl-tag" id="mvTag" style="display:none" onclick="openMvModal()" title="播放/下载 MV">MV</button>
    <button class="dl-tag" onclick="openDlModal()" title="下载歌曲/歌词">下载</button>
  </div>
</div>

<!-- 下载弹窗(居中,两个选项竖排) -->
<div class="modal-mask" id="dlModal">
  <div class="modal-box">
    <button class="modal-x" onclick="closeDlModal()" title="关闭">○</button>
    <div class="modal-title"><span id="dlSongName">当前歌曲</span></div>
    <button class="modal-btn" onclick="downloadSong()">下载歌曲</button>
    <button class="modal-btn secondary" onclick="downloadLyric()">下载歌词</button>
  </div>
</div>

<div class="modal-mask" id="mvModal">
  <div class="modal-box">
    <button class="modal-x" onclick="closeMvModal()" title="关闭">○</button>
    <div class="modal-title" id="mvTitle">▶ MV播放器</div>
    <video id="mvVideo" controls playsinline style="display:none"></video>
    <div class="loading" id="mvLoading">MV 解析中</div>
    <button class="modal-btn" onclick="downloadMv()">下载 MV</button>
  </div>
</div>

<!-- 常驻下载任务面板:有任务时常挂页面、点标题可收缩、全部结束自动隐藏;
     点击已完成条目可复制完整保存路径 -->
<div id="dlPanel" class="hidden">
  <div class="dl-head" onclick="toggleDlPanel()">
    <span>⬇</span><span id="dlHeadText">下载任务</span><span class="dl-arrow">▾</span>
  </div>
  <div class="dl-list" id="dlList"></div>
</div>

<div id="toasts"></div>

<!-- 隐藏的原生 audio:只用于出声,控制由自定义播放器接管 -->
<audio id="audio" preload="auto" style="position:absolute;left:-9999px;width:0;height:0"></audio>

<script>
/* ============ 配置 ============ */
const QUALITY = '320k';              // 统一音质
const LYRIC_OFFSET = 0;              /* 全局默认净偏移(秒):严格对齐时间戳,不再预提前(正=提前,负=延后) */
const HOT_LIST_ID = '3778678';       // 网易云热歌榜
const PAGE_SIZE = 20;
/* PC 端检测(hover+精确指针):首次搜索预加载 60 条 */
const IS_PC = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
const PC_INIT_TARGET = IS_PC ? 60 : 0;

/* ============ 全局状态(按面板拆分,各自独立刷新,互不牵连) ============ */
const state = {
  list: [],          // 当前播放列表(搜索结果或热门歌曲)
  page: 1,
  allPage: 0,
  total: 0,
  song: null,        // 当前播放歌曲
  songIndex: -1,
  lyricIdx: -1,      // 当前高亮歌词行(只影响歌词面板)
  lyricTimes: [],    // 当前歌词时间轴(只影响歌词面板)
};
let hotSongs = [];

const $ = id => document.getElementById(id);
function esc(s) { return (s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
/* ============ API 传输层:无端口架构 ============
 * App 内:经 AndroidBridge 直连 Python(异步线程池,结果回调 __onApiResult);
 * 桌面浏览器兜底:fetch 直连 wy-web-server。调用方语义不变(返回路由 JSON)。 */
let _reqSeq = 0;
const _pending = {};
function api(path) {
  if (window.AndroidBridge && AndroidBridge.request) {
    return new Promise((resolve, reject) => {
      const id = ++_reqSeq;
      const timer = setTimeout(() => {
        if (_pending[id]) { delete _pending[id]; reject(new Error('请求超时')); }
      }, 60000);
      _pending[id] = { resolve, reject, timer };
      AndroidBridge.request(String(id), path);      // 立即返回,不阻塞页面
    });
  }
  return fetch(path).then(r => r.json());           // 桌面浏览器兑底
}
window.__onApiResult = (id, status, body) => {
  const p = _pending[id]; if (!p) return;           // 过期/超时结果丢弃
  delete _pending[id]; clearTimeout(p.timer);
  try { p.resolve(JSON.parse(body)); } catch (e) { p.reject(new Error('响应解析失败')); }
};

/* ============ 迷你下载任务面板(可收缩)+ 下载器事件 ============
 * 所有下载统一落盘到 公共Download/网易云下载器/ 文件夹。
 * 面板与普通 toast 不同:有任务时常驻挂在页面上(网络慢也能看到进度与任务数),
 * 点击标题可收缩;进度到 100% 后显示「即将完成」而非「下载中」;
 * 只要没有进行中的任务了,整个面板短暂展示结果后自动消失。 */
const DL_TASKS = new Map();                       // 文件名 → {st,pct,path,timer,finTimer}
let dlCollapsed = false;
let dlHideTimer = null;

function toggleDlPanel() {
  dlCollapsed = !dlCollapsed;
  $('dlPanel').classList.toggle('collapsed', dlCollapsed);
}

function dlRender() {
  const panel = $('dlPanel');
  if (dlHideTimer) { clearTimeout(dlHideTimer); dlHideTimer = null; }
  if (!DL_TASKS.size) { panel.classList.add('hidden'); $('dlList').innerHTML = ''; return; }
  panel.classList.remove('hidden');
  const all = [...DL_TASKS.values()];
  const running   = all.filter(t => (t.st === 'run' && t.pct < 100) || t.st === 'sys').length;
  const finishing = all.filter(t => t.st === 'run' && t.pct >= 100).length;   // 已 100% 等收尾
  const doneN     = all.filter(t => t.st === 'done').length;
  $('dlHeadText').textContent = running
    ? `⬇ ${running + finishing}`
    : finishing ? '即将完成'
    : `✓ ${doneN || DL_TASKS.size}`;
  /* 关键:没有任何进行中的任务 → 短暂展示结果后整个面板自动消失,
   * 不会出现「进度条已 100% 还一直挂着下载中」的情况 */
  if (!running) dlHideTimer = setTimeout(() => { DL_TASKS.clear(); dlRender(); }, finishing ? 2500 : 1200);
  $('dlList').innerHTML = [...DL_TASKS.entries()].map(([name, t]) => `
    <div class="dl-item ${t.st}"${t.path ? ` data-path="${esc(t.path)}" title="点击复制完整路径"` : ''}>
      <div class="nm"><span class="dl-nm">${esc(name)}</span><span class="pc">${t.st === 'done' ? '✓ 完成'
        : t.st === 'fail' ? '✗ 失败'
        : t.st === 'sys' ? '⇣ 系统下载器'
        : t.pct >= 100 ? '收尾中…'
        : t.pct + '%'}</span></div>
      <div class="dl-bar"><i style="width:${Math.min(t.pct, 100)}%"></i></div>
      ${t.st === 'done' && t.path ? `<div class="dl-path">${esc(t.path)}</div>` : ''}
    </div>`).join('');
}

/* 保险丝:进度到 100% 但 done 事件迟迟未到(极端丢事件)→ 客户端 5 秒后自动收尾,
 * 避免条目永远停在「下载中」 */
function dlAutoFinish(name, t) {
  if (t.finTimer) return;
  t.finTimer = setTimeout(() => {
    if (DL_TASKS.get(name) === t && t.st === 'run') { t.st = 'done'; dlRender(); }
  }, 5000);
}

/* 点击已完成的条目 → 复制完整保存路径 */
$('dlList').addEventListener('click', e => {
  const it = e.target.closest('.dl-item');
  const p = it && it.dataset.path;
  if (!p) return;
  if (navigator.clipboard) navigator.clipboard.writeText(p)
    .then(() => toast('保存路径已复制', 'success')).catch(() => {});
});

window.__onDownloadEvent = (status, filename, detail) => {
  const t = DL_TASKS.get(filename);
  if (status === 'start') {
    DL_TASKS.set(filename, { st:'run', pct:0 });
    if (dlCollapsed) toggleDlPanel();             // 新任务到达自动展开
  } else if (status === 'progress') {
    if (!t || t.st !== 'run') return;             // 迟到的进度事件丢弃
    t.pct = Math.max(t.pct, parseInt(detail, 10) || 0);
    if (t.pct >= 100) dlAutoFinish(filename, t);  // 保险丝上膛
  } else if (status === 'sys') {
    if (t) { clearTimeout(t.timer); clearTimeout(t.finTimer); t.st = 'sys'; }   // 系统下载器接管中
  } else if (status === 'done') {
    if (t) {
      clearTimeout(t.timer); clearTimeout(t.finTimer);
      t.st = 'done'; t.path = detail;
    }
    /* 无论面板里有没有该任务,完成必弹包含绝对路径的提示 */
    toast(`「${filename}」下载完成\n已保存到:${detail}`, 'success', 12000);
  } else if (status === 'error') {
    if (t) {
      clearTimeout(t.timer); clearTimeout(t.finTimer);
      t.st = 'fail';
    }
    toast(`下载失败「${filename}」:${detail}`, 'error', 7000);
  }
  dlRender();
};

/* 禁止搜索框主动拉起输入法:启动时清掉自动焦点,用户点击输入框时才弹键盘 */
window.addEventListener('load', () => setTimeout(() => {
  const ae = document.activeElement;
  if (ae && (ae.tagName === 'INPUT' || ae.tagName === 'TEXTAREA')) ae.blur();
}, 60));
function fmtTime(s) { if (!isFinite(s) || s <= 0) return '00:00'; s = Math.floor(s); return String(Math.floor(s / 60)).padStart(2, '0') + ':' + String(s % 60).padStart(2, '0'); }

/* 全局封面背景:直接用官方接口搜索数据自带的专辑封面(img 字段),零额外请求 */
function setBgCover(url) {
  $('bgCover').style.backgroundImage = url ? `url("${url}")` : 'none';
}

/* ============ 播放器跑马灯(歌名+VIP标签整体滚动) ============ */
function refreshPlayerMarquees() {
  document.querySelectorAll('.p-name,.p-artist').forEach(el => {
    const track = el.querySelector('.p-track');
    if (!track) return;
    track.classList.remove('marquee');
    const dist = track.scrollWidth - el.clientWidth;
    if (dist > 4) {
      track.style.setProperty('--dist', dist + 'px');
      track.style.setProperty('--dur', Math.max(5, Math.min(14, dist / 14)) + 's');
      void track.offsetWidth;   // 强制重排以重置动画
      track.classList.add('marquee');
    }
  });
}
function setPlayerLine(el, html) {
  el.innerHTML = `<div class="p-track">${html}</div>`;
  requestAnimationFrame(refreshPlayerMarquees);
}

/* ============ Toast 弹窗 ============ */
const TOAST_ICONS = { info:'ℹ', success:'✓', warn:'⚠', error:'✕' };
function toast(msg, type = 'info', duration = 3500) {
  const wrap = $('toasts');
  if (wrap.children.length >= 5) wrap.firstChild.remove();
  const t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<span class="toast-icon">${TOAST_ICONS[type] || 'ℹ'}</span>
    <span class="toast-msg">${esc(msg)}</span>
    <button class="toast-close" title="关闭">×</button>`;
  wrap.appendChild(t);
  const close = () => { t.classList.add('hide'); setTimeout(() => t.remove(), 260); };
  t.querySelector('.toast-close').onclick = close;
  setTimeout(close, duration);
}

const ICON_PLAY  = '<svg viewBox="0 0 24 24"><path d="M8 5v14l11-7z"/></svg>';
const ICON_PAUSE = '<svg viewBox="0 0 24 24"><path d="M6 19h4V5H6v14zm8-14v14h4V5h-4z"/></svg>';

/* ============ 热门歌曲(只渲染一次,与搜索/歌词互不干扰) ============ */
async function loadHotSongs() {
  try {
    const r = await api(`/api/songlist?id=${HOT_LIST_ID}&limit=15`);
    if (r.code !== 200 || !r.data.list || !r.data.list.length) throw new Error(r.message || 'empty');
    hotSongs = r.data.list;
    $('hotList').innerHTML = hotSongs.map((s, i) =>
      `<button type="button" class="chip" title="${esc(s.name)} - ${esc(s.singer)}" onclick="playHot(${i})">
         <span class="n">${i + 1}</span>${esc(s.name)}</button>`).join('');
    return true;                       // 供启动引导判断后端是否就绪
  } catch (e) {
    $('hotList').innerHTML = '<span class="loading">热门歌曲加载失败</span>';
    return false;
  }
}
function playHot(i) {
  // 播放 + 自动搜索同名歌曲填充右侧结果列表(不写入搜索框)
  if (!hotSongs[i]) return;
  const song = hotSongs[i];
  state.list = hotSongs;      // 热门歌曲作为当前播放列表
  play(i, hotSongs);          // 先播放
  silentSearch(song.name);    // 再自动搜索同名歌名填充结果面板
}

/* ============ 启动引导:界面先行渲染,首个接口异常时自动重试 + toast 提示 ============
 * 若首个 API 调用因任何原因失败(如极端情况下的桥延迟),仅首次失败弹一次
 * 「服务正在启动中」toast(不遮挡界面),每 500ms 自动重试拉取热门歌曲。
 * 注:Java 桥已改为排队模式(Python 就绪前请求挂起等待),正常冷启动不会走到这里。 */
let bootTries = 0, bootDone = false;
function hideBootTip() { bootDone = true; }
async function bootLoop() {
  if (await loadHotSongs()) { hideBootTip(); return; }
  if (++bootTries === 1) toast('服务正在启动中…', 'info', 2500);
  if (bootTries < 60) setTimeout(bootLoop, 500);   // 最多重试约 30 秒
}
bootLoop();
window.onServerReady = async () => {   // Java 层探测到本地端口就绪时立即刷新
  if (bootDone) return;
  if (await loadHotSongs()) hideBootTip();
};

/* ============ 搜索结果面板(独立渲染,翻页/搜索只动这里) ============ */

function songRow(s, i) {
  return `
      <div class="song" id="song-${s.songmid}" onclick="play(${i})" title="${esc(s.name)} - ${esc(s.singer)}">
        <div class="idx">${i + 1}</div>
        <div class="info">
          <span class="track"><span class="name">${esc(s.name)}</span><span class="singer">${esc(s.singer)}</span></span>
        </div>
      </div>`;
}

function updateMeta() {
  const m = document.querySelector('#resultBody .meta');
  if (m) m.textContent = `// 共 ${state.total} 条 · 已加载 ${state.list.length}`;
}

function markPlayingRow() {
  if (!state.song) return;
  const row = document.getElementById(`song-${state.song.songmid}`);
  if (row) row.classList.add('playing');
}

function renderResults() {
  const body = $('resultBody');
  $('resultEmpty').style.display = state.list.length ? 'none' : 'block';
  if (!state.list.length) { body.innerHTML = ''; return; }
  body.innerHTML =
    `<div class="meta">// 共 ${state.total} 条 · 已加载 ${state.list.length}</div>` +
    state.list.map(songRow).join('');
  setupMarquees();           // 渲染后检测超宽行并启用滚动
  markPlayingRow();          // 重新标记当前播放行(热门歌自动搜索后也要高亮)
}

/* 超宽内容检测:溢出则加跑马灯动画(完整展示单行内容) */
function setupMarquees() {
  document.querySelectorAll('#resultBody .song .info').forEach(info => {
    const track = info.querySelector('.track');
    if (!track) return;
    track.classList.remove('marquee');
    if (!mqEnabled) return;                 // 跑马灯总开关关闭:保持静态文本
    const dist = track.scrollWidth - info.clientWidth;
    if (dist > 4) {
      track.style.setProperty('--dist', dist + 'px');
      track.style.setProperty('--dur', Math.max(5, Math.min(14, dist / 14)) + 's');
      void track.offsetWidth;   // 强制重排以重置动画
      track.classList.add('marquee');
    }
  });
}
let rsTimer;
window.addEventListener('resize', () => {
  clearTimeout(rsTimer);
  rsTimer = setTimeout(() => { setupMarquees(); refreshPlayerMarquees(); autoFill(0); }, 200);
});

/* ---- 搜索结果跑马灯开关(默认开启,localStorage 记忆) ---- */
let mqEnabled = true;
function applyMqState() {
  const btn = $('mqToggle');
  btn.style.color = mqEnabled ? 'var(--accent)' : 'var(--text-bright)';        // 开=红(与列表选中同色) 关=白
  btn.style.borderColor = mqEnabled ? 'var(--accent)' : 'var(--border)';
  document.querySelectorAll('#resultBody .track').forEach(t => t.classList.remove('marquee'));
  if (mqEnabled) setupMarquees();          // 开启:重新测量并恢复滚动动画
}
function setMq(on) {
  mqEnabled = on;
  try { localStorage.setItem('mqOn', on ? '1' : '0'); } catch (e) {}
  applyMqState();
}
$('mqToggle').addEventListener('click', () => setMq(!mqEnabled));
try { mqEnabled = localStorage.getItem('mqOn') !== '0'; } catch (e) {}
applyMqState();

/* 下滑加载 + 前瞻预取(替代上一页/下一页按钮) */
let loadingMore = false;
let lastAppendCount = 1;   // 上次预取新增行数(为 0 时停止链式预取,防死循环)
let searchSeq = 0;         // 搜索代数令牌:每次新搜索+1,旧搜索/旧预取的过期响应一律丢弃
async function loadMore() {
  if (loadingMore || !state.kw) return;
  if (state.allPage && state.page >= state.allPage) return;   // 已到最后一页
  loadingMore = true;
  const seq = searchSeq;     // 记领当前搜索代数,返回后核对(防新旧搜索串页)
  let tip = document.getElementById('loadTip');
  if (!tip) {
    tip = document.createElement('div');
    tip.id = 'loadTip'; tip.className = 'loading'; tip.style.padding = '10px 0';
    $('resultBody').appendChild(tip);
  }
  tip.textContent = '加载中';
  try {
    const r = await api(`/api/search?keyword=${encodeURIComponent(state.kw)}&page=${state.page + 1}&limit=${PAGE_SIZE}`);
    if (seq !== searchSeq) { tip.remove(); return; }   // 新搜索已开始:旧关键词数据整包丢弃
    if (r.code !== 200) { tip.remove(); return; }
    state.page += 1;
    state.total = r.data.total || state.total;
    state.allPage = r.data.allPage || state.allPage;
    const exist = new Set(state.list.map(s => s.songmid));
    const fresh = (r.data.list || []).filter(s => s.songmid && !exist.has(s.songmid));   // 跨页去重
    state.list = state.list.concat(fresh);
    tip.remove();
    const start = state.list.length - fresh.length;
    $('resultBody').insertAdjacentHTML('beforeend', fresh.map((s, k) => songRow(s, start + k)).join(''));
    updateMeta();
    setupMarquees();
    lastAppendCount = fresh.length;
    // 预取链:用户位置仍靠后则继续后台补页,保持领先一屏以上
    requestAnimationFrame(maybePrefetch);
  } catch (e) {
    if (seq !== searchSeq) { tip.remove(); }
    else { tip.textContent = '加载失败 · 继续下滑可重试'; }   // 保留提示,下次触发重试
  } finally {
    loadingMore = false;   // 过期请求同样释放锁,保证新搜索可继续加载
  }
}

/* 自动补齐循环:面板未撑满一屏或未达预加载目标时持续追加(PC 大屏适配) */
async function autoFill(minCount) {
  const el = $('resultPanel');
  const seq = searchSeq;     // 新搜索开始后立即终止旧填充循环
  let guard = 0;
  while (guard++ < 12 && seq === searchSeq && !loadingMore && state.kw
         && !(state.allPage && state.page >= state.allPage)) {
    const needMore = el.scrollHeight <= el.clientHeight + 40        // 未撑满,无滚动条
                  || (minCount && state.list.length < minCount);    // 未达 PC 预载目标
    if (!needMore) break;
    const before = state.list.length;
    await loadMore();
    if (state.list.length === before) break;   // 无新增(全重复/请求失败)防死循环
  }
}

/* ══════════ 链接直搜：识别歌单/单曲/歧义残链，官方接口解析后整包装入列表 ══════════
 * 支持：① 歌单 PC/手机端 playlist?id=N、/playlist/N 路径
 *       ② 单曲 song?id=N(PC/手机端)、/song/N 路径
 *       ③ 纯数字 ≥6 位：默认按歌单解析(失败自动回退普通搜索)
 *       ④ 残缺链接兜底：含 id=数字 但无法区分歌单/单曲 → 双解析,标题栏 ♫ 切换 */
function parseMusicLink(kw) {
  const t = kw.trim();
  let m;
  if ((m = t.match(/song\?id=(\d+)/i)) || (m = t.match(/\/song\/(\d+)/)))
    return { type: 'song', id: m[1] };
  if ((m = t.match(/playlist\?id=(\d+)/i)) || (m = t.match(/\/playlist\/(\d+)/)))
    return { type: 'playlist', id: m[1] };
  if (/^\d{6,}$/.test(t)) return { type: 'playlist', id: t };
  const f = t.match(/[?&]id=(\d+)/i);
  if (f && f[1].length >= 5) return { type: 'both', id: f[1] };
  return null;
}

async function loadPlaylist(pid, fromUrl, seq) {
  $('resultEmpty').style.display = 'none';
  $('resultBody').innerHTML = '<div class="loading">歌单解析中</div>';
  state.kw = '';   // 一次性载入:清空关键词即可禁用下滑分页/自动补齐(loadMore/autoFill 均有 !state.kw 保护)
  try {
    const r = await api(`/api/songlist?id=${encodeURIComponent(pid)}&limit=500`);
    if (seq !== searchSeq) return null;
    if (r.code !== 200 || !(r.data && r.data.list && r.data.list.length)) {
      if (!fromUrl) { await runSearch(pid, 1, false, true); return null; }   // 纯数字不是有效歌单:回退普通搜索
      const msg = r.message || '歌单解析失败';
      $('resultBody').innerHTML = `<div class="err">${esc(msg)}</div>`;
      toast(msg, 'error');
      return null;
    }
    const d = r.data, info = d.info || {};
    applyListData(d.list,
      `♫ ${info.name ? '歌单「' + info.name + '」' : ''}${info.creator || ''} · 共 ${d.list.length} 首${info.play_count ? ' · ' + info.play_count : ''}`);
    toast(`歌单「${info.name || pid}」已加载 ${d.list.length} 首`, 'success', 2500);
    return { list: d.list, meta: `♫ ${info.name ? '歌单「' + info.name + '」' : ''}${info.creator || ''} · 共 ${d.list.length} 首` };
  } catch (e) {
    if (seq !== searchSeq) return null;
    if (!fromUrl) { await runSearch(pid, 1, false, true); return null; }
    $('resultBody').innerHTML = '<div class="err">歌单请求失败</div>';
    toast('歌单请求失败', 'error');
    return null;
  }
}

/* 整包套用一组歌曲数据到结果列表(歌单/单曲/双解析切换共用) */
function applyListData(list, metaText) {
  state.list = list;
  state.total = list.length;
  state.allPage = 0; state.page = 1;
  renderResults();
  const meta = document.querySelector('#resultBody .meta');
  if (meta && metaText) meta.textContent = '// ' + metaText;
  autoFill(PC_INIT_TARGET);
}

/* 单曲链接官方解析:songmid → 歌曲详情整包。collectOnly=true 时只取数不渲染(双解析用) */
async function loadSingleSong(sid, seq, collectOnly) {
  $('resultEmpty').style.display = 'none';
  if (!collectOnly) {
    $('resultBody').innerHTML = '<div class="loading">歌曲解析中</div>';
    state.kw = '';
  }
  try {
    const r = await api(`/api/songdetail?songmid=${encodeURIComponent(sid)}`);
    if (seq !== searchSeq) return null;
    if (r.code !== 200 || !(r.data && r.data.list && r.data.list.length)) {
      if (!collectOnly) {
        const msg = r.message || '歌曲解析失败';
        $('resultBody').innerHTML = `<div class="err">${esc(msg)}</div>`;
        toast(msg, 'error');
      }
      return null;
    }
    const list = r.data.list, s0 = list[0];
    if (collectOnly) return list;
    applyListData(list, `♪ ${s0.name} · ${s0.singer} · 单曲解析`);
    toast(`已加载单曲「${s0.name}」`, 'success', 2000);
    return list;
  } catch (e) {
    if (seq !== searchSeq) return null;
    if (!collectOnly) {
      $('resultBody').innerHTML = '<div class="err">歌曲请求失败</div>';
      toast('歌曲请求失败', 'error');
    }
    return null;
  }
}

/* ═══ 歧义残链双解析:歌单优先展示,单曲后台就绪后点亮 ♫ 切换标签 ═══ */
let dualSets = null;   // { pl:[...], plMeta:'', song:[...], showing:'pl'|'song' }
function setSwitchTab(active) {
  const b = $('srcToggle');
  b.style.display = dualSets ? '' : 'none';
  b.style.color = active ? 'var(--accent)' : 'var(--muted)';
  b.style.borderColor = active ? 'var(--accent)' : 'var(--border)';
}
async function loadDualFallback(id, seq) {
  dualSets = null; setSwitchTab(false);
  $('resultEmpty').style.display = 'none';
  $('resultBody').innerHTML = '<div class="loading">链接不完整，歌单+单曲同时解析中</div>';
  state.kw = '';
  const songP = loadSingleSong(id, seq, true);          // 并发:单曲只收集
  const plRes = await loadPlaylist(id, true, seq);      // 歌单优先展示
  if (seq !== searchSeq) return;
  const songList = await songP;
  if (plRes && songList) {
    dualSets = { pl: plRes.list, plMeta: plRes.meta, song: songList, showing: 'pl' };
    setSwitchTab(false);   // 显示按钮(默认态配色)
    toast('链接不完整:已同时解析出歌单与单曲，点标题栏右侧 ♫ 切换', 'info', 3500);
  } else if (!plRes && songList) {
    applyListData(songList, `♪ ${songList[0].name} · ${songList[0].singer} · 单曲解析`);
    toast(`已加载单曲「${songList[0].name}」`, 'success', 2000);
  }
}
$('srcToggle').addEventListener('click', () => {
  if (!dualSets || !dualSets.song || !dualSets.pl) return;
  if (dualSets.showing === 'pl') {
    dualSets.showing = 'song';
    const s0 = dualSets.song[0];
    applyListData(dualSets.song, `♪ ${s0.name} · ${s0.singer} · 单曲解析`);
    setSwitchTab(true);
    toast('已切换为单曲数据', 'success', 1500);
  } else {
    dualSets.showing = 'pl';
    applyListData(dualSets.pl, dualSets.plMeta);
    setSwitchTab(false);
    toast('已切回歌单数据', 'success', 1500);
  }
})

async function doSearch() {
  const kw = $('kw').value.trim();
  if (!kw) return;
  await runSearch(kw, 1, true);
}

/* 自动搜索(热门歌名用):不写搜索框、不弹提示 */
async function silentSearch(kw) {
  state.page = 1;
  await runSearch(kw, 1, false);
}

async function runSearch(kw, p, toastOn, noPlaylist) {
  const seq = ++searchSeq;   // 新搜索开始：作废所有在途旧搜索/旧预取响应
  if (p === 1 && !noPlaylist) {
    dualSets = null; setSwitchTab(false);          // 新搜索开始:重置双解析状态与切换标签
    const ml = parseMusicLink(kw);
    if (ml) {
      state.page = 1;
      if (ml.type === 'song') { await loadSingleSong(ml.id, seq); return; }
      if (ml.type === 'playlist') { await loadPlaylist(ml.id, true, seq); return; }
      await loadDualFallback(ml.id, seq); return;   // 残缺无法区分:歌单+单曲双解析
    }
  }
  // 只刷新搜索结果面板
  state.kw = kw;             // 记住关键词,供下滑自动加载使用
  $('resultEmpty').style.display = 'none';
  $('resultBody').innerHTML = '<div class="loading">搜索中</div>';
  try {
    const r = await api(`/api/search?keyword=${encodeURIComponent(kw)}&page=${p}&limit=${PAGE_SIZE}`);
    if (seq !== searchSeq) return;   // 过期响应:用户已发起新搜索,丢弃
    if (r.code !== 200) {
      $('resultBody').innerHTML = `<div class="err">${esc(r.message)}</div>`;
      if (toastOn) toast(r.message, 'error');
      return;
    }
    state.list = r.data.list || [];
    state.total = r.data.total || 0;
    state.allPage = r.data.allPage || 0;
    renderResults();          // 不自动播放
    if (state.list.length) autoFill(PC_INIT_TARGET);   // PC 预加载60条 / 补满一屏
    if (toastOn) toast(`找到 ${state.total} 条结果`, 'success', 2000);
  } catch (e) {
    if (seq !== searchSeq) return;
    $('resultBody').innerHTML = '<div class="err">请求失败</div>';
    if (toastOn) toast('搜索请求失败', 'error');
  }
}

/* ============ 滚动预取算法(滑动窗口前瞻加载,手机/PC 通用) ============
 * 滚过已加载内容的 65% 即后台预取下一页,用户滑到底前数据已就绪;
 * 距底部 150px 内则立即加载。预取链自动终止条件:
 *   1) 进度回落到 65% 以下(内容已领先足够多)
 *   2) 没有更多页 / 上次预取无新增行(防死循环)
 *   3) 同一时刻只允许一个在途请求(loadingMore 锁) */
const PREFETCH_PROGRESS = 0.65;   // 预取触发点:已加载进度的 65%
const BOTTOM_THRESHOLD = 150;     // 距底部阈值(px):立即加载

function maybePrefetch() {
  if (loadingMore || lastAppendCount === 0 || !state.kw) return;
  if (state.allPage && state.page >= state.allPage) return;
  const el = $('resultPanel');
  if (el.scrollHeight <= el.clientHeight) return;   // 未撑满一屏由 autoFill 负责
  const progress = (el.scrollTop + el.clientHeight) / el.scrollHeight;
  const more = !state.allPage || state.page < state.allPage;
  if (progress >= PREFETCH_PROGRESS && more) loadMore();
}

$('resultPanel').addEventListener('scroll', () => {
  const el = $('resultPanel');
  const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - BOTTOM_THRESHOLD;
  if (nearBottom) loadMore();          // 到底:立即加载
  else maybePrefetch();                // 未到底:前瞻预取
});

/* ============ 播放(不自动触发,需用户点击) ============ */
let playSeq = 0;   // 播放请求序号(latest-wins):连点切歌时,过期响应一律丢弃

/* ══════════ 统一取链容错：超时重试 + 失败回滚（官方/VIP兑底通道共用） ══════════
 * 单次请求 4 秒未返回即视为超时，自动重试最多 3 次；
 * 全部失败提示网络差并回滚到之前正在播放的歌曲继续播。 */
const URL_TIMEOUT_MS = 4000, URL_MAX_RETRY = 3;

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, rej) => { timer = setTimeout(() => rej(new Error('请求超时')), ms); }),
  ]).finally(() => clearTimeout(timer));
}

/* 返回：成功响应对象 | 'EXPIRED'=期间已切歌 | 'FAILED'=三次均失败 */
async function fetchUrlWithRetry(song, seq, onRetry) {
  for (let attempt = 1; attempt <= URL_MAX_RETRY; attempt++) {
    try {
      const r = await withTimeout(
        api(`/api/url?songmid=${encodeURIComponent(song.songmid)}&quality=${QUALITY}`), URL_TIMEOUT_MS);
      if (seq !== playSeq) return 'EXPIRED';
      if (r.code === 200 && r.data && r.data.url) return r;
      throw new Error(r.message || '解析失败');       // 业务失败同样计入重试
    } catch (e) {
      if (seq !== playSeq) return 'EXPIRED';
      if (attempt >= URL_MAX_RETRY) return 'FAILED';
      if (onRetry) onRetry(attempt);
    }
  }
  return 'FAILED';
}

/* 回滚到切换前的歌曲：恢复高亮/信息/校准并续播（audio.src 未被覆盖，原地 resume） */
function rollbackPlayback(prev) {
  if (!prev) return;
  state.song = prev.song; state.songIndex = prev.index; state.playList = prev.plist;
  document.querySelectorAll('#resultBody .song').forEach(el => el.classList.remove('playing'));
  const row = $(`song-${prev.song.songmid}`);
  if (row) row.classList.add('playing');
  setPlayerLine($('nowName'), esc(prev.song.name));
  setPlayerLine($('nowArtist'), esc(`${prev.song.singer} · ${prev.song.albumName || ''}`.replace(/·\s*$/, '').trim() || prev.song.singer));
  setBgCover(prev.song.img);
  loadSongCal();
  const a = $('audio');
  if (a.src) a.play().catch(() => { });
}

async function play(i, list) {
  const src = list || state.list;
  const song = src[i];
  if (!song) return;
  const seq = ++playSeq;          // 领取本次播放序号
  // ═══ 回滚点：记录切换前的播放状态（总失败时恢复） ═══
  const prev = (state.song && state.song.songmid !== song.songmid)
    ? { song: state.song, index: state.songIndex, plist: state.playList } : null;
  state.song = song;
  state.songIndex = i;
  state.playList = src;   // 记住当前播放来源列表(供自动连播使用)

  // 立即暂停旧歌 + 高亮新行(不等直链返回,消除“还在放原歌”的窗口期)
  const audio = $('audio');
  audio.pause();
  document.querySelectorAll('#resultBody .song').forEach(el => el.classList.remove('playing'));
  const row = $(`song-${song.songmid}`);
  if (row) row.classList.add('playing');

  // 播放器信息(独立面板) + 加载占位
  setPlayerLine($('nowName'), `加载中… ${esc(song.name)}`);
  setPlayerLine($('nowArtist'), esc(`${song.singer} · ${song.albumName || ''}`.replace(/·\s*$/, '').trim() || song.singer));
  setBgCover(song.img);   // 官方接口返回的专辑封面 → 页面底层模糊背景
  loadSongCal();          // 载入这首歌的用户校准值(按 songmid 记忆)
  checkMv(song, seq);     // 异步检测该曲是否有官方 MV → 显示/隐藏 MV 标签
  toast(`正在加载「${song.name}」…`, 'info', 2000);   // 切歌即时反馈(官方/VIP兑底统一生效)
  try {
    const res = await fetchUrlWithRetry(song, seq, (attempt) => {
      if (seq === playSeq) {
        setPlayerLine($('nowName'), `加载中(${attempt}/${URL_MAX_RETRY})… ${esc(song.name)}`);
        toast(`响应超时，自动重试 ${attempt}/${URL_MAX_RETRY - 1}`, 'warn', 1500);
      }
    });
    if (res === 'EXPIRED') return;                  // 过期响应:用户已切歌,丢弃
    if (res === 'FAILED') {                         // 三次均失败:提示 + 回滚上一曲
      setPlayerLine($('nowName'), '网络较差');
      setPlayerLine($('nowArtist'), '稍后重新尝试');
      toast('当前网络环境较差，稍后重新尝试', 'error', 3000);
      rollbackPlayback(prev);
      return;
    }
    const r = res;
    if (r.code !== 200) {
      setPlayerLine($('nowName'), '播放失败');
      setPlayerLine($('nowArtist'), esc(r.message || ''));
      toast(`播放失败: ${r.message}`, 'error');
      rollbackPlayback(prev);
      return;
    }
    const viaTag = r.data.via === 'toubiec' ? '<span class="tag3rd">VIP</span>' : '';
    setPlayerLine($('nowName'), `${esc(song.name)}${viaTag}`);   // 歌名+VIP标签作为整体跑马灯
    if (r.data.via === 'toubiec') toast(`已通过VIP通道解析播放「${song.name}」`, 'warn', 3000);
    audio.src = r.data.url;
    audio.play().catch(() => { });   // 自动播放被拦截时静默,用户手动点击播放即可
  } catch (e) {
    if (seq !== playSeq) return;
    setPlayerLine($('nowName'), '播放失败');
    toast('播放失败', 'error');
    rollbackPlayback(prev);
  }
  if (seq === playSeq) loadLyric(song, seq);
}

/* ============ 自定义播放器控制 ============ */
function togglePlay() {
  const a = $('audio');
  if (a.paused) a.play().catch(() => toast('无法播放', 'error'));
  else a.pause();
}
function seek(e) {
  const wrap = $('progWrap'), rect = wrap.getBoundingClientRect();
  const a = $('audio');
  if (a.duration && rect.width > 0) {
    a.currentTime = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width)) * a.duration;
  }
}
function updateProg() {
  const a = $('audio'), dur = a.duration || 0, cur = a.currentTime || 0;
  $('progFill').style.width = dur ? (cur / dur * 100) + '%' : '0%';
  $('nowTime').textContent = `${fmtTime(cur)} / ${fmtTime(dur)}`;
}
$('audio').addEventListener('timeupdate', updateProg);
$('audio').addEventListener('loadedmetadata', updateProg);
$('audio').addEventListener('play', () => $('btnPlay').innerHTML = ICON_PAUSE);
$('audio').addEventListener('pause', () => $('btnPlay').innerHTML = ICON_PLAY);
$('btnPlay').innerHTML = ICON_PLAY;

/* ============ 下载(弹窗选择 歌曲/歌词) ============ */
const safeName = n => (n || '未知').replace(/[\\/:*?"<>|]/g, '_').trim();

function openDlModal() {
  if (!state.song) { toast('还没有播放中的歌曲', 'warn'); return; }
  $('dlSongName').textContent = `${state.song.name} - ${state.song.singer}`;   // 标题显示当前歌曲,单行超出截断为...
  $('dlModal').classList.add('show');
}
function closeDlModal() { $('dlModal').classList.remove('show'); }
$('dlModal').addEventListener('click', e => { if (e.target.id === 'dlModal') closeDlModal(); });
$('mvModal').addEventListener('click', e => { if (e.target.id === 'mvModal') closeMvModal(); });

document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeDlModal(); closeMvModal(); } });

function triggerDownload(href, filename, revoke) {
  const a = document.createElement('a');
  a.href = href; a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
  if (revoke) setTimeout(() => URL.revokeObjectURL(href), 30000);
}

/* 无端口模式下载出口:大文件交原生 DownloadManager 直链下载,
 * 小文本由桥直接写入公共 Download 目录;桌面浏览器仍走 <a download> 兑底 */
function nativeDownload(filename, url) {
  if (window.AndroidBridge && AndroidBridge.download) AndroidBridge.download(filename, url);
  else triggerDownload(url, filename, false);
}
function saveTextFile(filename, content) {
  if (window.AndroidBridge && AndroidBridge.downloadText) AndroidBridge.downloadText(filename, content);
  else triggerDownload(URL.createObjectURL(new Blob([content], {type: 'application/octet-stream'})), filename, true);
}

async function downloadSong() {
  const s = state.song;
  closeDlModal();
  toast('正在获取音乐格式…', 'info', 4000);
  try {
    const r = await api(`/api/url?songmid=${s.songmid}&quality=${QUALITY}`);
    if (r.code !== 200) { toast(`获取失败: ${r.message}`, 'error'); return; }
    // 先向后端探测真实封装格式(与实际下载文件后缀一致,避免提示 .mp3 实际 .m4a)
    let ext = r.data.quality === 'flac' ? 'flac' : 'mp3';
    try {
      const fi = await api(`/api/download?songmid=${s.songmid}&quality=${QUALITY}&info=1`);
      if (fi.code === 200 && fi.data && fi.data.ext) ext = fi.data.ext;
    } catch (e) { /* 探测失败退回猜测后缀 */ }
    const filename = `${safeName(s.name)}-${safeName(s.singer)}.${ext}`;
    // 无端口模式:直链交给原生 DownloadManager(文件名由 App 精确控制,
    // 不再依赖同源代理与 Content-Disposition 防止后缀错乱)
    nativeDownload(filename, r.data.url);
  } catch (e) {
    toast('下载请求失败', 'error');
  }
}

async function downloadLyric() {
  const s = state.song;
  closeDlModal();
  toast('正在准备下载歌词…', 'info', 2000);
  try {
    // 先确认有歌词(顺便给出友好错误提示)
    const r = await api(`/api/lyric?songmid=${s.songmid}`);
    const d = (r.code === 200 && r.data) ? r.data : null;
    const lrc = d ? (d.lyric || '').trim() : '';
    if (!lrc) { toast('这首歌暂无歌词可下载', 'warn'); return; }
    // 拼接翻译歌词(与原后端下载代理逻辑一致),由桥写入公共 Download 目录,
    // 文件名精确控制为 .lrc(不再依赖 Content-Disposition)
    let content = lrc;
    const tlyric = ((d.tlyric) || '').trim();
    if (tlyric) content += '\n\n' + tlyric;
    const filename = `${safeName(s.name)}-${safeName(s.singer)}.lrc`;
    saveTextFile(filename, content);                    // 完成后由原生事件弹窗提示路径
  } catch (e) {
    toast('歌词下载失败', 'error');
  }
}

/* ============ MV 检测 / 播放 / 下载 ============ */
let mvState = { mvid: 0 };

async function checkMv(song, seq) {
  $('mvTag').style.display = 'none';                       // 默认隐藏,确认有 MV 才显示
  mvState.mvid = 0;
  let mvid = parseInt((song.meta || {}).mv) || 0;           // 官方搜索数据自带 mv 字段(0=无MV)
  if (!mvid) {                                              // 数据缺字段 → 官方接口兑底查询
    try {
      const r = await api(`/api/mv/check?songmid=${song.songmid}`);
      if (seq !== playSeq) return;                          // 已切歌,丢弃
      mvid = (r.code === 200 && r.data) ? (parseInt(r.data.mvid) || 0) : 0;
    } catch (e) { return; }
  }
  if (seq !== playSeq) return;                              // 双保险:过期检测不显示标签
  if (mvid > 0) { mvState.mvid = mvid; $('mvTag').style.display = ''; }
}

async function openMvModal() {
  if (!mvState.mvid) return;
  const bg = $('audio');
  if (!bg.paused) bg.pause();          // 打开 MV 弹窗时暂停背景音乐
  $('mvModal').classList.add('show');
  const v = $('mvVideo'), ld = $('mvLoading');
  $('mvTitle').textContent = `▶ ${state.song ? state.song.name : ''} · MV`;
  v.pause(); v.removeAttribute('src'); v.style.display = 'none';
  ld.style.display = ''; ld.textContent = 'MV 解析中';
  try {
    const r = await api(`/api/mv/url?mvid=${mvState.mvid}`);
    if (r.code === 200 && r.data && r.data.url) {
      v.src = r.data.url;                                   // 官方接口解析的直链
      v.style.display = '';
      ld.style.display = 'none';
      v.play().catch(() => {});
    } else {
      ld.textContent = r.message || 'MV 解析失败';
    }
  } catch (e) {
    ld.textContent = 'MV 解析失败';
  }
}

function closeMvModal() {
  const v = $('mvVideo');
  v.pause(); v.removeAttribute('src'); v.load();            // 停止播放并释放缓冲
  $('mvModal').classList.remove('show');
}

async function downloadMv() {
  if (!mvState.mvid || !state.song) return;
  closeMvModal();   // 与歌曲一致:点击下载立即关弹窗,避免遮挡提示与任务面板
  const filename = `${safeName(state.song.name)}-${safeName(state.song.singer)}-MV.mp4`;
  try {
    const r = await api(`/api/mv/url?mvid=${mvState.mvid}`);
    if (r.code !== 200 || !r.data || !r.data.url) { toast(`MV 解析失败: ${r.message || '未知错误'}`, 'error'); return; }
    nativeDownload(filename, r.data.url);               // 完成后由原生事件弹窗提示路径
  } catch (e) {
    toast('MV 下载失败', 'error');
  }
}

/* ============ 歌词面板(独立渲染,只动歌词面板) ============ */
function renderLyricsEmpty() {
  $('lyricsEmpty').style.display = 'block';
  $('lyricsBody').innerHTML = '';
  state.lyricTimes = [];
  state.lyricIdx = -1;
  lyricOffsetTag = 0;
}
function renderLyrics(lines) {
  $('lyricsEmpty').style.display = 'none';
  $('lyricsBody').innerHTML = lines.map((l, i) => `<div id="lyr-${i}">${esc(l.text)}</div>`).join('');
}

async function loadLyric(song, seq) {
  const songKey = song.songmid;
  // 先清空歌词面板(防止上一首残留导致高亮"原地不动")
  renderLyricsEmpty();
  /* ═══ 统一容错(与取链路一致):4 秒超时 × 3 次,仅网络超时才重试,"暂无歌词"不重试 ═══ */
  let r = null;
  for (let attempt = 1; attempt <= URL_MAX_RETRY; attempt++) {
    try {
      r = await withTimeout(api(`/api/lyric?songmid=${encodeURIComponent(songKey)}`), URL_TIMEOUT_MS);
      if (!state.song || state.song.songmid !== songKey) return; // 切歌竞态保护
      if (seq !== undefined && seq !== playSeq) return;          // 双保险:过期响应丢弃
      break;   // 收到业务响应(含暂无歌词):不再重试
    } catch (e) {
      r = null;
      if (!state.song || state.song.songmid !== songKey) return;
      if (seq !== undefined && seq !== playSeq) return;
      if (attempt < URL_MAX_RETRY) toast(`歌词加载超时，自动重试 ${attempt}/${URL_MAX_RETRY - 1}`, 'warn', 1500);
    }
  }
  if (!r) {   // 三次全败:提示网络差
    if (state.song && state.song.songmid === songKey) toast('当前网络环境较差，歌词暂时无法加载', 'error', 3000);
    return;
  }
  try {
    if (r.code !== 200 || !r.data || !r.data.lyric) {
      toast('这首歌暂无歌词', 'info', 2500);
      return;
    }
    const lines = r.data.lyric.split('\n').map(l => {
      const m = l.match(/^\[(\d+):(\d+)(?:\.(\d+))?\](.*)$/);
      if (!m) return null;
      const t = (+m[1]) * 60 + (+m[2]) + (+(m[3] || 0)) / 1000;
      return { t, text: m[4] };
    }).filter(x => x && x.text.trim());
    if (!lines.length) { toast('这首歌暂无歌词', 'info', 2500); return; }
    state.lyricTimes = lines;
    state.lyricIdx = -1;
    lyricOffsetTag = parseOffsetTag(r.data.lyric);   // LRC [offset:] 全局校准
    renderLyrics(lines);
    startLyricLoop();                                // 立即对齐当前播放位置
  } catch (e) {
    if (state.song && state.song.songmid === songKey) toast('歌词加载失败', 'error');
  }
}

/* ============ 歌词同步算法(帧级驱动 + 二分查找 + 双重预补偿) ============
 * 有效时间轴:t_eff = 播放进度 + LYRIC_OFFSET + 歌曲校准(songCal) + [offset:]标签
 *   ① LYRIC_OFFSET:全局默认净偏移(单一参数,正=提前负=延后)
 *   ② songCal:当前歌曲的用户校准(面板标题 −/+ 按钮,按歌记忆 localStorage)
 * 二分查找 O(log n):任意拖动进度条都能瞬时定位正确行,无需顺序扫描 */
let lyricOffsetTag = 0;    // 当前歌词的 [offset:] 校准量(秒)
let lyricRaf = null;

function parseOffsetTag(raw) {
  const m = raw.match(/^\s*\[offset:\s*([+-]?\d+)\s*\]/im);
  return m ? (+m[1]) / 1000 : 0;
}

function lyricIndexAt(t) {                 // 返回最后一个 t_i <= t 的行号
  const times = state.lyricTimes;
  let lo = 0, hi = times.length - 1, ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (times[mid].t <= t) { ans = mid; lo = mid + 1; } else { hi = mid - 1; }
  }
  return ans;
}

function applyLyricHighlight(idx) {        // 高亮变化才碰 DOM + 平滑居中滚动
  if (idx === state.lyricIdx || !$('lyricsBody').children.length) return;
  state.lyricIdx = idx;
  const els = $('lyricsBody').children;
  for (let i = 0; i < els.length; i++) els[i].classList.toggle('active', i === idx);
  if (idx >= 0) {
    const box = $('lyrics');
    const el = document.getElementById(`lyr-${idx}`);
    if (el) {
      const relTop = el.getBoundingClientRect().top - box.getBoundingClientRect().top + box.scrollTop;
      const target = relTop - box.clientHeight / 2 + el.offsetHeight / 2;
      box.scrollTo({ top: Math.max(target, 0), behavior: 'smooth' });
    }
  }
}

function lyricTick() {
  lyricRaf = null;
  if (!state.lyricTimes.length) return;
  const cal = LYRIC_OFFSET + songCal + lyricOffsetTag;                     // 净校准量
  applyLyricHighlight(lyricIndexAt($('audio').currentTime + cal));
  if (!$('audio').paused) lyricRaf = requestAnimationFrame(lyricTick);     // 播放中帧级持续同步
}

function startLyricLoop() { if (!lyricRaf) lyricRaf = requestAnimationFrame(lyricTick); }

/* ---- 每首歌独立校准(±0.1s,按 songmid 记忆) ---- */
let songCal = 0;   // 当前歌曲用户校准(秒)
function calKey() { return 'lyroff:' + ((state.song && state.song.songmid) || ''); }
function loadSongCal() {
  try { songCal = parseFloat(localStorage.getItem(calKey())) || 0; } catch (e) { songCal = 0; }
  updateCalUi();
}
function applyCal(delta) {
  songCal = Math.round((songCal + delta) * 10) / 10;
  try { localStorage.setItem(calKey(), String(songCal)); } catch (e) {}
  updateCalUi(); startLyricLoop();   // 立即生效并重新对齐
}
function updateCalUi() { $('calVal').textContent = (songCal > 0 ? '+' : '') + songCal.toFixed(1); }
function resetCal() {   // 点击校准数值:复位当前歌曲为 0 并清除记忆
  songCal = 0;
  try { localStorage.removeItem(calKey()); } catch (e) {}
  updateCalUi(); startLyricLoop();
}

$('audio').addEventListener('play', startLyricLoop);       // 播放启动帧级循环(~16ms 精度)
$('audio').addEventListener('seeked', startLyricLoop);     // 拖动进度条后立即重新对齐
$('audio').addEventListener('ended', () => { applyLyricHighlight(-1); });  // 播完清除高亮

/* 校准按钮:+=高亮提前0.1s(歌词慢于歌声时按),-=延后0.1s;点数值复位为0 */
$('calPlus').addEventListener('click', () => applyCal(+0.1));
$('calMinus').addEventListener('click', () => applyCal(-0.1));
$('calVal').addEventListener('click', resetCal);

/* ============ 自动连播(仅播放结束后) ============ */
$('audio').addEventListener('ended', () => {
  const list = state.playList || state.list;
  if (state.songIndex >= 0 && state.songIndex + 1 < list.length) {
    toast(`下一首: ${list[state.songIndex + 1].name}`, 'info', 2000);
    play(state.songIndex + 1, list);
  } else if (state.song) {
    toast('播放列表已播放完毕', 'info', 2500);
  }
});
</script>
</body>
</html>
'''