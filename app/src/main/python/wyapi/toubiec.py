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
from __future__ import annotations

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

_ip_cache: dict = {'ip': '', 'ts': 0.0}
_lock = threading.Lock()


def _get_ip() -> str:
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


def _post(path: str, payload: dict) -> dict:
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


def get_song_url(song_id, quality: str = '320k', max_retry: int = 2) -> str:
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


def _yrc_json_to_lrc(raw: str) -> str:
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


def _clean_lrc(raw: str) -> str:
    """清洗歌词字段:逐字JSON转标准LRC;无法解析的JSON视为无效返回空串。"""
    raw = (raw or '').strip()
    if raw.startswith('{'):
        converted = _yrc_json_to_lrc(raw)
        return converted          # 转换失败返回空串,避免前端显示乱码
    return raw


def get_lyric(song_id, max_retry: int = 2) -> dict:
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
