# -*- coding: utf-8 -*-
"""
net.py — 网络层
- requests + 超时 + 自动重试 + 统一 UA
- 所有请求可被全局取消标记中断
- 对比原版 RN 的 httpFetch:增加指数退避重试、连接复用、gzip 自动解压
"""
from __future__ import annotations

import threading

import requests

from .log import get_logger

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
_warm_ups: dict = {}
_warm_lock = threading.Lock()


def warm_up(host_url: str):
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
_cache: dict = {}
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
    def __init__(self, message: str, status_code: int = 0):
        super().__init__(message)
        self.status_code = status_code


def http_fetch(
    url: str,
    method: str = 'get',
    params: dict | None = None,
    data: dict | None = None,
    form: dict | None = None,
    json_body: dict | None = None,
    headers: dict | None = None,
    timeout: float = 15.0,
    retry: int = 3,
    use_cache: bool = False,
) -> dict:
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

    last_err: Exception | None = None
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


def _parse_response(body_bytes: bytes, headers, url: str, status_code: int = 200) -> dict:
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


def _sleep(sec: float):
    import time
    for _ in range(int(sec * 10)):
        if _cancel_flag.is_set():
            break
        time.sleep(0.1)
