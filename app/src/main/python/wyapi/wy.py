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
from __future__ import annotations

import re
import threading
import time

from .crypto import eapi, weapi
from .net import http_fetch, warm_up
from .text import decode_name, format_play_count, format_play_time, size_formate
from .base import MusicSource, make_song

# 独立服务:不再依赖 lxmusic.config。网易云 Cookie(可选,用于解锁 VIP/无版权歌曲)可从环境变量 WY_COOKIE 传入
_WY_COOKIE = ''


def set_wy_cookie(cookie: str):
    global _WY_COOKIE
    _WY_COOKIE = (cookie or '').strip()


def get_wy_cookie() -> str:
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

    def __init__(self, ttl: float):
        self.ttl = ttl
        self._data: dict = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            item = self._data.get(key)
            if item and item[0] + self.ttl > time.time():
                return item[1]
        return None

    def set(self, key: str, value):
        with self._lock:
            self._data[key] = (time.time(), value)


def eapi_request(url: str, data: dict) -> dict:
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
    def search(self, keyword: str, page: int = 1, limit: int | None = None, retry_num: int = 0) -> dict:
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
    def _get_singer(singers) -> str:
        return '、'.join(s.get('name', '') for s in (singers or []))

    @staticmethod
    def _handle_result(raw_list) -> list | None:
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
    def songlist_detail(self, list_id: str, page: int = 1, limit: int | None = None) -> dict:
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

    def _resolve_list_id(self, raw_id: str):
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

    def _get_song_details(self, ids: list, batch: int = 100) -> list:
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

    def leaderboard(self) -> dict:
        cached = self._leaderboard_cache.get('list')
        if cached:
            return cached
        result = {
            'source': self.id,
            'list': [{'id': f'wy__{bid}', 'name': name, 'bangid': bid} for bid, name in self._TOP_LIST],
        }
        self._leaderboard_cache.set('list', result)
        return result

    def leaderboard_detail(self, bangid: str, limit: int = 100) -> dict:
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
    def hot_search(self) -> list:
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
    def lyric(self, song: dict) -> dict:
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
    def get_music_url(self, song: dict, quality: str) -> str:
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

    def get_mv_url(self, mvid, r: int = 1080) -> str:
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
    def _get_no_copyright_song_id(song: dict):
        ncr = song.get('noCopyrightRcmd') or (song.get('meta') or {}).get('noCopyrightRcmd')
        if not ncr:
            return None
        return ncr.get('songId') or ncr.get('id') or (ncr.get('song') or {}).get('id')

    # ---------------- 其他 ----------------
    def pic_url(self, song: dict) -> str:
        return (song.get('meta') or {}).get('picUrl') or song.get('img') or ''

    def song_detail_page_url(self, song: dict) -> str:
        return f'https://music.163.com/#/song?id={song.get("songmid")}'


# ---------------------------------------------------------------- 歌词解析(移植 parseTools)

def _ms_format(time_ms: int) -> str:
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


def _parse_lyric(lines) -> tuple:
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


def _parse_header_info(text: str) -> list:
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


def _get_intv(interval: str) -> int:
    if not interval:
        return 0
    if '.' not in interval:
        interval += '.0'
    parts = re.split(r':|\.', interval)
    while len(parts) < 3:
        parts.insert(0, '0')
    m, s, ms = parts
    return int(m) * 3600000 + int(s) * 1000 + int(ms)


def _fix_time_tag(lrc: str, target_lrc: str) -> str:
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


def parse_netease_lyric(body: dict) -> dict:
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
