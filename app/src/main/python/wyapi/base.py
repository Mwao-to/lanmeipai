# -*- coding: utf-8 -*-
"""base.py — 音源抽象基类

与原版 src/utils/musicSdk/* 的接口对齐:
  musicSearch / search / songList / leaderboard / hotSearch / lyric / getMusicUrl / comment
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class MusicSource(ABC):
    id: str = ''          # 音源标识: wy / kw / kg / tx / mg
    name: str = ''        # 显示名: 网易 / 酷我 / 酷狗 / QQ / 咪咕
    limit: int = 30
    # 支持的音质(从高到低)
    qualitys: list = ['hires', 'flac', '320k', '128k']

    # ---------------- 搜索 ----------------
    @abstractmethod
    def search(self, keyword: str, page: int = 1, limit: int | None = None) -> dict:
        """返回 {list, total, allPage, limit, source}"""
        ...

    # ---------------- 歌单 ----------------
    @abstractmethod
    def songlist_detail(self, list_id: str, page: int = 1, limit: int | None = None) -> dict:
        """返回 {list, total, page, limit, source, info}"""
        ...

    # ---------------- 排行榜 ----------------
    @abstractmethod
    def leaderboard(self) -> dict:
        """返回 {list: [{id, name, bangid}], source}"""
        ...

    # ---------------- 热搜 ----------------
    @abstractmethod
    def hot_search(self) -> list:
        """返回 [词1, 词2, ...]"""
        ...

    # ---------------- 歌词 ----------------
    @abstractmethod
    def lyric(self, song: dict) -> dict:
        """返回 {lyric, tlyric, rlyric, lxlyric}"""
        ...

    # ---------------- 播放链接 ----------------
    @abstractmethod
    def get_music_url(self, song: dict, quality: str) -> str:
        """返回可直接播放的 URL"""
        ...

    # ---------------- 附加 ----------------
    def pic_url(self, song: dict) -> str:
        """封面图 URL(可覆盖)"""
        return song.get('img') or ''

    def song_detail_page_url(self, song: dict) -> str:
        return ''

    # ---------------- 工具 ----------------
    def _format_interval(self, ms: int | None) -> str:
        from .text import format_play_time
        if not ms:
            return '00:00'
        return format_play_time(ms / 1000 if ms > 10000 else ms)


# ---------------------------------------------------------------- 歌曲数据结构

def make_song(
    source: str,
    songmid: str,
    name: str,
    singer: str,
    img: str = '',
    interval: str = '',
    album_name: str = '',
    album_id: str = '',
    types: list | None = None,
    meta: dict | None = None,
) -> dict:
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
