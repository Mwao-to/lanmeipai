# -*- coding: utf-8 -*-
"""wyapi — 网易云音乐 API 独立包(从 LX-Pro-Music-Python 抽取)

功能: 搜索 / 播放链接 / 歌词 / 热搜 / 歌单
只依赖 requests,不依赖 kivy。
"""
from .wy import WYSource, set_wy_cookie, get_wy_cookie

wy = WYSource()

__all__ = ['wy', 'WYSource', 'set_wy_cookie', 'get_wy_cookie']
