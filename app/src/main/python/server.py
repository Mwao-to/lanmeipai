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
from wyapi import wy, set_wy_cookie
from wyapi import toubiec

# 是否启用第三方解析兑底(官方取不到链接时,如 VIP/无版权歌曲)
TOUBIEC_ENABLED = os.environ.get('TOUBIEC_ENABLED', '1') != '0'

app = Flask(__name__, static_folder='static', static_url_path='/static')


@app.after_request
def _no_cache(resp):
    """禁用页面缓存,保证刷新即拿到最新版本(旧缓存页会导致热歌点击误触发搜索等历史行为)"""
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

# 搜索缓存:songmid -> song dict(供 /api/url 按 id 取歌)
_song_cache: dict = {}
_SONG_CACHE_MAX = 2000

# 播放链接缓存:songmid|quality -> (url, via, ts),TTL 10 分钟(第三方接口有限流)
_url_cache: dict = {}
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
    return send_from_directory(app.static_folder, 'index.html')


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


def _cd_header(filename: str, ctype: str) -> dict:
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
