"""App 内启动入口:Chaquopy 调用 start() 后阻塞运行 Flask 服务。"""
import os
import sys

_BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(_BASE)                    # static/ 相对路径基于 python 源码目录
if _BASE not in sys.path:
    sys.path.insert(0, _BASE)


def start():
    import server
    print('蓝莓派 App 内嵌服务启动: http://127.0.0.1:5000')
    server.app.run(host='127.0.0.1', port=5000, debug=False, threaded=True)
