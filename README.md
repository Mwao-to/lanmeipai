# 蓝莓派 · NetEase Music App

网页版音乐播放器(www/wy-web-server)打包的 Android 应用。

## 架构
- **Chaquopy** 在 App 内嵌 Python 运行时,运行原版 Flask 服务(`app/src/main/python/server.py`)
- 服务监听 `127.0.0.1:5000`,WebView 加载原版 `static/index.html` 界面
- 下载经系统 DownloadManager 写入公共 Download 目录(文件名取自 Content-Disposition)

## 构建
- 仅 arm64-v8a 正式版(已签名 release)
- GitHub Actions:push 到 main 自动编译;push `v*` tag 自动创建 Release 并附 APK
