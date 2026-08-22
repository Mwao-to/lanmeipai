package com.binsys.wy;

import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.webkit.CookieManager;
import android.webkit.JavascriptInterface;
import android.webkit.URLUtil;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Toast;

import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity {
    private static final String TAG = "wy-app";
    /** 仅作为页面源(origin):保持 localStorage 与历史版本互通。无任何服务监听此地址 */
    private static final String BASE_URL = "http://127.0.0.1:5000/";
    private static final int REQ_WRITE = 42;

    private WebView web;
    /** JS→Python 桥的调用线程池(每次 API 调用一个任务,互不阻塞) */
    private final ExecutorService apiPool = Executors.newCachedThreadPool();
    /** <Q 设备申请存储权限期间暂存的歌词内容 {name, content} */
    private final String[] pendingText = new String[2];

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Dbg.w(this, "═══ onCreate 进入 ═══");
        // 全局未捕获异常也落盘(定位闪退)
        final Context self = this;
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            Dbg.w(self, "‼️ 未捕获异常 thread=" + t.getName(), e);
            Log.e(TAG, "uncaught", e);
            android.os.Process.killProcess(android.os.Process.myPid());
        });

        // 第一件事:后台并行初始化 Python(与界面渲染同时进行,谁也不等谁)
        startPythonInit();

        setContentView(R.layout.activity_main);
        web = findViewById(R.id.web);

        WebSettings st = web.getSettings();
        st.setJavaScriptEnabled(true);
        st.setDomStorageEnabled(true);
        st.setAllowFileAccess(true);
        st.setMediaPlaybackRequiresUserGesture(false);
        st.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        // 完全隐藏内嵌浏览器的滚动条(横向/纵向都不再显示)
        web.setVerticalScrollBarEnabled(false);
        web.setHorizontalScrollBarEnabled(false);
        // JS↔Python 桥(无端口架构核心):页面所有 API 经此直连 Python
        web.addJavascriptInterface(new ApiBridge(), "AndroidBridge");
        web.setWebViewClient(new WebViewClient() {
            @Override public void onPageStarted(WebView view, String url, android.graphics.Bitmap f) {
                Dbg.w(self, "WebView onPageStarted: " + url);
            }
            @Override public void onPageFinished(WebView view, String url) {
                Dbg.w(self, "WebView onPageFinished: " + url);
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest rq, WebResourceError er) {
                Dbg.w(self, "WebView 错误: " + rq.getUrl() + " " + er.getDescription());
            }
        });
        web.setDownloadListener(this::onDownload);

        // 界面从内置 assets 即时渲染(毫秒级):
        // 没有启动画面、没有二次切换、没有多余历史记录 —— 打开即真界面。
        // 数据由前端 bootLoop 在 Python 就绪后自动补载;
        // BASE_URL 仅固定页面 origin 以兼容旧版 localStorage
        String html = readAsset("index.html");
        web.loadDataWithBaseURL(BASE_URL, html, "text/html", "utf-8", null);
        Dbg.w(this, "[ui] 界面已从 assets 即时渲染(" + html.length() + " 字节)");
        Dbg.w(this, "onCreate 完成");
    }

    /**
     * 后台初始化 Python(无端口架构):没有 Flask 服务线程、没有端口监听,
     * 模块加载完成即后端就绪 → 回调前端补数据 + Toast 提示。
     * 就绪前的桥调用会安全返回业务错误,由前端自动重试,无需任何锁等待。
     */
    private void startPythonInit() {
        final Context self = this;
        toast(self, "蓝莓派启动中…");
        new Thread(() -> {
            try {
                try {
                    Python.start(new AndroidPlatform(self));   // ← 缺了这步导致的崩溃
                } catch (Throwable dup) {
                    // 同一进程内二次进入:Python 已初始化过会抛异常,复用现有实例即可
                    Dbg.w(self, "[py] Python 已初始化(进程复用): " + dup.getMessage());
                }
                Python.getInstance().getModule("main_app");    // 预热导入(flask/requests 等)
                Dbg.w(self, "[py] Python 就绪(无端口模式)");
                postJs("window.onServerReady && window.onServerReady()");   // 触发数据补载
                runOnUiThread(() -> toast(self, "✓ 启动完成"));
            } catch (Throwable t) {
                Dbg.w(self, "‼️ [py] 初始化失败", t);
                uiToast("服务初始化失败,详见 debug.log");
            }
        }, "py-init").start();
    }

    /** 从内置 assets 读取文本文件(构建期由 syncEmbeddedHtml 任务从 main_app.py 同步)。 */
    private String readAsset(String name) {
        try (InputStream is = getAssets().open(name)) {
            ByteArrayOutputStream bo = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toString("UTF-8");
        } catch (Exception e) {
            Dbg.w(this, "‼️ 读取内置界面失败: " + name, e);
            return "<h3 style='color:#e33;font-family:sans-serif'>内置界面缺失</h3>";
        }
    }

    /** 把结果送回页面 JS(evaluateJavascript 必须在主线程)。 */
    private void postJs(String js) {
        runOnUiThread(() -> { if (web != null) web.evaluateJavascript(js, null); });
    }

    /**
     * JS ↔ Python 桥:页面经 window.AndroidBridge 直达 Python,
     * 全程无 HTTP、无端口。request 立即返回,耗时工作在线程池执行,
     * 完成后回调页面的 __onApiResult(id, status, body)。
     */
    private class ApiBridge {
        @JavascriptInterface
        public void request(final String id, final String path) {
            final Context self = getApplicationContext();
            apiPool.execute(() -> {
                String payload;
                try {
                    payload = Python.getInstance().getModule("main_app")
                        .callAttr("handle_api", path).toString();
                } catch (Throwable t) {
                    // Python 尚未就绪/调用异常:返回业务级错误,前端会自动重试
                    Dbg.w(self, "‼️ [bridge] " + path + " 调用失败", t);
                    try {
                        payload = new JSONObject()
                            .put("status", 500)
                            .put("body", new JSONObject()
                                .put("code", 500)
                                .put("message", "服务初始化中").toString())
                            .toString();
                    } catch (Exception ignored) { return; }
                }
                try {
                    JSONObject jo = new JSONObject(payload);
                    postJs("window.__onApiResult && window.__onApiResult("
                        + id + "," + jo.optInt("status", 500)
                        + "," + JSONObject.quote(jo.optString("body", "")) + ")");
                } catch (Exception e) {
                    Dbg.w(self, "‼️ [bridge] 回传解析失败: " + path, e);
                }
            });
        }

        /** 大文件(歌曲/MV)直链下载:系统 DownloadManager,带通知栏进度。 */
        @JavascriptInterface
        public void download(String filename, String url) {
            nativeDownload(filename, url);
        }

        /** 小文本(歌词)写入公共 Download 目录。 */
        @JavascriptInterface
        public void downloadText(String filename, String content) {
            saveTextToDownloads(filename, content);
        }
    }

    private void nativeDownload(String filename, String url) {
        try {
            DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
            req.setTitle(filename);
            req.setDescription("蓝莓派下载");
            req.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, filename);
            req.addRequestHeader("User-Agent", "Mozilla/5.0");
            ((DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE)).enqueue(req);
            Dbg.w(this, "[dl] 已入队: " + filename);
        } catch (Throwable t) {
            Dbg.w(this, "‼️ [dl] 下载入队失败: " + filename, t);
            uiToast("下载失败: " + t.getMessage());
        }
    }

    /** 歌词保存:Q+ 走 MediaStore 零权限;<Q 需运行时存储权限(先申请再写)。 */
    private void saveTextToDownloads(String filename, String content) {
        try {
            if (Build.VERSION.SDK_INT >= 29) {
                ContentValues cv = new ContentValues();
                cv.put(android.provider.MediaStore.Downloads.DISPLAY_NAME, filename);
                cv.put(android.provider.MediaStore.Downloads.MIME_TYPE, "text/plain");
                Uri uri = getContentResolver().insert(
                    android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                try (OutputStream os = getContentResolver().openOutputStream(uri)) {
                    os.write(content.getBytes(StandardCharsets.UTF_8));
                }
                Dbg.w(this, "[dl] 歌词已保存(MediaStore): " + filename);
                uiToast("已保存「" + filename + "」");
            } else if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED) {
                boolean ok = writeLegacyText(filename, content);
                uiToast(ok ? "已保存「" + filename + "」" : "保存失败");
            } else {
                pendingText[0] = filename; pendingText[1] = content;
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_WRITE);
            }
        } catch (Throwable t) {
            Dbg.w(this, "‼️ [dl] 文本保存失败: " + filename, t);
            uiToast("保存失败: " + t.getMessage());
        }
    }

    private boolean writeLegacyText(String filename, String content) {
        try {
            File dir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            if (!dir.exists()) dir.mkdirs();
            File f = new File(dir, filename);
            try (FileOutputStream fo = new FileOutputStream(f)) {
                fo.write(content.getBytes(StandardCharsets.UTF_8));
            }
            return true;
        } catch (Exception e) {
            Dbg.w(this, "‼️ [dl] 兼容模式写文件失败: " + filename, e);
            return false;
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (code == REQ_WRITE) {
            if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED
                    && pendingText[0] != null) {
                boolean ok = writeLegacyText(pendingText[0], pendingText[1]);
                uiToast(ok ? "已保存「" + pendingText[0] + "」" : "保存失败");
            } else {
                uiToast("缺少存储权限,无法保存歌词");
            }
            pendingText[0] = pendingText[1] = null;
        }
    }

    private static void toast(Context ctx, String msg) {
        try { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show(); } catch (Throwable ignored) { }
    }

    /** 桥线程里也能安全弹 Toast(切回主线程)。 */
    private void uiToast(String msg) {
        runOnUiThread(() -> toast(this, msg));
    }

    private void onDownload(String url, String ua, String disposition, String mime, long len) {
        try {
            String name = guessName(url, disposition);
            DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url));
            req.setMimeType(mime);
            req.setTitle(name);
            req.setDescription("蓝莓派下载");
            req.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            req.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, name);
            String ck = CookieManager.getInstance().getCookie(url);
            if (ck != null) req.addRequestHeader("cookie", ck);
            if (ua != null) req.addRequestHeader("User-Agent", ua);
            DownloadManager dm = (DownloadManager) getSystemService(Context.DOWNLOAD_SERVICE);
            dm.enqueue(req);
        } catch (Throwable t) {
            Dbg.w(this, "下载失败", t);
        }
    }

    private static String guessName(String url, String disposition) {
        if (disposition != null) {
            Matcher m = Pattern.compile("filename\\*=UTF-8''([^;]+)").matcher(disposition);
            if (m.find()) {
                try { return URLDecoder.decode(m.group(1), "UTF-8"); } catch (Exception ignored) { }
            }
            m = Pattern.compile("filename=\"?([^\";]+)\"?").matcher(disposition);
            if (m.find()) return m.group(1);
        }
        return URLUtil.guessFileName(url, disposition, null);
    }

    @Override
    public void onBackPressed() {
        // 单页面应用:没有任何内部导航历史,返回键直接退出
        // (onDestroy 会杀掉整个进程,不留后台残留)
        finish();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        // 用户真正退出(非旋转屏幕等配置变更)时杀掉整个进程:
        // 确保 Python 运行时、线程池等全部释放,下次启动永远是干净冷启
        if (isFinishing()) {
            Dbg.w(this, "用户已退出,杀掉进程以彻底释放资源");
            android.os.Process.killProcess(android.os.Process.myPid());
        }
    }
}
