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

import com.chaquo.python.PyObject;
import com.chaquo.python.Python;
import com.chaquo.python.android.AndroidPlatform;

import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
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
    private boolean pageLoaded = false;
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
            @Override public void onPageStarted(WebView view, java.lang.String url, android.graphics.Bitmap f) {
                Dbg.w(self, "WebView onPageStarted: " + url);
            }
            @Override public void onPageFinished(WebView view, java.lang.String url) {
                Dbg.w(self, "WebView onPageFinished: " + url);
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest rq, WebResourceError er) {
                Dbg.w(self, "WebView 错误: " + rq.getUrl() + " " + er.getDescription());
            }
        });
        web.setDownloadListener(this::onDownload);

        // 启动画面:立即可见,用于区分「WebView 层」与「Python 层」故障
        web.loadData("<html><body style='background:#1e1e20;display:flex;align-items:center;"
            + "justify-content:center;height:90vh'><p style='color:#8ab4f8;font-family:sans-serif;"
            + "font-size:18px'>蓝莓派启动中…</p></body></html>", "text/html", "utf-8");
        Dbg.w(this, "启动画面已设置");

        startServerThenLoad();
        Dbg.w(this, "onCreate 完成");
    }

    /**
     * 无端口启动流程:初始化 Python → 渲染界面 → 完成。
     * 没有 Flask 服务线程、没有端口监听、没有轮询探测;
     * 页面数据全部经 AndroidBridge 直连 Python(handle_api 进程内分发)。
     */
    private void startServerThenLoad() {
        final Context self = this;
        toast(self, "蓝莓派启动中…");
        new Thread(() -> {
            Dbg.w(self, "[py] 线程启动,准备初始化 Python…");
            try {
                try {
                    Python.start(new AndroidPlatform(self));   // ← 缺了这步导致的崩溃
                } catch (Throwable dup) {
                    // 同一进程内二次进入:Python 已初始化过会抛异常,复用现有实例即可
                    Dbg.w(self, "[py] Python 已初始化(进程复用): " + dup.getMessage());
                }
                PyObject mainApp = Python.getInstance().getModule("main_app");
                String html = mainApp.callAttr("get_html").toString();
                runOnUiThread(() -> {
                    pageLoaded = true;
                    // baseURL 只用来固定页面 origin(localStorage 兼容),不发任何请求
                    web.loadDataWithBaseURL(BASE_URL, html, "text/html", "utf-8", null);
                    // 模块加载完成即后端就绪(无端口架构),直接提示完成
                    toast(self, "✓ 启动完成");
                    Dbg.w(self, "[ui] 界面已加载(" + html.length()
                        + " 字节),JS↔Python 桥就绪(无端口模式)");
                });
                Dbg.w(self, "[py] Python 已初始化,模块已加载");
            } catch (Throwable t) {
                Dbg.w(self, "‼️ [py] 初始化失败", t);
                runOnUiThread(() -> web.loadData(
                    "<h3 style='font-family:sans-serif;color:#e33'>服务初始化失败,详见 debug.log</h3>",
                    "text/html", "utf-8"));
            }
        }, "py-init").start();
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
                    Dbg.w(self, "‼️ [bridge] " + path + " 调用失败", t);
                    try {
                        payload = new JSONObject()
                            .put("status", 500)
                            .put("body", new JSONObject()
                                .put("code", 500)
                                .put("message", "Python 调用失败").toString())
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
        if (web != null && web.canGoBack()) web.goBack();
        else finish();   // 触发 onDestroy → 彻底杀进程,不留后台残留
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
