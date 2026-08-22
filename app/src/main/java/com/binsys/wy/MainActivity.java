package com.binsys.wy;

import android.app.Activity;
import android.app.DownloadManager;
import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.util.Log;
import android.webkit.CookieManager;
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity {
    private static final String TAG = "wy-app";
    private static final String PAGE = "http://127.0.0.1:5000/";
    private WebView web;
    private boolean pageLoaded = false;

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

    private void startServerThenLoad() {
        final Context self = this;
        toast(self, "蓝莓派启动中…");
        // 线程 A:初始化 Python → 立即把界面 HTML 渲染进 WebView(不等 Flask 绑定端口,
        // 消除白屏窗口期)→ 再阻塞运行 Flask 服务;后端就绪前由前端自动重试补数据
        new Thread(() -> {
            Dbg.w(self, "[py] 线程启动,准备初始化 Python…");
            try {
                Python.start(new AndroidPlatform(self));   // ← 缺了这步导致的崩溃
                PyObject mainApp = Python.getInstance().getModule("main_app");
                Dbg.w(self, "[py] Python 已初始化,模块已加载");
                String html = mainApp.callAttr("get_html").toString();
                final int htmlLen = html.length();
                runOnUiThread(() -> {
                    pageLoaded = true;
                    // baseURL 指向本地服务:页面内相对 API 请求自动落到 127.0.0.1:5000,
                    // 与 loadUrl 同源(localStorage 歌词校准等数据互通)
                    web.loadDataWithBaseURL(PAGE, html, "text/html", "utf-8", null);
                    Dbg.w(self, "[ui] 界面已提前渲染(" + htmlLen + " 字节),后端继续启动");
                });
                mainApp.callAttr("start");   // 阻塞直到服务停止
                Dbg.w(self, "[py] start() 已返回(Flask 服务退出)");
            } catch (Throwable t) {
                Dbg.w(self, "‼️ [py] 服务启动失败", t);
            }
        }, "py-server").start();

        // 线程 B:轮询本地端口,就绪即弹「启动完成」并通知前端刷新数据
        new Thread(() -> {
            for (int i = 1; i <= 400; i++) {          // 150ms × 400 ≈ 60s 上限
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress("127.0.0.1", 5000), 300);
                    Dbg.w(self, "[poll] 服务就绪(第" + i + "次探测)");
                    runOnUiThread(() -> {
                        toast(self, "✓ 启动完成");
                        if (!pageLoaded) {            // 兑底:提前渲染因异常未执行
                            pageLoaded = true;
                            web.loadUrl(PAGE);
                        } else {
                            web.evaluateJavascript(
                                "window.onServerReady && window.onServerReady()", null);
                        }
                    });
                    return;
                } catch (IOException e) {
                    if (i == 1 || i % 40 == 0) Dbg.w(self, "[poll] 第" + i + "次探测失败(服务未就绪)");
                }
                try { Thread.sleep(150); } catch (InterruptedException e) { return; }
            }
            Dbg.w(self, "‼️ [poll] 60 秒超时,服务始终未监听 5000");
            runOnUiThread(() -> web.loadData(
                "<h3 style='font-family:sans-serif;color:#e33'>服务启动失败,详见 debug.log</h3>",
                "text/html", "utf-8"));
        }, "port-wait").start();
    }

    private static void toast(Context ctx, String msg) {
        try { Toast.makeText(ctx, msg, Toast.LENGTH_SHORT).show(); } catch (Throwable ignored) { }
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
        else super.onBackPressed();
    }
}
