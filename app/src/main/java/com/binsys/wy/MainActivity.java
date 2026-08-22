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
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

import com.chaquo.python.Python;

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
        setContentView(R.layout.activity_main);
        web = findViewById(R.id.web);

        WebSettings st = web.getSettings();
        st.setJavaScriptEnabled(true);
        st.setDomStorageEnabled(true);                       // localStorage(歌词校准/跑马灯开关)
        st.setAllowFileAccess(true);
        st.setMediaPlaybackRequiresUserGesture(false);
        st.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        web.setWebViewClient(new WebViewClient());
        // 所有 <a download> 触发的下载交给系统下载管理器(保存到公共 Download 目录)
        web.setDownloadListener(this::onDownload);

        // 先显示启动画面,服务就绪后自动切换到主界面
        web.loadData("<html><body style='background:#1e1e20;display:flex;align-items:center;justify-content:center;height:90vh'>"
            + "<p style='color:#8ab4f8;font-family:sans-serif;font-size:18px'>蓝莓派启动中…</p></body></html>",
            "text/html", "utf-8");

        startServerThenLoad();
    }

    private void startServerThenLoad() {
        // 线程A:启动内嵌 Python/Flask 服务(callAttr 阻塞直到服务停止)
        new Thread(() -> {
            try {
                Python.getInstance().getModule("server_launcher").callAttr("start");
            } catch (Throwable t) {
                Log.e(TAG, "python server crashed", t);
            }
        }, "py-server").start();

        // 线程B:轮询端口就绪后再加载页面
        new Thread(() -> {
            for (int i = 0; i < 120; i++) {
                try (Socket s = new Socket()) {
                    s.connect(new InetSocketAddress("127.0.0.1", 5000), 500);
                    runOnUiThread(() -> {
                        if (!pageLoaded) { pageLoaded = true; web.loadUrl(PAGE); }
                    });
                    return;
                } catch (IOException ignore) { }
                try { Thread.sleep(500); } catch (InterruptedException e) { return; }
            }
            runOnUiThread(() -> web.loadData(
                "<h3 style='font-family:sans-serif;color:#e33'>服务启动失败,请重启应用</h3>",
                "text/html", "utf-8"));
        }, "port-wait").start();
    }

    /** 系统下载管理器:文件名优先取 Content-Disposition(与页面提示一致),存到公共 Download */
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
            Log.e(TAG, "download failed", t);
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
