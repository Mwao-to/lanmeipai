package com.binsys.wy;

import android.Manifest;
import android.app.Activity;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.ParcelFileDescriptor;
import android.util.Log;
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
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity {
    private static final String TAG = "wy-app";
    /** 仅作为页面源(origin):保持 localStorage 与历史版本互通。无任何服务监听此地址 */
    private static final String BASE_URL = "http://127.0.0.1:5000/";
    private static final int REQ_WRITE = 42;

    /** ═══ 内置下载器:wget 式 12 线程 Range 分块并发,统一落盘目录 ═══ */
    private static final int DL_THREADS = 12;
    /** MediaStore 相对路径(物理路径即 /storage/emulated/0/Download/网易云下载器/) */
    private static final String DL_SUBDIR = Environment.DIRECTORY_DOWNLOADS + "/网易云下载器";
    /** <Q 设备的物理路径 */
    private static final File DL_LEGACY_DIR =
        new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "网易云下载器");

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
        web.setDownloadListener((url, ua, disposition, mime, len)
            -> internalDownload(guessName(url, disposition), url));

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
     * 模块加载完成即后端就绪 → 回调前端补数据。
     * 就绪前的桥调用会安全返回业务错误,由前端自动重试,无需任何锁等待。
     */
    private void startPythonInit() {
        final Context self = this;
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

        /** 大文件(歌曲/MV):内置 12 线程下载器直链下载到 公共Download/网易云下载器/ */
        @JavascriptInterface
        public void download(String filename, String url) {
            internalDownload(filename, url);
        }

        /** 小文本(歌词):写入同一目录 */
        @JavascriptInterface
        public void downloadText(String filename, String content) {
            saveTextToDownloads(filename, content);
        }
    }

    /** 向页面派发下载器事件(status: start/progress/done/error)。 */
    private void dlEvent(String status, String filename, String detail) {
        postJs("window.__onDownloadEvent && window.__onDownloadEvent("
            + JSONObject.quote(status) + "," + JSONObject.quote(filename == null ? "" : filename)
            + "," + JSONObject.quote(detail == null ? "" : detail) + ")");
    }

    /** 探测目标是否支持 Range 分块(断点续传)并获取总大小,返回 {支持?1:0, 总大小或-1}。 */
    private static long[] probeUrl(String url) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestProperty("Range", "bytes=0-0");
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        c.setConnectTimeout(10000);
        c.setReadTimeout(15000);
        int code = c.getResponseCode();
        long total = -1;
        int ranged = 0;
        String cr = c.getHeaderField("Content-Range");          // 形如 bytes 0-0/5242880
        if (code == 206 && cr != null && cr.contains("/")) {
            try {
                total = Long.parseLong(cr.substring(cr.lastIndexOf('/') + 1).trim());
                ranged = 1;
            } catch (Exception ignored) { }
        } else {
            String cl = c.getHeaderField("Content-Length");
            if (cl != null) try { total = Long.parseLong(cl.trim()); } catch (Exception ignored) { }
        }
        try { c.getInputStream().close(); } catch (Exception ignored) { }
        c.disconnect();
        return new long[]{ranged, total};
    }

    /** 预分配文件大小(多线程随机写的前提)。 */
    private void preAllocate(Context self, Uri mediaUri, File legacy, long total) throws Exception {
        if (mediaUri != null) {
            try (ParcelFileDescriptor pfd = self.getContentResolver().openFileDescriptor(mediaUri, "rw");
                 RandomAccessFile rf = new RandomAccessFile(pfd.getFileDescriptor(), "rw")) {
                rf.setLength(total);
            }
        } else {
            try (RandomAccessFile rf = new RandomAccessFile(legacy, "rw")) {
                rf.setLength(total);
            }
        }
    }

    /** 打开整文件随机写通道(Q+ 经 MediaStore fd,<Q 直写文件)。 */
    private RandomAccessFile openRandom(Context self, Uri mediaUri, File legacy) throws Exception {
        if (mediaUri != null) {
            ParcelFileDescriptor pfd = self.getContentResolver().openFileDescriptor(mediaUri, "rw");
            return new RandomAccessFile(pfd.getFileDescriptor(), "rw");
        }
        return new RandomAccessFile(legacy, "rw");
    }

    /** 单线程顺序下载(Range 不可用/小文件兜底)。 */
    private void singleThreadDownload(Context self, Uri mediaUri, File legacy,
                                      String url, AtomicLong done) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestProperty("User-Agent", "Mozilla/5.0");
        c.setConnectTimeout(10000);
        c.setReadTimeout(30000);
        int code = c.getResponseCode();
        if (code / 100 != 2) throw new IOException("HTTP " + code);
        InputStream in = c.getInputStream();
        RandomAccessFile rf = openRandom(self, mediaUri, legacy);
        try {
            rf.seek(0);
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                rf.write(buf, 0, n);
                done.addAndGet(n);
            }
        } finally {
            try { rf.close(); } catch (Exception ignored) { }
            try { in.close(); } catch (Exception ignored) { }
            c.disconnect();
        }
    }

    /** wget 式多线程分块下载:12 线程各自负责一段 Range,段内断线自动续传(最多重试 3 次)。 */
    private void multiThreadDownload(Context self, Uri mediaUri, File legacy,
                                     String url, long total, AtomicLong done) throws Exception {
        final long seg = total / DL_THREADS;
        final AtomicLongArray pos = new AtomicLongArray(DL_THREADS);   // 各线程段内当前偏移
        for (int i = 0; i < DL_THREADS; i++) pos.set(i, i * seg);
        preAllocate(self, mediaUri, legacy, total);

        final ConcurrentLinkedQueue<Exception> errors = new ConcurrentLinkedQueue<>();
        final CountDownLatch latch = new CountDownLatch(DL_THREADS);
        ExecutorService pool = Executors.newFixedThreadPool(DL_THREADS);
        for (int i = 0; i < DL_THREADS; i++) {
            final int idx = i;
            final long end = (i == DL_THREADS - 1) ? total : (i + 1) * seg;
            pool.execute(() -> {
                Exception lastErr = null;
                int retry = 3;
                while (retry-- > 0 && errors.isEmpty()) {       // 其它线程已失败则尽早放弃
                    HttpURLConnection c = null;
                    RandomAccessFile rf = null;
                    ParcelFileDescriptor pfd = null;
                    InputStream in = null;
                    try {
                        long p = pos.get(idx);
                        c = (HttpURLConnection) new URL(url).openConnection();
                        c.setRequestProperty("Range", "bytes=" + p + "-" + (end - 1));
                        c.setRequestProperty("User-Agent", "Mozilla/5.0");
                        c.setConnectTimeout(10000);
                        c.setReadTimeout(30000);
                        int code = c.getResponseCode();
                        if (code != 206) throw new IOException("分块响应异常 HTTP " + code);
                        in = c.getInputStream();
                        rf = openRandom(self, mediaUri, legacy);
                        rf.seek(p);
                        byte[] buf = new byte[64 * 1024];
                        int n;
                        while ((n = in.read(buf)) > 0 && errors.isEmpty()) {
                            rf.write(buf, 0, n);
                            p += n;
                            pos.set(idx, p);
                            done.addAndGet(n);
                        }
                        if (pos.get(idx) >= end) return;         // 本段完成
                        throw new IOException("连接提前中断");
                    } catch (Exception e) {
                        lastErr = e;
                    } finally {
                        try { if (rf != null) rf.close(); } catch (Exception ignored) { }
                        try { if (pfd != null) pfd.close(); } catch (Exception ignored) { }
                        try { if (in != null) in.close(); } catch (Exception ignored) { }
                        if (c != null) c.disconnect();
                    }
                }
                if (pos.get(idx) < end && lastErr != null) errors.add(lastErr);
                latch.countDown();
            });
        }
        latch.await();
        pool.shutdown();
        if (!errors.isEmpty()) throw errors.peek();
        if (done.get() != total) throw new java.io.IOException(
            "完整性校验失败(已下载 " + done.get() + "/" + total + " 字节)");
    }

    /** 统一下载入口:创建目标文件 → 探测 Range → 12 线程/单线程 → 发布并回传保存路径。 */
    private void internalDownload(String filename, String url) {
        final Context self = getApplicationContext();
        apiPool.execute(() -> {
            Uri mediaUri = null;
            File legacy = null;
            AtomicLong done = new AtomicLong();
            ScheduledExecutorService prog = Executors.newSingleThreadScheduledExecutor();
            boolean ok = false;
            String errMsg = null;
            try {
                dlEvent("start", filename, "");
                // 1. 创建目标文件(Q+ 经 MediaStore 落到 Download/网易云下载器/,<Q 直写路径)
                if (Build.VERSION.SDK_INT >= 29) {
                    ContentValues cv = new ContentValues();
                    cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, filename);
                    cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, mimeOf(filename));
                    cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, DL_SUBDIR);
                    cv.put(android.provider.MediaStore.MediaColumns.IS_PENDING, 1);
                    mediaUri = self.getContentResolver().insert(
                        android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                    if (mediaUri == null) throw new java.io.IOException("创建下载文件失败(存储不可用)");
                } else {
                    if (!DL_LEGACY_DIR.exists() && !DL_LEGACY_DIR.mkdirs())
                        throw new java.io.IOException("创建目录失败:" + DL_LEGACY_DIR);
                    legacy = uniqueLegacy(new File(DL_LEGACY_DIR, filename));
                }
                // 2. 探测 Range 支持与总大小
                long[] probe = probeUrl(url);
                final long total = probe[1];
                // 3. 进度上报(每 500ms 采样,25% 一档提示)
                final long[] lastPct = {-1};
                prog.scheduleAtFixedRate(() -> {
                    if (total <= 0) return;
                    int pct = (int) (done.get() * 100 / total);
                    if (pct != lastPct[0] && pct % 25 == 0 && pct > lastPct[0]) {
                        lastPct[0] = pct;
                        dlEvent("progress", filename, String.valueOf(pct));
                    }
                }, 400, 500, TimeUnit.MILLISECONDS);
                // 4. 分发下载(大文件且支持 Range → 12 线程;否则单线程兜底)
                try {
                    if (probe[0] == 1 && total > 1024 * 1024) {
                        Dbg.w(self, "[dl] 12 线程下载 " + filename + "(" + total + " 字节)");
                        multiThreadDownload(self, mediaUri, legacy, url, total, done);
                    } else {
                        Dbg.w(self, "[dl] 单线程下载 " + filename + "(range="
                            + probe[0] + ", size=" + total + ")");
                        singleThreadDownload(self, mediaUri, legacy, url, done);
                    }
                    ok = true;
                } catch (Throwable firstErr) {
                    // 多线程失败(如服务器不支持 Range 却返回 200 全量体):
                    // 重置进度从零单线程重试一次(同目标文件整体覆写)
                    Dbg.w(self, "[dl] 多线程失败,转单线程重试: " + firstErr);
                    done.set(0);
                    singleThreadDownload(self, mediaUri, legacy, url, done);
                    ok = true;
                }
            } catch (Throwable t) {
                errMsg = t.getMessage() == null ? t.toString() : t.getMessage();
                Dbg.w(self, "‼️ [dl] " + filename + " 下载失败: " + errMsg, t);
            } finally {
                prog.shutdownNow();
                // 5. 收尾:成功发布文件(IS_PENDING=0)并回传真实路径;失败清理残留
                String finalPath = null;
                try {
                    if (ok && mediaUri != null) {
                        ContentValues cv = new ContentValues();
                        cv.put(android.provider.MediaStore.MediaColumns.IS_PENDING, 0);
                        self.getContentResolver().update(mediaUri, cv, null, null);
                        finalPath = queryDataPath(self, mediaUri);
                        if (finalPath == null) finalPath = "/" + DL_SUBDIR + "/" + filename;
                    } else if (ok) {
                        finalPath = legacy.getAbsolutePath();
                    }
                    if (!ok && mediaUri != null) self.getContentResolver().delete(mediaUri, null, null);
                    if (!ok && legacy != null && legacy.exists()) legacy.delete();
                } catch (Throwable ignore) { }
                if (ok) {
                    Dbg.w(self, "[dl] 完成: " + finalPath);
                    dlEvent("done", filename, finalPath);
                } else {
                    dlEvent("error", filename, errMsg == null ? "未知错误" : errMsg);
                }
            }
        });
    }

    private static String queryDataPath(Context self, Uri uri) {
        try (Cursor c = self.getContentResolver().query(uri,
            new String[]{android.provider.MediaStore.MediaColumns.DATA}, null, null, null)) {
            if (c != null && c.moveToFirst()) return c.getString(0);
        } catch (Exception ignored) { }
        return null;
    }

    private static String mimeOf(String name) {
        String n = name.toLowerCase();
        if (n.endsWith(".mp3")) return "audio/mpeg";
        if (n.endsWith(".flac")) return "audio/flac";
        if (n.endsWith(".m4a")) return "audio/mp4";
        if (n.endsWith(".aac")) return "audio/aac";
        if (n.endsWith(".mp4")) return "video/mp4";
        if (n.endsWith(".lrc") || n.endsWith(".txt")) return "text/plain";
        return "application/octet-stream";
    }

    /** 同名文件自动加 " (n)" 序号(<Q 无 MediaStore 自动改名)。 */
    private static File uniqueLegacy(File f) {
        if (!f.exists()) return f;
        String n = f.getName();
        int dot = n.lastIndexOf('.');
        String base = dot > 0 ? n.substring(0, dot) : n;
        String ext = dot > 0 ? n.substring(dot) : "";
        for (int i = 1; i < 999; i++) {
            File t = new File(f.getParentFile(), base + " (" + i + ")" + ext);
            if (!t.exists()) return t;
        }
        return f;
    }

    /** 歌词落盘:与歌曲/MV 同一目录 Download/网易云下载器/,完成后同样弹窗回传路径。 */
    private void saveTextToDownloads(String filename, String content) {
        final Context self = getApplicationContext();
        apiPool.execute(() -> {
            try {
                String finalPath;
                if (Build.VERSION.SDK_INT >= 29) {
                    ContentValues cv = new ContentValues();
                    cv.put(android.provider.MediaStore.MediaColumns.DISPLAY_NAME, filename);
                    cv.put(android.provider.MediaStore.MediaColumns.MIME_TYPE, "text/plain");
                    cv.put(android.provider.MediaStore.MediaColumns.RELATIVE_PATH, DL_SUBDIR);
                    Uri uri = self.getContentResolver().insert(
                        android.provider.MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv);
                    try (OutputStream os = self.getContentResolver().openOutputStream(uri)) {
                        os.write(content.getBytes(StandardCharsets.UTF_8));
                    }
                    finalPath = queryDataPath(self, uri);
                    if (finalPath == null) finalPath = "/" + DL_SUBDIR + "/" + filename;
                } else if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                        == PackageManager.PERMISSION_GRANTED) {
                    if (!DL_LEGACY_DIR.exists() && !DL_LEGACY_DIR.mkdirs())
                        throw new java.io.IOException("创建目录失败");
                    File f = uniqueLegacy(new File(DL_LEGACY_DIR, filename));
                    try (FileOutputStream fo = new FileOutputStream(f)) {
                        fo.write(content.getBytes(StandardCharsets.UTF_8));
                    }
                    finalPath = f.getAbsolutePath();
                } else {
                    pendingText[0] = filename; pendingText[1] = content;
                    requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_WRITE);
                    return;
                }
                Dbg.w(self, "[dl] 歌词已保存: " + finalPath);
                dlEvent("done", filename, finalPath);
            } catch (Throwable t) {
                Dbg.w(self, "‼️ [dl] 文本保存失败: " + filename, t);
                dlEvent("error", filename, t.getMessage() == null ? t.toString() : t.getMessage());
            }
        });
    }

    private boolean writeLegacyText(String filename, String content) {
        try {
            if (!DL_LEGACY_DIR.exists() && !DL_LEGACY_DIR.mkdirs()) return false;
            File f = uniqueLegacy(new File(DL_LEGACY_DIR, filename));
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
                if (ok) dlEvent("done", pendingText[0],
                    new File(DL_LEGACY_DIR, pendingText[0]).getAbsolutePath());
                else dlEvent("error", pendingText[0], "写入文件失败");
            } else {
                dlEvent("error", pendingText[0] == null ? "" : pendingText[0], "缺少存储权限");
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
