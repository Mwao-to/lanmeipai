package com.binsys.wy;

import android.Manifest;
import android.app.Activity;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
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
    /** JS→Python 桥的调用线程池(有界 4 线程:CPython GIL 下更高并发无益,且防请求风暴) */
    private final ExecutorService apiPool = Executors.newFixedThreadPool(4,
        r -> new Thread(r, "api-worker"));
    /** 下载专用队列(并发 ≤2:第 3 个任务起排队,防多任务时 12线程/任务 的连接与 fd 风暴) */
    private final ExecutorService dlPool = Executors.newFixedThreadPool(2,
        r -> new Thread(r, "dl-worker"));
    /** <Q 设备申请存储权限期间暂存的歌词内容 {name, content} */
    private final String[] pendingText = new String[2];
    /** 系统下载器兜底:任务 id → 文件名(完成后广播里查路径用) */
    private final java.util.Map<Long, String> sysDownloads = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Dbg.w(this, "═══ onCreate 进入 ═══");
        // 输入法零关联:ADJUST_NOTHING 让键盘弹出时窗口不平移不缩放,
        // 背景封面/双栏布局尺寸与输入法彻底解耦;STATE_ALWAYS_HIDDEN 防启动即弹键盘
        getWindow().setSoftInputMode(
            android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_NOTHING
            | android.view.WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
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
        // WebView 渲染前的默认底色同为深色,与窗口背景一致,彻底消除白闪
        web.setBackgroundColor(0xFF0F0F0F);

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

        // 系统下载器兜底:内置下载器失败时转交系统继续,完成后同样把保存路径弹给页面
        final BroadcastReceiver sysDlReceiver = new BroadcastReceiver() {
            @Override public void onReceive(Context c, Intent i) {
                long id = i.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1);
                String name = sysDownloads.remove(id);
                if (name == null) return;
                String path = resolveSysDownloadPath(id);
                if (path != null) {
                    Dbg.w(self, "[dl][sys] 完成: " + path);
                    dlEvent("done", name, path);
                    doneToast(name, path);   // 系统 Toast 双保险
                } else {
                    dlEvent("error", name, "系统下载器下载失败");
                }
            }
        };
        IntentFilter sysFilter = new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE);
        if (Build.VERSION.SDK_INT >= 33)
            registerReceiver(sysDlReceiver, sysFilter, Context.RECEIVER_NOT_EXPORTED);
        else
            registerReceiver(sysDlReceiver, sysFilter);

        // 界面从内置 assets 即时渲染(毫秒级):
        // 没有启动画面、没有二次切换、没有多余历史记录 —— 打开即真界面。
        // 数据由前端 bootLoop 在 Python 就绪后自动补载;
        // BASE_URL 仅固定页面 origin 以兼容旧版 localStorage
        String html = readAsset("index.html");
        web.loadDataWithBaseURL(BASE_URL, html, "text/html", "utf-8", null);
        web.clearFocus();   // 清掉 WebView 自动抢走的焦点(避免焦点落到搜索框弹键盘)
        Dbg.w(this, "[ui] 界面已从 assets 即时渲染(" + html.length() + " 字节)");
        Dbg.w(this, "onCreate 完成");
    }

    /** Python 业务核心就绪标志:桥调用在就绪前排队等待,避免竞态报错 */
    private static volatile boolean PY_READY = false;

    /**
     * 后台初始化 Python(无端口架构):没有 Flask 服务线程、没有端口监听,
     * 模块加载完成即后端就绪 → 回调前端补数据。
     * 就绪前的桥调用在 ApiBridge 内部排队等待,就绪后立即补发。
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
                // 装载加密业务核心:Java 解密 → 内存字节码注入(无明文落盘)
                byte[] coreCode = unwrapCore();
                Python.getInstance().getModule("pyloader").callAttr("install", coreCode);
                // 注入私有目录:A键扫码登录的 cooir.json 落盘位置(启动自检自动代入全局 Cookie)
                Python.getInstance().getModule("main_app")
                    .callAttr("init_data_dir", self.getFilesDir().getAbsolutePath());
                Python.getInstance().getModule("main_app");    // 预热导入(flask/requests 等)
                PY_READY = true;
                Dbg.w(self, "[py] Python 就绪(无端口模式,核心已装载 " + coreCode.length + "B)");
                postJs("window.onServerReady && window.onServerReady()");   // 触发数据补载
            } catch (Throwable t) {
                Dbg.w(self, "‼️ [py] 初始化失败", t);
                uiToast("服务初始化失败,详见 debug.log");
            }
        }, "py-init").start();
    }

    /*
     * ═══ 业务核心解密(AES-256-CBC) ═══
     * 密钥不整段出现在常量池:拆成 3 个分片,各自与掩码异或存储,
     * 运行时拼装。R8 混淆后逆向者需同时理解分片/掩码/拼装逻辑才能还原。
     * core.bin 由 CI 构建期加密生成(明文字节码从未进入仓库/APK)。
     */
    private static final int[] C1 = {-21, 81, 49, -65, 11, -53, 105, 100, -20, 61, -77, -69, 89, -70, -75, 103};
    private static final int[] C1M = {-31, -10, 60, -72, 25, -48, 44, 73, -70, 67, 5, 20, -39, -23, 96, -31};
    private static final int[] C2 = {126, -122, 52, 17, -104, -64, 87, 127, 0, -12, 63, 106, 74, -98, -1, 34};
    private static final int[] C2M = {-57, -98, 75, -61, -125, -91, 10, 5, -38, -51, -62, 113, 99, -119, 49, -16};
    private static final int[] C9 = {-100, -71, -107, -37, -9, -107, 100, 88, -8, -95, 70, 90, -109, 8, 90, 20};
    private static final int[] C9M = {14, -58, -70, 112, 102, -31, -68, -78, 58, -22, 17, -83, 120, 35, -120, -7};

    private static byte[] reveal(int[] masked, int[] mask) {
        byte[] out = new byte[masked.length];
        for (int i = 0; i < masked.length; i++) out[i] = (byte) (masked[i] ^ mask[i]);
        return out;
    }

    /** 解密并返回内存中的业务核心字节码(去掉 pyc 头的 marshal 数据)。 */
    private byte[] unwrapCore() throws Exception {
        byte[] key = new byte[32];
        System.arraycopy(reveal(C1, C1M), 0, key, 0, 16);
        System.arraycopy(reveal(C2, C2M), 0, key, 16, 16);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(reveal(C9, C9M)));
        ByteArrayOutputStream blob = new ByteArrayOutputStream();
        try (InputStream is = getAssets().open("core.bin")) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) > 0) blob.write(buf, 0, n);
        }
        return cipher.doFinal(blob.toByteArray());
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
     * 断网短路探测(P1):仅要求存在具备 INTERNET 能力的活动网络,
     * 不苛求 VALIDATED(captive portal 校验中不误判)。
     * 判定异常时返回 true —— 宁可多试一次,不可误判断网。
     */
    private static boolean isOnline(Context c) {
        try {
            ConnectivityManager cm = (ConnectivityManager)
                c.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.Network n = cm == null ? null : cm.getActiveNetwork();
            if (n == null) return false;
            NetworkCapabilities cap = cm.getNetworkCapabilities(n);
            return cap != null && cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET);
        } catch (Throwable t) {
            return true;
        }
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
                    // ═══ 断网短路(P1):无活动网络立即返回业务级错误,不烧 Python 重试链 ═══
                    if (!isOnline(self)) {
                        payload = new JSONObject()
                            .put("status", 200)
                            .put("body", new JSONObject()
                                .put("code", -1)
                                .put("message", "网络未连接，请检查网络后重试").toString())
                            .toString();
                    } else {
                        // ═══ 排队等待 Python 就绪(冷启动竞态根除):最多等 15 秒 ═══
                        for (int i = 0; !PY_READY && i < 150; i++) Thread.sleep(100);
                        if (!PY_READY) throw new IllegalStateException("服务初始化超时");
                        payload = Python.getInstance().getModule("main_app")
                            .callAttr("handle_api", path).toString();
                    }
                } catch (Throwable t) {
                    // 真正的异常(非就绪等待)才落盘;排队超时返回业务级错误由前端重试
                    if (!(t instanceof IllegalStateException))
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

        /** 分享兑底:把文本递给系统输入法 —— 写入剪贴板(主流中文输入法键盘上方会显示
         *  这条剪贴板建议,点一下即可上屏到任何输入框),并尝试弹出键盘让建议立即可见。 */
        @JavascriptInterface
        public void imeCommit(final String text) {
            runOnUiThread(() -> {
                boolean ok = false;
                try {
                    android.content.ClipboardManager cm = (android.content.ClipboardManager)
                        getSystemService(Context.CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(android.content.ClipData.newPlainText("wy-share", text));
                        ok = true;
                    }
                    try {   // 弹出键盘,输入法的剪贴板建议条随即呈现刚写入的内容
                        android.view.inputmethod.InputMethodManager imm =
                            (android.view.inputmethod.InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                        if (imm != null && web != null) { web.requestFocus(); imm.showSoftInput(web, 0); }
                    } catch (Throwable ignore) { }
                } catch (Throwable t) {
                    Dbg.w(MainActivity.this, "‼️ [ime] imeCommit 失败", t);
                }
                Dbg.w(MainActivity.this, "[ime] 兑底传递完成 clipboard=" + ok
                    + " len=" + (text == null ? 0 : text.length()));
                toast(MainActivity.this, ok ? "已传给输入法：点击键盘上方剪贴板建议即可上屏" : "分享失败");
            });
        }
    }

    /** 向页面派发下载器事件(status: start/progress/done/error)。 */
    private void dlEvent(String status, String filename, String detail) {
        postJs("window.__onDownloadEvent && window.__onDownloadEvent("
            + JSONObject.quote(status) + "," + JSONObject.quote(filename == null ? "" : filename)
            + "," + JSONObject.quote(detail == null ? "" : detail) + ")");
    }

    /** 完成路径提示双保险:除页面内弹窗外,再用系统 Toast 弹一次绝对路径(必达)。 */
    private void doneToast(String filename, String path) {
        runOnUiThread(() -> {
            try { Toast.makeText(this,
                "「" + filename + "」下载完成\n已保存到:" + path,
                Toast.LENGTH_LONG).show(); } catch (Throwable ignored) { }
        });
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
        try (RandWriter w = new RandWriter(self, mediaUri, legacy)) {
            w.setLength(total);
        }
    }

    /**
     * 统一随机写句柄:Q+ 经 MediaStore fd 用 FileOutputStream+FileChannel 定位写
     * (基于已有 fd 不截断、各线程独立 fd 互不干扰);<Q 直写 RandomAccessFile。
     */
    private static final class RandWriter implements AutoCloseable {
        private final ParcelFileDescriptor pfd;
        private final FileOutputStream fos;
        private final RandomAccessFile raf;
        private final FileChannel ch;

        RandWriter(Context self, Uri mediaUri, File legacy) throws Exception {
            if (mediaUri != null) {
                pfd = self.getContentResolver().openFileDescriptor(mediaUri, "rw");
                fos = new FileOutputStream(pfd.getFileDescriptor());   // 基于已有 fd,不截断
                raf = null;
                ch = fos.getChannel();
            } else {
                pfd = null;
                fos = null;
                raf = new RandomAccessFile(legacy, "rw");
                ch = raf.getChannel();
            }
        }

        void writeAt(long pos, byte[] buf, int off, int len) throws Exception {
            ch.position(pos);
            ch.write(ByteBuffer.wrap(buf, off, len));
        }

        void setLength(long total) throws Exception {
            if (raf != null) { raf.setLength(total); return; }
            ch.position(total - 1);
            ch.write(ByteBuffer.wrap(new byte[1]));   // 写末尾字节扩展到 total
        }

        @Override public void close() {
            try { ch.close(); } catch (Exception ignored) { }
            try { if (fos != null) fos.close(); } catch (Exception ignored) { }
            try { if (pfd != null) pfd.close(); } catch (Exception ignored) { }
            try { if (raf != null) raf.close(); } catch (Exception ignored) { }
        }
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
        try (RandWriter w = new RandWriter(self, mediaUri, legacy)) {
            long p = 0;
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                w.writeAt(p, buf, 0, n);
                p += n;
                done.addAndGet(n);
            }
        } finally {
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
                try {
                    Exception lastErr = null;
                    int retry = 3;
                    RandWriter w = null;
                    while (retry-- > 0 && errors.isEmpty()) {       // 其它线程已失败则尽早放弃
                        HttpURLConnection c = null;
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
                        w = new RandWriter(self, mediaUri, legacy);
                        byte[] buf = new byte[64 * 1024];
                        int n;
                        while ((n = in.read(buf)) > 0 && errors.isEmpty()) {
                            w.writeAt(p, buf, 0, n);
                            p += n;
                            pos.set(idx, p);
                            done.addAndGet(n);
                        }
                        w.close(); w = null;
                        if (pos.get(idx) >= end) break;          // 本段完成 → 跳出重试循环(finally 必定 countDown)
                        throw new IOException("连接提前中断");
                    } catch (Exception e) {
                        lastErr = e;
                    } finally {
                        if (w != null) { try { w.close(); } catch (Exception ignored) { } }
                        try { if (in != null) in.close(); } catch (Exception ignored) { }
                        if (c != null) c.disconnect();
                    }
                }
                if (pos.get(idx) < end && lastErr != null) errors.add(lastErr);
                } finally {
                    // ★ 关键:无论成功(break/return)、失败还是异常,必定计数,
                    //   否则成功路径会永久卡死 latch.await(),done 事件永远发不出
                    latch.countDown();
                }
            });
        }
        latch.await();
        pool.shutdown();
        if (!errors.isEmpty()) throw errors.peek();
        if (done.get() != total) throw new java.io.IOException(
            "完整性校验失败(已下载 " + done.get() + "/" + total + " 字节)");
    }

    /** 统一下载入口:创建目标文件 → 探测 Range → 12 线程/单线程 → 发布并回传保存路径。
     *  跑在 dlPool(并发≤2 队列):第 3 个起排队,防止连接/fd 风暴。 */
    private void internalDownload(String filename, String url) {
        final Context self = getApplicationContext();
        dlPool.execute(() -> {
            // ═══ 断网短路(P1):未联网直接报错,不建文件、不转系统下载器空挂 ═══
            if (!isOnline(self)) {
                dlEvent("error", filename, "网络未连接，请检查网络后重试");
                return;
            }
            Uri mediaUri = null;
            File legacy = null;
            AtomicLong done = new AtomicLong();
            ScheduledExecutorService prog = Executors.newSingleThreadScheduledExecutor();
            boolean ok = false;
            boolean fallback = false;   // 已转交系统下载器
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
                // 3. 进度上报(每 500ms 采样;面板进度条平滑推进,不再发零碎 toast)
                final long[] lastPct = {-1};
                prog.scheduleAtFixedRate(() -> {
                    if (total <= 0) return;
                    int pct = (int) (done.get() * 100 / total);
                    if (pct != lastPct[0]) {
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
                // 兑底:内置下载器失败 → 转交系统下载器在同一目录继续下载
                fallback = trySystemFallback(filename, url);
            } finally {
                prog.shutdownNow();
                // 5. 收尾:成功发布文件(IS_PENDING=0)并回传真实路径;未成功清理残留
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
                    } else {
                        // 内置未成功:清掉半成品残留(系统兑底会重新完整下载)
                        if (mediaUri != null) self.getContentResolver().delete(mediaUri, null, null);
                        if (legacy != null && legacy.exists()) legacy.delete();
                    }
                } catch (Throwable ignore) { }
                if (ok) {
                    Dbg.w(self, "[dl] 完成: " + finalPath);
                    dlEvent("done", filename, finalPath);
                    doneToast(filename, finalPath);   // 系统 Toast 双保险
                } else if (!fallback) {
                    // 系统下载器接管时由完成广播再报 done/error,这里不发 error 避免误报
                    dlEvent("error", filename, errMsg == null ? "未知错误" : errMsg);
                }
            }
        });
    }

    /**
     * 内置下载器失败后的兑底:转交系统 DownloadManager 继续下载,
     * 目标目录一致(Download/网易云下载器/)。返回是否成功接管。
     */
    private boolean trySystemFallback(String filename, String url) {
        try {
            DownloadManager dm = (DownloadManager) getSystemService(DOWNLOAD_SERVICE);
            if (dm == null) return false;
            DownloadManager.Request rq = new DownloadManager.Request(Uri.parse(url));
            rq.setTitle(filename);
            rq.setDescription("网易云下载器");
            rq.setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
            rq.setDestinationInExternalPublicDir(Environment.DIRECTORY_DOWNLOADS, "网易云下载器/" + filename);
            long id = dm.enqueue(rq);
            sysDownloads.put(id, filename);
            Dbg.w(this, "[dl] 内置失败,已转交系统下载器 id=" + id);
            dlEvent("sys", filename, "");
            return true;
        } catch (Throwable t) {
            Dbg.w(this, "‼️ [dl] 系统下载器接管失败", t);
            return false;
        }
    }

    /** 查询系统下载器已完成任务的本地文件路径。 */
    private String resolveSysDownloadPath(long id) {
        Cursor c = null;
        try {
            DownloadManager.Query q = new DownloadManager.Query().setFilterById(id);
            c = ((DownloadManager) getSystemService(DOWNLOAD_SERVICE)).query(q);
            if (c != null && c.moveToFirst()
                    && c.getInt(c.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS))
                       == DownloadManager.STATUS_SUCCESSFUL) {
                String loc = c.getString(c.getColumnIndexOrThrow(DownloadManager.COLUMN_LOCAL_URI));
                if (loc == null) return null;
                Uri u = Uri.parse(loc);
                if ("file".equals(u.getScheme())) return u.getPath();
                String p = queryDataPath(this, u);          // Q+ 是 content:// → 查真实路径
                return p != null ? p : loc;
            }
        } catch (Throwable t) {
            Dbg.w(this, "‼️ [dl][sys] 查询结果失败", t);
        } finally {
            if (c != null) try { c.close(); } catch (Exception ignored) { }
        }
        return null;
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
                dlEvent("start", filename, "");   // 面板同步显示歌词任务
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
                doneToast(filename, finalPath);   // 系统 Toast 双保险
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
