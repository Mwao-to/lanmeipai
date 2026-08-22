package com.binsys.wy;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** 轻量诊断日志:追加写入 App 外部私有目录,文件管理器可直接查看。
 *  路径: /sdcard/Android/data/com.binsys.wy/files/debug.log */
public final class Dbg {
    private static final Object LOCK = new Object();
    private static final SimpleDateFormat FMT =
        new SimpleDateFormat("MM-dd HH:mm:ss.SSS", Locale.US);

    public static void w(Context ctx, String msg) {
        Log.i("wy-dbg", msg);
        append(ctx, msg);
    }

    public static void w(Context ctx, String msg, Throwable t) {
        StringWriter sw = new StringWriter();
        t.printStackTrace(new PrintWriter(sw));
        String body = msg + "\n" + sw;
        Log.e("wy-dbg", msg, t);
        append(ctx, body);
    }

    private static void append(Context ctx, String body) {
        synchronized (LOCK) {
            FileWriter fw = null;
            try {
                File dir = ctx.getExternalFilesDir(null);
                if (dir == null) {
                    dir = new File(Environment.getExternalStorageDirectory(),
                        "Android/data/com.binsys.wy/files");
                    dir.mkdirs();
                }
                fw = new FileWriter(new File(dir, "debug.log"), true);
                fw.write(FMT.format(new Date()) + "  " + body + "\n");
                fw.flush();
            } catch (Throwable ignore) {
            } finally {
                if (fw != null) try { fw.close(); } catch (Exception ignored) { }
            }
        }
    }
}
