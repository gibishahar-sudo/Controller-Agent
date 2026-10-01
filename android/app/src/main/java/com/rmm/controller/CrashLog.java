package com.rmm.controller;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/** Last-resort crash catcher: the default handler kills the process
 * with zero on-device evidence ("it crashes, no log, no nothing").
 * This one pickles the stack + device facts to the private files dir
 * first, so the next launch can SHOW it for copy-paste diagnosis.
 */
public final class CrashLog {

    private static final String NAME = "crash.log";

    private CrashLog() {
    }

    public static void install(Context c) {
        final Thread.UncaughtExceptionHandler prev =
                Thread.getDefaultUncaughtExceptionHandler();
        final File target = new File(c.getFilesDir(), NAME);
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> {
            try {
                StringWriter sw = new StringWriter();
                PrintWriter pw = new PrintWriter(sw);
                pw.println("time=" + new SimpleDateFormat(
                        "yyyy-MM-dd HH:mm:ss", Locale.US).format(new Date()));
                pw.println("device=" + android.os.Build.MANUFACTURER
                        + " " + android.os.Build.MODEL);
                pw.println("android=" + android.os.Build.VERSION.RELEASE
                        + " sdk=" + android.os.Build.VERSION.SDK_INT);
                pw.println("abis=" + String.join(",",
                        android.os.Build.SUPPORTED_ABIS));
                pw.println("thread=" + t.getName());
                e.printStackTrace(pw);
                pw.flush();
                FileOutputStream out = new FileOutputStream(target, false);
                try {
                    out.write(sw.toString().getBytes("UTF-8"));
                } finally {
                    out.close();
                }
            } catch (Exception ignored) {
                // never interfere with the shutdown itself
            }
            if (prev != null) {
                prev.uncaughtException(t, e);
            } else {
                android.os.Process.killProcess(android.os.Process.myPid());
                System.exit(10);
            }
        });
    }

    /** Returns the recorded crash and clears it, or null when clean. */
    public static String consume(Context c) {
        File target = new File(c.getFilesDir(), NAME);
        if (!target.isFile()) {
            return null;
        }
        try {
            byte[] buf = new byte[(int) Math.min(target.length(), 65536)];
            java.io.FileInputStream in = new java.io.FileInputStream(target);
            try {
                int n = 0, r;
                while (n < buf.length
                        && (r = in.read(buf, n, buf.length - n)) >= 0) {
                    n += r;
                }
                return new String(buf, 0, n, "UTF-8");
            } finally {
                in.close();
            }
        } catch (Exception e) {
            return null;
        } finally {
            target.delete();
        }
    }
}
