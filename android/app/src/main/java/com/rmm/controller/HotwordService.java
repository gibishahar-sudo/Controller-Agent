package com.rmm.controller;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.media.AudioFormat;
import android.media.AudioRecord;
import android.media.MediaRecorder;
import android.os.IBinder;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Locale;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import ai.picovoice.porcupine.Porcupine;
import ai.picovoice.porcupine.PorcupineException;
import ai.picovoice.porcupine.PorcupineManager;

/** Always-on "Jarvis" hotword listener (tablet only — desktop browsers
 * cannot background-listen). On-device ONLY: Porcupine (primary, needs a
 * free access key) or Vosk keyword spotting (fallback, needs a ~50MB model
 * pulled once). Nothing audio ever leaves the tablet. On wake, Home opens
 * with autolisten (the P1 recognizer flow takes it from there; the operator
 * still taps Send — a misheard destructive command must not run itself).
 * Android shows a mic indicator while listening — OS design, not ours.
 */
public class HotwordService extends Service {

    public static final String CHANNEL = "rmm_hotword";
    private static final int NOTIF_ID = 42;
    public static final String EXTRA_AUTOLISTEN = "rmm_autolisten";

    private static final String PREF_STATUS = "hotword_status";
    private static final String VOSK_MODEL_URL =
            "https://alphacephei.com/vosk/models/vosk-model-small-en-us-0.15.zip";
    private static final long WAKE_DEBOUNCE_MS = 4000;

    private volatile boolean running = false;
    private Thread loopThread;
    private volatile AudioRecord liveRecorder;
    private PorcupineManager porcupineManager;
    private volatile long lastWake = 0;

    public static void setStatus(Context c, String s) {
        c.getSharedPreferences(SetupActivity.PREFS, MODE_PRIVATE)
                .edit().putString(PREF_STATUS, s).apply();
    }

    public static String status(Context c) {
        return c.getSharedPreferences(SetupActivity.PREFS, MODE_PRIVATE)
                .getString(PREF_STATUS, "off");
    }

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(
                CHANNEL, "Jarvis hotword", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Listens for 'Jarvis' on this device only");
        nm.createNotificationChannel(ch);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (checkSelfPermission(android.Manifest.permission.RECORD_AUDIO)
                != PackageManager.PERMISSION_GRANTED) {
            fail("mic permission missing — re-enable listening in Setup");
            return START_NOT_STICKY;
        }
        Notification notif = new Notification.Builder(this, CHANNEL)
                .setContentTitle("🎤 Listening for Jarvis")
                .setContentText("On-device only — say the word")
                .setSmallIcon(R.drawable.ic_fg)
                .setOngoing(true)
                .build();
        startForeground(NOTIF_ID, notif);
        if (loopThread != null && loopThread.isAlive()) {
            return START_STICKY;
        }
        running = true;
        setStatus(this, "starting…");
        loopThread = new Thread(this::loop, "rmm-hotword");
        loopThread.start();
        return START_STICKY;
    }

    private void loop() {
        String key = SetupActivity.pref(this, SetupActivity.KEY_PORCUPINE, "").trim();
        if (!key.isEmpty()) {
            if (runPorcupine(key)) {
                return; // ran until stopped
            }
            // Key present but unusable: fall through to Vosk rather than
            // going silent (status already names the Porcupine failure).
        }
        runVosk();
    }

    // Returns true if Porcupine ran (until stop); false to fall back.
    private boolean runPorcupine(String key) {
        try {
            porcupineManager = new PorcupineManager.Builder()
                    .setAccessKey(key)
                    .setKeyword(Porcupine.BuiltInKeyword.JARVIS)
                    .setSensitivity(0.6f)
                    .build(getApplicationContext(), keywordIndex -> onWake("porcupine"));
            porcupineManager.start();
        } catch (PorcupineException e) {
            setStatus(this, "porcupine: " + shortErr(e) + " — Vosk fallback");
            cleanupPorcupine();
            return false;
        } catch (Exception e) {
            setStatus(this, "porcupine init failed — Vosk fallback");
            cleanupPorcupine();
            return false;
        }
        setStatus(this, "listening (porcupine)");
        while (running) {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                break;
            }
        }
        cleanupPorcupine();
        return true;
    }

    private void cleanupPorcupine() {
        try {
            if (porcupineManager != null) {
                porcupineManager.stop();
                porcupineManager.delete();
            }
        } catch (Exception e) {
            // shutting down anyway
        }
        porcupineManager = null;
    }

    private static String shortErr(Exception e) {
        String n = e.getClass().getSimpleName().replace("Porcupine", "").replace("Exception", "");
        String m = e.getMessage();
        return (n.isEmpty() ? "error" : n.toLowerCase(Locale.US)) + (m == null ? "" : ": " + m);
    }

    private void runVosk() {
        File modelDir = new File(getFilesDir(), "vosk-model");
        if (!new File(modelDir, ".ready").isFile()) {
            if (!pullVoskModel(modelDir)) {
                return; // status set inside; service stops
            }
        }
        org.vosk.Model model = null;
        org.vosk.Recognizer rec = null;
        AudioRecord ar = null;
        try {
            setStatus(this, "listening (vosk) — hungrier than porcupine");
            model = new org.vosk.Model(modelDir.getAbsolutePath());
            rec = new org.vosk.Recognizer(model, 16000.0f, "[\"jarvis\", \"[unk]\"]");
            int minBuf = AudioRecord.getMinBufferSize(16000,
                    AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT);
            ar = new AudioRecord(MediaRecorder.AudioSource.MIC, 16000,
                    AudioFormat.CHANNEL_IN_MONO, AudioFormat.ENCODING_PCM_16BIT,
                    Math.max(minBuf * 4, 8192));
            if (ar.getState() != AudioRecord.STATE_INITIALIZED) {
                fail("mic busy or unavailable");
                return;
            }
            liveRecorder = ar;
            ar.startRecording();
            byte[] buf = new byte[4096];
            while (running) {
                int n = ar.read(buf, 0, buf.length);
                if (n > 0) {
                    rec.acceptWaveForm(buf, n);
                    String partial = rec.getPartialResult();
                    if (partial != null && partial.toLowerCase(Locale.US).contains("jarvis")) {
                        onWake("vosk");
                        rec.reset();
                        cooldown(1500);
                    }
                }
            }
        } catch (Exception e) {
            fail("vosk: " + e.getMessage());
        } finally {
            liveRecorder = null;
            try {
                if (ar != null) {
                    ar.stop();
                    ar.release();
                }
            } catch (Exception e) {
                // shutting down anyway
            }
            try {
                if (rec != null) {
                    rec.close();
                }
            } catch (Exception e) {
                // shutting down anyway
            }
            try {
                if (model != null) {
                    model.close();
                }
            } catch (Exception e) {
                // shutting down anyway
            }
        }
    }

    private void cooldown(long ms) {
        long end = System.currentTimeMillis() + ms;
        while (running && System.currentTimeMillis() < end) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException e) {
                return;
            }
        }
    }

    // One-time ~50MB voice model pull (same pattern as llm-pull: background,
    // announced, cancellable by stopping the service).
    private boolean pullVoskModel(File modelDir) {
        File zip = new File(getFilesDir(), "vosk-model.zip.tmp");
        HttpURLConnection c = null;
        try {
            setStatus(this, "pulling voice model (~50MB, one-time)…");
            URL url = new URL(VOSK_MODEL_URL);
            c = (HttpURLConnection) url.openConnection();
            c.setConnectTimeout(15000);
            c.setReadTimeout(30000);
            c.connect();
            int total = c.getContentLength();
            InputStream in = new BufferedInputStream(c.getInputStream());
            OutputStream out = new BufferedOutputStream(new FileOutputStream(zip));
            byte[] chunk = new byte[65536];
            long got = 0;
            int lastPct = -1;
            int n;
            try {
                while (running && (n = in.read(chunk)) >= 0) {
                    out.write(chunk, 0, n);
                    got += n;
                    if (total > 0) {
                        int pct = (int) (100 * got / total);
                        if (pct != lastPct && pct % 10 == 0) {
                            lastPct = pct;
                            setStatus(this, "pulling voice model " + pct + "%…");
                        }
                    }
                }
            } finally {
                out.close();
                in.close();
            }
            if (!running) {
                return false;
            }
            setStatus(this, "unpacking voice model…");
            unzip(zip, modelDir);
            // The zip wraps one top-level dir; hoist it.
            File[] kids = modelDir.listFiles();
            if (kids != null && kids.length == 1 && kids[0].isDirectory()) {
                File inner = kids[0];
                File tmp = new File(getFilesDir(), "vosk-model.tmp");
                if (inner.renameTo(tmp)) {
                    deleteRec(modelDir);
                    if (!tmp.renameTo(modelDir)) {
                        return failRet("model unpack failed");
                    }
                }
            }
            new FileOutputStream(new File(modelDir, ".ready")).close();
            return true;
        } catch (Exception e) {
            return failRet("model pull failed: " + e.getMessage());
        } finally {
            if (c != null) {
                c.disconnect();
            }
            zip.delete();
        }
    }

    private boolean failRet(String s) {
        fail(s);
        return false;
    }

    private void unzip(File zip, File dst) throws Exception {
        ZipInputStream zin = new ZipInputStream(new BufferedInputStream(
                new java.io.FileInputStream(zip)));
        try {
            ZipEntry e;
            byte[] chunk = new byte[65536];
            while (running && (e = zin.getNextEntry()) != null) {
                File f = new File(dst, e.getName());
                // Zip-slip guard.
                if (!f.getCanonicalPath().startsWith(dst.getCanonicalPath() + File.separator)) {
                    throw new Exception("bad zip entry: " + e.getName());
                }
                if (e.isDirectory()) {
                    f.mkdirs();
                } else {
                    f.getParentFile().mkdirs();
                    OutputStream out = new BufferedOutputStream(new FileOutputStream(f));
                    try {
                        int n;
                        while ((n = zin.read(chunk)) >= 0) {
                            out.write(chunk, 0, n);
                        }
                    } finally {
                        out.close();
                    }
                }
                zin.closeEntry();
            }
        } finally {
            zin.close();
        }
    }

    private static void deleteRec(File f) {
        if (f.isDirectory()) {
            File[] kids = f.listFiles();
            if (kids != null) {
                for (File k : kids) {
                    deleteRec(k);
                }
            }
        }
        f.delete();
    }

    private void onWake(String engine) {
        long now = System.currentTimeMillis();
        if (now - lastWake < WAKE_DEBOUNCE_MS) {
            return;
        }
        lastWake = now;
        setStatus(this, "heard Jarvis (" + engine + ")");
        try {
            Intent i = new Intent(this, HomeActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            i.putExtra(HomeActivity.EXTRA_AUTOLISTEN, true);
            startActivity(i);
        } catch (Exception e) {
            setStatus(this, "wake failed: " + e.getMessage());
        }
    }

    private void fail(String err) {
        setStatus(this, err);
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification failed = new Notification.Builder(this, CHANNEL)
                .setContentTitle("Jarvis hotword stopped")
                .setContentText(err)
                .setSmallIcon(R.drawable.ic_fg)
                .setOngoing(false)
                .build();
        nm.notify(NOTIF_ID + 1, failed);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        running = false;
        try {
            if (liveRecorder != null) {
                liveRecorder.stop();
            }
        } catch (Exception e) {
            // shutting down anyway
        }
        cleanupPorcupine();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
