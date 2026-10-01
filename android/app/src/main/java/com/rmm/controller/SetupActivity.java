package com.rmm.controller;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.util.Arrays;

/** One-time setup: only the UI password (kept by the operator). The
 * controller identity (agent token + server cert/key) ships inside the
 * app (res/raw, staged at build from the controller PC, never in git)
 * and is copied to the private core dir on first run — refreshed when
 * the bundled copy changes (rotation via app update).
 */
public class SetupActivity extends Activity {

    public static final String PREFS = "rmm_setup";
    public static final String KEY_PASSWORD = "ui_password";
    public static final String KEY_MONBTN = "monbtn";

    public static boolean monbtnEnabled(Context c) {
        return c.getSharedPreferences(PREFS, MODE_PRIVATE).getBoolean(KEY_MONBTN, true);
    }

    public static void setMonbtn(Context c, boolean on) {
        c.getSharedPreferences(PREFS, MODE_PRIVATE).edit().putBoolean(KEY_MONBTN, on).apply();
    }

    public static String pref(Context c, String k, String def) {
        return c.getSharedPreferences(PREFS, MODE_PRIVATE).getString(k, def);
    }

    public static boolean hasSecrets(Context c) {
        return !c.getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(KEY_PASSWORD, "").trim().isEmpty();
    }

    /** Copies the bundled identity into the core dir (refreshing on
     * change so rotations ride app updates). */
    public static void ensureIdentity(Context c) throws Exception {
        File dir = new File(c.getFilesDir(), "core");
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new Exception("cannot create " + dir.getAbsolutePath());
        }
        copyRaw(c, R.raw.agent_token, new File(dir, "agent_token.txt"));
        copyRaw(c, R.raw.server_crt, new File(dir, "server.crt"));
        copyRaw(c, R.raw.server_key, new File(dir, "server.key"));
    }

    private static void copyRaw(Context c, int resId, File dst) throws Exception {
        byte[] bundled = readAll(c.getResources().openRawResource(resId));
        if (dst.isFile()) {
            byte[] cur = readAll(new FileInputStream(dst));
            if (Arrays.equals(cur, bundled)) {
                return;
            }
        }
        FileOutputStream out = new FileOutputStream(dst);
        try {
            out.write(bundled);
        } finally {
            out.close();
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int n;
        try {
            while ((n = in.read(chunk)) >= 0) {
                bos.write(chunk, 0, n);
            }
        } finally {
            in.close();
        }
        return bos.toByteArray();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout v = new LinearLayout(this);
        v.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        v.setPadding(pad, pad, pad, pad);
        scroll.addView(v);

        TextView title = new TextView(this);
        title.setText("RMM Console setup");
        title.setTextSize(20);
        title.setTextColor(0xFF7EE787);
        title.setTypeface(android.graphics.Typeface.MONOSPACE);
        v.addView(title);

        TextView help = new TextView(this);
        help.setText("Controller identity ships inside the app.\nEnter your UI password to finish:");
        help.setTextColor(0xFF8B949E);
        help.setTextSize(12);
        v.addView(help);

        TextView label = new TextView(this);
        label.setText("UI password");
        label.setTextColor(0xFFD6DEEB);
        label.setTextSize(12);
        v.addView(label);

        EditText password = new EditText(this);
        password.setHint("UI password");
        password.setHintTextColor(0xFF8B949E);
        password.setTextColor(0xFFD6DEEB);
        password.setTypeface(android.graphics.Typeface.MONOSPACE);
        password.setTextSize(13);
        password.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        password.setText(pref(this, KEY_PASSWORD, ""));
        v.addView(password);

        TextView err = new TextView(this);
        err.setTextColor(0xFFF85149);
        v.addView(err);

        Button save = new Button(this);
        save.setText("Save & start console");
        save.setOnClickListener(unused -> {
            String p = password.getText().toString().trim();
            if (p.isEmpty()) {
                err.setText("A UI password is required.");
                return;
            }
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString(KEY_PASSWORD, p)
                    .apply();
            // Restart the core so the password takes effect immediately.
            stopService(new Intent(this, RmmService.class));
            startForegroundService(new Intent(this, RmmService.class));
            Intent i = new Intent(this, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(i);
            finish();
        });
        v.addView(save);

        TextView diag = new TextView(this);
        String abi = android.os.Build.SUPPORTED_ABIS.length > 0
                ? android.os.Build.SUPPORTED_ABIS[0] : "?";
        String ver = "?";
        try {
            ver = getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
        } catch (Exception e) {
            // leave placeholder
        }
        diag.setText("app " + ver + " | " + abi
                + " | android " + android.os.Build.VERSION.RELEASE);
        diag.setTextColor(0xFF8B949E);
        diag.setTextSize(11);
        v.addView(diag);

        setContentView(scroll);
    }
}
