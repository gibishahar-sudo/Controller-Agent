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

/** One-time setup: the three secrets that make this device exactly as
 * trusted as the desktop controller (agent token + server cert/key,
 * all shown on / copyable from the desktop install), plus the UI
 * password (keep the existing one). Stored app-private, never leave
 * the device except to your own agents/buses.
 */
public class SetupActivity extends Activity {

    public static final String PREFS = "rmm_setup";
    public static final String KEY_TOKEN = "agent_token";
    public static final String KEY_PASSWORD = "ui_password";
    public static final String KEY_CERT = "server_cert";
    public static final String KEY_KEY = "server_key";

    public static String pref(Context c, String k, String def) {
        return c.getSharedPreferences(PREFS, MODE_PRIVATE).getString(k, def);
    }

    public static boolean hasSecrets(Context c) {
        SharedPreferences p = c.getSharedPreferences(PREFS, MODE_PRIVATE);
        return !p.getString(KEY_TOKEN, "").trim().isEmpty()
                && !p.getString(KEY_PASSWORD, "").trim().isEmpty()
                && !p.getString(KEY_CERT, "").trim().isEmpty()
                && !p.getString(KEY_KEY, "").trim().isEmpty();
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
        help.setText("Paste once from your controller PC:\n"
                + "• agent_token.txt content\n"
                + "• UI password (keep the current one)\n"
                + "• server.crt + server.key (full PEM text)");
        help.setTextColor(0xFF8B949E);
        help.setTextSize(12);
        v.addView(help);

        EditText token = field(v, "Agent token", false);
        EditText password = field(v, "UI password", true);
        EditText cert = field(v, "server.crt (PEM)", false);
        EditText key = field(v, "server.key (PEM)", false);
        cert.setMinLines(4);
        key.setMinLines(4);

        token.setText(pref(this, KEY_TOKEN, ""));
        password.setText(pref(this, KEY_PASSWORD, ""));
        cert.setText(pref(this, KEY_CERT, ""));
        key.setText(pref(this, KEY_KEY, ""));

        TextView err = new TextView(this);
        err.setTextColor(0xFFF85149);
        v.addView(err);

        Button save = new Button(this);
        save.setText("Save & start console");
        save.setOnClickListener(unused -> {
            String t = token.getText().toString().trim();
            String p = password.getText().toString().trim();
            String c = cert.getText().toString().trim();
            String k = key.getText().toString().trim();
            if (t.isEmpty() || p.isEmpty() || c.isEmpty() || k.isEmpty()) {
                err.setText("All four fields are required.");
                return;
            }
            if (!c.contains("BEGIN CERTIFICATE") || !k.contains("PRIVATE KEY")) {
                err.setText("Cert/key don't look like PEM (need BEGIN ... blocks).");
                return;
            }
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString(KEY_TOKEN, t)
                    .putString(KEY_PASSWORD, p)
                    .putString(KEY_CERT, c)
                    .putString(KEY_KEY, k)
                    .apply();
            // Restart the core so new secrets take effect immediately.
            stopService(new Intent(this, RmmService.class));
            startForegroundService(new Intent(this, RmmService.class));
            Intent i = new Intent(this, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            startActivity(i);
            finish();
        });
        v.addView(save);

        setContentView(scroll);
    }

    private EditText field(LinearLayout v, String hint, boolean pw) {
        TextView label = new TextView(this);
        label.setText(hint);
        label.setTextColor(0xFFD6DEEB);
        label.setTextSize(12);
        v.addView(label);
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(0xFF8B949E);
        e.setTextColor(0xFFD6DEEB);
        e.setTypeface(android.graphics.Typeface.MONOSPACE);
        e.setTextSize(13);
        if (pw) {
            e.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                    | android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD);
        } else {
            e.setInputType(android.text.InputType.TYPE_CLASS_TEXT
                    | android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        }
        v.addView(e);
        return e;
    }
}
