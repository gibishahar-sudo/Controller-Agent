package com.rmm.controller;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Home screen: fleet status at a glance, service switch, one-tap
 * console, and a command sender with an offline queue. Replies live
 * in the console (commands stream back over its socket) — sends here
 * are fire-and-forget, and the UI says so.
 */
public class HomeActivity extends Activity {

    private static final String QUEUE_KEY = "rmm_queue"; // ts \u0001 target \u0001 cmd
    private static final String SEP = String.valueOf((char) 1);
    private static final int VOICE_REQ = 0x5A1;

    private TextView statusText;
    private ListView agentList;
    private ArrayAdapter<String> agentAdapter;
    private final List<String> agentIds = new ArrayList<>();
    private final List<String> agentNames = new ArrayList<>();
    private Spinner agentSpinner;
    private ArrayAdapter<String> spinnerAdapter;
    private EditText cmdInput;
    private TextView queueText;
    private Button serviceBtn;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!SetupActivity.hasSecrets(this)) {
            startActivity(new Intent(this, SetupActivity.class));
            finish();
            return;
        }
        boolean restored = savedInstanceState != null
                && savedInstanceState.getBoolean("rmm_unlocked", false);
        if (AppLock.requiresPrompt(this, restored, this::initHome)) {
            return;
        }
        initHome();
    }

    @Override
    protected void onSaveInstanceState(Bundle out) {
        super.onSaveInstanceState(out);
        out.putBoolean("rmm_unlocked", true);
    }

    @Override
    protected void onStop() {
        super.onStop();
        AppLock.onBackgrounded();
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (statusText != null) {
            refreshStatus();
            flushQueue(false);
        }
    }

    private LinearLayout row() {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        return r;
    }

    private void initHome() {
        ScrollView scroll = new ScrollView(this);
        LinearLayout v = new LinearLayout(this);
        v.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (20 * getResources().getDisplayMetrics().density);
        v.setPadding(pad, pad, pad, pad);
        scroll.addView(v);

        TextView title = new TextView(this);
        title.setText("RMM Console");
        title.setTextSize(20);
        title.setTextColor(0xFF7EE787);
        title.setTypeface(android.graphics.Typeface.MONOSPACE);
        v.addView(title);

        statusText = new TextView(this);
        statusText.setTextColor(0xFFD6DEEB);
        statusText.setTypeface(android.graphics.Typeface.MONOSPACE);
        statusText.setText("…");
        v.addView(statusText);

        LinearLayout btns = row();
        Button open = new Button(this);
        open.setText("Open console");
        open.setOnClickListener(unused -> startActivity(new Intent(this, MainActivity.class)));
        btns.addView(open);
        serviceBtn = new Button(this);
        serviceBtn.setText("Restart core");
        serviceBtn.setOnClickListener(unused -> {
            stopService(new Intent(this, RmmService.class));
            startForegroundService(new Intent(this, RmmService.class));
            toast("Core restarting…");
            serviceBtn.postDelayed(this::refreshStatus, 4000);
        });
        btns.addView(serviceBtn);
        v.addView(btns);

        TextView agentsLabel = new TextView(this);
        agentsLabel.setText("Agents");
        agentsLabel.setTextColor(0xFF8B949E);
        v.addView(agentsLabel);

        agentList = new ListView(this);
        agentAdapter = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1,
                new ArrayList<String>());
        agentList.setAdapter(agentAdapter);
        // Fixed height: list lives inside a scroll view (never nest-scroll).
        agentList.setLayoutParams(new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, (int) (220 * getResources().getDisplayMetrics().density)));
        agentList.setOnItemClickListener((parent, view, pos, id) -> {
            if (pos < agentSpinner.getCount()) {
                agentSpinner.setSelection(pos);
            }
        });
        v.addView(agentList);

        TextView sendLabel = new TextView(this);
        sendLabel.setText("Send command (replies in console)");
        sendLabel.setTextColor(0xFF8B949E);
        v.addView(sendLabel);

        agentSpinner = new Spinner(this);
        spinnerAdapter = new ArrayAdapter<>(this, android.R.layout.simple_spinner_item,
                new ArrayList<String>());
        spinnerAdapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        agentSpinner.setAdapter(spinnerAdapter);
        v.addView(agentSpinner);

        cmdInput = new EditText(this);
        cmdInput.setHint("version, get-agent-log 50, play-troll …");
        cmdInput.setHintTextColor(0xFF8B949E);
        cmdInput.setTextColor(0xFFD6DEEB);
        cmdInput.setTypeface(android.graphics.Typeface.MONOSPACE);
        v.addView(cmdInput);

        Button mic = new Button(this);
        mic.setText("🎤 Voice (fills command — you tap Send)");
        mic.setOnClickListener(unused -> startVoiceInput());
        v.addView(mic);

        Button send = new Button(this);
        send.setText("Send");
        send.setOnClickListener(unused -> sendCommand());
        v.addView(send);

        queueText = new TextView(this);
        queueText.setTextColor(0xFF8B949E);
        v.addView(queueText);

        setContentView(scroll);
        refreshStatus();
        flushQueue(false);
        // Last-resort evidence: if the previous run died, show the
        // recorded stack for copy-paste diagnosis.
        String crash = CrashLog.consume(this);
        if (crash != null && !crash.isEmpty()) {
            showCrash(crash);
        }
    }

    private void showCrash(String crash) {
        android.widget.ScrollView scroll = new android.widget.ScrollView(this);
        TextView body = new TextView(this);
        body.setText(crash);
        body.setTypeface(android.graphics.Typeface.MONOSPACE);
        body.setTextSize(11);
        body.setTextIsSelectable(true);
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        body.setPadding(pad, pad, pad, pad);
        scroll.addView(body);
        new android.app.AlertDialog.Builder(this)
                .setTitle("Previous run crashed — copy this to Jarvis")
                .setView(scroll)
                .setPositiveButton("Copy", (d, w) -> {
                    android.content.ClipboardManager cm =
                            (android.content.ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                    cm.setPrimaryClip(android.content.ClipData.newPlainText("rmm-crash", crash));
                    toast("Copied — paste it to Jarvis");
                })
                .setNegativeButton("Dismiss", null)
                .show();
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }

    private String password() {
        return SetupActivity.pref(this, SetupActivity.KEY_PASSWORD, "");
    }

    // ----- status -----

    private void refreshStatus() {
        new Thread(() -> {
            String running = "down";
            List<String> names = new ArrayList<>();
            List<String> ids = new ArrayList<>();
            try {
                org.json.JSONObject st = new org.json.JSONObject(mobile.Mobile.status());
                if (st.optBoolean("running", false)) {
                    running = "up";
                }
                org.json.JSONArray arr = st.optJSONArray("agents");
                if (arr != null) {
                    for (int i = 0; i < arr.length(); i++) {
                        org.json.JSONObject a = arr.optJSONObject(i);
                        if (a == null) {
                            continue;
                        }
                        String hn = a.optString("hostname", "?");
                        String ver = a.optString("version", "?");
                        String id = a.optString("id", "");
                        names.add(hn + "  " + ver);
                        ids.add(id.isEmpty() ? hn : id);
                    }
                }
            } catch (Throwable e) {
                running = "error: " + e.getMessage();
            }
            final String fRunning = running;
            final List<String> fNames = names;
            final List<String> fIds = ids;
            runOnUiThread(() -> {
                statusText.setText("core: " + fRunning + "   •   " + fNames.size() + " agents");
                agentAdapter.clear();
                agentAdapter.addAll(fNames);
                agentIds.clear();
                agentIds.addAll(fIds);
                agentNames.clear();
                agentNames.addAll(fNames);
                spinnerAdapter.clear();
                spinnerAdapter.addAll(fNames);
                updateQueueText();
            });
        }, "rmm-status").start();
    }

    // ----- queue -----

    private Set<String> queue() {
        SharedPreferences p = getSharedPreferences(SetupActivity.PREFS, MODE_PRIVATE);
        return new TreeSet<>(p.getStringSet("rmm_queue", new HashSet<String>()));
    }

    private void saveQueue(Set<String> q) {
        getSharedPreferences(SetupActivity.PREFS, MODE_PRIVATE)
                .edit().putStringSet("rmm_queue", q).apply();
        updateQueueText();
    }

    private void updateQueueText() {
        if (queueText == null) {
            return;
        }
        int n = queue().size();
        queueText.setText(n == 0 ? "queue: empty" : "queue: " + n + " (sends when core is up)");
    }

    /** Jarvis mic: system recognizer intent (no RECORD_AUDIO needed — the
     * system activity records on our behalf). Heard text fills the command
     * box prefixed as voice-cmd; the operator still taps Send (a misheard
     * destructive command must not run itself). */
    private void startVoiceInput() {
        try {
            Intent i = new Intent(android.speech.RecognizerIntent.ACTION_RECOGNIZE_SPEECH);
            i.putExtra(android.speech.RecognizerIntent.EXTRA_LANGUAGE_MODEL,
                    android.speech.RecognizerIntent.LANGUAGE_MODEL_FREE_FORM);
            i.putExtra(android.speech.RecognizerIntent.EXTRA_LANGUAGE, "en-US");
            i.putExtra(android.speech.RecognizerIntent.EXTRA_PROMPT, "Say it, Jarvis is listening…");
            startActivityForResult(i, VOICE_REQ);
        } catch (Exception e) {
            toast("Voice input unavailable (" + e.getMessage() + ")");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != VOICE_REQ || resultCode != RESULT_OK || data == null) {
            return;
        }
        ArrayList<String> heard = data.getStringArrayListExtra(
                android.speech.RecognizerIntent.EXTRA_RESULTS);
        if (heard == null || heard.isEmpty() || heard.get(0) == null) {
            return;
        }
        String text = heard.get(0).trim();
        if (text.isEmpty()) {
            return;
        }
        cmdInput.setText("voice-cmd " + text);
        toast("Heard: " + text);
    }

    private void sendCommand() {        final String cmd = cmdInput.getText().toString().trim();
        if (cmd.isEmpty()) {
            return;
        }
        int pos = agentSpinner.getSelectedItemPosition();
        final String target = (pos >= 0 && pos < agentIds.size()) ? agentIds.get(pos) : "";
        new Thread(() -> {
            try {
                ApiClient.send(cmd, target, password());
                runOnUiThread(() -> {
                    toast("Sent — replies in console");
                    cmdInput.setText("");
                });
                flushQueue(false);
            } catch (Exception e) {
                Set<String> q = queue();
                q.add(System.currentTimeMillis() + SEP + target + SEP + cmd);
                saveQueue(q);
                runOnUiThread(() -> toast("Core unreachable — queued (" + e.getMessage() + ")"));
            }
        }, "rmm-send").start();
    }

    private void flushQueue(boolean verbose) {
        new Thread(() -> {
            Set<String> q = queue();
            if (q.isEmpty()) {
                return;
            }
            List<String> done = new ArrayList<>();
            for (String item : q) {
                String[] parts = item.split(SEP, 3);
                if (parts.length != 3) {
                    done.add(item);
                    continue;
                }
                try {
                    ApiClient.send(parts[2], parts[1], password());
                    done.add(item);
                } catch (Exception e) {
                    break; // still down; keep the rest queued
                }
            }
            if (!done.isEmpty()) {
                Set<String> rest = queue();
                rest.removeAll(done);
                saveQueue(rest);
                runOnUiThread(() -> {
                    toast("Flushed " + done.size() + " queued");
                    updateQueueText();
                });
            }
        }, "rmm-flush").start();
    }
}
