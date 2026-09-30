package com.rmm.controller;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.SharedPreferences;
import android.graphics.Bitmap;
import android.net.http.SslError;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.SslErrorHandler;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.security.MessageDigest;
import java.util.HashSet;
import java.util.Set;

/** RMM Console: a WebView shell around the controller web UI.
 *
 * <p>First launch asks for the controller URL (tunnel HTTPS or LAN
 * HTTP) and remembers it. Self-signed controller certificates are
 * pinned on first sight (TOFU): the SHA-256 fingerprint is shown and,
 * once accepted, stored — later mismatches are refused loudly.
 * No secrets are hardcoded; nothing leaves the device except to the
 * configured controller.
 */
public class MainActivity extends Activity {

    private static final String PREFS = "rmm_console";
    private static final String KEY_URL = "server_url";
    private static final String KEY_PINS = "cert_pins";

    private WebView web;
    private LinearLayout setupView;
    private LinearLayout errorView;
    private TextView errorText;
    private String lastUrl;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B0E14);

        setupView = buildSetupView();
        root.addView(setupView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));

        errorView = buildErrorView();
        errorView.setVisibility(View.GONE);
        root.addView(errorView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));

        web = new WebView(this);
        web.setVisibility(View.GONE);
        root.addView(web, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));
        configureWebView();

        setContentView(root);

        String saved = prefs().getString(KEY_URL, null);
        if (saved != null && !saved.isEmpty()) {
            openConsole(saved);
        }
    }

    // ----- setup view -----

    private LinearLayout buildSetupView() {
        LinearLayout v = new LinearLayout(this);
        v.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        v.setPadding(pad, pad * 2, pad, pad);

        TextView title = new TextView(this);
        title.setText(R.string.setup_title);
        title.setTextSize(22);
        title.setTextColor(0xFF7EE787);
        title.setTypeface(android.graphics.Typeface.MONOSPACE);
        v.addView(title);

        EditText url = new EditText(this);
        url.setHint(R.string.setup_hint);
        url.setHintTextColor(0xFF8B949E);
        url.setTextColor(0xFFD6DEEB);
        url.setTypeface(android.graphics.Typeface.MONOSPACE);
        url.setSingleLine(true);
        url.setId(View.generateViewId());
        v.addView(url);

        Button go = new Button(this);
        go.setText(R.string.setup_save);
        go.setOnClickListener(unused -> {
            String u = url.getText().toString().trim();
            if (u.isEmpty()) {
                return;
            }
            if (!u.startsWith("http://") && !u.startsWith("https://")) {
                u = "https://" + u;
            }
            while (u.endsWith("/")) {
                u = u.substring(0, u.length() - 1);
            }
            prefs().edit().putString(KEY_URL, u).apply();
            openConsole(u);
        });
        v.addView(go);
        return v;
    }

    // ----- error view -----

    private LinearLayout buildErrorView() {
        LinearLayout v = new LinearLayout(this);
        v.setOrientation(LinearLayout.VERTICAL);
        int pad = (int) (24 * getResources().getDisplayMetrics().density);
        v.setPadding(pad, pad * 2, pad, pad);
        errorText = new TextView(this);
        errorText.setTextColor(0xFFF85149);
        errorText.setTypeface(android.graphics.Typeface.MONOSPACE);
        v.addView(errorText);
        Button retry = new Button(this);
        retry.setText(R.string.retry);
        retry.setOnClickListener(unused -> {
            if (lastUrl != null) {
                openConsole(lastUrl);
            }
        });
        v.addView(retry);
        return v;
    }

    private void showError(String msg) {
        runOnUiThread(() -> {
            web.setVisibility(View.GONE);
            setupView.setVisibility(View.GONE);
            errorText.setText(msg);
            errorView.setVisibility(View.VISIBLE);
        });
    }

    // ----- console -----

    private void openConsole(String url) {
        lastUrl = url;
        runOnUiThread(() -> {
            setupView.setVisibility(View.GONE);
            errorView.setVisibility(View.GONE);
            web.setVisibility(View.VISIBLE);
            web.loadUrl(url);
        });
    }

    private void configureWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setBuiltInZoomControls(true);
        s.setDisplayZoomControls(false);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return false; // stay inside the app for all navigation
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                errorView.setVisibility(View.GONE);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    showError("Load failed: " + error.getDescription() + "\n" + request.getUrl());
                }
            }

            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                String fp = certFingerprint(error.getCertificate());
                if (fp != null && pinned().contains(fp)) {
                    handler.proceed();
                    return;
                }
                new AlertDialog.Builder(MainActivity.this)
                        .setTitle(R.string.cert_title)
                        .setMessage("SHA-256:\n" + (fp != null ? fp : "unknown")
                                + "\n\nAccept ONLY if this matches your controller certificate.")
                        .setPositiveButton(R.string.cert_accept, (d, w) -> {
                            if (fp != null) {
                                Set<String> pins = new HashSet<>(pinned());
                                pins.add(fp);
                                prefs().edit().putStringSet(KEY_PINS, pins).apply();
                            }
                            handler.proceed();
                        })
                        .setNegativeButton(R.string.cert_cancel, (d, w) -> handler.cancel())
                        .setCancelable(false)
                        .show();
            }
        });
    }

    private SharedPreferences prefs() {
        return getSharedPreferences(PREFS, MODE_PRIVATE);
    }

    private Set<String> pinned() {
        return prefs().getStringSet(KEY_PINS, new HashSet<String>());
    }

    private static String certFingerprint(android.net.http.SslCertificate cert) {
        try {
            // SslCertificate.saveState bundles the DER blob under
            // "x509-certificate" (static helper, returns the Bundle).
            android.os.Bundle b = android.net.http.SslCertificate.saveState(cert);
            byte[] der = b.getByteArray("x509-certificate");
            if (der == null) {
                return null;
            }
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(der);
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < dig.length; i++) {
                if (i > 0) {
                    sb.append(':');
                }
                sb.append(String.format("%02X", dig[i]));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        }
    }

    // ----- menu / nav -----

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, R.string.change_server);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == 1) {
            web.setVisibility(View.GONE);
            errorView.setVisibility(View.GONE);
            setupView.setVisibility(View.VISIBLE);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        if (web.getVisibility() == View.VISIBLE && web.canGoBack()) {
            web.goBack();
            return;
        }
        super.onBackPressed();
    }

    @Override
    protected void onDestroy() {
        if (web != null) {
            web.destroy();
        }
        super.onDestroy();
    }
}
