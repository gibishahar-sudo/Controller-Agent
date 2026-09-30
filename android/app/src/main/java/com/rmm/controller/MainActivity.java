package com.rmm.controller;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

/** Console window: the controller core runs in RmmService (same MQTT
 * buses, same login gate as desktop) and serves here on localhost.
 * First run diverts to SetupActivity until the three secrets exist.
 */
public class MainActivity extends Activity {

    private static final String CONSOLE_URL = "http://127.0.0.1:8080/";

    private WebView web;
    private LinearLayout errorView;
    private TextView errorText;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!SetupActivity.hasSecrets(this)) {
            startActivity(new Intent(this, SetupActivity.class));
            finish();
            return;
        }

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B0E14);

        errorView = buildErrorView();
        errorView.setVisibility(View.GONE);
        root.addView(errorView, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));

        web = new WebView(this);
        root.addView(web, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.MATCH_PARENT));
        configureWebView();

        setContentView(root);

        // Workstation mode: immersive fullscreen (status + nav bars hide,
        // swipe reveals transiently) and no sleep while the console is up.
        // Re-asserted on focus return; SetupActivity stays normal chrome.
        enterImmersive();
        getWindow().addFlags(android.view.WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);

        try {
            startForegroundService(new Intent(this, RmmService.class));
        } catch (Exception e) {
            showError("Service failed to start: " + e.getMessage());
            return;
        }
        web.loadUrl(CONSOLE_URL);
    }

    private void enterImmersive() {
        View decor = getWindow().getDecorView();
        int flags = View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY
                | View.SYSTEM_UI_FLAG_FULLSCREEN
                | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION
                | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION
                | View.SYSTEM_UI_FLAG_LAYOUT_STABLE;
        decor.setSystemUiVisibility(flags);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (hasFocus) {
            enterImmersive();
        }
    }

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
            errorView.setVisibility(View.GONE);
            web.setVisibility(View.VISIBLE);
            web.loadUrl(CONSOLE_URL);
        });
        v.addView(retry);
        return v;
    }

    private void showError(String msg) {
        runOnUiThread(() -> {
            web.setVisibility(View.GONE);
            errorText.setText(msg);
            errorView.setVisibility(View.VISIBLE);
        });
    }

    private void configureWebView() {
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setBuiltInZoomControls(true);
        s.setDisplayZoomControls(false);
        // Fit the desktop console to the tablet viewport (page zoom,
        // no buttons — the console has its own pinch on the screen).
        s.setUseWideViewPort(true);
        s.setLoadWithOverviewMode(true);
        s.setAllowFileAccess(false);
        s.setAllowContentAccess(false);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                return false; // stay inside the app for all navigation
            }

            @Override
            public void onPageFinished(WebView view, String url) {
                super.onPageFinished(view, url);
                injectTabletFit(view);
            }

            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                errorView.setVisibility(View.GONE);
            }

            @Override
            public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) {
                    showError("Console not up yet (core still starting?) — retry in a few seconds.\n"
                            + error.getDescription());
                }
            }
        });
    }

    /** Injects the tablet-fit stylesheet (res/raw/tablet.css) once per
     * document: desktop index.html is never modified, the override lives
     * in the APK. Base64 transport avoids every quoting trap. */
    private void injectTabletFit(WebView view) {
        String css = readRaw(R.raw.tablet);
        if (css == null || css.isEmpty()) {
            return;
        }
        String b64 = android.util.Base64.encodeToString(
                css.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                android.util.Base64.NO_WRAP);
        String js = "(function(){"
                + "if(document.getElementById('rmm-tablet-fit'))return;"
                + "document.body.classList.add('rmm-tablet');"
                // Compact declutter is a stock desktop feature (hides
                // secondary buttons behind the ⋯ toggle); the tablet
                // opts in on load without touching localStorage, so the
                // desktop never sees it.
                + "document.body.classList.add('compact');"
                + "var s=document.createElement('style');"
                + "s.id='rmm-tablet-fit';"
                + "s.textContent=new TextDecoder().decode(Uint8Array.from(atob('"
                + b64
                + "'),function(c){return c.charCodeAt(0)}));"
                + "document.head.appendChild(s);"
                + "})()";
        view.evaluateJavascript(js, null);
    }

    private String readRaw(int resId) {
        try {
            java.io.InputStream in = getResources().openRawResource(resId);
            java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                bos.write(chunk, 0, n);
            }
            in.close();
            return bos.toString("UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, "Setup (token / password / certs)");
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == 1) {
            startActivity(new Intent(this, SetupActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    public void onBackPressed() {
        if (web != null && web.getVisibility() == View.VISIBLE && web.canGoBack()) {
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
