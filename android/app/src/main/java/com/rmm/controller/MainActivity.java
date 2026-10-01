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
    private LinearLayout rootView;
    private View customView;
    private android.webkit.WebChromeClient.CustomViewCallback customCallback;
    private android.webkit.WebChromeClient chrome;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        if (!SetupActivity.hasSecrets(this)) {
            startActivity(new Intent(this, SetupActivity.class));
            finish();
            return;
        }
        // App lock (no secrets to protect before first setup, so the
        // gate sits here, not above). Rotation restore carries a
        // one-time pass; process death re-locks.
        boolean restored = savedInstanceState != null
                && savedInstanceState.getBoolean("rmm_unlocked", false);
        if (AppLock.requiresPrompt(this, restored, this::startConsole)) {
            return;
        }
        startConsole();
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

    private void startConsole() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(0xFF0B0E14);
        rootView = root;

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

    private void configureWebView() {        WebSettings s = web.getSettings();
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
        // File downloads (Files tab "download to browser", snapshots):
        // without this listener WebView drops them silently on Android.
        // The session cookie is forwarded so authed endpoints serve.
        web.setDownloadListener((url, userAgent, contentDisposition, mimeType, contentLength) -> {
            try {
                android.app.DownloadManager dm =
                        (android.app.DownloadManager) getSystemService(DOWNLOAD_SERVICE);
                android.app.DownloadManager.Request req =
                        new android.app.DownloadManager.Request(android.net.Uri.parse(url));
                String cookie = android.webkit.CookieManager.getInstance().getCookie(url);
                if (cookie != null) {
                    req.addRequestHeader("Cookie", cookie);
                }
                req.addRequestHeader("User-Agent", userAgent);
                String name = android.webkit.URLUtil.guessFileName(url, contentDisposition, mimeType);
                req.setDestinationInExternalPublicDir(
                        android.os.Environment.DIRECTORY_DOWNLOADS, "RMM-" + name);
                req.setNotificationVisibility(
                        android.app.DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);
                dm.enqueue(req);
                android.widget.Toast.makeText(this, "Downloading " + name,
                        android.widget.Toast.LENGTH_SHORT).show();
            } catch (Exception e) {
                android.widget.Toast.makeText(this, "Download failed: " + e.getMessage(),
                        android.widget.Toast.LENGTH_LONG).show();
            }
        });
        // Fullscreen support (the console's ⛶ button): without a chrome
        // client the request is denied ("Fullscreen blocked" toast).
        // The custom view fills our root; BACK exits (below).
        chrome = new android.webkit.WebChromeClient() {
            @Override
            public void onShowCustomView(View view,
                    android.webkit.WebChromeClient.CustomViewCallback callback) {
                if (customView != null) {
                    callback.onCustomViewHidden();
                    return;
                }
                customView = view;
                customCallback = callback;
                rootView.addView(view, new LinearLayout.LayoutParams(
                        LinearLayout.LayoutParams.MATCH_PARENT,
                        LinearLayout.LayoutParams.MATCH_PARENT));
                web.setVisibility(View.GONE);
                web.evaluateJavascript(
                        "document.body.classList.add('rmm-full')", null);
                enterImmersive();
            }

            @Override
            public void onHideCustomView() {
                if (customView == null) {
                    return;
                }
                rootView.removeView(customView);
                customView = null;
                web.setVisibility(View.VISIBLE);
                web.evaluateJavascript(
                        "document.body.classList.remove('rmm-full')", null);
                if (customCallback != null) {
                    customCallback.onCustomViewHidden();
                    customCallback = null;
                }
                enterImmersive();
            }

            // JS dialogs (alert/confirm/prompt): a custom chrome client
            // disables the defaults, which silently breaks console flows
            // (save-path prompt, confirmations). Native dialogs restore
            // them one-for-one.
            @Override
            public boolean onJsAlert(WebView view, String url, String message,
                    android.webkit.JsResult result) {
                new android.app.AlertDialog.Builder(MainActivity.this)
                        .setMessage(message)
                        .setPositiveButton("OK", (d, w) -> result.confirm())
                        .setOnCancelListener(d -> result.confirm())
                        .show();
                return true;
            }

            @Override
            public boolean onJsConfirm(WebView view, String url, String message,
                    android.webkit.JsResult result) {
                new android.app.AlertDialog.Builder(MainActivity.this)
                        .setMessage(message)
                        .setPositiveButton("OK", (d, w) -> result.confirm())
                        .setNegativeButton("Cancel", (d, w) -> result.cancel())
                        .setOnCancelListener(d -> result.cancel())
                        .show();
                return true;
            }

            @Override
            public boolean onJsPrompt(WebView view, String url, String message,
                    String def, android.webkit.JsPromptResult result) {
                final android.widget.EditText input =
                        new android.widget.EditText(MainActivity.this);
                input.setText(def != null ? def : "");
                new android.app.AlertDialog.Builder(MainActivity.this)
                        .setMessage(message)
                        .setView(input)
                        .setPositiveButton("OK",
                                (d, w) -> result.confirm(input.getText().toString()))
                        .setNegativeButton("Cancel", (d, w) -> result.cancel())
                        .setOnCancelListener(d -> result.cancel())
                        .show();
                return true;
            }
        };
        web.setWebChromeClient(chrome);
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
                // Fullscreen monitor switcher (tablet): the button must
                // live INSIDE #screenWrap — native fullscreen renders only
                // that subtree, so a body-level button is never visible.
                // Stream (re)starts wipe the wrap's children, hence the
                // node is kept in window.rmmMonBtn and re-placed by a
                // MutationObserver. Shown only in native fullscreen
                // (body.rmm-full, toggled by the app).
                + "function rmmMonLabel(){var s=document.getElementById('monitorSel');"
                + "if(!s||!s.options.length)return 'Mon';var v=s.value;"
                + "return v==='-1'?'All':(v==='0'?'Primary':'Mon '+v);}"
                + "function rmmMonPlace(){var w=document.getElementById('screenWrap');"
                + "if(w&&window.rmmMonBtn&&!w.contains(window.rmmMonBtn))w.appendChild(window.rmmMonBtn);}"
                + "if(!window.rmmMonBtn){"
                + "var mb=document.createElement('button');mb.id='rmm-monbtn';"
                + "mb.textContent='scr '+rmmMonLabel();"
                + "mb.onclick=function(){var s=document.getElementById('monitorSel');"
                + "if(!s||!s.options.length)return;"
                + "s.selectedIndex=(s.selectedIndex+1)%s.options.length;"
                + "s.dispatchEvent(new Event('change'));"
                + "if(window.rmmMonBtn)window.rmmMonBtn.textContent='scr '+rmmMonLabel();};"
                + "window.rmmMonBtn=mb;"
                + "var ms=document.getElementById('monitorSel');"
                + "if(ms&&!ms.rmmHooked){ms.rmmHooked=1;"
                + "ms.addEventListener('change',function(){"
                + "if(window.rmmMonBtn)window.rmmMonBtn.textContent='scr '+rmmMonLabel();});}"
                + "if(window.rmmMonObs)window.rmmMonObs.disconnect();"
                + "window.rmmMonObs=new MutationObserver(function(){rmmMonPlace();});"
                + "window.rmmMonObs.observe(document.body,{childList:true,subtree:true});}"
                + "rmmMonPlace();"
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

    private static final int REQ_IMPORT = 1001;

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(0, 1, 0, "Setup (password)");
        menu.add(0, 2, 0, "Import file to device");
        menu.add(0, 3, 0, "Lock app now");
        menu.add(0, 4, 0, AppLock.enabled(this) ? "App lock: ON" : "App lock: OFF");
        return true;
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        MenuItem lock = menu.findItem(4);
        if (lock != null) {
            lock.setTitle(AppLock.enabled(this) ? "App lock: ON" : "App lock: OFF");
        }
        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == 1) {
            startActivity(new Intent(this, SetupActivity.class));
            return true;
        }
        if (item.getItemId() == 2) {
            // System picker -> copy into the core files home, so the
            // Files tab local pane (sandbox) can upload it onward.
            // No storage permission needed (SAF grant).
            Intent i = new Intent(Intent.ACTION_OPEN_DOCUMENT);
            i.addCategory(Intent.CATEGORY_OPENABLE);
            i.setType("*/*");
            try {
                startActivityForResult(i, REQ_IMPORT);
            } catch (Exception e) {
                toast("No file picker: " + e.getMessage());
            }
            return true;
        }
        if (item.getItemId() == 3) {
            AppLock.lockNow(this);
            return true;
        }
        if (item.getItemId() == 4) {
            boolean on = !AppLock.enabled(this);
            AppLock.setEnabled(this, on);
            toast(on ? "App lock on" : "App lock off");
            if (on) {
                AppLock.lockNow(this);
            }
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != REQ_IMPORT || resultCode != RESULT_OK || data == null
                || data.getData() == null) {
            return;
        }
        try {
            android.net.Uri uri = data.getData();
            String name = displayName(uri);
            if (name == null || name.isEmpty()) {
                name = "import-" + System.currentTimeMillis();
            }
            java.io.File dir = new java.io.File(getFilesDir(), "core/files/import");
            if (!dir.isDirectory() && !dir.mkdirs()) {
                throw new Exception("cannot create " + dir.getAbsolutePath());
            }
            java.io.File dst = new java.io.File(dir, new java.io.File(name).getName());
            java.io.InputStream in = getContentResolver().openInputStream(uri);
            java.io.OutputStream out = new java.io.FileOutputStream(dst);
            byte[] chunk = new byte[65536];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                out.write(chunk, 0, n);
            }
            in.close();
            out.close();
            toast("Imported to device files/import/" + dst.getName()
                    + " — pick it in the Files local pane");
            if (web != null) {
                web.evaluateJavascript("try{typeof refreshFiles==='function'&&refreshFiles(false)}catch(e){}", null);
            }
        } catch (Exception e) {
            toast("Import failed: " + e.getMessage());
        }
    }

    private String displayName(android.net.Uri uri) {
        try {
            android.database.Cursor c = getContentResolver().query(
                    uri, new String[]{android.provider.OpenableColumns.DISPLAY_NAME},
                    null, null, null);
            if (c == null) {
                return null;
            }
            try {
                if (c.moveToFirst()) {
                    return c.getString(0);
                }
            } finally {
                c.close();
            }
        } catch (Exception e) {
            // fall through
        }
        return null;
    }

    private void toast(String msg) {
        android.widget.Toast.makeText(this, msg, android.widget.Toast.LENGTH_LONG).show();
    }

    @Override
    public void onBackPressed() {
        if (customView != null && chrome != null) {
            chrome.onHideCustomView();
            return;
        }
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
