package com.rmm.controller;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Minimal localhost API client (no dependencies): logs in with the
 * stored UI password, keeps the session cookie, sends commands.
 * Command replies stream over the console WebSocket, so sends are
 * fire-and-forget here — the UI says exactly that.
 */
final class ApiClient {

    static final String BASE = "http://127.0.0.1:8080";
    private static String cookie = null;

    private ApiClient() {
    }

    static synchronized void login(String password) throws Exception {
        String body = "{\"password\":" + quote(password) + "}";
        HttpURLConnection c = post("/api/login", body, null);
        int code = c.getResponseCode();
        readAll(c);
        c.disconnect();
        if (code != 200) {
            cookie = null;
            throw new Exception("login failed (code " + code + ")");
        }
    }

    static synchronized String send(String cmd, String target, String password) throws Exception {
        String id = "a" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String body = "{\"cmd\":" + quote(cmd) + ",\"target\":" + quote(target)
                + ",\"cmdId\":" + quote(id) + "}";
        for (int attempt = 0; attempt < 2; attempt++) {
            if (cookie == null) {
                login(password);
            }
            HttpURLConnection c = post("/api/cmd", body, cookie);
            int code = c.getResponseCode();
            String resp = readAll(c);
            c.disconnect();
            if (code == 401) {
                cookie = null; // session died; one re-login, then give up
                continue;
            }
            if (code != 200) {
                throw new Exception("send failed (code " + code + ")");
            }
            return resp;
        }
        throw new Exception("send failed (login expired)");
    }

    private static HttpURLConnection post(String path, String body, String ck) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(BASE + path).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(15000);
        c.setReadTimeout(30000);
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "application/json");
        if (ck != null) {
            c.setRequestProperty("Cookie", ck); // stored "rmm_ui=..." pair
        }
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        OutputStream out = c.getOutputStream();
        try {
            out.write(b);
        } finally {
            out.close();
        }
        // Capture a fresh session cookie when the server sets one.
        Map<String, List<String>> h = c.getHeaderFields();
        if (h != null) {
            List<String> set = h.get("Set-Cookie");
            if (set == null) {
                set = h.get("set-cookie");
            }
            if (set != null) {
                for (String s : set) {
                    if (s.startsWith("rmm_ui=")) {
                        cookie = s.split(";", 2)[0];
                    }
                }
            }
        }
        return c;
    }

    private static String readAll(HttpURLConnection c) {
        try {
            InputStream in;
            try {
                in = c.getInputStream();
            } catch (Exception e) {
                in = c.getErrorStream();
            }
            if (in == null) {
                return "";
            }
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            int n;
            while ((n = in.read(chunk)) >= 0) {
                bos.write(chunk, 0, n);
            }
            in.close();
            return new String(bos.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

    private static String quote(String s) {
        return "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
}
