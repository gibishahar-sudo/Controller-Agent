package com.rmm.controller;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Build;
import android.os.CancellationSignal;
import android.widget.Toast;

import java.util.concurrent.Executor;

/** App lock: system biometric with device-PIN fallback, gating the
 * console activities. On by default (a tablet that drives the fleet
 * must not open straight into it); toggle in the menu. State:
 * locked at process start and whenever backgrounded; rotation restore
 * carries a one-time pass so turning the tablet never re-prompts.
 */
public final class AppLock {

    private static final String KEY = "app_lock";
    private static boolean locked = true;

    private AppLock() {
    }

    public static boolean enabled(Context c) {
        return c.getSharedPreferences(SetupActivity.PREFS, Context.MODE_PRIVATE)
                .getBoolean(KEY, true);
    }

    public static void setEnabled(Context c, boolean on) {
        c.getSharedPreferences(SetupActivity.PREFS, Context.MODE_PRIVATE)
                .edit().putBoolean(KEY, on).apply();
    }

    public static void lockNow(Activity a) {
        locked = true;
        prompt(a, () -> locked = false);
    }

    public static void onBackgrounded() {
        locked = true;
    }

    /** Returns true when the caller must defer (prompt shown); onUnlocked
     * runs on the UI thread after a successful unlock. */
    public static boolean requiresPrompt(Activity a, boolean restoredUnlocked, Runnable onUnlocked) {
        if (!enabled(a)) {
            locked = false;
            return false;
        }
        if (!locked || restoredUnlocked) {
            locked = false;
            return false;
        }
        prompt(a, onUnlocked);
        return true;
    }

    private static void prompt(Activity a, Runnable onOk) {
        KeyguardManager km = (KeyguardManager) a.getSystemService(Context.KEYGUARD_SERVICE);
        if (km == null || !km.isDeviceSecure()) {
            Toast.makeText(a, "Set a device PIN first (app lock needs one)",
                    Toast.LENGTH_LONG).show();
            setEnabled(a, false);
            locked = false;
            a.runOnUiThread(onOk);
            return;
        }
        try {
            promptBiometric(a, onOk);
        } catch (Exception e) {
            // Vendor ROM quirks around BiometricPrompt must never brick
            // the app: fail open, loudly, like the no-PIN path.
            Toast.makeText(a, "Biometric unavailable (" + e.getMessage() + ") — app lock off",
                    Toast.LENGTH_LONG).show();
            setEnabled(a, false);
            locked = false;
            a.runOnUiThread(onOk);
        }
    }

    private static void promptBiometric(Activity a, Runnable onOk) {
        Executor exec = a.getMainExecutor();
        BiometricPrompt.Builder b = new BiometricPrompt.Builder(a)
                .setTitle("RMM Console")
                .setDescription("Unlock to continue");
        if (Build.VERSION.SDK_INT >= 30) {
            b.setAllowedAuthenticators(
                    android.hardware.biometrics.BiometricManager.Authenticators.BIOMETRIC_STRONG
                            | android.hardware.biometrics.BiometricManager.Authenticators.DEVICE_CREDENTIAL);
        } else {
            b.setDeviceCredentialAllowed(true);
        }
        CancellationSignal cancel = new CancellationSignal();
        b.build().authenticate(cancel, exec, new BiometricPrompt.AuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                locked = false;
                a.runOnUiThread(onOk);
            }

            @Override
            public void onAuthenticationError(int errorCode, CharSequence errString) {
                a.finish();
            }
        });
    }
}
