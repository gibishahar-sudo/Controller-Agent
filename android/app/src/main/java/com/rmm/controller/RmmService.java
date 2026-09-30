package com.rmm.controller;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;

import java.io.File;

import mobile.Mobile;

/** Foreground service owning the controller core: same MQTT buses,
// same login gate, same console on localhost as the desktop app.
// START_STICKY + persistent notification keep it alive like a desktop
// process; the OS may still kill under extreme pressure (then the
// user reopens the app, exactly like relaunching desktop).
 */
public class RmmService extends Service {

    public static final String CHANNEL = "rmm_core";
    private static final int NOTIF_ID = 41;

    @Override
    public void onCreate() {
        super.onCreate();
        NotificationManager nm = getSystemService(NotificationManager.class);
        NotificationChannel ch = new NotificationChannel(
                CHANNEL, "RMM Console core", NotificationManager.IMPORTANCE_LOW);
        ch.setDescription("Keeps the on-device controller serving your agents");
        nm.createNotificationChannel(ch);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification notif = new Notification.Builder(this, CHANNEL)
                .setContentTitle("RMM Console active")
                .setContentText("Serving your agents on this device")
                .setSmallIcon(R.drawable.ic_fg)
                .setOngoing(true)
                .build();
        startForeground(NOTIF_ID, notif);
        new Thread(() -> {
            String dir = new File(getFilesDir(), "core").getAbsolutePath();
            try {
                SetupActivity.ensureIdentity(this);
            } catch (Exception e) {
                fail("identity: " + e.getMessage());
                return;
            }
            String err = Mobile.start(
                    dir, "", SetupActivity.pref(this, SetupActivity.KEY_PASSWORD, ""), "", "");
            if (err != null && !err.isEmpty()) {
                fail(err);
            }
        }, "rmm-core-start").start();
        return START_STICKY;
    }

    private void fail(String err) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        Notification failed = new Notification.Builder(this, CHANNEL)
                .setContentTitle("RMM Console failed to start")
                .setContentText(err)
                .setSmallIcon(R.drawable.ic_fg)
                .setOngoing(false)
                .build();
        nm.notify(NOTIF_ID + 1, failed);
        stopSelf();
    }

    @Override
    public void onDestroy() {
        try {
            Mobile.stop();
        } catch (Exception e) {
            // shutting down anyway
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
