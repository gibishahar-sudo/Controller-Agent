package com.rmm.controller;

import android.app.Application;

/** Installs the crash catcher before anything else runs. */
public class RmmApp extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
        CrashLog.install(this);
    }
}
