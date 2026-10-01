package com.rmm.controller;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.Context;
import android.content.Intent;
import android.widget.RemoteViews;

/** Home-screen widget: live agent count, tap to open. Updates on the
 * platform cadence plus every service start (the service pokes
 * updateNow after the core is up).
 */
public class RmmWidget extends AppWidgetProvider {

    @Override
    public void onUpdate(Context context, AppWidgetManager mgr, int[] ids) {
        for (int id : ids) {
            updateOne(context, mgr, id);
        }
    }

    public static void updateNow(Context context) {
        AppWidgetManager mgr = AppWidgetManager.getInstance(context);
        int[] ids = mgr.getAppWidgetIds(
                new android.content.ComponentName(context, RmmWidget.class));
        for (int id : ids) {
            updateOne(context, mgr, id);
        }
    }

    private static void updateOne(Context context, AppWidgetManager mgr, int id) {
        int agents = -1;
        try {
            org.json.JSONObject st = new org.json.JSONObject(mobile.Mobile.status());
            if (st.optBoolean("running", false)) {
                org.json.JSONArray arr = st.optJSONArray("agents");
                agents = arr != null ? arr.length() : 0;
            }
        } catch (Exception e) {
            // leave -1 (core down / starting)
        }
        RemoteViews views = new RemoteViews(context.getPackageName(), R.layout.widget);
        if (agents < 0) {
            views.setTextViewText(R.id.widget_text, "RMM — core down");
        } else if (agents == 1) {
            views.setTextViewText(R.id.widget_text, "RMM — 1 agent");
        } else {
            views.setTextViewText(R.id.widget_text, "RMM — " + agents + " agents");
        }
        Intent open = new Intent(context, HomeActivity.class);
        PendingIntent pi = PendingIntent.getActivity(context, 0, open,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        views.setOnClickPendingIntent(R.id.widget_text, pi);
        mgr.updateAppWidget(id, views);
    }
}
