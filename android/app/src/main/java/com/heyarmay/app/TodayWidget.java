package com.heyarmay.app;

import android.app.PendingIntent;
import android.appwidget.AppWidgetManager;
import android.appwidget.AppWidgetProvider;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.text.SpannableString;
import android.text.Spanned;
import android.text.style.RelativeSizeSpan;
import android.text.style.StyleSpan;
import android.graphics.Typeface;
import android.widget.RemoteViews;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

public class TodayWidget extends AppWidgetProvider {
    static final String BASE = "https://heyarmay.com";
    static final String ACTION_REFRESH = "com.heyarmay.app.REFRESH";

    static class Unauthorized extends Exception {}

    static SharedPreferences prefs(Context c) { return c.getSharedPreferences("hey", Context.MODE_PRIVATE); }

    @Override
    public void onUpdate(Context ctx, AppWidgetManager mgr, int[] ids) { refresh(ctx, goAsync()); }

    @Override
    public void onReceive(Context ctx, Intent intent) {
        super.onReceive(ctx, intent);
        if (ACTION_REFRESH.equals(intent.getAction())) refresh(ctx, goAsync());
    }

    static void refresh(Context ctx, final PendingResult pr) {
        final Context app = ctx.getApplicationContext();
        render(app, cached(app), "…");
        new Thread(() -> {
            try {
                JSONObject j = fetch(app);
                prefs(app).edit().putString("cache", j.toString()).putLong("at", System.currentTimeMillis()).apply();
                render(app, j, null);
            } catch (Unauthorized e) {
                render(app, null, null);
            } catch (Exception e) {
                render(app, cached(app), "offline");
            } finally {
                if (pr != null) pr.finish();
            }
        }).start();
    }

    static JSONObject cached(Context c) {
        try { String s = prefs(c).getString("cache", null); return s == null ? null : new JSONObject(s); }
        catch (Exception e) { return null; }
    }

    static JSONObject fetch(Context c) throws Exception {
        String token = prefs(c).getString("token", null);
        if (token == null) throw new Unauthorized();
        HttpURLConnection h = (HttpURLConnection) new URL(BASE + "/api/widget").openConnection();
        h.setConnectTimeout(10000);
        h.setReadTimeout(15000);
        h.setRequestProperty("Authorization", "Bearer " + token);
        h.setRequestProperty("Accept", "application/json");
        int code = h.getResponseCode();
        if (code == 401) { prefs(c).edit().remove("token").remove("cache").apply(); throw new Unauthorized(); }
        if (code != 200) throw new Exception("http " + code);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader r = new BufferedReader(new InputStreamReader(h.getInputStream(), StandardCharsets.UTF_8))) {
            String line; while ((line = r.readLine()) != null) sb.append(line);
        }
        return new JSONObject(sb.toString());
    }

    static PendingIntent open(Context c, int req, String path) {
        Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(BASE + path)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
        return PendingIntent.getActivity(c, req, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static CharSequence stat(int n, String label) {
        String num = String.valueOf(n);
        SpannableString s = new SpannableString(num + "\n" + label);
        s.setSpan(new RelativeSizeSpan(1.75f), 0, num.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        s.setSpan(new StyleSpan(Typeface.BOLD), 0, num.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
        return s;
    }

    static void render(Context c, JSONObject j, String note) {
        RemoteViews v = new RemoteViews(c.getPackageName(), R.layout.widget_today);
        boolean connected = prefs(c).getString("token", null) != null;
        if (!connected) {
            v.setTextViewText(R.id.label, "SET UP");
            v.setTextViewText(R.id.time, "Connect");
            v.setTextViewText(R.id.title, "Tap here to link this widget");
            v.setTextViewText(R.id.sub, "to your Hey Armay account");
            Intent setup = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            v.setOnClickPendingIntent(R.id.root, PendingIntent.getActivity(c, 9, setup, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));
        } else {
            v.setOnClickPendingIntent(R.id.root, open(c, 1, "/#hari-ini"));
            v.setOnClickPendingIntent(R.id.stat_tasks, open(c, 2, "/#tugasan"));
            v.setOnClickPendingIntent(R.id.stat_inv, open(c, 3, "/#bayaran"));
            v.setOnClickPendingIntent(R.id.stat_team, open(c, 4, "/#team"));
        }
        v.setOnClickPendingIntent(R.id.btn_speak, open(c, 5, "/?go=speak"));
        v.setOnClickPendingIntent(R.id.btn_write, open(c, 6, "/?go=write"));
        Intent r = new Intent(c, TodayWidget.class).setAction(ACTION_REFRESH);
        v.setOnClickPendingIntent(R.id.btn_refresh, PendingIntent.getBroadcast(c, 7, r, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT));

        if (j != null) {
            v.setTextViewText(R.id.date, j.optString("date", ""));
            JSONObject n = j.optJSONObject("next");
            if (n != null) {
                v.setTextViewText(R.id.label, ("UP NEXT · " + n.optString("day", "Today")).toUpperCase(Locale.ROOT));
                v.setTextViewText(R.id.time, n.optString("time", ""));
                v.setTextViewText(R.id.title, n.optString("title", ""));
                int more = j.optInt("more", 0);
                String sub = n.optString("sub", "");
                v.setTextViewText(R.id.sub, sub + (more > 0 ? (sub.isEmpty() ? "" : " · ") + "+" + more + " more" : ""));
            } else {
                v.setTextViewText(R.id.label, "TODAY");
                v.setTextViewText(R.id.time, "All clear");
                v.setTextViewText(R.id.title, "Nothing else on the schedule");
                v.setTextViewText(R.id.sub, "");
            }
            JSONObject w = j.optJSONObject("weather");
            if (w != null) {
                v.setTextViewText(R.id.temp, w.optInt("temp") + "°");
                String hl = (w.isNull("hi") ? "" : w.optInt("hi") + "°/" + w.optInt("lo") + "°") + (w.isNull("rain") ? "" : " · " + w.optInt("rain") + "%");
                v.setTextViewText(R.id.wx, w.optString("desc", "") + "\n" + hl);
            }
            v.setTextViewText(R.id.stat_tasks, stat(j.optInt("tasks"), "Tasks"));
            v.setTextViewText(R.id.stat_inv, stat(j.optInt("invoices"), "Invoices"));
            v.setTextViewText(R.id.stat_team, stat(j.optInt("team"), "Team jobs"));
        }
        String upd = j != null ? j.optString("updated", "") : "";
        if (!upd.isEmpty()) {
            try { upd = new SimpleDateFormat("h:mma", Locale.ENGLISH).format(new SimpleDateFormat("HH:mm", Locale.ENGLISH).parse(upd)).toLowerCase(Locale.ROOT); } catch (Exception ignored) {}
        }
        v.setTextViewText(R.id.btn_refresh, "↻ " + ("…".equals(note) ? "…" : "offline".equals(note) ? "offline" : upd));

        AppWidgetManager.getInstance(c).updateAppWidget(new ComponentName(c, TodayWidget.class), v);
    }
}
