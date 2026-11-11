package com.heyarmay.app;

import android.app.Activity;
import android.appwidget.AppWidgetManager;
import android.content.ComponentName;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public class MainActivity extends Activity {
    LinearLayout box;

    int dp(int v) { return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v, getResources().getDisplayMetrics()); }

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Color.parseColor("#0A0E22"));
        getWindow().setNavigationBarColor(Color.parseColor("#0A0E22"));
        handle(getIntent());
        build();
    }

    @Override
    protected void onNewIntent(Intent i) { super.onNewIntent(i); handle(i); build(); }

    @Override
    protected void onResume() { super.onResume(); build(); }

    void handle(Intent i) {
        Uri u = i == null ? null : i.getData();
        if (u != null && "heyarmay".equals(u.getScheme()) && "connect".equals(u.getHost())) {
            String t = u.getQueryParameter("t");
            if (t != null && t.matches("[A-Za-z0-9_-]{40,}")) {
                TodayWidget.prefs(this).edit().putString("token", t).remove("cache").apply();
                TodayWidget.refresh(this, null);
            }
        }
    }

    TextView text(String s, int sp, String color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s); t.setTextSize(sp); t.setTextColor(Color.parseColor(color));
        if (bold) t.setTypeface(t.getTypeface(), android.graphics.Typeface.BOLD);
        t.setLineSpacing(0, 1.2f);
        return t;
    }

    Button button(String s, boolean primary, Runnable r) {
        Button bt = new Button(this);
        bt.setText(s); bt.setAllCaps(false); bt.setTextSize(16);
        bt.setTextColor(primary ? Color.parseColor("#0A0E22") : Color.WHITE);
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(dp(14));
        if (primary) g.setColor(Color.parseColor("#5EEAD4")); else { g.setColor(Color.parseColor("#1AFFFFFF")); g.setStroke(dp(1), Color.parseColor("#665EEAD4")); }
        bt.setBackground(g);
        bt.setOnClickListener(x -> r.run());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, dp(52));
        lp.topMargin = dp(12);
        bt.setLayoutParams(lp);
        return bt;
    }

    void openUrl(String path) { startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(TodayWidget.BASE + path))); }

    void build() {
        boolean on = TodayWidget.prefs(this).getString("token", null) != null;
        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(Color.parseColor("#0A0E22"));
        box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(24), dp(48), dp(24), dp(32));
        sv.addView(box);

        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.logo_white);
        logo.setAdjustViewBounds(true);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(dp(140), -2);
        lp.gravity = Gravity.START;
        box.addView(logo, lp);

        TextView h = text(on ? "Widget connected ✓" : "Connect your widget", 26, "#FFFFFF", true);
        h.setPadding(0, dp(28), 0, dp(8));
        box.addView(h);

        if (on) {
            box.addView(text("Your home-screen widget shows today's next event, tasks, invoices, team jobs and weather. It refreshes every 30 minutes, or tap ↻ on the widget.", 15, "#B8C0E0", false));
            box.addView(button("Add widget to home screen", true, this::pin));
            box.addView(text("Or: long-press an empty spot on your home screen → Widgets → Hey Armay Widget → drag “Hey Armay · Today”.", 13, "#8A93B8", false));
            box.addView(button("Refresh widget now", false, () -> TodayWidget.refresh(this, null)));
            box.addView(button("Open Hey Armay", false, () -> openUrl("/#hari-ini")));
            box.addView(button("Disconnect this phone", false, () -> {
                TodayWidget.prefs(this).edit().clear().apply();
                TodayWidget.refresh(this, null);
                build();
            }));
        } else {
            box.addView(text("1. Tap the button below. Hey Armay opens on the Account page (sign in if asked).\n2. Under “Phone widget”, tap “Connect widget on this phone”.\n3. You'll come back here, connected.", 15, "#B8C0E0", false));
            box.addView(button("Open Account page", true, () -> openUrl("/akaun")));
        }
        setContentView(sv);
    }

    void pin() {
        AppWidgetManager m = getSystemService(AppWidgetManager.class);
        if (m != null && m.isRequestPinAppWidgetSupported()) m.requestPinAppWidget(new ComponentName(this, TodayWidget.class), null, null);
    }
}
