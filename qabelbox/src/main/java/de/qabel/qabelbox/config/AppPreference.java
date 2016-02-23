package de.qabel.qabelbox.config;

import android.content.Context;
import android.content.SharedPreferences;

/**
 * Created by danny on 27.01.16.
 */
public class AppPreference {

    private final SharedPreferences settings;
    private final String P_TOKEN = "token";
    private final String P_LAST_APP_START_VERSION = "lastappstartversion";
    private final String P_LAST_APP_UPDATE_QUESTION_TIME = "lastupdatequestiontime";
    private final long NEW_UPATE_QUESTION_TIME_INTERVAL = 1000 * 60 * 60 * 24 * 3l;
    private final String P_ENABLEBUGREPORTING = "enable_bugreporting";

    public AppPreference(Context context) {

        settings = context.getSharedPreferences("settings", Context.MODE_PRIVATE);
    }

    public void setToken(String token) {

        settings.edit().putString(P_TOKEN, token).commit();
    }

    public String getToken() {

        return settings.getString(P_TOKEN, null);
    }

    public int getLastAppStartVersion() {

        return settings.getInt(P_LAST_APP_START_VERSION, 0);
    }

    public void setLastAppStartVersion(int version) {

        settings.edit().putInt(P_LAST_APP_START_VERSION, version).commit();
    }

    private long getLastAppUpdateQuestion() {

        return settings.getLong(P_LAST_APP_UPDATE_QUESTION_TIME, 0);
    }

    public void setLastAppUpdateQuestion(long time) {

        settings.edit().putLong(P_LAST_APP_UPDATE_QUESTION_TIME, time).commit();
    }

    public boolean shouldUpdateQuestionShowed(long currentTime) {

        return getLastAppUpdateQuestion() + NEW_UPATE_QUESTION_TIME_INTERVAL < currentTime;
    }

    public void setCrashreportingEnabled(boolean enableReporting) {
        settings.edit().putBoolean(P_ENABLEBUGREPORTING, enableReporting).commit();
    }

    public boolean isCrashreportingEnabled() {
        return settings.getBoolean(P_ENABLEBUGREPORTING, false);
    }
}
