package de.qabel.qabelbox.ui;

import android.app.Activity;

import org.junit.Test;

import de.qabel.qabelbox.R;
import de.qabel.qabelbox.ui.helper.UITestHelper;

import static android.support.test.espresso.Espresso.onView;
import static android.support.test.espresso.assertion.ViewAssertions.doesNotExist;
import static android.support.test.espresso.assertion.ViewAssertions.matches;
import static android.support.test.espresso.matcher.ViewMatchers.isDisplayed;
import static android.support.test.espresso.matcher.ViewMatchers.withText;

public class OfflineUITest extends AbstractUITest{

    private MockConnectivityManager connectivityManager;

    class MockConnectivityManager extends de.qabel.qabelbox.communication.connection.ConnectivityManager {

        private boolean connected = true;
        private Activity context;

        public MockConnectivityManager(Activity context) {
            super(context);
            this.context = context;
        }

        @Override
        public boolean isConnected() {
            return connected;
        }

        public void setConnected(final boolean connected) {
            this.connected = connected;
            final ConnectivityListener listener = this.getListener();
            context.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (connected) {
                        listener.handleConnectionEstablished();
                    } else {
                        listener.handleConnectionLost();
                    }
                }
            });
        }
    }


    @Override
    public void setUp() throws Throwable {
        super.setUp();
        launchActivity(null);
        connectivityManager = new MockConnectivityManager(getMActivity());
        getMActivity().installConnectivityManager(connectivityManager);
        connectivityManager.setConnected(true);
    }


    @Test
    public void testOfflineIndicator() throws Throwable {
        onView(withText(R.string.no_connection)).check(doesNotExist());
        connectivityManager.setConnected(false);
        onView(withText(R.string.no_connection)).check(matches(isDisplayed()));
        UITestHelper.screenShot(getMActivity(), "offlineIndicator");
    }

    @Test
    public void testOnline() {
        onView(withText(R.string.no_connection)).check(doesNotExist());
    }

}
