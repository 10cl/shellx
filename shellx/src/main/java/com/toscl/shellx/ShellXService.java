package com.toscl.shellx;

import android.content.Context;
import android.os.Looper;
import android.os.ServiceManager;

import com.toscl.shellx.utils.Logger;
import java.io.IOException;

public class ShellXService {
    public static final String TAG = "ShellXService";
    protected static final Logger LOGGER = new Logger(TAG);

    public static void main(String[] args) {
        Looper.prepare();
        PtyProcess.setLibraryPath(System.getProperty("persist.toscl.shellx.path"));
        new ShellXService();
        Looper.loop();
    }

    private static void waitSystemService(String name) {
        while (ServiceManager.getService(name) == null) {
            try {
                LOGGER.i("service " + name + " is not started, wait 1s.");
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                LOGGER.w(e.getMessage(), e);
            }
        }
    }

    public ShellXService() {
        super();
        LOGGER.i("starting server...");
        waitSystemService("package");
        waitSystemService(Context.ACTIVITY_SERVICE);
        waitSystemService(Context.USER_SERVICE);
        waitSystemService(Context.APP_OPS_SERVICE);
        ShellXWebSocketServer.getInstance(9090, false).start();
    }

}
