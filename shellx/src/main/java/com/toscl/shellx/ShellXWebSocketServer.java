package com.toscl.shellx;

import com.toscl.shellx.client.RemoteWsClient;
import com.toscl.shellx.server.JavaWebServer;
import com.toscl.shellx.server.NanoWSDWebServer;
import com.toscl.shellx.utils.Logger;
import com.toscl.shellx.utils.Util;

import java.io.IOException;

public class ShellXWebSocketServer {
    public static final String TAG = "ShellXWebSocketServer";
    protected static final Logger LOGGER = new Logger(TAG);

    private final boolean debug;
    private PtyClient mPty;
    private final int port;
    private static ShellXWebSocketServer instance;
    private final boolean local = false;
    private final boolean nano = true;
    private IWebSocketServer mWebSocketServer;
    private ShellXHttpServer mShellXHttpServer;

    public ShellXWebSocketServer(int port, boolean debug) {
        this.debug = debug;
        this.port = port;
    }

    public static ShellXWebSocketServer getInstance(int port, boolean debug){
        if (instance == null){
            instance = new ShellXWebSocketServer(port, debug);
        }
        return instance;
    }

    public void start() {
        String httpLink = System.getProperty("persist.toscl.shellx.link");
        LOGGER.d("start, httpLink: " + httpLink);
        if ("0".equals(httpLink)){
            try {
                mShellXHttpServer = new ShellXHttpServer(9091, true);
                mShellXHttpServer.start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            initPty();
            createWsClient(httpLink, true);
        }
    }

    public void createWsServer(){
        LOGGER.d("create ws server");
        mWebSocketServer = nano ? new NanoWSDWebServer(port, mPty) : new JavaWebServer(port, mPty);
        createPty(mWebSocketServer, true);
        mWebSocketServer.start();
    }

    public void initPty(){
        mPty = new PtyClient();
    }

    private void createPty(IWebSocketServer webSocketServer, boolean load){
        LOGGER.d("create pty");
        if (load)
            PtyProcess.loadLibrary();
        mPty.setWebSocket(webSocketServer);
    }

    public void setPtyReconnect() {
        mPty.setReconnectMark(true);
    }

    public void reconnect(){
        String httpLink = System.getProperty("persist.toscl.shellx.link");
        LOGGER.d("start, httpLink: " + httpLink);
        if (mWebSocketServer != null) {
            mWebSocketServer.close();
        }
        if ("0".equals(httpLink)){
            ShellXWebSocketServer.getInstance(9090, false).createWsServer();
            ShellXWebSocketServer.getInstance(9090, false).setPtyReconnect();
        }else{
            createWsClient(System.getProperty("persist.toscl.shellx.link"), false);
        }
    }

    private void createWsClient(String httpLink, boolean load){
        String wsUrl = "";
        if (httpLink != null){
            if (httpLink.startsWith("https")){
                wsUrl = httpLink.replace("https", "wss");
            }else if (httpLink.startsWith("http")){
                wsUrl = httpLink.replace("http", "ws");
            }
            wsUrl = wsUrl.replace("/s/", "/api/t/");
        }
        try {
            mWebSocketServer = new RemoteWsClient(mPty, wsUrl);
            createPty(mWebSocketServer, load);
            mWebSocketServer.start();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void destroy() {
        LOGGER.d("destroy");

        try {
            if (mWebSocketServer != null){
                mWebSocketServer.destroy();
            }
            if (mShellXHttpServer != null){
                mShellXHttpServer.stop();
            }
            Util.executeShell("am force-stop com.toscl.shellx");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void execute(String command) {
        LOGGER.d("execute :" + command);

        try {
           mPty.focusShellInput(command);
           LOGGER.d("focus input: " + command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
