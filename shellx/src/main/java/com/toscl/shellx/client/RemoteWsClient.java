package com.toscl.shellx.client;

import android.os.Handler;


import com.toscl.shellx.IWebSocketServer;
import com.toscl.shellx.PtyClient;
import com.toscl.shellx.ShellXWebSocketServer;
import com.toscl.shellx.utils.Logger;
import com.toscl.shellx.utils.UniqueIdentifierGenerator;

import org.java_websocket.WebSocket;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ServerHandshake;
import org.json.JSONObject;

import java.io.IOException;
import java.net.SocketException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class RemoteWsClient extends WebSocketClient implements IWebSocketServer {
    private static final String TAG = "RemoteWsClient";
    protected static final Logger LOGGER = new Logger(TAG);

    private final PtyClient ptyClient;

    public RemoteWsClient(PtyClient ptyClient, String wsUrl) {
        super(URI.create(wsUrl));
        this.ptyClient = ptyClient;
        LOGGER.d("wsUrl: " + wsUrl);
        this.setConnectionLostTimeout(2000);
    }

    @Override
    public void broadcast(byte[] encodeToBytes) {
        LOGGER.d("broadcast...");

        if (this.isOpen()){
            this.send(encodeToBytes);
        }
    }

    @Override
    public void start() {
        LOGGER.d("start...");
        try {
            this.connectBlocking();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onMessage(ByteBuffer bytes) {
        LOGGER.d("onMessage byte...");

        ptyClient.onMessage(bytes.array());
    }

    @Override
    public void onMessage(String message) {
        LOGGER.d("start...");
    }


    @Override
    public void onClose(int code, String reason, boolean remote) {
        LOGGER.d("onClose, code: " + code + ", reason: " + reason + ", remote: " + remote);
        ptyClient.onClose();
    }

    @Override
    public void onError(Exception e) {
        LOGGER.d("onError..." + e);

    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        ptyClient.onOpen();
    }

//    @Override
//    public void onWebsocketPong(WebSocket conn, Framedata f) {
//        ptyClient.onPong();
//    }

    @Override
    public void onWebsocketPing(WebSocket conn, Framedata f) {
        //ptyClient.onPong();
    }

    @Override
    public void destroy() {
        try {
            this.closeBlocking();
            this.finalize();
            ptyClient.destroy();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }

    @Override
    public void close() {
        super.close();
    }
}
