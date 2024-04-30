package com.toscl.shellx.server;



import com.toscl.shellx.IWebSocketServer;
import com.toscl.shellx.PtyClient;

import org.java_websocket.WebSocket;
import org.java_websocket.framing.Framedata;
import org.java_websocket.handshake.ClientHandshake;
import org.java_websocket.server.WebSocketServer;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class JavaWebServer extends WebSocketServer implements IWebSocketServer {

    private final PtyClient ptyClient;
    private String TAG = "JavaWebServer";

    public JavaWebServer(int port, PtyClient ptyClient) {
        super(new InetSocketAddress(port));
        this.ptyClient = ptyClient;
        this.setConnectionLostTimeout(2000);
    }

    @Override
    public void onWebsocketPong(WebSocket conn, Framedata f) {
        //ptyClient.onPong();
    }

    @Override
    public void onOpen(org.java_websocket.WebSocket conn, ClientHandshake handshake) {
        ptyClient.onOpen();
    }

    @Override
    public void onClose(org.java_websocket.WebSocket conn, int code, String reason, boolean remote) {
        ptyClient.onClose();
    }

    @Override
    public void onMessage(org.java_websocket.WebSocket conn, ByteBuffer message) {
        if (conn.isOpen()){
            ptyClient.onMessage(message.array());
        }
    }

    @Override
    public void onMessage(org.java_websocket.WebSocket conn, String message) {

    }

    @Override
    public void onError(org.java_websocket.WebSocket conn, Exception ex) {

    }

    @Override
    public void onStart() {

    }

    @Override
    public void reconnect() {

    }

    @Override
    public void close() {
        try {
            this.stop();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void destroy() {
        try {
            this.stop();
            this.finalize();
            ptyClient.destroy();
        } catch (Throwable e) {
            e.printStackTrace();
        }
    }
}