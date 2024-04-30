package com.toscl.shellx.server;



import com.toscl.shellx.IWebSocketServer;
import com.toscl.shellx.PtyClient;
import com.toscl.shellx.utils.Logger;

import org.json.JSONException;
import org.nanohttpd.protocols.http.IHTTPSession;
import org.nanohttpd.protocols.websockets.CloseCode;
import org.nanohttpd.protocols.websockets.NanoWSD;
import org.nanohttpd.protocols.websockets.WebSocket;
import org.nanohttpd.protocols.websockets.WebSocketFrame;

import java.io.IOException;
import java.net.SocketException;

public class NanoWSDWebServer extends NanoWSD implements IWebSocketServer {
    private final PtyClient ptyClient;
    private WebSocket websocket;
    private static String TAG = "NanoWSDWebServer";
    protected static final Logger LOGGER = new Logger(TAG);

    public NanoWSDWebServer(int port, PtyClient ptyClient) {
        super(port);
        this.ptyClient = ptyClient;
    }

    @Override
    protected WebSocket openWebSocket(IHTTPSession handshake) {
        LOGGER.d("open web socket: " + handshake.getHeaders());
        websocket = new WebSocket(handshake) {
            @Override
            protected void onOpen() {
                ptyClient.onOpen();
            }

            @Override
            protected void onClose(CloseCode code, String reason, boolean initiatedByRemote) {
                ptyClient.onClose();
            }

            @Override
            protected void onMessage(WebSocketFrame message) {
                ptyClient.onMessage(message.getBinaryPayload());
            }

            @Override
            protected void onPong(WebSocketFrame pong) {
                //ptyClient.onPong();
            }

            @Override
            protected void onException(IOException exception) {
                exception.printStackTrace();
            }
        };
        return websocket;
    }

    @Override
    public synchronized void closeAllConnections() {
        super.closeAllConnections();
    }

    @Override
    public void broadcast(byte[] encodeToBytes) {
        if (websocket == null || !websocket.isOpen()){
            return;
        }
        try {
            websocket.send(encodeToBytes);
        } catch (SocketException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void start(){
        try {
            super.start();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void reconnect() {

    }

    @Override
    public void close() {
        try {
            super.stop();
        } catch (Throwable e) {
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


