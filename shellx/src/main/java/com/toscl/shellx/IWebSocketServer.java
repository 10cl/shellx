package com.toscl.shellx;

public interface IWebSocketServer {

    void broadcast(byte[] encodeToBytes);

    void start();

    void reconnect();

    void close();

    void destroy();
}
