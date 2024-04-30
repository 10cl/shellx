package com.toscl.shellx;



import com.toscl.shellx.utils.Logger;
import com.toscl.shellx.utils.UniqueIdentifierGenerator;
import com.toscl.shellx.utils.Util;
import com.upokecenter.cbor.CBORObject;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Random;

public class PtyClient {
    public static final String TAG = "PtyClient";
    protected static final Logger LOGGER = new Logger(TAG);
    private static final String ALPHANUMERIC_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private final HashMap<String, PtyModule> ptyModuleHashMap = new HashMap<>();
    private IWebSocketServer mWebSocket;
    private final JSONArray mShells = new JSONArray();
    private final JSONArray mUsers = new JSONArray();
    private JSONObject mWsUser;
    public String mUid = "";
    private String mAuthenticate;
    private boolean mReconnectMark;

    public void setWebSocket(IWebSocketServer debugWebSocketServer) {
        mWebSocket = debugWebSocketServer;
    }

    public void createPty(int x, int y) {
        String sid = UniqueIdentifierGenerator.generateUniqueIdentifier();
        PtyModule ptyModule = new PtyModule();
        ptyModule.setOutputStream(new OutputStream() {
            @Override
            public void close() throws IOException {
                super.close();
            }

            @Override
            public void write(final int b) {

            }

            @Override
            public void write(final byte[] b, final int off, final int len) {
                ByteBuffer result = ByteBuffer.wrap(b, off, len);
                sendCborObj("chunks", new JSONArray().put(sid).put(len).put(Util.byteBufferToString(result)));
            }

            @Override
            public void write(final byte[] b) {

            }
        });
        ptyModule.connect();
        ptyModuleHashMap.put(sid, ptyModule);
        resizePty(sid, x, y, 30, 100);
    }

    public void resizePty(String sid, int x, int y, int row, int col){
        int widthPx = row*16;
        int heightPx = col*16;

        ptyModuleHashMap.get(sid).resize(col, row, widthPx, heightPx);
        sendResizeInfo(sid, x, y, row, col);

    }

    private void sendResizeInfo(String sid, int x, int y, int rows, int cols) {
        /*export type WsWinsize = {
          x: number;
          y: number;
          rows: number;
          cols: number;
        };
        shells?: [Sid, WsWinsize][];*/
        try {
            checkShells();
            JSONObject wsWinsize = new JSONObject();
            wsWinsize.put("x", x);
            wsWinsize.put("y", y);
            wsWinsize.put("rows", rows);
            wsWinsize.put("cols", cols);
            for (int i = 0; i < mShells.length(); i++) {
                JSONArray shell = mShells.getJSONArray(i);
                if (shell.get(0).equals(sid)) {
                    shell.remove(1);
                    shell.put(1, wsWinsize);
                    sendCborObj("shells", mShells);
                    return;
                }
            }
            mShells.put(new JSONArray().put(sid).put(wsWinsize));
            sendCborObj("shells", mShells);
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private void checkShells() throws JSONException {
        for (int i = 0; i < mShells.length(); i++) {
            JSONArray shell = mShells.getJSONArray(i);
            String sid = shell.getString(0);
            PtyModule ptyModule = ptyModuleHashMap.get(sid);
            if (ptyModule == null || !ptyModule.isConnected()) {
                try {
                    ptyModule.finalize();
                } catch (Throwable e) {
                    e.printStackTrace();
                }
                mShells.remove(i);
                i--; // Adjust the index as we removed an element
            }
        }
    }

    public void reConnectShells() throws JSONException {
        LOGGER.d("re connect shells");
        for (int i = 0; i < mShells.length(); i++) {
            JSONArray shell = mShells.getJSONArray(i);
            String sid = shell.getString(0);
            PtyModule ptyModule = ptyModuleHashMap.get(sid);
            if (ptyModule == null || !ptyModule.isConnected()) {
                try {
                    ptyModule.finalize();
                } catch (Throwable e) {
                    e.printStackTrace();
                }
                mShells.remove(i);
                i--; // Adjust the index as we removed an element
            }else{
                ptyModule.connect();
            }
        }
    }


    public void input(String sid, byte[] input) {
        try {
            if (ptyModuleHashMap.get(sid) != null){
                OutputStream inputProc = ptyModuleHashMap.get(sid).getOutputStream();
                if (inputProc != null){
                    inputProc.write(input);
                    inputProc.flush();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sendCborObj(String key, Object obj) {
        try {
            LOGGER.d("sendCborObj, key: " + key + ", obj: " + obj);
            JSONObject serverObj = new JSONObject();
            serverObj.put(key, obj);
            CBORObject encodeObj = CBORObject.FromJSONString(serverObj.toString());
            mWebSocket.broadcast(encodeObj.EncodeToBytes());
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public static String generateRandomString(int length) {
        StringBuilder sb = new StringBuilder(length);
        Random random = new Random();
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(ALPHANUMERIC_CHARS.length());
            char randomChar = ALPHANUMERIC_CHARS.charAt(randomIndex);
            sb.append(randomChar);
        }
        return sb.toString();
    }

    public void removeShells(String closeShellId) {
        try {
            for (int i = 0; i < mShells.length(); i++) {
                JSONArray shell = mShells.getJSONArray(i);
                if (shell.getString(0).equals(closeShellId)) {
                    PtyModule ptyModule = ptyModuleHashMap.get(closeShellId);
                    if (ptyModule != null) {
                        try {
                            ptyModule.finalize();
                        } catch (Throwable e) {
                            e.printStackTrace();
                        }
                    }
                    mShells.remove(i);
                    sendCborObj("shells", mShells);
                    return;
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void hello() {
        LOGGER.d("hello");
        try {
            mUid = UniqueIdentifierGenerator.generateUniqueIdentifier();
            JSONObject serverObj = new JSONObject();
            serverObj.put("hello", mUid);
            CBORObject encodeObj = CBORObject.FromJSONString(serverObj.toString());
            mWebSocket.broadcast(encodeObj.EncodeToBytes());
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void onMessage(byte[] receiveByte) {

        try {
            /*receive*/
                /*export type WsClient = {
                  authenticate?: Uint8Array;
                  setName?: string;
                  setCursor?: [number, number] | null;
                  setFocus?: number | null;
                  create?: [number, number];
                  close?: Sid;
                  move?: [Sid, WsWinsize | null];
                  data?: [Sid, Uint8Array, bigint];
                  subscribe?: [Sid, number];
                  chat?: string;
                  ping?: bigint;
                };
                */
            if (receiveByte.length == 0) {
                return;
            }
            CBORObject decodeObj = CBORObject.DecodeFromBytes(receiveByte);
            LOGGER.d(decodeObj.ToJSONString());
            JSONObject clientInfo = new JSONObject(decodeObj.ToJSONString());
            if (clientInfo.has("authenticate")){
                String authenticate = clientInfo.optString("authenticate");
                LOGGER.d("authenticate: " + authenticate);
                mAuthenticate = authenticate;
                sendCborObj("shells", mShells);

                if (mReconnectMark){
                    setReconnectMark(false);
                    reConnectShells();
                }

            }else if (clientInfo.has("setName")){
                String name = clientInfo.optString("setName");
                LOGGER.d("setName: " + name);
                updateUser("name", name);
                //hello();

            }else if (clientInfo.has("setCursor")) {
                JSONArray cursor = clientInfo.optJSONArray("setCursor");
                LOGGER.d("setCursor: " + cursor);
                //updateUser("cursor", cursor);
            }else if (clientInfo.has("setFocus")) {
                int focus = clientInfo.optInt("setFocus");
                LOGGER.d("setFocus: " + focus);
                //updateUser("focus", focus);
            }else if (clientInfo.has("create")) {
                JSONArray create = clientInfo.optJSONArray("create");
                LOGGER.d("create: " + create);
                int row = (int) create.get(0);
                int col = (int) create.get(1);
                createPty(row, col);

            }else if (clientInfo.has("close")) {
                String close = clientInfo.optString("close");
                LOGGER.d("close: " + close);
                removeShells(close);
            }else if (clientInfo.has("move")) {
                JSONArray move = clientInfo.optJSONArray("move");
                LOGGER.d("move: " + move);
                if (move != null){
                    String sid = (String) move.get(0);
                    if (!move.get(1).toString().equals("null")){
                        JSONObject winSizeObj = (JSONObject) move.get(1);
                        //["11111",{"x":-231,"y":-198,"cols":32,"rows":80}]

                        resizePty(sid, winSizeObj.optInt("x"), winSizeObj.optInt("y"), winSizeObj.optInt("rows"), winSizeObj.optInt("cols"));
                    }
                }
            }else if (clientInfo.has("data")) {
                byte[] byteArray = decodeObj.get("data").get(1).GetByteString();
                String sid = decodeObj.get("data").get(0).AsString();
                LOGGER.d("data: " + decodeObj.ToJSONString());

                input(sid, byteArray);

            }else if (clientInfo.has("subscribe")) {
                JSONArray subscribe = clientInfo.optJSONArray("subscribe");
                LOGGER.d("subscribe: " + subscribe);
            }else if (clientInfo.has("chat")) {
                String chat = clientInfo.optString("chat");
                LOGGER.d("chat: " + chat);
            }else if (clientInfo.has("ping")) {
                long ping = clientInfo.optLong("ping");
                long current = System.currentTimeMillis();
                LOGGER.d("ping: " + ping + ", current: " + current);
                JSONObject serverObj = new JSONObject();
                serverObj.put("shellLatency", current - ping);
                CBORObject encodeObj = CBORObject.FromJSONString(serverObj.toString());
                mWebSocket.broadcast(encodeObj.EncodeToBytes());
                onPong(current);
            }

        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    private void updateUser(String key, Object value){
        if (mWsUser == null){
            mWsUser = new JSONObject();
        }
        try {
            mWsUser.put(key, value);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        //sendUsers();
    }

    private void sendUsers() {
        try {
            for (int i = 0; i < mUsers.length(); i++) {
                JSONArray user = mUsers.getJSONArray(i);
                if (user.get(0).equals(mUid)) {
                    user.remove(1);
                    user.put(1, mWsUser);
                    sendCborObj("users", mUsers);
                    return;
                }
            }
            mUsers.put(new JSONArray().put(mUid).put(mWsUser));
            sendCborObj("users", mUsers);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void onPong(long pong) {
        LOGGER.d("pong: " + pong);
        JSONObject serverObj = new JSONObject();
        try {
            serverObj.put("pong", pong);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        CBORObject encodeObj = CBORObject.FromJSONString(serverObj.toString());
        mWebSocket.broadcast(encodeObj.EncodeToBytes());
    }

    public void onClose() {
        LOGGER.d("onClose");
        ShellXWebSocketServer.getInstance(9090, false).reconnect();
    }

    public void onOpen() {
        LOGGER.d("onOpen");
    }

    public void setReconnectMark(boolean mark) {
        mReconnectMark = mark;
    }

    public void destroy() throws JSONException {
        for (int i = 0; i < mShells.length(); i++) {
            JSONArray shell = mShells.getJSONArray(i);
            String sid = shell.getString(0);
            PtyModule ptyModule = ptyModuleHashMap.get(sid);
            try {
                ptyModule.finalize();
            } catch (Throwable e) {
                e.printStackTrace();
            }
            mShells.remove(i);
            i--; // Adjust the index as we removed an element
        }
    }
}
