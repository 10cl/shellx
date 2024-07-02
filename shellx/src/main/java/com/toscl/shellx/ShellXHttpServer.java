package com.toscl.shellx;



import com.toscl.shellx.utils.Logger;
import com.toscl.shellx.utils.Util;

import org.json.JSONException;
import org.json.JSONObject;
import org.nanohttpd.protocols.http.IHTTPSession;
import org.nanohttpd.protocols.http.NanoHTTPD;
import org.nanohttpd.protocols.http.response.Response;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

import static org.nanohttpd.protocols.http.response.Response.newFixedLengthResponse;
import static org.nanohttpd.protocols.http.response.Status.INTERNAL_ERROR;
import static org.nanohttpd.protocols.http.response.Status.NOT_FOUND;
import static org.nanohttpd.protocols.http.response.Status.OK;

public class ShellXHttpServer extends NanoHTTPD {
    private final static String TAG = "ShellXHttpServer";
    protected static final Logger LOGGER = new Logger(TAG);

    private static final String STATIC_DIR = "/data/local/tmp/build";
    private final boolean debug;
    private boolean webAccessMark = false;

    public ShellXHttpServer(int port, boolean debug) {
        super(port);
        this.debug = debug;
        unZipHttpBuild();
    }

    private void unZipHttpBuild() {
        if (debug)
            LOGGER.d("unZipHttpBuild");
        String zipFilePath = "/data/local/tmp/build.zip";
        String extractToPath = "/data/local/tmp/build/";

        if (Util.isFileExists(zipFilePath)) {
            Util.extractZip(zipFilePath, extractToPath);
            Util.deleteFile(zipFilePath);
        } else {
            LOGGER.d("Zip file does not exist.");
        }
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        LOGGER.d("uri: " + uri);
        if (uri.startsWith("/x/")) {
            uri = "/spa.html";
            if (!webAccessMark){
                webAccessMark = true;
                ShellXWebSocketServer.getInstance(9090, false).initPty();
                ShellXWebSocketServer.getInstance(9090, false).createWsServer();
            }
            ShellXWebSocketServer.getInstance(9090, false).setPtyReconnect();
        }else if (uri.equals("/")) {
            uri = "/index.html";
        }else if (uri.equals("/check")){
            JSONObject jsonObject = new JSONObject();
            try{
                jsonObject.put("status", 1);
            } catch (JSONException e) {
                e.printStackTrace();
            }

            return newFixedLengthResponse(OK, "application/json", jsonObject.toString());
        }else if (uri.equals("/stop")){
            ShellXWebSocketServer.getInstance(9090, false).destroy();
        }else if (uri.equals("/shell")){
            Map<String, List<String>> params = session.getParameters();
            if (params.size() > 0){
                List<String> command = params.get("command");
                if (command != null && !command.isEmpty())
                    ShellXWebSocketServer.getInstance(9090, false).execute(command.get(0));

                LOGGER.d("parameters: " + session.getParameters());
            }
            return newFixedLengthResponse(OK, "application/json", "{result: 'success'}");
        }

        File file = new File(STATIC_DIR + uri);
        if (!file.exists() || file.isDirectory()) {
            LOGGER.d("file path： " + file.getAbsolutePath());
            return newFixedLengthResponse(NOT_FOUND, NanoHTTPD.MIME_PLAINTEXT, "Not Found");
        }

        try {
            String mimeType = Util.getMimeTypeForFile(uri);
            if (debug)
                LOGGER.d("uri: " + uri + ", file: " + file.getAbsolutePath() + ", mime type: " + mimeType);

            FileInputStream fileInputStream = new FileInputStream(file);
            return newFixedLengthResponse(OK, mimeType, fileInputStream, file.length());
        } catch (IOException e) {
            e.printStackTrace();
            return newFixedLengthResponse(INTERNAL_ERROR, NanoHTTPD.MIME_PLAINTEXT, "Internal Error");
        }
    }

}