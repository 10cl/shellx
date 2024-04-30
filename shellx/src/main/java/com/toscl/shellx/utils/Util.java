package com.toscl.shellx.utils;

import android.content.Context;
import android.content.res.Resources;
import android.util.Log;


import org.nanohttpd.protocols.http.NanoHTTPD;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Util {
    private static final String TAG = "Util";
    protected static final Logger LOGGER = new Logger(TAG);

    private static final Map<String, String> MIME_TYPES = new HashMap<String, String>() {{
        put("css", "text/css");
        put("htm", "text/html");
        put("html", "text/html");
        put("xml", "text/xml");
        put("java", "text/x-java-source, text/java");
        put("md", "text/plain");
        put("txt", "text/plain");
        put("asc", "text/plain");
        put("gif", "image/gif");
        put("jpg", "image/jpeg");
        put("jpeg", "image/jpeg");
        put("png", "image/png");
        put("svg", "image/svg+xml");
        put("mp3", "audio/mpeg");
        put("m3u", "audio/mpeg-url");
        put("mp4", "video/mp4");
        put("ogv", "video/ogg");
        put("flv", "video/x-flv");
        put("mov", "video/quicktime");
        put("swf", "application/x-shockwave-flash");
        put("js", "application/javascript");
        put("pdf", "application/pdf");
        put("doc", "application/msword");
        put("ogg", "application/x-ogg");
        put("zip", "application/octet-stream");
        put("exe", "application/octet-stream");
        put("class", "application/octet-stream");
        put("m3u8", "application/vnd.apple.mpegurl");
        put("ts", "video/mp2t");
    }};


    public static String getMimeTypeForFile(String uri) {
        int dot = uri.lastIndexOf('.');
        String mime = null;
        if (dot >= 0) {
            mime = MIME_TYPES.get(uri.substring(dot + 1).toLowerCase());
        }
        return mime == null ? "application/octet-stream" : mime;
    }

    public static String byteBufferToString(ByteBuffer buffer) {
        Charset charset = null;
        CharsetDecoder decoder = null;
        CharBuffer charBuffer = null;
        try {
            charset = StandardCharsets.UTF_8;
            decoder = charset.newDecoder();
            charBuffer = decoder.decode(buffer.asReadOnlyBuffer());

            return charBuffer.toString();

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return "";
    }

    public static boolean isFileExists(String filePath) {
        File file = new File(filePath);
        return file.exists();
    }

    public static File writeRawZipToFile(InputStream inputStream, File outFile) throws IOException {
        try (OutputStream outputStream = new FileOutputStream(outFile)) {
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) > 0) {
                outputStream.write(buffer, 0, length);
            }
        } finally {
            inputStream.close();
        }

        return outFile;
    }

    public static void extractZip(String zipFilePath, String extractToPath) {
        byte[] buffer = new byte[1024];

        try {
            File folder = new File(extractToPath);
            if (!folder.exists()) {
                folder.mkdirs();
            }

            ZipInputStream zipInputStream = new ZipInputStream(new FileInputStream(zipFilePath));
            ZipEntry zipEntry = zipInputStream.getNextEntry();

            while (zipEntry != null) {
                String fileName = zipEntry.getName();
                File newFile = new File(extractToPath + File.separator + fileName);

                if (!zipEntry.isDirectory()) {
                    FileOutputStream outputStream = new FileOutputStream(newFile);

                    int length;
                    while ((length = zipInputStream.read(buffer)) > 0) {
                        outputStream.write(buffer, 0, length);
                    }

                    outputStream.close();
                } else {
                    newFile.mkdirs();
                }

                zipEntry = zipInputStream.getNextEntry();
            }

            zipInputStream.closeEntry();
            zipInputStream.close();

            LOGGER.d("Zip file extracted successfully.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void deleteFile(String zipFilePath) {
        File file = new File(zipFilePath);
        if (file.exists()) {
            if (file.delete()) {
                LOGGER.d("File deleted successfully.");
            } else {
                LOGGER.d("Failed to delete the file.");
            }
        } else {
            LOGGER.d("File does not exist.");
        }
    }

    public static String executeShell(String shellCommand) throws IOException {
        StringBuilder stringBuffer = new StringBuilder();
        BufferedReader bufferedReader = null;
        try {
            Process pid = null;
            String[] cmd = { "/bin/sh", "-c", shellCommand };
            pid = Runtime.getRuntime().exec(cmd);
            if (pid != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(pid.getInputStream()), 1024);
                pid.waitFor();
            }
            String line = null;
            while (bufferedReader != null && (line = bufferedReader.readLine()) != null) {
                stringBuffer.append(line).append("\r\n");
            }
        } catch (Exception ioe) {
            stringBuffer.append("error");
        } finally {
            if (bufferedReader != null) {
                bufferedReader.close();
            }
        }
        return stringBuffer.toString();
    }

}
