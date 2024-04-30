package com.toscl.shellx;

import com.upokecenter.cbor.CBORObject;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

/**
 * The type Pty module.
 */
public final class PtyModule {

    private final Object connectionLock = new Object();
    private String terminalString = "xterm";

    public PtyProcess getProc() {
        return proc;
    }

    public void setProc(PtyProcess proc) {
        this.proc = proc;
    }

    private PtyProcess proc = null;
    private final OutputStream input = new OutputStream() {
        @Override
        public void write(int b) throws IOException {
            if (proc == null) {
                return;
            }
            proc.getOutputStream().write(b);
        }

        @Override
        public void write(byte[] b) throws IOException {
            if (proc == null) {
                return;
            }
            proc.getOutputStream().write(b);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            if (proc == null) {
                return;
            }
            proc.getOutputStream().write(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            if (proc == null) {
                return;
            }
            proc.getOutputStream().flush();
        }

        @Override
        public void close() throws IOException {
            if (proc == null) {
                return;
            }
            proc.getOutputStream().close();
        }
    };
    private OutputStream output = null;
    private Thread readerThread = null;

    private final class ProcOutputR implements Runnable {
        private final byte[] buf = new byte[8192];
        private final InputStream stream;

        ProcOutputR(final InputStream stream) {
            this.stream = stream;
        }

        @Override
        public void run() {
            while (true) {
                try {
                    final int len = stream.read(buf);
                    if (len < 0) {
                        return;
                    }
                    output.write(buf, 0, len);
                } catch (final IOException e) {
                    return;
                }
            }
        }
    }

    public String getExecute() {
        return execute;
    }

    public void setExecute(String execute) {
        this.execute = execute;
    }

    private String execute = "";

    public void setOutputStream(final OutputStream stream) {
        output = stream;
    }

    public OutputStream getOutputStream() {
        return input;
    }

    public boolean isConnected() {
        return proc != null;
    }

    public void connect() {
        final Map<String, String> env = new HashMap<>(System.getenv());
        env.put("TERM", terminalString);
        synchronized (connectionLock) {
            proc = PtyProcess.system(execute, env);
            readerThread = new Thread(new ProcOutputR(proc.getInputStream()));
            readerThread.setDaemon(true);
            readerThread.start();
        }
    }

    public void disconnect() {
        synchronized (connectionLock) {
            final Process p = proc;
            if (p == null) {
                return;
            }
            proc = null;
            p.destroy();
            try {
                p.waitFor();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            try {
                readerThread.join();
            } catch (final InterruptedException ignored) {
            }
            readerThread = null;
        }
    }

    public void resize(final int col, final int row, final int wp, final int hp) {
        try {
            proc.resize(col, row, wp, hp);
        } catch (final IOException ignored) {
        }
    }


    @Override
    protected void finalize() throws Throwable {
        disconnect();
        super.finalize();
    }
}
