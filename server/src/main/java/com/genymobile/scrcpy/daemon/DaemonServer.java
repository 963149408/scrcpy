package com.genymobile.scrcpy.daemon;

import android.os.Looper;

import com.genymobile.scrcpy.Options;
import com.genymobile.scrcpy.daemon.display.VirtualDisplayRegistry;
import com.genymobile.scrcpy.daemon.display.DisplaySurfaceBroker;
import com.genymobile.scrcpy.daemon.net.TcpDesktopConnection;
import com.genymobile.scrcpy.daemon.net.TcpServerSocketListener;
import com.genymobile.scrcpy.daemon.video.FrameBroadcasterRegistry;
import com.genymobile.scrcpy.util.Ln;

import java.io.IOException;
import java.net.Socket;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public final class DaemonServer {

    private static final int MAX_SESSIONS = 16;

    /** Socket read timeout (ms) applied to all accepted sockets.
     *  Protects acceptLoop and per-session recv loops from indefinite
     *  blocking on half-open connections. The value is long enough that
     *  legitimate SLOW commands (create VD, list apps, start activity)
     *  can still run end-to-end, but short enough to break a dead socket
     *  within an operational window. */
    private static final int SOCKET_READ_TIMEOUT_MS = 60_000;

    /** How long (ms) an IP stays locked out after a failed authentication.
     *  Previously the blacklist was permanent for the lifetime of the daemon
     *  process: a single wrong password (a typo, or a stale password cached on
     *  the client) locked that peer out forever, and every later attempt was
     *  accepted then closed instantly — which looks like a random "connects but
     *  nothing happens" failure. A timed lockout keeps the brute-force defense
     *  while making the failure recoverable without restarting the server. */
    private static final long BLACKLIST_TTL_MS = 5 * 60_000L;

    private final Options options;
    private final DaemonOptions daemonOptions;
    private final String[] baseArgs;

    private final Map<Integer, ClientSession> sessions = new ConcurrentHashMap<>();
    private final AtomicInteger nextSessionId = new AtomicInteger(1);
    private final AtomicBoolean running = new AtomicBoolean(true);

    private final VirtualDisplayRegistry registry;
    private final DisplaySurfaceBroker surfaceBroker;
    private final DaemonExitCoordinator exitCoordinator;
    private final FrameBroadcasterRegistry broadcasterRegistry;

    private final String secretToken;
    /** ip -> epoch millis until which the IP is locked out (expired entries are
     *  purged lazily, so this map only ever holds currently-active lockouts). */
    private final Map<String, Long> blacklistedIps = new ConcurrentHashMap<>();

    private ExecutorService acceptExecutor;
    private ExecutorService clientExecutor;

    public DaemonServer(Options options, DaemonOptions daemonOptions, String[] baseArgs) {
        this.options = options;
        this.daemonOptions = daemonOptions;
        this.baseArgs = baseArgs;
        this.registry = new VirtualDisplayRegistry();
        this.surfaceBroker = new DisplaySurfaceBroker(registry);
        this.exitCoordinator = new DaemonExitCoordinator(this);
        this.broadcasterRegistry = new FrameBroadcasterRegistry(surfaceBroker);

        String token = daemonOptions.getSecretToken();
        if ("auto".equalsIgnoreCase(token)) {
            token = java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16);
            Ln.i(">>> AUTOMATIC DAEMON SECRET TOKEN GENERATED: " + token + " <<<");
        }
        this.secretToken = token;
    }

    public void run() throws IOException {
        Ln.i("DaemonServer starting on port " + daemonOptions.getPort() + ", bind=" + daemonOptions.getBindAddress());

        try {
            TcpServerSocketListener.initServerSocket(options.getScid(), daemonOptions.getPort(), daemonOptions.getBindAddress());

            acceptExecutor = Executors.newSingleThreadExecutor(r -> {
                Thread t = new Thread(r, "daemon-accept");
                t.setDaemon(true);
                return t;
            });
            clientExecutor = Executors.newFixedThreadPool(MAX_SESSIONS, r -> {
                Thread t = new Thread(() -> {
                    Looper.prepare();
                    r.run();
                }, "daemon-client");
                t.setDaemon(true);
                return t;
            });

            acceptExecutor.submit(this::acceptLoop);

            try {
                synchronized (running) {
                    while (running.get()) {
                        running.wait();
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        } finally {
            shutdown();
        }
    }

    private void acceptLoop() {
        Ln.i("DaemonServer accept loop started");
        while (running.get()) {
            try {
                Socket socket = TcpServerSocketListener.acceptNextSocket();
                long acceptedAt = System.currentTimeMillis();
                String remote = String.valueOf(socket.getRemoteSocketAddress());
                Ln.i("CONN accept: socket from " + remote + " (activeSessions=" + sessions.size()
                        + ", blacklisted=" + blacklistedIps.size() + ")");
                try {
                    socket.setSoTimeout(SOCKET_READ_TIMEOUT_MS);
                } catch (Exception ignored) {
                    // Some socket implementations may not support SO_TIMEOUT;
                    // continue without it — the accept path already has
                    // defense-in-depth against half-open connections.
                }
                String ip = socket.getInetAddress().getHostAddress();
                long lockRemainingMs = blacklistRemainingMs(ip);
                if (lockRemainingMs > 0) {
                    Ln.w("Connection rejected from blacklisted IP: " + ip);
                    Ln.w("CONN reject: blacklisted ip=" + ip + " remote=" + remote
                            + " — lockout expires in " + (lockRemainingMs / 1000) + "s,"
                            + " restart the daemon or wait it out");
                    socket.close();
                    continue;
                }
                int role;
                try {
                    role = TcpDesktopConnection.readSocketRole(socket);
                } catch (IOException e) {
                    Ln.w("Failed to read socket role: " + e.getMessage());
                    Ln.w("CONN reject: role read failed from " + remote + " after "
                            + (System.currentTimeMillis() - acceptedAt) + "ms — " + e.getMessage());
                    socket.close();
                    continue;
                }
                Ln.i("CONN role: " + roleName(role) + "(" + role + ") from " + remote
                        + " handshakeElapsed=" + (System.currentTimeMillis() - acceptedAt) + "ms");

                switch (role) {
                    case TcpDesktopConnection.ROLE_NEGOTIATION:
                        handleNegotiationSocket(socket);
                        break;
                    case TcpDesktopConnection.ROLE_CONTROL:
                        handleControlSocket(socket);
                        break;
                    case TcpDesktopConnection.ROLE_VIDEO:
                        handleVideoSocket(socket);
                        break;
                    case TcpDesktopConnection.ROLE_AUDIO:
                        handleAudioSocket(socket);
                        break;
                    default:
                        Ln.w("Unknown socket role: " + role);
                        Ln.w("CONN reject: unknown role=" + role + " remote=" + remote);
                        socket.close();
                }
            } catch (IOException e) {
                if (running.get()) {
                    Ln.w("Accept loop error: " + e.getMessage());
                }
            }
        }
        Ln.i("DaemonServer accept loop exited");
    }

    private static String roleName(int role) {
        switch (role) {
            case TcpDesktopConnection.ROLE_VIDEO:
                return "VIDEO";
            case TcpDesktopConnection.ROLE_AUDIO:
                return "AUDIO";
            case TcpDesktopConnection.ROLE_CONTROL:
                return "CONTROL";
            case TcpDesktopConnection.ROLE_NEGOTIATION:
                return "NEGOTIATION";
            default:
                return "UNKNOWN";
        }
    }

    private void blacklist(String ip) {
        blacklistedIps.put(ip, System.currentTimeMillis() + BLACKLIST_TTL_MS);
    }

    /**
     * @return remaining lockout in ms, or 0 (and the entry is purged) if the IP
     *         is not locked out. Purging lazily keeps the map small without a
     *         background sweeper thread.
     */
    private long blacklistRemainingMs(String ip) {
        Long until = blacklistedIps.get(ip);
        if (until == null) {
            return 0;
        }
        long remaining = until - System.currentTimeMillis();
        if (remaining <= 0) {
            blacklistedIps.remove(ip, until);
            Ln.i("CONN blacklist: lockout expired for ip=" + ip + ", accepting again");
            return 0;
        }
        return remaining;
    }

    private void handleNegotiationSocket(Socket socket) {
        // Atomically reserve a session id in [1, Integer.MAX_VALUE]; wrap to 1
        // on overflow. getAndUpdate is atomic, unlike the previous
        // getAndIncrement + non-atomic reset-to-1 which could let two
        // concurrent callers both pick the same (possibly 0 or negative) id.
        int sessionId = nextSessionId.getAndUpdate(prev -> prev >= Integer.MAX_VALUE ? 1 : prev + 1);
        String remote = String.valueOf(socket.getRemoteSocketAddress());
        Ln.i("CONN nego: assigned sessionId=" + sessionId + " remote=" + remote
                + " auth=" + (secretToken != null ? "required" : "none"));

        try {
            TcpDesktopConnection.writeSessionId(socket, sessionId);
            Ln.i("CONN nego: sessionId=" + sessionId + " written to client, waiting for"
                    + (secretToken != null ? " token verification" : " device meta"));
        } catch (IOException e) {
            Ln.w("Failed to write sessionId: " + e.getMessage());
            Ln.w("CONN nego: ABORT sessionId=" + sessionId + " remote=" + remote
                    + " — failed to write sessionId: " + e.getMessage());
            try { socket.close(); } catch (IOException closeEx) {
                Ln.d("Failed to close negotiation socket after sessionId write failure: " + closeEx.getMessage());
            }
            return;
        }

        if (secretToken != null) {
            long authStart = System.currentTimeMillis();
            try {
                if (!authenticate(socket, secretToken)) {
                    String ip = socket.getInetAddress().getHostAddress();
                    blacklist(ip);
                    Ln.w("Authentication failed for IP: " + ip + ". IP blacklisted for "
                            + (BLACKLIST_TTL_MS / 1000) + "s.");
                    Ln.w("CONN auth: FAILED sessionId=" + sessionId + " ip=" + ip
                            + " elapsed=" + (System.currentTimeMillis() - authStart) + "ms — ip blacklisted for "
                            + (BLACKLIST_TTL_MS / 1000) + "s");
                    try { socket.close(); } catch (IOException ignored) {}
                    return;
                }
                Ln.i("CONN auth: OK sessionId=" + sessionId + " ip="
                        + socket.getInetAddress().getHostAddress()
                        + " elapsed=" + (System.currentTimeMillis() - authStart) + "ms");
            } catch (Exception e) {
                String ip = socket.getInetAddress().getHostAddress();
                blacklist(ip);
                Ln.w("Authentication error for IP: " + ip + ". IP blacklisted for "
                        + (BLACKLIST_TTL_MS / 1000) + "s. Error: " + e.getMessage());
                Ln.w("CONN auth: ERROR sessionId=" + sessionId + " ip=" + ip
                        + " elapsed=" + (System.currentTimeMillis() - authStart) + "ms — " + e.getMessage());
                try { socket.close(); } catch (IOException ignored) {}
                return;
            }
        }

        ClientSession session;
        try {
            session = new ClientSession(socket, sessionId, options, baseArgs, registry, surfaceBroker, exitCoordinator, this, broadcasterRegistry);
        } catch (IOException e) {
            Ln.w("Failed to create client session: " + e.getMessage());
            Ln.w("CONN nego: ABORT sessionId=" + sessionId + " remote=" + remote
                    + " — ClientSession ctor failed: " + e.getMessage());
            try { socket.close(); } catch (IOException closeEx) {
                Ln.d("Failed to close negotiation socket after session creation failure: " + closeEx.getMessage());
            }
            return;
        }

        sessions.put(sessionId, session);
        Ln.i("DaemonServer: new negotiation session " + sessionId + " from " + socket.getRemoteSocketAddress());
        Ln.i("CONN nego: sessionId=" + sessionId + " registered (activeSessions=" + sessions.size()
                + "), submitting to client executor");

        try {
            clientExecutor.submit(session);
        } catch (RejectedExecutionException e) {
            // Executor was shut down between accept and submit (during daemon
            // shutdown). Remove the map entry and tear down the session so the
            // socket does not leak.
            Ln.w("DaemonServer: rejected session " + sessionId + " (executor shut down?), cleaning up");
            Ln.w("CONN nego: REJECT sessionId=" + sessionId + " — client executor shut down");
            sessions.remove(sessionId);
            session.shutdown();
        }
    }

    private void handleControlSocket(Socket socket) {
        try {
            int sessionId = TcpDesktopConnection.readSessionId(socket);
            int displayId = TcpDesktopConnection.readDisplayId(socket);
            Ln.i("CONN control: sessionId=" + sessionId + " displayId=" + displayId
                    + " remote=" + socket.getRemoteSocketAddress());
            ClientSession session = sessions.get(sessionId);
            if (session == null) {
                Ln.w("Control socket for unknown session " + sessionId);
                Ln.w("CONN control: REJECT sessionId=" + sessionId + " displayId=" + displayId
                        + " — unknown session (activeSessions=" + sessions.keySet() + ")");
                socket.close();
                return;
            }
            session.onControlSocket(displayId, socket);
            Ln.i("CONN control: sessionId=" + sessionId + " displayId=" + displayId + " dispatched to session");
        } catch (IOException e) {
            Ln.w("Failed to handle control socket: " + e.getMessage());
            Ln.w("CONN control: ERROR reading handshake — " + e.getMessage());
            try { socket.close(); } catch (IOException closeEx) {
                Ln.d("Failed to close control socket after handling error: " + closeEx.getMessage());
            }
        }
    }

    private void handleVideoSocket(Socket socket) {
        try {
            int sessionId = TcpDesktopConnection.readSessionId(socket);
            int displayId = TcpDesktopConnection.readDisplayId(socket);
            Ln.i("CONN video: sessionId=" + sessionId + " displayId=" + displayId
                    + " remote=" + socket.getRemoteSocketAddress());
            ClientSession session = sessions.get(sessionId);
            if (session == null) {
                Ln.w("Video socket for unknown session " + sessionId);
                Ln.w("CONN video: REJECT sessionId=" + sessionId + " displayId=" + displayId
                        + " — unknown session (activeSessions=" + sessions.keySet() + ")");
                socket.close();
                return;
            }
            session.onVideoSocket(displayId, socket);
            Ln.i("CONN video: sessionId=" + sessionId + " displayId=" + displayId + " dispatched to session");
        } catch (IOException e) {
            Ln.w("Failed to handle video socket: " + e.getMessage());
            Ln.w("CONN video: ERROR reading handshake — " + e.getMessage());
            try { socket.close(); } catch (IOException closeEx) {
                Ln.d("Failed to close video socket after handling error: " + closeEx.getMessage());
            }
        }
    }

    private void handleAudioSocket(Socket socket) {
        try {
            int sessionId = TcpDesktopConnection.readSessionId(socket);
            int displayId = TcpDesktopConnection.readDisplayId(socket);
            Ln.i("CONN audio: sessionId=" + sessionId + " displayId=" + displayId
                    + " remote=" + socket.getRemoteSocketAddress());
            ClientSession session = sessions.get(sessionId);
            if (session == null) {
                Ln.w("Audio socket for unknown session " + sessionId);
                Ln.w("CONN audio: REJECT sessionId=" + sessionId + " displayId=" + displayId
                        + " — unknown session (activeSessions=" + sessions.keySet() + ")");
                socket.close();
                return;
            }
            session.onAudioSocket(displayId, socket);
            Ln.i("CONN audio: sessionId=" + sessionId + " displayId=" + displayId + " dispatched to session");
        } catch (IOException e) {
            Ln.w("Failed to handle audio socket: " + e.getMessage());
            Ln.w("CONN audio: ERROR reading handshake — " + e.getMessage());
            try { socket.close(); } catch (IOException closeEx) {
                Ln.d("Failed to close audio socket after handling error: " + closeEx.getMessage());
            }
        }
    }

    private void shutdown() {
        Ln.i("DaemonServer shutting down, " + sessions.size() + " active sessions");

        for (ClientSession session : sessions.values()) {
            session.shutdown();
        }
        sessions.clear();

        if (broadcasterRegistry != null) {
            // Stop all encoders BEFORE destroying the virtual displays: a
            // running encoder's capture holds a reference to the VD surface.
            broadcasterRegistry.releaseAll();
        }

        if (registry != null) {
            registry.releaseAll();
        }

        if (acceptExecutor != null) {
            acceptExecutor.shutdown();
        }
        if (clientExecutor != null) {
            clientExecutor.shutdown();
        }

        TcpServerSocketListener.closeServerSocket();
    }

    public void requestExit() {
        running.set(false);
        synchronized (running) {
            running.notifyAll();
        }
    }

    void removeSession(int sessionId) {
        sessions.remove(sessionId);
        Ln.i("DaemonServer: session " + sessionId + " removed");
    }

    private boolean authenticate(Socket socket, String expectedToken) throws IOException {
        java.io.InputStream in = socket.getInputStream();
        int b1 = in.read();
        int b2 = in.read();
        int b3 = in.read();
        int b4 = in.read();
        if (b1 < 0 || b2 < 0 || b3 < 0 || b4 < 0) {
            return false;
        }
        int len = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4;
        if (len < 0 || len > 1024) {
            return false;
        }
        byte[] buf = new byte[len];
        int read = 0;
        while (read < len) {
            int r = in.read(buf, read, len - read);
            if (r < 0) {
                return false;
            }
            read += r;
        }
        String clientToken = new String(buf, java.nio.charset.StandardCharsets.UTF_8);
        return expectedToken.equals(clientToken);
    }
}
