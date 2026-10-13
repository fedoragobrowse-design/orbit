import { createServer, type Server, type Socket } from "node:net";
import { mkdirSync, rmSync } from "node:fs";
import { rm } from "node:fs/promises";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import * as pty from "node-pty";
import type { IPty } from "node-pty";

// ---------------------------------------------------------------------------
// Environment contract (never trust the network: bearer + socket only).
// ---------------------------------------------------------------------------
const SOCKET_PATH = process.env.EXEC_HOST_SOCKET ?? "/run/orbit-exec-host.sock";
const TOKEN_SECRET = process.env.EXEC_HOST_TOKEN_SECRET ?? "";
const WORKSPACE_ROOT = process.env.EXEC_HOST_WORKSPACE_ROOT ?? "/var/lib/orbit/sessions";
const IDLE_TIMEOUT_MS = Number(process.env.EXEC_HOST_IDLE_TIMEOUT_SECS ?? "900") * 1000;
const MAX_SESSIONS = Number(process.env.EXEC_HOST_MAX_SESSIONS ?? "64");
const TOKEN_TTL_MS = Number(process.env.EXEC_HOST_TOKEN_TTL_SECS ?? "60") * 1000;
const SHELL = process.env.EXEC_HOST_SHELL ?? "/bin/sh";
const COLS = Number(process.env.EXEC_HOST_COLS ?? "80");
const ROWS = Number(process.env.EXEC_HOST_ROWS ?? "24");

if (!TOKEN_SECRET) {
  console.error("FATAL: EXEC_HOST_TOKEN_SECRET is not set; refusing to start");
  process.exit(1);
}

type Frame = Record<string, unknown>;

interface TokenRecord {
  sessionId: string;
  expiresAt: number;
}

interface Session {
  id: string;
  pty: IPty;
  dir: string;
  lastActivity: number;
  dead: boolean;
  /** Live sockets subscribed to this session's output. */
  subscribers: Set<Socket>;
}

const pendingTokens = new Map<string, TokenRecord>();
const sessions = new Map<string, Session>();

function frame(socket: Socket, frame: Frame): void {
  socket.write(`${JSON.stringify(frame)}\n`);
}

function error(socket: Socket, id: string | undefined, message: string): void {
  frame(socket, { error: message, id, ok: false });
}

/** Constant-time bearer comparison against the Rust-minted shared secret. */
function bearerValid(token: string): boolean {
  if (token.length !== TOKEN_SECRET.length || token.length === 0) return false;
  let diff = 0;
  for (let i = 0; i < token.length; i++) {
    diff |= token.charCodeAt(i) ^ TOKEN_SECRET.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Mint a short-lived single-use claim ticket. Called over the private Unix
 * socket by the Rust server (already owner-authenticated); the real shell
 * spawns only after the WebSocket/HTTP layer redeems this token — never on
 * a bare spawn request.
 */
export function mintToken(sessionId: string): string {
  const token = randomUUID();
  pendingTokens.set(token, { expiresAt: Date.now() + TOKEN_TTL_MS, sessionId });
  return token;
}

/** Resolve a session workspace dir; rejects escapes outside the root. */
export function sessionDir(sessionId: string): string {
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(sessionId)) {
    throw new Error("invalid session id");
  }
  const root = resolve(WORKSPACE_ROOT);
  const dir = resolve(join(root, sessionId));
  if (dir !== join(root, sessionId) || !dir.startsWith(`${root}/`)) {
    throw new Error("session path escape");
  }
  return dir;
}

/** Kill an entire session process group (negative pgid). Never the host. */
function killTree(session: Session, signal: NodeJS.Signals = "SIGKILL"): void {
  try {
    // pty.pid is the session leader; spawned setsid so -pid is the group.
    process.kill(-session.pty.pid, signal);
  } catch {
    try {
      session.pty.kill(signal);
    } catch {
      /* already dead */
    }
  }
}

function destroySession(id: string): void {
  const session = sessions.get(id);
  if (!session || session.dead) return;
  session.dead = true;
  sessions.delete(id);
  for (const socket of session.subscribers) {
    try {
      frame(socket, { event: "exit", id, ok: true });
    } catch {
      /* subscriber gone */
    }
  }
  session.subscribers.clear();
  killTree(session);
  try {
    session.pty.kill("SIGKILL");
  } catch {
    /* already dead */
  }
  // Best-effort workspace cleanup; never throws into the request path.
  void rm(session.dir, { force: true, recursive: true });
}

/** Close sessions idle longer than the expiry window (default 15 min). */
function reapIdle(): void {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.lastActivity > IDLE_TIMEOUT_MS) {
      destroySession(id);
    }
  }
  for (const [token, record] of pendingTokens) {
    if (record.expiresAt <= now) pendingTokens.delete(token);
  }
}

function touch(session: Session): void {
  session.lastActivity = Date.now();
}

function handleSpawn(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const requestedId = typeof msg.sessionId === "string" ? msg.sessionId : randomUUID();
  const cols = typeof msg.cols === "number" ? Math.min(Math.max(msg.cols, 20), 512) : COLS;
  const rows = typeof msg.rows === "number" ? Math.min(Math.max(msg.rows, 5), 256) : ROWS;
  const bearer = typeof msg.bearer === "string" ? msg.bearer : "";
  if (!bearerValid(bearer)) return error(socket, id, "forbidden");

  // Admission control before any spawn.
  if (sessions.has(requestedId)) return error(socket, id, "session exists");
  if (sessions.size >= MAX_SESSIONS) return error(socket, id, "too many sessions");

  let dir: string;
  try {
    dir = sessionDir(requestedId);
  } catch {
    return error(socket, id, "invalid session id");
  }
  try {
    mkdirSync(dir, { mode: 0o700, recursive: true });
  } catch {
    return error(socket, id, "workspace unavailable");
  }

  // setsid: the child leads its own process group so killTree (-pgid) can
  // only ever reach descendants of this session, never host processes.
  // No Docker socket, no host mounts: cwd is confined to the session dir.
  let term: IPty;
  try {
    term = pty.spawn(SHELL, [], {
      cols,
      cwd: dir,
      env: {
        HOME: dir,
        LANG: "C.UTF-8",
        PATH: "/usr/bin:/bin",
        TERM: "xterm-256color",
      } as Record<string, string>,
      name: "xterm-256color",
      rows,
      useConpty: false,
    });
  } catch {
    return error(socket, id, "spawn failed");
  }

  const session: Session = {
    dead: false,
    dir,
    id: requestedId,
    lastActivity: Date.now(),
    pty: term,
    subscribers: new Set(),
  };
  sessions.set(requestedId, session);

  term.onData((data: string) => {
    touch(session);
    const out = JSON.stringify({ data, event: "output", id: requestedId, ok: true });
    for (const subscriber of session.subscribers) {
      try {
        subscriber.write(`${out}\n`);
      } catch {
        session.subscribers.delete(subscriber);
      }
    }
  });
  term.onExit(() => destroySession(requestedId));

  session.subscribers.add(socket);
  socket.on("close", () => session.subscribers.delete(socket));
  const token = mintToken(requestedId);
  frame(socket, { id, ok: true, sessionId: requestedId, token });
}

function handleInput(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const sessionId = msg.sessionId;
  const token = msg.token;
  if (typeof sessionId !== "string" || typeof token !== "string") {
    return error(socket, id, "sessionId and token required");
  }
  const claim = pendingTokens.get(token);
  if (!claim || claim.sessionId !== sessionId || claim.expiresAt <= Date.now()) {
    if (claim) pendingTokens.delete(token);
    return error(socket, id, "invalid or expired token");
  }
  pendingTokens.delete(token);
  const session = sessions.get(sessionId);
  if (!session || session.dead) return error(socket, id, "no such session");
  touch(session);

  if (typeof msg.cols === "number" || typeof msg.rows === "number") {
    const cols = typeof msg.cols === "number" ? Math.min(Math.max(msg.cols, 20), 512) : COLS;
    const rows = typeof msg.rows === "number" ? Math.min(Math.max(msg.rows, 5), 256) : ROWS;
    try {
      session.pty.resize(cols, rows);
    } catch {
      /* resize on a dying pty is harmless */
    }
  }
  if (typeof msg.data === "string" && msg.data.length > 0) {
    if (msg.data.length > 65536) return error(socket, id, "input too large");
    try {
      session.pty.write(msg.data);
    } catch {
      return error(socket, id, "session closed");
    }
  }
  session.subscribers.add(socket);
  socket.on("close", () => session.subscribers.delete(socket));
  frame(socket, { id, ok: true, sessionId });
}

function handleResize(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const session = typeof msg.sessionId === "string" ? sessions.get(msg.sessionId) : undefined;
  if (!session || session.dead) return error(socket, id, "no such session");
  if (typeof msg.cols !== "number" || typeof msg.rows !== "number") {
    return error(socket, id, "cols and rows required");
  }
  touch(session);
  try {
    session.pty.resize(
      Math.min(Math.max(msg.cols, 20), 512),
      Math.min(Math.max(msg.rows, 5), 256),
    );
  } catch {
    return error(socket, id, "session closed");
  }
  frame(socket, { id, ok: true, sessionId: session.id });
}

function handleSignal(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const session = typeof msg.sessionId === "string" ? sessions.get(msg.sessionId) : undefined;
  if (!session || session.dead) return error(socket, id, "no such session");
  const signal = msg.signal === "SIGTERM" || msg.signal === "SIGINT" ? msg.signal : "SIGKILL";
  touch(session);
  killTree(session, signal);
  frame(socket, { id, ok: true, sessionId: session.id });
}

function handleStop(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const session = typeof msg.sessionId === "string" ? sessions.get(msg.sessionId) : undefined;
  if (!session) return error(socket, id, "no such session");
  destroySession(session.id);
  frame(socket, { id, ok: true, sessionId: session.id });
}

function handleAttach(socket: Socket, msg: Frame): void {
  const id = typeof msg.id === "string" ? msg.id : undefined;
  const session = typeof msg.sessionId === "string" ? sessions.get(msg.sessionId) : undefined;
  if (!session || session.dead) return error(socket, id, "no such session");
  touch(session);
  session.subscribers.add(socket);
  socket.on("close", () => session.subscribers.delete(socket));
  frame(socket, { id, ok: true, sessionId: session.id });
}

function handleMessage(socket: Socket, line: string): void {
  let msg: Frame;
  try {
    const parsed: unknown = JSON.parse(line);
    if (typeof parsed !== "object" || parsed === null) throw new Error("bad frame");
    msg = parsed as Frame;
  } catch {
    return error(socket, undefined, "invalid JSON frame");
  }
  if (typeof msg.op !== "string") return error(socket, undefined, "op required");
  switch (msg.op) {
    case "spawn":
      handleSpawn(socket, msg);
      break;
    case "input":
      handleInput(socket, msg);
      break;
    case "resize":
      handleResize(socket, msg);
      break;
    case "signal":
      handleSignal(socket, msg);
      break;
    case "stop":
      handleStop(socket, msg);
      break;
    case "attach":
      handleAttach(socket, msg);
      break;
    case "ping":
      frame(socket, {
        id: typeof msg.id === "string" ? msg.id : undefined,
        ok: true,
        sessions: sessions.size,
      });
      break;
    default:
      error(socket, typeof msg.id === "string" ? msg.id : undefined, "unknown op");
      break;
  }
}

export function startServer(socketPath: string = SOCKET_PATH): Server {
  mkdirSync(resolve(WORKSPACE_ROOT), { mode: 0o700, recursive: true });
  // Reclaim a stale socket file left by an unclean shutdown. If a live
  // server holds the path, listen() below fails with EADDRINUSE instead.
  try {
    rmSync(socketPath, { force: true });
  } catch {
    /* listen() reports the real error */
  }
  const server = createServer((socket: Socket) => {
    socket.setEncoding("utf8");
    let buffer = "";
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      // 1 MiB cap per connection: PTY input is chunked by the client.
      if (buffer.length > 1024 * 1024) {
        error(socket, undefined, "frame too large");
        socket.destroy();
        return;
      }
      let newline: number;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length > 0) handleMessage(socket, line);
      }
    });
    socket.on("error", () => {
      for (const session of sessions.values()) session.subscribers.delete(socket);
    });
    socket.on("close", () => {
      for (const session of sessions.values()) session.subscribers.delete(socket);
    });
  });
  const reaper = setInterval(reapIdle, 60_000);
  reaper.unref();
  server.on("close", () => clearInterval(reaper));
  server.listen(socketPath, () => {
    console.log(`orbit-execution-host listening on ${socketPath}`);
  });
  return server;
}

if (process.env.EXEC_HOST_STANDALONE !== "0") {
  startServer();
}
