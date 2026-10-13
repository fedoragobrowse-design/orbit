// orbit-browser-host — managed Chromium behind a private Unix socket.
//
// One browser singleton, one context+page per browser session. The Rust API
// server holds the socket; it never exposes this service on TCP. Frames are
// JPEG and flow only while a viewer or snapshot subscriber exists (max 2fps
// per session). Cookie/profile bytes are returned raw to the caller, which
// seals them as 30d artifacts — they never touch our disk or logs.
// Passwords: fill values for type=password fields are never echoed in
// replies, events, or logs — only selector names and value lengths.
import { createServer, type Socket } from "node:net";
import { mkdirSync, rmSync } from "node:fs";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { lookup as dnsLookup } from "node:dns";
import { isIP } from "node:net";
import { chromium, type Browser, type BrowserContext, type Page } from "playwright-core";

const SOCKET = process.env.BROWSER_HOST_SOCKET ?? "/run/orbit/browser-host.sock";
const TOKEN_SECRET = process.env.BROWSER_HOST_TOKEN_SECRET ?? "";
// Profile-gated session ceiling: Pi fits one live Chromium context on 2GiB,
// full keeps two. No other profile changes here — 2fps frames, launch flags,
// and nav limits are profile-independent.
const MAX_SESSIONS = process.env.ORBIT_PROFILE?.toLowerCase() === "pi" ? 1 : 2;
// JPEG frames: at most one in flight per 500ms per session (2fps cap).
const FRAME_MIN_INTERVAL_MS = 500;
const FRAME_QUALITY = 55;
const FRAME_MAX_WIDTH = 1280;
const NAV_TIMEOUT_MS = 30_000;
const BODY_LIMIT = 1 << 20; // 1 MiB per NDJSON line.

if (!TOKEN_SECRET) {
  console.error("BROWSER_HOST_TOKEN_SECRET is required");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// Egress screen: brokered web only. Loopback, private, link-local,
// unspecified, multicast, broadcast, 0/8, CGNAT-adjacent metadata hosts, and
// cloud metadata IPs resolve-deny before any navigation. DNS is re-resolved
// per navigation (rebinding guard): every resolved address must pass.
// Missing broker capability (no allowlisted origins configured on the
// session) is UNAVAILABLE — never a raw guest network.
// ---------------------------------------------------------------------------
const METADATA_IPS: Record<string, true> = { "169.254.169.254": true, "100.100.100.200": true, "fd00:ec2::254": true };
const BLOCKED_HOSTNAMES: Record<string, true> = { localhost: true, "metadata.google.internal": true, "metadata.goog": true };

function ipv4Blocked(parts: number[]): boolean {
  const [a, b] = parts;
  return (
    a === 10 || // RFC1918
    (a === 172 && b >= 16 && b <= 31) || // RFC1918
    (a === 192 && b === 168) || // RFC1918
    a === 127 || // loopback
    (a === 169 && b === 254) || // link-local + metadata
    a === 0 || // unspecified / 0/8 broadcast-adjacent
    a >= 224 || // multicast + broadcast
    (a === 100 && b >= 64 && b <= 127) // CGNAT (covers 100.100.100.200)
  );
}

function ipBlocked(ip: string): boolean {
  if (METADATA_IPS[ip.toLowerCase()] === true) return true;
  const v = isIP(ip);
  if (v === 4) {
    const parts = ip.split(".").map(Number);
    if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
    return ipv4Blocked(parts);
  }
  if (v === 6) {
    const lower = ip.toLowerCase();
    return (
      lower === "::1" ||
      lower === "::" ||
      lower.startsWith("fc") ||
      lower.startsWith("fd") || // unique-local
      lower.startsWith("fe80") || // link-local
      lower.startsWith("ff") || // multicast
      lower === "fd00:ec2::254"
    );
  }
  return true; // unparseable: fail closed.
}

function lookupAll(host: string): Promise<string[]> {
  const { promise, resolve, reject } = Promise.withResolvers<string[]>();
  dnsLookup(host, { all: true }, (err, addresses) => {
    if (err) reject(err);
    else resolve(addresses.map((a) => a.address));
  });
  return promise;
}

// Screen a navigation URL before dispatch AND on every redirect: http(s)
// only, no credentials, no literal blocked IP, hostname resolving only to
// allowed addresses, and origin covered by the session's brokered grant.
async function screenUrl(raw: string, allowedOrigins: Set<string>): Promise<{ origin: string }> {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new OpError("INVALID_URL", "navigation URL does not parse");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new OpError("EGRESS_DENY", "only http(s) navigation is brokered");
  }
  if (url.username !== "" || url.password !== "") {
    throw new OpError("EGRESS_DENY", "URLs with credentials are never navigated");
  }
  const host = url.hostname.toLowerCase();
  if (host === "" || host.length > 253 || BLOCKED_HOSTNAMES[host] === true) {
    throw new OpError("EGRESS_DENY", "host is not navigable");
  }
  // Literal-IP hosts: check directly (no DNS to rebind through).
  if (isIP(host) !== 0) {
    if (ipBlocked(host)) throw new OpError("EGRESS_DENY", "loopback/private/metadata addresses are never navigated");
  } else {
    // DNS-rebinding guard: resolve now and require EVERY address to pass.
    // Redirects re-enter this screen, so a record that flips to 127.0.0.1
    // mid-session is denied at the redirect, not trusted from first use.
    let addresses: string[];
    try {
      addresses = await lookupAll(host);
    } catch {
      throw new OpError("EGRESS_DENY", "host does not resolve");
    }
    if (addresses.length === 0 || addresses.some(ipBlocked)) {
      throw new OpError("EGRESS_DENY", "host resolves to a denied address");
    }
  }
  const origin = `${url.protocol}//${url.host}`;
  if (!allowedOrigins.has(origin)) {
    throw new OpError("EGRESS_DENY", "origin is outside this session's brokered grant");
  }
  return { origin };
}

class OpError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------
interface Session {
  id: string;
  token: string;
  context: BrowserContext;
  page: Page;
  url: string;
  title: string;
  loading: boolean;
  domRevision: number;
  origins: Set<string>;
  navStamps: number[];
  frameSubscribers: Set<Socket>;
  lastFrameAt: number;
  frameTimer: NodeJS.Timeout | undefined;
  frameInFlight: boolean;
  /** Last viewer/nav activity; drives the 5min idle reap (frame ticks don't count). */
  lastActivity: number;
}
let browser: Browser | null = null;
const sessions = new Map<string, Session>();

async function ensureBrowser(): Promise<Browser> {
  if (browser?.isConnected()) return browser;
  browser = await chromium.launch({
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--hide-scrollbars",
      "--mute-audio",
      // Pi 2GiB: cap each renderer heap (~256MB) so one live context plus
      // the browser process stays well under the host budget; full keeps
      // the default heap. Flags spread inside args (no extra processes).
      ...(process.env.ORBIT_PROFILE?.toLowerCase() === "pi"
        ? ["--js-flags=--max-old-space-size=256"]
        : []),
    ],
  });
  return browser;
}

function checkBearer(bearer: unknown): boolean {
  if (typeof bearer !== "string" || bearer === "") return false;
  const a = Buffer.from(bearer);
  const b = Buffer.from(TOKEN_SECRET);
  return a.length === b.length && timingSafeEqual(a, b);
}

function checkSession(id: unknown, token: unknown): Session | null {
  if (typeof id !== "string" || typeof token !== "string") return null;
  const session = sessions.get(id);
  if (!session) return null;
  const a = Buffer.from(token);
  const b = Buffer.from(session.token);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  return session;
}

function reply(socket: Socket, id: unknown, ok: boolean, payload: Record<string, unknown>): void {
  socket.write(`${JSON.stringify({ id, ok, ...payload })}\n`);
}

function sessionState(session: Session): Record<string, unknown> {
  return {
    sessionId: session.id,
    url: session.url,
    title: session.title,
    loading: session.loading,
    domRevision: session.domRevision,
  };
}

function wirePageEvents(session: Session): void {
  session.page.on("framenavigated", (frame) => {
    if (frame !== session.page.mainFrame()) return;
    session.url = session.page.url();
    session.domRevision += 1;
    broadcast(session, { event: "nav", sessionId: session.id, url: session.url, domRevision: session.domRevision });
    broadcast(session, { event: "url", sessionId: session.id, url: session.url });
  });
  session.page.on("load", () => {
    session.loading = false;
    session.title = "";
    void session.page.title().then(
      (title) => {
        session.title = title.slice(0, 256);
        broadcast(session, { event: "title", sessionId: session.id, title: session.title });
      },
      () => {},
    );
    broadcast(session, { event: "loading", sessionId: session.id, loading: false });
  });
  session.page.on("domcontentloaded", () => {
    session.domRevision += 1;
  });
}

function broadcast(session: Session, message: Record<string, unknown>): void {
  const line = `${JSON.stringify(message)}\n`;
  for (const subscriber of session.frameSubscribers) {
    subscriber.write(line);
  }
}

function maybeStartFrames(session: Session): void {
  if (session.frameTimer || session.frameSubscribers.size === 0) return;
  session.frameTimer = setInterval(() => {
    void captureFrame(session);
  }, FRAME_MIN_INTERVAL_MS);
  session.frameTimer.unref();
}

function stopFramesIfIdle(session: Session): void {
  if (session.frameSubscribers.size === 0 && session.frameTimer) {
    clearInterval(session.frameTimer);
    session.frameTimer = undefined;
  }
}

async function captureFrame(session: Session): Promise<void> {
  if (session.frameInFlight || session.frameSubscribers.size === 0) return;
  const now = Date.now();
  if (now - session.lastFrameAt < FRAME_MIN_INTERVAL_MS) return;
  session.frameInFlight = true;
  try {
    const buffer = await session.page.screenshot({ type: "jpeg", quality: FRAME_QUALITY });
    session.lastFrameAt = Date.now();
    broadcast(session, {
      event: "frame",
      sessionId: session.id,
      jpegBase64: buffer.toString("base64"),
    });
  } catch {
    // Page closing mid-capture is routine; drop the frame.
  } finally {
    session.frameInFlight = false;
  }
}

async function closeSession(session: Session): Promise<void> {
  sessions.delete(session.id);
  clearInterval(session.frameTimer);
  session.frameTimer = undefined;
  for (const subscriber of session.frameSubscribers) {
    try {
      subscriber.write(`${JSON.stringify({ event: "close", sessionId: session.id })}\n`);
    } catch {
      /* viewer gone */
    }
  }
  session.frameSubscribers.clear();
  await session.context.close().catch(() => {});
  // No sessions left: shut down Chromium itself so an idle host holds no
  // renderer processes. Next launch re-creates it lazily (existing path).
  if (sessions.size === 0 && browser) {
    try {
      await browser.close();
    } catch {
      /* already closing */
    }
    browser = null;
  }
}

// Idle reap: no viewer and no nav for 5 minutes closes the context (and
// Chromium itself when nothing remains). Proven by the API-side 5min sweep
// using the same window; recoverable state (row + events) survives there.
const IDLE_TIMEOUT_MS = Number(process.env.BROWSER_HOST_IDLE_TIMEOUT_SECS ?? "300") * 1000;
const IDLE_SWEEP_MS = 30_000;

function reapIdleSessions(): void {
  const now = Date.now();
  for (const session of [...sessions.values()]) {
    if (session.frameSubscribers.size === 0 && now - session.lastActivity > IDLE_TIMEOUT_MS) {
      void closeSession(session);
    }
  }
}

const idleSweeper = setInterval(reapIdleSessions, IDLE_SWEEP_MS);
idleSweeper.unref();

// ---------------------------------------------------------------------------
// Op dispatch (NDJSON over the Unix socket; one JSON object per line)
// ---------------------------------------------------------------------------
type Op =
  | { op: "ping" }
  | { op: "launch"; bearer?: unknown; sessionId?: unknown; origins?: unknown }
  | { op: "navigate"; sessionId?: unknown; token?: unknown; url?: unknown }
  | { op: "fill"; sessionId?: unknown; token?: unknown; selector?: unknown; fields?: unknown; submitSelector?: unknown }
  | { op: "snapshot"; sessionId?: unknown; token?: unknown }
  | { op: "cookies"; sessionId?: unknown; token?: unknown }
  | { op: "profile"; sessionId?: unknown; token?: unknown }
  | { op: "frames-start"; sessionId?: unknown; token?: unknown }
  | { op: "frames-stop"; sessionId?: unknown; token?: unknown }
  | { op: "close"; sessionId?: unknown; token?: unknown };

async function handleOp(socket: Socket, id: unknown, raw: Op): Promise<void> {
  switch (raw.op) {
    case "ping": {
      reply(socket, id, true, { sessions: sessions.size });
      return;
    }
    case "launch": {
      if (!checkBearer(raw.bearer)) {
        reply(socket, id, false, { error: "UNAUTHORIZED" });
        return;
      }
      if (sessions.size >= MAX_SESSIONS) {
        reply(socket, id, false, { error: "BROWSER_BUSY" });
        return;
      }
      // No broker grant, no browser: the session names its allowlisted
      // origins up front. Empty/missing = UNAVAILABLE, never raw net.
      const origins = Array.isArray(raw.origins) ? raw.origins.filter((o): o is string => typeof o === "string") : [];
      if (origins.length === 0 || origins.length > 16) {
        reply(socket, id, false, { error: "BROWSER_UNAVAILABLE" });
        return;
      }
      const requestedId = typeof raw.sessionId === "string" && raw.sessionId !== "" ? raw.sessionId : randomBytes(16).toString("hex");
      if (sessions.has(requestedId)) {
        reply(socket, id, false, { error: "SESSION_EXISTS" });
        return;
      }
      const owner = await ensureBrowser();
      const context = await owner.newContext({ viewport: { width: FRAME_MAX_WIDTH, height: 800 }, acceptDownloads: false });
      // Defense in depth with the per-navigation screen: route-level deny
      // for anything that smells like loopback/private/metadata, so even a
      // subframe or redirect that bypasses the op screen fails closed.
      await context.route("**/*", (route) => {
        const target = new URL(route.request().url());
        const host = target.hostname.toLowerCase();
        if (target.username !== "" || target.password !== "" || BLOCKED_HOSTNAMES[host] === true || (isIP(host) !== 0 && ipBlocked(host))) {
          void route.abort("blockedbyclient");
          return;
        }
        void route.continue();
      });
      const page = await context.newPage();
      const session: Session = {
        id: requestedId,
        token: randomBytes(32).toString("hex"),
        context,
        page,
        url: "",
        title: "",
        loading: false,
        domRevision: 0,
        origins: new Set(origins),
        navStamps: [],
        frameSubscribers: new Set(),
        lastFrameAt: 0,
        frameTimer: undefined,
        frameInFlight: false,
        lastActivity: Date.now(),
      };
      sessions.set(session.id, session);
      wirePageEvents(session);
      reply(socket, id, true, { sessionId: session.id, token: session.token });
      return;
    }
    case "navigate": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      if (typeof raw.url !== "string" || raw.url.length > 2048) {
        reply(socket, id, false, { error: "INVALID_URL" });
        return;
      }
      const now = Date.now();
      session.navStamps = session.navStamps.filter((stamp) => now - stamp < 60_000);
      if (session.navStamps.length >= MAX_NAVS_PER_MIN) {
        reply(socket, id, false, { error: "NAV_RATE_LIMITED" });
        return;
      }
      session.navStamps.push(now);
      session.lastActivity = now;
      try {
        await screenUrl(raw.url, session.origins);
      } catch (err) {
        reply(socket, id, false, { error: err instanceof OpError ? err.code : "EGRESS_DENY" });
        return;
      }
      session.loading = true;
      broadcast(session, { event: "loading", sessionId: session.id, loading: true });
      try {
        const response = await session.page.goto(raw.url, { timeout: NAV_TIMEOUT_MS, waitUntil: "domcontentloaded" });
        // Redirects re-screen: the final URL's origin must be granted too.
        const finalUrl = session.page.url();
        try {
          await screenUrl(finalUrl, session.origins);
        } catch {
          session.loading = false;
          broadcast(session, { event: "loading", sessionId: session.id, loading: false });
          reply(socket, id, false, { error: "EGRESS_DENY" });
          return;
        }
        session.url = finalUrl;
        session.domRevision += 1;
        session.title = (await session.page.title().catch(() => "")).slice(0, 256);
        session.loading = false;
        broadcast(session, { event: "loading", sessionId: session.id, loading: false });
        broadcast(session, { event: "title", sessionId: session.id, title: session.title });
        reply(socket, id, true, { ...sessionState(session), status: response?.status() ?? null });
      } catch (err) {
        session.loading = false;
        broadcast(session, { event: "loading", sessionId: session.id, loading: false });
        reply(socket, id, false, { error: err instanceof OpError ? err.code : "NAV_FAILED" });
      }
      return;
    }
    case "fill": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      // Password masking: the reply names selectors + value lengths only.
      // type=password values never round-trip through replies, events, logs.
      const fields = Array.isArray(raw.fields) ? raw.fields : [];
      const masked: Array<{ selector: string; length: number; password: boolean }> = [];
      try {
        for (const field of fields) {
          if (field === null || typeof field !== "object" || !("selector" in field) || !("value" in field)) throw new OpError("INVALID_FIELDS", "fields must be objects");
          const selector: unknown = field.selector;
          const value: unknown = field.value;
          const password: unknown = "password" in field ? field.password : false;
          if (typeof selector !== "string" || selector === "" || selector.length > 512) {
            throw new OpError("INVALID_FIELDS", "each field needs a selector");
          }
          if (typeof value !== "string" || value.length > 4096) {
            throw new OpError("INVALID_FIELDS", "each field needs a string value");
          }
          const locator = session.page.locator(selector).first();
          await locator.fill(value, { timeout: 10_000 });
          masked.push({ selector, length: value.length, password: password === true });
        }
        if (typeof raw.submitSelector === "string" && raw.submitSelector !== "") {
          await session.page.locator(raw.submitSelector).first().click({ timeout: 10_000 });
        } else if (typeof raw.selector === "string" && raw.selector !== "") {
          await session.page.locator(raw.selector).first().press("Enter", { timeout: 10_000 }).catch(() => {});
        }
        session.domRevision += 1;
        reply(socket, id, true, { ...sessionState(session), filled: masked });
      } catch (err) {
        reply(socket, id, false, { error: err instanceof OpError ? err.code : "FILL_FAILED" });
      }
      return;
    }
    case "snapshot": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      // No bytes here: URL/title/loading/revision only. Requesting a
      // snapshot starts the frame loop for this socket so the caller can
      // pair state with a live frame; frames-stop ends it.
      session.frameSubscribers.add(socket);
      session.lastActivity = Date.now();
      maybeStartFrames(session);
      return;
    }
    case "cookies": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      // Raw bytes for the caller to seal as a 30d artifact. Never logged.
      const cookies = await session.context.cookies().catch(() => []);
      reply(socket, id, true, { cookies });
      return;
    }
    case "profile": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      // Storage state (localStorage/cookies) for the caller to seal.
      // Returned raw; never written to our disk or logs.
      const storage = await session.context.storageState().catch(() => ({ cookies: [], origins: [] }));
      reply(socket, id, true, { storage });
      return;
    }
    case "frames-start": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      session.frameSubscribers.add(socket);
      session.lastActivity = Date.now();
      maybeStartFrames(session);
      return;
    }
    case "frames-stop": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      session.frameSubscribers.delete(socket);
      stopFramesIfIdle(session);
      reply(socket, id, true, { streaming: false });
      return;
    }
    case "close": {
      const session = checkSession(raw.sessionId, raw.token);
      if (!session) {
        reply(socket, id, false, { error: "NO_SESSION" });
        return;
      }
      await closeSession(session);
      reply(socket, id, true, { closed: true });
      return;
    }
    default: {
      reply(socket, id, false, { error: "UNKNOWN_OP" });
      return;
    }
  }
}

const server = createServer((socket: Socket) => {
  let buffer = "";
  socket.setEncoding("utf8");
  socket.on("data", (chunk: string) => {
    buffer += chunk;
    if (buffer.length > BODY_LIMIT * 4) {
      socket.destroy();
      return;
    }
    let newline: number;
    while ((newline = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, newline);
      buffer = buffer.slice(newline + 1);
      if (line.trim() === "") continue;
      if (line.length > BODY_LIMIT) continue;
      let message: (Op & { id?: unknown }) | null = null;
      try {
        message = JSON.parse(line) as Op & { id?: unknown };
      } catch {
        continue;
      }
      if (!message || typeof message.op !== "string") continue;
      const { id, ...op } = message;
      void handleOp(socket, id ?? null, op as Op).catch(() => {
        reply(socket, id ?? null, false, { error: "INTERNAL" });
      });
    }
  });
  socket.on("close", () => {
    // A dropped viewer socket stops its frame loops; sessions outlive it.
    for (const session of sessions.values()) {
      session.frameSubscribers.delete(socket);
      stopFramesIfIdle(session);
    }
  });
  socket.on("error", () => {});
});

rmSync(SOCKET, { force: true });
mkdirSync(new URL(".", `file://${SOCKET}`).pathname.replace(/\/$/, "") || "/run/orbit", { recursive: true });
server.listen(SOCKET, () => {
  console.log(`browser-host listening on ${SOCKET}`);
});

process.on("SIGTERM", () => {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5_000).unref();
});
