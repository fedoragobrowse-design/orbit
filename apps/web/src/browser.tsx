// Managed browser — task-linked live view (no auto-start).
//
// Honor contract: this pane only ever talks to the browser-sessions REST API
// (`/api/v1/browser/sessions`, owner-authenticated, `deny_unknown_fields`
// bodies) plus two live channels — an SSE stream for `nav`/`loading`/`title`
// events and an authenticated owner WebSocket for binary JPEG frames. There
// is no host fallback, no personal-browser import, and no static screenshot
// rendered as interactive: the live <img> is watch-only (no pointer
// handlers map clicks to page coordinates) and snapshots surface as links.
// Closing the viewer (Pause, unmount, socket drop) only stops frames — the
// session and its task keep running, viewing never owns the task. Owner
// takeover pauses agent mutations; Return hands control back to Orbit.
//
// Route contract (crates/api/src/browser_routes.rs): every path below is
// built by one helper so a backend rename is a one-line change. Mutations
// carry `expected_revision` (stale pins are 409); foreign ids are 404 and
// broker/egress outages are 503 (never raw net). Text that must appear in
// the DOM goes through React text nodes, never dangerouslySetInnerHTML.
import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { api, post, queryClient, remove, text, type RecordData } from "./api";
import { Empty, ErrorNotice, PageHeader } from "./ui";

const SESSIONS = "/browser/sessions";
const sessionPath = (id: string) => `/browser/sessions/${id}`;
const snapshotPath = (id: string) => `/api/v1/browser/sessions/${id}/snapshot`;
const streamPath = (id: string) => `/api/v1/browser/sessions/${id}/stream`;
const takeoverPath = (id: string) => `/api/v1/browser/sessions/${id}/takeover`;
const returnPath = (id: string) => `/api/v1/browser/sessions/${id}/return`;
function liveSocketUrl(id: string): string {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}/api/v1/browser/sessions/${id}/live`;
}

type BrowserSession = {
  id: string;
  revision: number;
  state: string;
  url: string;
  title: string;
  loading: boolean;
  dom_revision: number;
  takeover: boolean;
  task_id: string;
};

type SnapshotLink = { label: string; href: string };
type BrowserSnapshot = {
  url: string;
  title: string;
  dom_revision: number;
  takeover: boolean;
  links: SnapshotLink[];
};

function toSession(row: RecordData): BrowserSession {
  return {
    id: text(row.id),
    revision: Number(row.revision ?? 1) || 1,
    state: text(row.state),
    url: text(row.url),
    title: text(row.title),
    loading: row.loading === true,
    dom_revision: Number(row.dom_revision ?? 0) || 0,
    takeover: row.takeover === true,
    task_id: text(row.task_id),
  };
}

function toSnapshot(row: RecordData): BrowserSnapshot {
  // Metadata only (no image bytes, per contract). `links` is tolerated when
  // present and empty otherwise; the page URL itself always renders as a link.
  const links = Array.isArray(row.links)
    ? (row.links as RecordData[])
        .map((l) => ({ label: text(l.label) || text(l.href), href: text(l.href) }))
        .filter((l) => l.href !== "")
    : [];
  return {
    url: text(row.url),
    title: text(row.title),
    dom_revision: Number(row.dom_revision ?? 0) || 0,
    takeover: row.takeover === true,
    links,
  };
}

export function BrowserPage() {
  return (
    <>
      <PageHeader
        title="Browser"
        description="A managed browser in your workspace. Opens only when you ask — nothing loads until you open a session."
      />
      <BrowserPane taskId={null} />
    </>
  );
}

/// Task-linked pane: the same live view scoped to the task's sessions.
/// Rendered inside TaskDetail; starts closed like the full page.
export function TaskBrowserPane({ taskId }: { taskId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <section className="panel browser-task-pane">
      <h2>Browser</h2>
      {!open ? (
        <>
          <p className="muted">
            Watch the managed browser for this task. Nothing starts until you
            press the button.
          </p>
          <button onClick={() => setOpen(true)}>Watch browser</button>
        </>
      ) : (
        <BrowserPane taskId={taskId} />
      )}
    </section>
  );
}

function BrowserPane({ taskId }: { taskId: string | null }) {
  const [creating, setCreating] = useState(false);
  const [newUrl, setNewUrl] = useState("");
  const [createError, setCreateError] = useState<unknown>(null);
  const [activeId, setActiveId] = useState<string | null>(null);

  const listPath = taskId
    ? `${SESSIONS}?task_id=${encodeURIComponent(taskId)}&limit=50`
    : `${SESSIONS}?limit=50`;
  const sessions = useQuery({
    queryKey: ["browser", "sessions", taskId],
    queryFn: () => api<{ items: RecordData[] }>(listPath),
  });
  const items = (sessions.data?.items ?? []).map(toSession);
  useEffect(() => {
    if (!activeId && items.length) setActiveId(items[0].id);
    if (activeId && !items.some((s) => s.id === activeId)) setActiveId(null);
    // Seed once from the listing; owner tab choice wins after that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions.data]);

  const createSession = useCallback(async () => {
    setCreateError(null);
    try {
      const created = await post<RecordData>(SESSIONS, {
        url: newUrl.trim() || undefined,
        task_id: taskId ?? undefined,
      });
      const id = text(created.id);
      setNewUrl("");
      setCreating(false);
      void queryClient.invalidateQueries({ queryKey: ["browser", "sessions"] });
      if (id) setActiveId(id);
    } catch (e) {
      setCreateError(e);
    }
  }, [newUrl, taskId]);

  return (
    <section className="panel browser-pane" aria-label="Browser">
      {sessions.error && (
        <ErrorNotice error={sessions.error} retry={() => sessions.refetch()} />
      )}
      {items.length > 0 && (
        <div className="browser-tabs" role="tablist" aria-label="Browser sessions">
          {items.map((s) => (
            <button
              key={s.id}
              role="tab"
              aria-selected={s.id === activeId}
              className="secondary mini browser-tab"
              onClick={() => setActiveId(s.id)}
            >
              {s.title || s.url || `Session ${s.id.slice(0, 8)}`}
            </button>
          ))}
          <button
            className="secondary mini"
            onClick={() => setCreating((v) => !v)}
          >
            {creating ? "Cancel" : "New"}
          </button>
        </div>
      )}

      {(creating || items.length === 0) && (
        <form
          className="browser-new"
          onSubmit={(e) => {
            e.preventDefault();
            void createSession();
          }}
        >
          <label>
            <span className="browser-label">Start URL (optional)</span>
            <input
              value={newUrl}
              onChange={(e) => setNewUrl(e.target.value)}
              placeholder="https://…"
              spellCheck={false}
              autoComplete="off"
            />
          </label>
          <button type="submit">Open browser</button>
        </form>
      )}
      {createError ? <ErrorNotice error={createError} /> : null}

      {!activeId && items.length > 0 && (
        <Empty title="No session selected">
          Pick a tab above to watch that session.
        </Empty>
      )}
      {sessions.isPending && <p role="status">Loading sessions…</p>}

      {activeId && (
        <SessionView
          key={activeId}
          sessionId={activeId}
          taskId={taskId}
          onSwitch={setActiveId}
        />
      )}
    </section>
  );
}

function SessionView({
  sessionId,
  taskId,
  onSwitch,
}: {
  sessionId: string;
  taskId: string | null;
  onSwitch: (id: string | null) => void;
}) {
  const [url, setUrl] = useState("");
  const [actionError, setActionError] = useState<unknown>(null);
  const [watching, setWatching] = useState(false);
  const [watchError, setWatchError] = useState<unknown>(null);
  const [frame, setFrame] = useState<string | null>(null);
  const [lastFrameAt, setLastFrameAt] = useState(0);
  const wsRef = useRef<WebSocket | null>(null);
  const frameUrlRef = useRef<string | null>(null);

  const detail = useQuery({
    queryKey: ["browser", "session", sessionId],
    queryFn: () => api<RecordData>(sessionPath(sessionId)),
    refetchInterval: (query) => (query.state.data ? 15000 : 4000),
  });
  const snapshot = useQuery({
    queryKey: ["browser", "snapshot", sessionId],
    queryFn: () => api<RecordData>(snapshotPath(sessionId)),
  });
  const session = detail.data ? toSession(detail.data) : null;
  const snap = snapshot.data ? toSnapshot(snapshot.data) : null;

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({
      queryKey: ["browser", "session", sessionId],
    });
    void queryClient.invalidateQueries({
      queryKey: ["browser", "snapshot", sessionId],
    });
  }, [sessionId]);

  useEffect(() => {
    if (session && url === "") setUrl(session.url);
    // Seed the address bar from the session once; owner edits win after that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [detail.data]);

  // SSE: `nav`/`loading`/`title` events carry { id, kind, payload }.
  // Reconnect replays from the cursor via Last-Event-ID. Frames never ride
  // this channel — only state that refreshes the detail/snapshot queries.
  useEffect(() => {
    const src = new EventSource(streamPath(sessionId));
    const refresh = () => invalidate();
    src.addEventListener("nav", refresh);
    src.addEventListener("loading", refresh);
    src.addEventListener("title", refresh);
    src.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data) as { kind?: string };
        if (
          ["nav", "loading", "title", "snapshot", "state"].includes(
            String(msg.kind ?? "").toLowerCase(),
          )
        ) {
          refresh();
        }
      } catch {
        /* malformed event: keep last known state */
      }
    };
    return () => src.close();
  }, [invalidate, sessionId]);

  const stopWatch = useCallback(() => {
    // Viewer disconnect only stops frames: the session and its task keep
    // running. No stop/close call happens here, ever.
    wsRef.current?.close();
    wsRef.current = null;
    setWatching(false);
  }, []);

  // Tear down the viewer socket when the pane unmounts or switches session.
  // The task continues after viewer disconnect by design.
  useEffect(
    () => () => {
      wsRef.current?.close();
      wsRef.current = null;
      if (frameUrlRef.current) {
        URL.revokeObjectURL(frameUrlRef.current);
        frameUrlRef.current = null;
      }
    },
    [sessionId],
  );

  const startWatch = useCallback(() => {
    if (wsRef.current) return;
    setWatchError(null);
    try {
      // Same-origin socket: the owner session cookie authenticates the
      // viewer. Binary JPEG frames only (max ~2fps, only while attached);
      // text control frames ({ kind: nav|loading|title }) refresh state.
      const ws = new WebSocket(liveSocketUrl(sessionId));
      ws.binaryType = "blob";
      ws.onmessage = (ev) => {
        if (ev.data instanceof Blob) {
          const next = URL.createObjectURL(ev.data);
          if (frameUrlRef.current) URL.revokeObjectURL(frameUrlRef.current);
          frameUrlRef.current = next;
          setFrame(next);
          setLastFrameAt(Date.now());
          return;
        }
        if (typeof ev.data === "string") {
          try {
            const msg = JSON.parse(ev.data) as { kind?: string };
            if (
              ["nav", "loading", "title"].includes(
                String(msg.kind ?? "").toLowerCase(),
              )
            ) {
              invalidate();
            }
          } catch {
            /* non-JSON control text: ignore */
          }
        }
      };
      ws.onerror = () =>
        setWatchError(
          new Error("Live view disconnected. The task keeps running."),
        );
      ws.onclose = () => {
        wsRef.current = null;
        setWatching(false);
      };
      wsRef.current = ws;
      setWatching(true);
    } catch (e) {
      setWatchError(e);
    }
  }, [invalidate, sessionId]);

  const mutate = useCallback(
    async (path: string) => {
      if (!session) return;
      setActionError(null);
      try {
        await post(path, { expected_revision: session.revision });
        invalidate();
        void queryClient.invalidateQueries({
          queryKey: ["browser", "sessions"],
        });
      } catch (e) {
        setActionError(e);
      }
    },
    [invalidate, session],
  );

  // The address bar opens the URL in a session: a new tab when the current
  // session already has an address, so Go never destroys a live session.
  const openUrl = useCallback(async () => {
    const target = url.trim();
    if (!target) return;
    setActionError(null);
    try {
      const created = await post<RecordData>(SESSIONS, {
        url: target,
        task_id: taskId ?? session?.task_id ?? undefined,
      });
      const id = text(created.id);
      void queryClient.invalidateQueries({ queryKey: ["browser", "sessions"] });
      if (id) onSwitch(id);
    } catch (e) {
      setActionError(e);
    }
  }, [onSwitch, session?.task_id, taskId, url]);

  const closeSession = useCallback(async () => {
    if (!session) return;
    setActionError(null);
    try {
      stopWatch();
      await remove(sessionPath(sessionId));
      onSwitch(null);
      void queryClient.invalidateQueries({ queryKey: ["browser", "sessions"] });
    } catch (e) {
      setActionError(e);
    }
  }, [onSwitch, session, sessionId, stopWatch]);

  const closed =
    session && ["CLOSED", "STOPPED", "FAILED"].includes(session.state.toUpperCase());

  return (
    <div className="browser-session">
      {detail.error && (
        <ErrorNotice error={detail.error} retry={() => detail.refetch()} />
      )}

      <div className="browser-toolbar">
        <form
          className="browser-urlbar"
          onSubmit={(e) => {
            e.preventDefault();
            void openUrl();
          }}
        >
          <label>
            <span className="browser-label">Address</span>
            <input
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://…"
              spellCheck={false}
              autoComplete="off"
              disabled={!session || !!closed}
            />
          </label>
          <button type="submit" disabled={!session || !!closed || !url.trim()}>
            Go
          </button>
        </form>
        {session?.loading && (
          <span className="browser-loading" role="status">
            <span className="route-spinner" aria-hidden="true" />
            Loading…
          </span>
        )}
        {session && (
          <span
            className={`browser-badge ${session.takeover ? "owner" : "orbit"}`}
            role="status"
            title={
              session.takeover
                ? "You are controlling this browser; agent mutations are paused"
                : "Orbit is controlling this browser"
            }
          >
            {session.takeover ? "You are controlling" : "Orbit controlling"}
          </span>
        )}
      </div>

      {actionError ? <ErrorNotice error={actionError} /> : null}
      {watchError ? <ErrorNotice error={watchError} /> : null}

      <div className="browser-actions">
        {watching ? (
          <button className="secondary" onClick={stopWatch}>
            Pause live view
          </button>
        ) : (
          <button onClick={startWatch} disabled={!session || !!closed}>
            Watch live
          </button>
        )}
        {session?.takeover ? (
          <button
            className="secondary"
            onClick={() => void mutate(returnPath(sessionId))}
            disabled={!session}
          >
            Return to Orbit
          </button>
        ) : (
          <button
            className="secondary"
            onClick={() => void mutate(takeoverPath(sessionId))}
            disabled={!session || !!closed}
          >
            Take over
          </button>
        )}
        <button
          className="secondary"
          onClick={() => void snapshot.refetch()}
          disabled={!session}
        >
          Refresh snapshot
        </button>
        <button
          className="danger"
          onClick={() => void closeSession()}
          disabled={!session}
        >
          Close session
        </button>
      </div>

      {watching && !frame && (
        <p role="status">Waiting for live frames…</p>
      )}
      {frame && (
        <div className="browser-frame-wrap">
          {/* Watch-only: no pointer handlers. Control via Take over plus
              the address bar, never by clicking the picture. */}
          <img
            className="browser-frame"
            src={frame}
            alt={
              session?.title
                ? `Live view: ${session.title}`
                : "Live browser view"
            }
            draggable={false}
          />
          <p className="muted">
            Live view is watch-only
            {lastFrameAt
              ? ` · last frame ${new Date(lastFrameAt).toLocaleTimeString()}`
              : ""}
            . Pausing never stops the task — Orbit keeps working.
          </p>
        </div>
      )}

      {snapshot.error ? (
        <ErrorNotice error={snapshot.error} retry={() => snapshot.refetch()} />
      ) : snap ? (
        <section className="browser-snapshot" aria-label="Snapshot">
          <h3>Snapshot</h3>
          <dl>
            <div>
              <dt>URL</dt>
              <dd>
                {snap.url ? (
                  <a href={snap.url} target="_blank" rel="noreferrer">
                    {snap.url}
                  </a>
                ) : (
                  "—"
                )}
              </dd>
            </div>
            <div>
              <dt>Title</dt>
              <dd>{snap.title || "—"}</dd>
            </div>
            <div>
              <dt>DOM revision</dt>
              <dd>{snap.dom_revision}</dd>
            </div>
          </dl>
          {snap.links.length > 0 && (
            <ul>
              {snap.links.map((l) => (
                <li key={l.href}>
                  <a href={l.href}>{l.label || l.href}</a>
                </li>
              ))}
            </ul>
          )}
        </section>
      ) : (
        snapshot.isPending && <p role="status">Loading snapshot…</p>
      )}

      {session && (
        <p className="muted browser-meta">
          Session {session.id} · revision {session.revision} · DOM revision{" "}
          {session.dom_revision} · {session.state || "unknown state"}
          {taskId || session.task_id ? (
            <>
              {" "}
              · linked to{" "}
              <a href={`/tasks/${taskId ?? session.task_id}`}>
                task {taskId ?? session.task_id}
              </a>
            </>
          ) : null}
          .
        </p>
      )}
      {closed && <p role="status">Session closed.</p>}
    </div>
  );
}
