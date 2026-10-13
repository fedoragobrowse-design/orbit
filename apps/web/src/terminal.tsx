// Real shell, live terminal — task-linked shell session (no auto-start).
//
// Honor contract: every shell session mounts a scoped workspace subtree and
// runs either sandboxed (AIec, owner opted in) or unboxed in the isolated
// execution-host process group (owner opted out). This pane never starts a
// shell on page load: it opens one only when the owner presses "Open
// terminal", and it only ever talks to the shell-sessions REST API — there is
// no WebSocket, no direct-host execution, and no in-page HTML rendering of
// terminal bytes. Output renders through xterm.js (`term.write`), which
// parses ANSI itself; text that must appear in the DOM (status, errors) goes
// through React text nodes, never `dangerouslySetInnerHTML`.
//
// Run-event timeline: after a session is open, this pane GETs the session's
// run-event cursor every 2s and paints TERMINAL_OUTPUT deltas into the same
// xterm instance, so a dropped panel replays without losing output. Bounded
// memory: appended chunks accumulate in one rolling string buffer capped far
// below any tab crash threshold with a "trimmed" marker.
import { useCallback, useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import { api, post, text, type RecordData } from "./api";
import { Empty, ErrorNotice, PageHeader, Select } from "./ui";

const BODY_LIMIT = 64_000;
const POLL_MS = 2000;

type WorkspaceEntry = {
  id: string;
  name: string;
  kind: string;
  parent_id?: string | null;
};

type ShellSession = {
  id: string;
  revision: number;
  state: string;
  execution_mode: string;
  sandboxed: boolean;
};

type RunEventItem = {
  id: number;
  kind: string;
  payload?: Record<string, unknown>;
};

export function TerminalPage() {
  return (
    <>
      <PageHeader
        title="Terminal"
        description="A real shell in your workspace. Opens only when you ask — nothing runs until you press Open terminal."
      />
      <TerminalPane taskId={null} />
    </>
  );
}

/// Task-linked pane: the same on-demand shell scoped to the task's workspace.
/// Rendered inside TaskDetail; starts closed like the full page.
export function TaskTerminalPane({ taskId }: { taskId: string }) {
  const [open, setOpen] = useState(false);
  return (
    <section className="panel terminal-task-pane">
      <h2>Terminal</h2>
      {!open ? (
        <>
          <p className="muted">
            Open a shell for this task. Nothing starts until you press the
            button.
          </p>
          <button onClick={() => setOpen(true)}>Open terminal</button>
        </>
      ) : (
        <TerminalPane taskId={taskId} />
      )}
    </section>
  );
}

function TerminalPane({ taskId }: { taskId: string | null }) {
  const [workspaceId, setWorkspaceId] = useState("");
  const [cwd, setCwd] = useState("");
  const [session, setSession] = useState<ShellSession | null>(null);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<unknown>(null);
  const [sendError, setSendError] = useState<unknown>(null);
  const [cursor, setCursor] = useState(0);
  const [stopped, setStopped] = useState(false);
  const [input, setInput] = useState("");

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const bufferRef = useRef("");
  const seenRef = useRef<Set<number>>(new Set());
  const sessionRef = useRef<ShellSession | null>(null);
  sessionRef.current = session;

  const workspaces = useQuery({
    queryKey: ["terminal", "workspaces"],
    queryFn: () => api<{ items: RecordData[] }>("/workspace/tree?limit=200"),
  });
  const settings = useQuery({
    queryKey: ["terminal", "settings"],
    queryFn: () => api<RecordData>("/settings"),
    staleTime: 30_000,
  });

  const entries: WorkspaceEntry[] = (workspaces.data?.items ?? []).map((r) => ({
    id: text(r.id),
    name: text(r.name),
    kind: text(r.kind),
    parent_id: (r.parent_id as string | null) ?? null,
  }));
  const dirs = entries.filter((e) => e.kind === "DIRECTORY" || e.kind === "");
  useEffect(() => {
    if (!workspaceId && dirs.length) setWorkspaceId(dirs[0].id);
    // Seed once from the first listing; owner choice wins after that.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspaces.data]);

  const sandboxOn =
    settings.data?.sandbox_enabled === true ||
    text(settings.data?.sandbox_enabled) === "true";

  // xterm instance lives for exactly one open session: created when the
  // session arrives, disposed when it closes or stops. ANSI bytes go to
  // `term.write` only — never into the DOM as HTML.
  const sessionId = session?.id;
  useEffect(() => {
    const el = containerRef.current;
    if (!el || !sessionId) return;
    const term = new Terminal({
      convertEol: true,
      scrollback: 2000,
      cursorBlink: true,
    });
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.open(el);
    try {
      fit.fit();
    } catch {
      /* narrow panel: keep default 80 cols */
    }
    termRef.current = term;
    if (bufferRef.current) term.write(bufferRef.current);
    const onResize = () => {
      try {
        fit.fit();
      } catch {
        /* ignore */
      }
      const s = sessionRef.current;
      if (s && termRef.current) {
        const { cols, rows } = termRef.current;
        void post(`/shell/sessions/${s.id}/resize`, {
          expected_revision: s.revision,
          cols,
          rows,
        }).catch(() => {
          /* resize is best-effort; the shell keeps running */
        });
      }
    };
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      term.dispose();
      termRef.current = null;
    };
  }, [sessionId]);

  const appendOutput = useCallback((chunk: string) => {
    if (!chunk) return;
    const next = bufferRef.current + chunk;
    // Bounded output: keep the tail only; the terminal scrollback bounds
    // the visible side, this bounds the replay side.
    bufferRef.current =
      next.length > BODY_LIMIT
        ? `…trimmed…\n${next.slice(next.length - BODY_LIMIT)}`
        : next;
    termRef.current?.write(chunk);
  }, []);

  const openTerminal = useCallback(async () => {
    if (starting || sessionRef.current) return;
    setStarting(true);
    setStartError(null);
    setStopped(false);
    setCursor(0);
    bufferRef.current = "";
    seenRef.current = new Set();
    try {
      const created = await post<RecordData>("/shell/sessions", {
        workspace_id: workspaceId || undefined,
        cwd: cwd.trim() || undefined,
        cols: 80,
        rows: 24,
      });
      setSession({
        id: text(created.id),
        revision: Number(created.revision ?? 1) || 1,
        state: text(created.state) || "RUNNING",
        execution_mode: text(created.execution_mode),
        sandboxed:
          typeof created.sandboxed === "boolean"
            ? created.sandboxed
            : text(created.execution_mode).toLowerCase() === "sandboxed",
      });
    } catch (e) {
      setStartError(e);
    } finally {
      setStarting(false);
    }
  }, [cwd, starting, workspaceId]);

  const stopTerminal = useCallback(async () => {
    const s = sessionRef.current;
    if (!s) return;
    try {
      await post(`/shell/sessions/${s.id}/stop`, {
        expected_revision: s.revision,
      });
    } catch (e) {
      setSendError(e);
      return;
    }
    setStopped(true);
    setSession(null);
  }, []);

  // Tear down xterm when the pane unmounts without an explicit stop.
  useEffect(
    () => () => {
      termRef.current?.dispose();
      termRef.current = null;
    },
    [],
  );

  // 2s run-event poll while the session is active. run_events.id is the
  // cursor: replay from the last seen id, dedupe by id, paint only
  // TERMINAL_OUTPUT payloads, in id order.
  useEffect(() => {
    if (!session || stopped) return;
    let cancelled = false;
    const tick = async () => {
      try {
        const page = await api<{ items: RunEventItem[] }>(
          `/shell/sessions/${session.id}/stream?cursor=${cursor}`,
        );
        if (cancelled) return;
        const fresh = (page.items ?? [])
          .filter((e) => !seenRef.current.has(e.id))
          .sort((a, b) => a.id - b.id);
        if (!fresh.length) return;
        for (const e of fresh) seenRef.current.add(e.id);
        setCursor(fresh[fresh.length - 1].id);
        const status = fresh.find((e) => e.kind === "STATUS");
        if (status) {
          const s = text(
            (status.payload as Record<string, unknown> | undefined)?.state,
          );
          if (s === "STOPPED" || s === "FAILED") {
            setStopped(true);
            setSession(null);
            return;
          }
        }
        appendOutput(
          fresh
            .filter((e) => e.kind === "TERMINAL_OUTPUT")
            .map((e) => text(e.payload?.text))
            .filter((t) => t !== "")
            .join(""),
        );
      } catch {
        /* transient: next poll retries from the same cursor */
      }
    };
    const timer = window.setInterval(tick, POLL_MS);
    void tick();
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [appendOutput, cursor, session, stopped]);

  const sendInput = useCallback(async (line: string) => {
    const s = sessionRef.current;
    if (!s || !line) return;
    setSendError(null);
    try {
      const updated = await post<RecordData>(`/shell/sessions/${s.id}/input`, {
        expected_revision: s.revision,
        text: line.endsWith("\n") ? line : `${line}\n`,
      });
      const rev = Number(updated.revision);
      if (Number.isFinite(rev) && rev > 0) {
        setSession({ ...s, revision: rev });
      }
      setInput("");
    } catch (e) {
      setSendError(e);
    }
  }, []);

  const closed = !session && !starting;
  const modeLabel = session
    ? session.sandboxed
      ? "Sandboxed"
      : "Unsandboxed"
    : sandboxOn
      ? "Sandboxed"
      : "Unsandboxed";
  return (
    <section className="panel terminal-pane" aria-label="Terminal">
      <div className="terminal-controls">
        <Select
          label="Workspace"
          value={workspaceId}
          onChange={(e) => setWorkspaceId(e.target.value)}
          disabled={!!session || starting}
        >
          <option value="">Default workspace</option>
          {dirs.map((d) => (
            <option key={d.id} value={d.id}>
              {d.name === "" ? "/workspace" : d.name}
            </option>
          ))}
        </Select>
        <label className="terminal-cwd">
          <span className="terminal-cwd-label">Working directory</span>
          <input
            value={cwd}
            onChange={(e) => setCwd(e.target.value)}
            placeholder="/ (workspace root)"
            disabled={!!session || starting}
            spellCheck={false}
            autoComplete="off"
          />
        </label>
        <span
          className="terminal-mode"
          role="status"
          title={
            session
              ? `Session ${session.id} · revision ${session.revision}`
              : sandboxOn
                ? "Sandbox on: shells run isolated in AIec"
                : "Sandbox off: shells run in the isolated execution host"
          }
        >
          {modeLabel}
        </span>
      </div>

      {workspaces.error && (
        <ErrorNotice error={workspaces.error} retry={() => workspaces.refetch()} />
      )}
      {startError ? <ErrorNotice error={startError} /> : null}

      {closed && !stopped && (
        <>
          <Empty title="No shell running">
            Open a terminal to start a shell in the selected workspace.
            Nothing runs until you press the button.
          </Empty>
          <div className="actions">
            <button onClick={() => void openTerminal()} disabled={starting}>
              Open terminal
            </button>
          </div>
        </>
      )}

      {(session || starting) && (
        <>
          <div
            ref={containerRef}
            className="terminal-screen"
            role="log"
            aria-label="Terminal output"
          />
          {starting && !session && <p role="status">Starting shell…</p>}
          {session && (
            <>
              <form
                className="terminal-send"
                onSubmit={(e) => {
                  e.preventDefault();
                  void sendInput(input);
                }}
              >
                <label>
                  <span className="terminal-cwd-label">Send input</span>
                  <input
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    placeholder="Type a command, then Send (Enter)"
                    spellCheck={false}
                    autoComplete="off"
                  />
                </label>
                <button type="submit" disabled={!input}>
                  Send
                </button>
                <button
                  type="button"
                  className="danger"
                  onClick={() => void stopTerminal()}
                >
                  Stop
                </button>
              </form>
              {sendError ? <ErrorNotice error={sendError} /> : null}
              <p className="muted">
                Session {session.id} · revision {session.revision} ·{" "}
                {session.sandboxed ? "Sandboxed" : "Unsandboxed"} · output
                refreshes every 2 seconds
                {taskId ? (
                  <>
                    {" "}
                    · linked to <a href={`/tasks/${taskId}`}>task {taskId}</a>
                  </>
                ) : null}
                .
              </p>
            </>
          )}
        </>
      )}

      {!session && stopped && (
        <>
          <p role="status">Shell stopped.</p>
          <div className="actions">
            <button onClick={() => void openTerminal()} disabled={starting}>
              Open terminal
            </button>
          </div>
        </>
      )}
    </section>
  );
}
