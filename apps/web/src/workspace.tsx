import { lazy, Suspense, useEffect, useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Empty,
  ErrorNotice,
  Evidence,
  Input,
  Json,
  PageHeader,
  Resource,
  Select,
  Status,
  Textarea,
} from "./ui";
import {
  api,
  label,
  post,
  put,
  queryClient,
  remove,
  text,
  timestamp,
  type RecordData,
  type Session,
} from "./api";
import { enablePush } from "./push";
import { FAMILIES, useDraft } from "./nav";
import { DesktopObservationSection } from "./observation";
const TaskTerminalPane = lazy(() =>
  import("./terminal").then((m) => ({ default: m.TaskTerminalPane })),
);
const TaskBrowserPane = lazy(() =>
  import("./browser").then((m) => ({ default: m.TaskBrowserPane })),
);
const TERMINAL_TASK_STATES: Record<string, true> = {
  COMPLETED: true,
  FAILED: true,
  CANCELLED: true,
  TIMED_OUT: true,
};

const RECENT_EVENT_TYPES: Record<string, true> = {
  USER_MESSAGE: true,
  FILE_CREATED: true,
  FILE_MODIFIED: true,
  FILE_DELETED: true,
  FILE_SHARED: true,
};


export function Home() {
  const navigate = useNavigate();
  const [draft, setDraft] = useDraft("home");
  const session = useQuery({
    queryKey: ["session"],
    queryFn: () => api<Session>("/auth/session"),
  });
  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => api<RecordData>("/ready"),
  });
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api<RecordData>("/health"),
  });
  const [hidden, setHidden] = useState<string[]>(() => {
    try {
      const raw = localStorage.getItem("orbit.home.widgets");
      return raw ? (JSON.parse(raw) as string[]) : [];
    } catch {
      return [];
    }
  });
  const send = useMutation({
    mutationFn: () =>
      post<RecordData>("/events", {
        event_type: "USER_MESSAGE",
        payload: { text: draft },
        source_event_key: crypto.randomUUID(),
        privacy_class: "PRIVATE",
      }),
    onSuccess: (r) => {
      setDraft("");
      const taskId = text(r.task_id);
      navigate(taskId ? `/tasks/${taskId}` : "/tasks");
    },
  });
  const createdTaskId = send.data ? text(send.data.task_id) : "";
  const name = session.data?.user.display_name || session.data?.user.email || "";
  const toggle = (id: string) => {
    const next = hidden.includes(id) ? hidden.filter((h) => h !== id) : [...hidden, id];
    setHidden(next);
    try {
      localStorage.setItem("orbit.home.widgets", JSON.stringify(next));
    } catch {
      /* private mode: widget layout stays memory-only */
    }
  };
  const show = (id: string, title: string) => (
    <p>
      <button className="secondary mini" onClick={() => toggle(id)}>
        Show {title}
      </button>
    </p>
  );
  return (
    <>
      <PageHeader
        title={name ? `Hello, ${name}` : "Your workspace"}
        description="Review changes, continue your work, or ask Orbit."
      >
        {!!hidden.length && (
          <button className="secondary mini" onClick={() => toggle(hidden[0])}>
            Restore hidden ({hidden.length})
          </button>
        )}
      </PageHeader>
      <div className="home-grid">
        <div className="home-primary">
          {hidden.includes("attention") ? (
            show("attention", "attention")
          ) : (
            <section className="panel attention">
              <h2>
                Needs your attention{" "}
                <button className="secondary mini" onClick={() => toggle("attention")}>
                  Hide
                </button>
              </h2>
              <Resource
                path="/notifications"
                empty={
                  <p className="muted">
                    Important changes stay here until acknowledged.
                  </p>
                }
              >
                {(rows) =>
                  rows
                    .filter((r) => !r.acknowledged_at && !r.dismissed_at)
                    .slice(0, 8)
                    .map((r) => <Notification key={r.id} row={r} />)
                }
              </Resource>
              <Resource
                path="/tasks"
                empty={
                  <Empty title="No tasks in progress">
                    Ask Orbit below to start one.
                  </Empty>
                }
              >
                {(rows) =>
                  rows
                    .filter((r) => !TERMINAL_TASK_STATES[text(r.state)])
                    .slice(0, 5)
                    .map((r) => <TaskRow key={r.id} row={r} />)
                }
              </Resource>
              <Link className="safe-link" to="/attention">
                Open attention queue
              </Link>{" · "}
              <Link className="safe-link" to="/tasks">
                All tasks
              </Link>
            </section>
          )}
          <BriefPanel />
          {hidden.includes("today") ? (
            show("today", "today")
          ) : (
            <section className="panel">
              <h2>
                Today{" "}
                <button className="secondary mini" onClick={() => toggle("today")}>
                  Hide
                </button>
              </h2>
              <Resource
                path="/calendar/today"
                empty={
                  <p className="muted">
                    Nothing on the calendar.{" "}
                    <Link to="/connections/calendars">Connect one</Link>.
                  </p>
                }
              >
                {(rows) =>
                  rows.slice(0, 5).map((r) => (
                    <article className="row" key={text(r.id)}>
                      <div className="row-main">
                        <h3>{text(r.title) || "Untitled event"}</h3>
                        <div className="row-meta">
                          <span>{timestamp(text(r.starts_at))}</span>
                        </div>
                      </div>
                    </article>
                  ))
                }
              </Resource>
            </section>
          )}
          {hidden.includes("activity") ? (
            show("activity", "activity")
          ) : (
            <section className="recent">
              <h2>
                Recent activity{" "}
                <button className="secondary mini" onClick={() => toggle("activity")}>
                  Hide
                </button>
              </h2>
              <Resource
                path="/events"
                empty={
                  <Empty title="Nothing recorded yet">
                    Send a message below and it will appear here.
                  </Empty>
                }
              >
                {(rows) =>
                  rows
                    .filter((r) => RECENT_EVENT_TYPES[text(r.event_type)])
                    .slice(0, 5)
                    .map((r) => (
                      <article className="row" key={r.id}>
                        <div className="row-main">
                          <h3>
                            <Link to="/activity">
                              {label(r.event_type)}
                            </Link>
                          </h3>
                          <div className="row-meta">
                            <span>{timestamp(r.created_at)}</span>
                            <span>{label(r.privacy_class)}</span>
                          </div>
                          <Evidence correlationId={text(r.correlation_id)} />
                        </div>
                      </article>
                    ))
                }
              </Resource>
              <Link className="safe-link" to="/activity">
                All activity
              </Link>
            </section>
          )}
          {hidden.includes("systems") ? (
            show("systems", "health")
          ) : (
            <section className="panel systems">
              <h2>
                Connections and health{" "}
                <button className="secondary mini" onClick={() => toggle("systems")}>
                  Hide
                </button>
              </h2>
              {ready.isPending && <p role="status">Checking readiness…</p>}
              {ready.error && (
                <ErrorNotice error={ready.error} retry={() => ready.refetch()} />
              )}
              {ready.data && <Json value={ready.data} />}
              {health.isPending && <p role="status">Checking health…</p>}
              {health.error && (
                <ErrorNotice
                  error={health.error}
                  retry={() => health.refetch()}
                />
              )}
              {health.data && <Json value={health.data} />}
              <p>
                <Link to="/activity">Activity</Link> ·{" "}
                <Link to="/settings">Settings</Link>
              </p>
              <p className="muted">
                <Link to="/computers">Computers</Link> lists paired machines;
                pairing codes live there.
              </p>
              <h3>Active routines</h3>
              <p className="muted">
                <Link to="/automations">Automations</Link> lists schedules and
                event routines.
              </p>
            </section>
          )}
        </div>
        <div className="home-secondary">
          <section className="composer ask">
            <h2>Ask Orbit</h2>
            <form
              onSubmit={(e) => {
                e.preventDefault();
                send.mutate();
              }}
            >
              <Textarea
                label="What would you like help with?"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                required
              />
              <button disabled={send.isPending || !draft.trim()}>
                {send.isPending ? "Recording…" : "Ask Orbit"}
              </button>
              {send.error && <ErrorNotice error={send.error} />}
              {send.isSuccess && (
                <p role="status">
                  Recorded.{" "}
                  {createdTaskId ? (
                    <Link to={`/tasks/${createdTaskId}`}>
                      Open the created task
                    </Link>
                  ) : (
                    <Link to="/tasks">View tasks</Link>
                  )}
                </p>
              )}
            </form>
            <p className="muted">
              Messages are recorded as events and answered by the agent
              runtime over your configured models.
            </p>
          </section>
          {hidden.includes("projects") ? (
            show("projects", "projects")
          ) : (
            <section className="panel projects">
              <h2>
                Your projects{" "}
                <button className="secondary mini" onClick={() => toggle("projects")}>
                  Hide
                </button>
              </h2>
              <p className="muted">
                <Link to="/memory">Memory</Link> lists projects and what Orbit
                remembers. Recent file and message events appear under{" "}
                <Link to="/activity">Activity</Link> instead.
              </p>
            </section>
          )}
        </div>
      </div>
    </>
  );
}
function BriefPanel() {
 const brief = useQuery({ queryKey: ["brief"], queryFn: () => api<RecordData>("/brief"), staleTime: 60_000 });
 if (brief.isPending) return <section className="panel"><h2>Morning brief</h2><p role="status">Gathering…</p></section>;
 if (brief.error || !brief.data) return null;
 const d = brief.data;
 const approvals = Array.isArray(d.approvals) ? (d.approvals as RecordData[]) : [];
 const pending = Number(d.approvals_pending ?? 0);const unread = Number(d.notifications_unread ?? 0);const open = Number(d.tasks_open ?? 0);
 if (!pending && !unread && !open) return null;
 return <section className="panel attention"><h2>Morning brief</h2>
  <p>{pending} approval{pending === 1 ? "" : "s"} waiting · {unread} unread notification{unread === 1 ? "" : "s"} · {open} open task{open === 1 ? "" : "s"}</p>
  {approvals.slice(0, 3).map((a) => <div className="row" key={text(a.id)}><div className="row-main"><h3><Link to="/approvals">Pending approval</Link></h3><div className="row-meta"><span>{timestamp(text(a.created_at))}</span></div></div></div>)}
  <p className="muted"><Link to="/approvals">Approvals</Link> · <Link to="/tasks">Tasks</Link></p>
 </section>;
}
function Notification({ row }: { row: RecordData }) {
  const action = useMutation({
    mutationFn: (kind: string) => post(`/notifications/${row.id}/${kind}`),
    onSuccess: () => queryClient.invalidateQueries(),
  });
  return (
    <article className="row">
      <div className="row-main">
        <h3>{text(row.title)}</h3>
        <div className="row-meta">
          <Status value={row.severity} />
          <span>{timestamp(row.created_at)}</span>
          {!!row.acknowledged_at && <span>Acknowledged</span>}
        </div>
        <p>{text(row.body)}</p>
        {!!row.task_id && <Link to={`/tasks/${row.task_id}`}>Open task</Link>}
        <Evidence correlationId={text(row.correlation_id)} />
        {action.error && <ErrorNotice error={action.error} />}
      </div>
      <div className="item-actions">
        {!row.read_at && (
          <button
            className="secondary"
            disabled={action.isPending}
            onClick={() => action.mutate("read")}
          >
            Mark read
          </button>
        )}
        {!row.acknowledged_at && (
          <button
            disabled={action.isPending}
            onClick={() => action.mutate("acknowledge")}
          >
            Acknowledge
          </button>
        )}
        <button
          className="quiet"
          disabled={action.isPending}
          onClick={() => action.mutate("dismiss")}
        >
          Dismiss
        </button>
      </div>
    </article>
  );
}
export function TaskRow({ row }: { row: RecordData }) {
  return (
    <article className="row">
      <div className="row-main">
        <h3>
          <Link to={`/tasks/${row.id}`}>{text(row.title)}</Link>
        </h3>
        <div className="row-meta">
          <Status value={row.state} />
          <span>{timestamp(row.updated_at)}</span>
        </div>
        {!!row.wait_reason && <p>{label(row.wait_reason)}</p>}
        <Evidence correlationId={text(row.correlation_id)} />
      </div>
    </article>
  );
}
export function Tasks() {
  const [state, setState] = useState("");
  return (
    <>
      <PageHeader
        title="Tasks"
        description="Durable work, safe checkpoints, and outcomes you can inspect."
      />
      <Select
        label="Task state"
        value={state}
        onChange={(e) => setState(e.target.value)}
      >
        <option value="">All states</option>
        {[
          "QUEUED",
          "RUNNING",
          "WAITING_FOR_APPROVAL",
          "WAITING_FOR_RESOURCE",
          "COMPLETED",
          "FAILED",
          "CANCELLED",
          "TIMED_OUT",
        ].map((s) => (
          <option key={s} value={s}>
            {label(s)}
          </option>
        ))}
      </Select>
      <Resource
        path="/tasks"
        empty={
          <Empty title="No tasks here">
            Ask Orbit from Home to start a task.
          </Empty>
        }
      >
        {(rows) =>
          rows
            .filter((r) => !state || text(r.state) === state)
            .map((r) => <TaskRow key={r.id} row={r} />)
        }
      </Resource>
    </>
  );
}
export function TaskDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const q = useQuery({
    queryKey: ["task", id],
    queryFn: () => api<RecordData>(`/tasks/${id}`),
    refetchInterval: (query) => {
      const s = text(query.state.data?.state);
      return s && !TERMINAL_TASK_STATES[s] ? 5000 : false;
    },
  });
  const [callId, setCallId] = useState("");
  const [resolution, setResolution] = useState("CONFIRMED_NOT_APPLIED");
  const [evidence, setEvidence] = useDraft(`reconcile-${id}`);
  const action = useMutation({
    mutationFn: (kind: string) =>
      post<RecordData>(
        `/tasks/${id}/${kind}`,
        kind === "reconcile"
          ? {
              call_id: callId,
              expected_revision: q.data?.revision,
              resolution,
              evidence_reference: evidence,
            }
          : { expected_revision: q.data?.revision },
      ),
    onSuccess: (r, kind) => {
      queryClient.invalidateQueries();
      if (kind === "retry" && r.id) navigate(`/tasks/${r.id}`);
    },
  });
  if (q.isPending) return <p role="status">Loading task…</p>;
  if (q.error) return <ErrorNotice error={q.error} retry={() => q.refetch()} />;
  const row = q.data!;
  const allowed = Array.isArray(row.allowed_recovery_actions)
    ? row.allowed_recovery_actions.map(text)
    : [];
  const allows = (name: string) =>
    allowed.some(
      (a) =>
        a.toLowerCase() === name ||
        a.toLowerCase() === `${name}_safe_work` ||
        a.toLowerCase() === `${name}_as_new_task`,
    );
  return (
    <>
      <PageHeader title={text(row.title)} description={`Task ${id}`}>
        <Status value={row.state} />
      </PageHeader>
      <div className="detail-grid">
        <section className="panel">
          <h2>Current checkpoint</h2>
          <p>{label(row.wait_reason) || "No resource wait recorded."}</p>
          <Json value={row.checkpoint} />
          <Evidence
            correlationId={text(row.correlation_id)}
            evidence={row.evidence}
          />
          <div className="actions">
            {allows("resume") && (
              <button
                disabled={action.isPending}
                onClick={() => action.mutate("resume")}
              >
                Resume safe work
              </button>
            )}
            {allows("retry") && (
              <button
                disabled={action.isPending}
                onClick={() => action.mutate("retry")}
              >
                Retry as new task
              </button>
            )}
            {/MODEL/.test(text(row.wait_reason)) && (
              <Link className="safe-link" to="/models">
                Repair model connection
              </Link>
            )}
            {/NODE|COMPUTER|EMAIL|MCP|CONNECTION/.test(
              text(row.wait_reason),
            ) && (
              <Link className="safe-link" to="/connections">
                Repair connection
              </Link>
            )}
            {row.state === "WAITING_FOR_APPROVAL" && (
              <p className="muted">
                This call is waiting on you.{" "}
                <Link className="safe-link" to="/approvals">
                  Review it under Approvals
                </Link>
                .
              </p>
            )}
          </div>
          {allows("reconcile") && (
            <form
              className="section"
              onSubmit={(e) => {
                e.preventDefault();
                action.mutate("reconcile");
              }}
            >
              <h3>Review uncertain outcome</h3>
              <p>
                Check connector or node evidence first. An owner attestation is
                not independent proof. Acknowledging uncertainty never replays a
                submitted effect or clears runtime cleanup.
              </p>
              <Select
                label="Unresolved call"
                value={callId}
                onChange={(e) => setCallId(e.target.value)}
                required
              >
                <option value="">Select a call</option>
                {(Array.isArray(row.unresolved_call_ids)
                  ? row.unresolved_call_ids
                  : []
                ).map((c) => (
                  <option key={text(c)} value={text(c)}>
                    {text(c)}
                  </option>
                ))}
              </Select>
              <Select
                label="Verified resolution"
                value={resolution}
                onChange={(e) => setResolution(e.target.value)}
              >
                <option value="CONFIRMED_NOT_APPLIED">
                  Confirmed not applied
                </option>
                <option value="CONFIRMED_APPLIED">Confirmed applied</option>
              </Select>
              <Textarea
                label="Evidence reference"
                required
                value={evidence}
                onChange={(e) => setEvidence(e.target.value)}
              />
              <button
                disabled={action.isPending || !callId || !evidence.trim()}
              >
                Record evidence and reconcile
              </button>
            </form>
          )}
          {allows("cancel") && (
            <div className="destructive">
              <button
                className="danger"
                disabled={action.isPending}
                onClick={() => action.mutate("cancel")}
              >
                Cancel task
              </button>
              <p className="muted">
                Already submitted effects may finish. Cleanup and uncertain
                outcomes remain visible.
              </p>
            </div>
          )}
          {action.error && <ErrorNotice error={action.error} />}
        </section>
        <aside className="panel">
          <h2>Task record</h2>
          <dl>
            {[
              "revision",
              "fence",
              "created_at",
              "updated_at",
              "expires_at",
              "event_id",
              "correlation_id",
            ].map((k) => (
              <div key={k}>
                <dt>{label(k)}</dt>
                <dd>{text(row[k])}</dd>
              </div>
            ))}
          </dl>
          <h3>Runtime and cleanup evidence</h3>
          <Json value={row.evidence} />
        </aside>
      </div>
      <div className="section">
        <Suspense fallback={<p role="status">Loading terminal…</p>}>
          <TaskTerminalPane taskId={text(id)} />
        </Suspense>
        <Suspense fallback={<p role="status">Loading browser…</p>}>
          <TaskBrowserPane taskId={text(id)} />
        </Suspense>
        <LiveRun taskId={text(id)} state={text(row.state)} />
      </div>
    </>
  );
}
type TaskRun = {
  task_id: string;
  parent_task_id?: unknown;
  parent_run_id?: unknown;
  conversation_id?: unknown;
  title?: unknown;
  state?: unknown;
  sources?: unknown;
  phase: unknown;
  model_calls: unknown;
  model_retries: unknown;
  turn: unknown;
  depth: unknown;
  tool_calls: unknown;
  tokens: unknown;
  result?: unknown;
};
type TaskRuns = {
  task_id: string;
  parent_task_id?: unknown;
  children: TaskRun[];
  items?: TaskRun[];
};
const RUN_STEPS: Record<string, string> = {
  CONTEXT: "Reading your request",
  MODEL: "Thinking",
  MODEL_INFLIGHT: "Thinking",
  RESPONSE: "Drafting a reply",
  PROPOSE: "Planning the next step",
  DISPATCH: "Doing safe work",
  RESULT: "Checking the result",
  DONE: "Finished",
};
const RUN_ORDER = ["CONTEXT", "MODEL", "RESPONSE", "PROPOSE", "DISPATCH", "RESULT", "DONE"];
function LiveRun({ taskId, state }: { taskId: string; state: string }) {
  const active = !TERMINAL_TASK_STATES[state];
  const runs = useQuery({
    queryKey: ["task-runs", taskId],
    queryFn: () => api<TaskRuns>(`/tasks/${taskId}/runs`),
    enabled: !!taskId,
    refetchInterval: active ? 2000 : false,
  });
  const calls_q = useQuery({
    queryKey: ["task-tool-calls", taskId],
    queryFn: () => api<{ items: RecordData[] }>(`/tool-calls?limit=50`),
    enabled: !!taskId,
    refetchInterval: active ? 2000 : false,
  });
  // Explicit parent linkage only: `children` holds runs whose dispatch
  // persisted this task as parent. An empty set renders as no helpers —
  // never a synthesized progress row. `items` stays as a legacy fallback
  // for stale cached responses, never fabricated.
  const children: TaskRun[] =
    runs.data?.children ?? runs.data?.items ?? [];
  const parentId = text(runs.data?.parent_task_id);
  const toolItems = (calls_q.data?.items ?? []).filter((c) => text(c.task_id) === taskId);
  const calls = children.reduce((n, r) => n + (Number(r.model_calls) || 0), 0);
  const retries = children.reduce((n, r) => n + (Number(r.model_retries) || 0), 0);
  const tokens = children.reduce((n, r) => n + (Number(r.tokens) || 0), 0);
  const tools = children.reduce((n, r) => n + (Number(r.tool_calls) || 0), 0);
  // Session link: the conversation is the run's own chat thread.
  const sessionId = text(children[0]?.conversation_id);
  return (
    <section className="panel">
      <h2>Live run</h2>
      {runs.isPending && <p role="status">Loading run…</p>}
      {runs.error && <ErrorNotice error={runs.error} retry={() => runs.refetch()} />}
      {!!parentId && (
        <p className="muted">
          Helper of <Link className="safe-link" to={`/tasks/${parentId}`}>{parentId}</Link>.
        </p>
      )}
      {runs.data && !children.length && (
        <p className="muted">No agent run recorded for this task yet.</p>
      )}
      {!!children.length && (
        <>
          <p className="muted">
            {calls} model {calls === 1 ? "call" : "calls"} · {retries}{" "}
            {retries === 1 ? "retry" : "retries"} · {tools} tool{" "}
            {tools === 1 ? "call" : "calls"} · {tokens} tokens counted
            {active ? " · updating every 2 seconds" : " · final"}.
            {!!sessionId && (
              <> <Link className="safe-link" to={`/chat?conversation=${sessionId}`}>Open session</Link></>
            )}
          </p>
          {children.map((r) => {
            const phase = text(r.phase);
            const seen = RUN_ORDER.indexOf(phase.replace("MODEL_INFLIGHT", "MODEL"));
            const depth = Number(r.depth) || 0;
            const childState = text(r.state);
            const result = text((r.result as RecordData | null | undefined)?.text ?? (typeof r.result === "string" ? r.result : ""));
            return (
              <div key={text(r.task_id)} style={{ marginLeft: depth * 16 }}>
                <div className="row-meta">
                  <Status value={childState || phase} />
                  <Link className="safe-link" to={`/tasks/${text(r.task_id)}`}>
                    {text(r.title) || text(r.task_id)}
                  </Link>
                  <span>
                    {RUN_STEPS[phase] ?? label(phase)}
                    {depth > 0 ? ` · helper level ${depth}` : ""}
                  </span>
                </div>
                <p className="muted">
                  {RUN_ORDER.filter((_, i) => seen < 0 || i <= seen).join(" → ")}
                </p>
                <p className="muted">
                  Turn {text(r.turn)} · {text(r.model_calls)} model{" "}
                  {Number(r.model_calls) === 1 ? "call" : "calls"} ·{" "}
                  {text(r.tokens)} tokens counted
                </p>
                {!!result && <p>{result}</p>}
              </div>
            );
          })}
          {!!toolItems.length && (
            <>
              <h3>Tool activity{active ? " · live" : ""}</h3>
              <ul className="memory-files">
                {toolItems.slice(0, 12).map((c) => (
                  <ToolRow key={String(c.id)} row={c} />
                ))}
              </ul>
            </>
          )}
          <RunSources items={children} />
        </>
      )}
    </section>
  );
}
function toolName(row: RecordData): string {
  const d = row.descriptor;
  if (d && typeof d === "object" && "name" in d) return text(d.name);
  return "Tool call";
}
function ToolRow({ row }: { row: RecordData }) {
  return (
    <li>
      <span className="notes-item-title">{toolName(row)}</span>
      <span className="notes-item-meta">
        <Status value={row.state} /> · {timestamp(row.created_at)}
      </span>
    </li>
  );
}
type RunSourceView = { kind: string; reference: string; trust?: unknown; source_id?: unknown; source_version?: unknown; turn?: unknown; cited?: unknown; tombstone?: unknown; label?: unknown };
function runSourcesOf(r: TaskRun): RunSourceView[] {
  const v = r.sources;
  return Array.isArray(v) ? (v as RunSourceView[]) : [];
}
function RunSources({ items }: { items: TaskRun[] }) {
  const all = items.flatMap(runSourcesOf).slice(0, 8);
  if (!all.length) return null;
  return (
    <>
      <h3>What the answer used</h3>
      <ul className="memory-files">
        {all.map((s, i) => {
          const ref = s.reference || "";
          const id = text(s.source_id);
          const href =
            s.kind === "memory" && id ? `/memory/${id}`
            : s.kind === "file" && id ? `/connections/api?file=${encodeURIComponent(id)}`
            : s.kind === "mail" && id ? `/connections/email`
            : s.kind === "browser" ? `/browser`
            : null;
          const tombstone = s.tombstone === true;
          const untrusted = text(s.trust) !== "" && text(s.trust) !== "OwnerAuthenticated" && text(s.trust) !== "OWNER_AUTHENTICATED" && text(s.trust) !== "System" && text(s.trust) !== "SYSTEM";
          const name =
            s.kind === "memory" ? "Saved memory"
            : s.kind === "file" ? "Attached file"
            : s.kind === "chat" ? "Your message"
            : s.kind === "mail" ? "Mail message"
            : s.kind === "browser" ? "Browser snapshot"
            : ref.startsWith("orbit-memory:") ? "Saved memory"
            : ref.startsWith("attachment:") ? "Attached file"
            : s.kind || "Source";
          // Receipt label: Provided as context unless the model cited the
          // pin; deletion leaves a tombstone row, never removes the receipt.
          // The state names the exact pinned version the link resolves.
          const pin = text(s.source_version) !== "" ? `${s.reference} (version ${text(s.source_version)})` : s.reference;
          const state = `${tombstone ? "Deleted — source removed, receipt kept" : text(s.label) || (s.cited === true ? "Cited by model" : "Provided as context")} — ${pin}`;
          return (
            <li key={i}>
              <span className="notes-item-title">
                {href && !tombstone ? <Link to={href}>{name}</Link> : name}
                {tombstone ? " · deleted" : untrusted ? " · untrusted" : ""}
              </span>
              <span className="notes-item-meta">{state}{text(s.turn) !== "" ? ` · turn ${text(s.turn)}` : ""}</span>
            </li>
          );
        })}
      </ul>
    </>
  );
}
type SpendCall = {
  id: string;
  state?: unknown;
  actual_micro_usd?: unknown;
  input_tokens?: unknown;
  output_tokens?: unknown;
  model_id?: unknown;
  created_at?: unknown;
  timestamp?: unknown;
};
function microToUsd(v: unknown): number {
  const n = Number(v ?? 0);
  return Number.isFinite(n) ? n / 1_000_000 : 0;
}
function usd(n: number): string {
  return n < 0.01 && n > 0 ? "<$0.01" : `$${n.toFixed(n < 10 ? 4 : 2)}`;
}
function dayKey(d: Date): string {
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, "0")}-${String(d.getDate()).padStart(2, "0")}`;
}
function last14Days(): string[] {
  const out: string[] = [];
  const now = new Date();
  for (let i = 13; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(now.getDate() - i);
    out.push(dayKey(d));
  }
  return out;
}
function SpendBoard() {
  const [range, setRange] = useState<"7" | "14">("14");
  const calls = useQuery({
    queryKey: ["spend-calls"],
    queryFn: () => api<{ items: SpendCall[] }>(`/model-calls?limit=100`),
  });
  const models = useQuery({
    queryKey: ["spend-models"],
    queryFn: () => api<{ items: RecordData[] }>(`/models?limit=100`),
  });
  const items = (calls.data?.items ?? []).filter(
    (c) => text(c.state) === "COMPLETED",
  );
  const nameOf = (id: unknown) => {
    const m = (models.data?.items ?? []).find((r) => r.id === text(id));
    return text(m?.name) || text(m?.model) || "Unknown model";
  };
  const totalSpend = items.reduce((s, c) => s + microToUsd(c.actual_micro_usd), 0);
  const totalTokens =
    items.reduce((s, c) => s + Number(c.input_tokens ?? 0), 0) +
    items.reduce((s, c) => s + Number(c.output_tokens ?? 0), 0);
  const days = last14Days().slice(range === "7" ? 7 : 0);
  const perDay: Record<string, number> = Object.fromEntries(days.map((d) => [d, 0]));
  for (const c of items) {
    const at = text(c.created_at) || text(c.timestamp);
    if (!at) continue;
    const k = dayKey(new Date(at));
    if (k in perDay) perDay[k] += microToUsd(c.actual_micro_usd);
  }
  const peak = Math.max(0.000001, ...Object.values(perDay));
  const byModel: Record<string, { spend: number; calls: number; tokens: number }> = {};
  for (const c of items) {
    const name = nameOf(c.model_id);
    const e = byModel[name] ?? { spend: 0, calls: 0, tokens: 0 };
    e.spend += microToUsd(c.actual_micro_usd);
    e.calls += 1;
    e.tokens += Number(c.input_tokens ?? 0) + Number(c.output_tokens ?? 0);
    byModel[name] = e;
  }
  const modelRows = Object.entries(byModel).sort((a, b) => b[1].spend - a[1].spend);
  if (calls.isPending)
    return (
      <section className="panel section" aria-label="Trends">
        <p role="status">Loading…</p>
      </section>
    );
  if (calls.error)
    return (
      <section className="panel section" aria-label="Trends">
        <ErrorNotice error={calls.error} retry={() => calls.refetch()} />
      </section>
    );
  return (
    <section className="panel section" aria-label="Trends">
      <h2>Trends</h2>
      <p className="spend-total">
        Total spend <strong>{usd(totalSpend)}</strong>
        <span className="spend-sub">
          {" "}· {items.length} calls · {totalTokens.toLocaleString()} tokens
        </span>
      </p>
      <div className="spend-range" role="group" aria-label="Date range">
        {(["7", "14"] as const).map((r) => (
          <button
            key={r}
            type="button"
            className={range === r ? "spend-range-active" : ""}
            onClick={() => setRange(r)}
          >
            {r === "7" ? "Last 7 days" : "Last 14 days"}
          </button>
        ))}
      </div>
      {items.length === 0 ? (
        <Empty title="No model spend yet">
          Costs appear here after the first answered chat or agent run.
        </Empty>
      ) : (
        <>
          <div className="spend-chart" role="img" aria-label={`Daily spend, total ${usd(totalSpend)}`}>
            {days.map((d) => {
              const v = perDay[d] ?? 0;
              return (
                <div className="spend-bar" key={d} title={`${d}: ${usd(v)}`}>
                  <div className="spend-bar-track">
                    <div className="spend-bar-fill" style={{ height: `${Math.max(2, (v / peak) * 100)}%` }} />
                  </div>
                  <span className="spend-bar-day">{d.slice(5)}</span>
                </div>
              );
            })}
          </div>
          <table>
            <thead>
              <tr>
                <th scope="col">Model</th>
                <th scope="col">Spend</th>
                <th scope="col">Calls</th>
                <th scope="col">Tokens</th>
              </tr>
            </thead>
            <tbody>
              {modelRows.map(([name, e]) => (
                <tr key={name}>
                  <th scope="row">{name}</th>
                  <td>{usd(e.spend)}</td>
                  <td>{e.calls}</td>
                  <td>{e.tokens.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
export function Activity() {
  const { id } = useParams();
  const [params] = useSearchParams();
  const [correlation, setCorrelation] = useState(
    params.get("correlation_id") ?? "",
  );
  const detail = useQuery({
    queryKey: ["activity-detail", id],
    queryFn: () => api<RecordData>(`/activity/${id}`),
    enabled: !!id,
  });
  return (
    <>
      <PageHeader
        title="Activity"
        description="Follow the recorded source, decision, and result for every change."
      />
      <SpendBoard />
      <Input
        label="Correlation reference"
        value={correlation}
        onChange={(e) => setCorrelation(e.target.value)}
      />
      {id && (
        <section className="panel">
          {detail.error && <ErrorNotice error={detail.error} />}{" "}
          {detail.data && (
            <>
              <h2>{label(detail.data.operation)}</h2>
              <p>{text(detail.data.reason)}</p>
              <Json value={detail.data} />
              <Evidence correlationId={text(detail.data.correlation_id)} />
            </>
          )}
        </section>
      )}
      <Resource
        key={correlation}
        path={`/activity${correlation ? `?correlation_id=${encodeURIComponent(correlation)}` : ""}`}
        empty={
          <Empty title="No recorded activity">
            Activity appears when work enters your workspace.
          </Empty>
        }
      >
        {(rows) =>
          rows.map((r) => (
            <article className="row" key={r.id}>
              <div className="row-main">
                <h3>
                  <Link to={`/activity/${r.id}`}>{label(r.operation)}</Link>
                </h3>
                <p>{text(r.reason)}</p>
                <div className="row-meta">
                  <span>{timestamp(r.timestamp)}</span>
                  <span>Actor {text(r.principal_id) || "Not recorded"}</span>
                </div>
                {!!r.task_id && (
                  <Link to={`/tasks/${r.task_id}`}>Task record</Link>
                )}
                <Evidence
                  correlationId={text(r.correlation_id)}
                  evidence={r.metadata}
                />
              </div>
            </article>
          ))
        }
      </Resource>
    </>
  );
}
type SettingsData = {
  installation_mode: string;
  autonomy_mode: string;
  allow_private_cloud: boolean;
  agent_backend: string;
  inbox_enabled: boolean;
  sandbox_enabled: boolean;
  agent_may_change_settings: boolean;
  agent_may_manage_mcp: boolean;
  revision: number;
};
const HIDEABLE_TABS: [string, string, string][] = FAMILIES.flatMap((f) =>
  f.links
    .filter(([path]) => path !== "/" && path !== "/settings")
    .map(([path, name]) => [f.title, path, name] as [string, string, string]),
);
const THEME_VARS: Record<string, Record<string, string>> = {
  dusk: { "--ground": "#221c2e", "--surface": "#2d2540", "--ink": "#f0eaf7", "--action": "#e8a04c", "--secondary": "#b3a8c7", "--line": "#453a5c" },
  tide: { "--ground": "#eef3f1", "--surface": "#ffffff", "--ink": "#1f2e2b", "--action": "#0e7490", "--secondary": "#5c6f6a", "--line": "#cfdcd8" },
  paper: { "--ground": "#ffffff", "--surface": "#ffffff", "--ink": "#000000", "--action": "#000000", "--secondary": "#444444", "--line": "#999999" },
};
function TabVisibility() {
  const [hidden, setHidden] = useState<string[]>(() => {
    try {
      return JSON.parse(localStorage.getItem("orbit.nav.hidden") ?? "[]");
    } catch {
      return [];
    }
  });
  const toggle = (path: string) => {
    const next = hidden.includes(path)
      ? hidden.filter((p) => p !== path)
      : [...hidden, path];
    setHidden(next);
    try {
      localStorage.setItem("orbit.nav.hidden", JSON.stringify(next));
    } catch { /* private mode */ }
    window.dispatchEvent(new Event("orbit-nav"));
  };
  return (
    <section className="panel form">
      <h2>Sidebar tabs</h2>
      <p className="muted">
        Hide tabs you never open. Home and Settings always stay. Changes
        apply the moment you tick the box.
      </p>
      {HIDEABLE_TABS.map(([group, path, name]) => (
        <label className="check" key={path}>
          <input
            type="checkbox"
            checked={!hidden.includes(path)}
            onChange={() => toggle(path)}
          />
          {group} · {name}
        </label>
      ))}
    </section>
  );
}
function ThemePicker() {
  const themes: Record<string, { label: string; hint: string }> = {
    default: { label: "Porch light", hint: "Warm paper, green accents" },
    dusk: { label: "Dusk", hint: "Deep plum, amber accents" },
    tide: { label: "Tide", hint: "Sea slate, teal accents" },
    paper: { label: "Paper", hint: "High contrast black on white" },
  };
  const [theme, setTheme] = useState(() => {
    try {
      return localStorage.getItem("orbit.theme") ?? "default";
    } catch {
      return "default";
    }
  });
  const [custom, setCustom] = useState<Record<string, string>>(() => {
    try {
      return JSON.parse(localStorage.getItem("orbit.theme.custom") ?? "{}");
    } catch {
      return {};
    }
  });
  const apply = (name: string, vars: Record<string, string>) => {
    setTheme(name);
    setCustom(vars);
    try {
      localStorage.setItem("orbit.theme", name);
      localStorage.setItem("orbit.theme.custom", JSON.stringify(vars));
    } catch { /* private mode */ }
    const root = document.documentElement;
    for (const [k, v] of Object.entries(vars)) root.style.setProperty(k, v);
    if (name === "default") {
      for (const k of ["--ground", "--surface", "--ink", "--action", "--secondary", "--line"]) root.style.removeProperty(k);
    }
  };
  return (
    <section className="panel form">
      <h2>Theme</h2>
      <p className="muted">Pick a look, or mix your own colors below. Applies instantly.</p>
      <div className="theme-row" role="radiogroup" aria-label="Theme">
        {Object.entries(themes).map(([name, t]) => (
          <label key={name} className={theme === name ? "theme-active" : ""}>
            <input type="radio" name="orbit-theme" checked={theme === name} onChange={() => apply(name, name === "default" ? {} : THEME_VARS[name] ?? {})} />
            <strong>{t.label}</strong>
            <span className="muted">{t.hint}</span>
          </label>
        ))}
      </div>
      <div className="theme-custom">
        {(["--ground", "--surface", "--ink", "--action", "--secondary", "--line"] as const).map((k) => (
          <label key={k}>
            {k}
            <input type="color" value={custom[k] ?? "#808080"} onChange={(e) => apply("custom", { ...custom, [k]: e.target.value })} />
          </label>
        ))}
      </div>
    </section>
  );
}
function PushToggle() {
  const [status, setStatus] = useState("Push alerts for approvals are off in this browser.");
  const [busy, setBusy] = useState(false);
  async function enable() {
    setBusy(true);
    try {
      if (!("serviceWorker" in navigator) || !("PushManager" in window)) { setStatus("This browser does not support push notifications."); return; }
      const reg = await navigator.serviceWorker.ready;
      setStatus((await enablePush(reg)) ? "Push alerts are on in this browser." : "Push permission was not granted.");
    } finally { setBusy(false); }
  }
  async function test() {
    setBusy(true);
    try { await post("/push/test", {}); setStatus("Test push sent — check for a notification."); }
    catch (e) { setStatus(e instanceof Error ? e.message : "Test push failed."); }
    finally { setBusy(false); }
  }
  return (
    <section className="panel form">
      <h2>Push notifications</h2>
      <p className="muted">Get a push alert on this device when an approval needs your decision. In-app approvals stay authoritative.</p>
      <p role="status">{status}</p>
      <div className="row-buttons">
        <button disabled={busy} onClick={enable}>Enable push alerts</button>
        <button disabled={busy} onClick={test}>Send test push</button>
      </div>
    </section>
  );
}
function UpdateNotice() {
  const q = useQuery({ queryKey: ["updates-check"], queryFn: () => api<{ update_available: boolean; latest_version: string }>("/updates/check?channel=stable&current=web-0.1.0"), staleTime: 300_000 });
  if (!q.data?.update_available) return null;
  return (<p role="status">Update available: v{q.data.latest_version} — refresh to apply.</p>);
}

export function Settings() {
  const q = useQuery({
    queryKey: ["settings"],
    queryFn: () => api<SettingsData>("/settings"),
  });
  const [settings, setSettings] = useState<SettingsData>();
  const [notice, setNotice] = useState("");
  useEffect(() => {
    if (q.data && !settings) setSettings(q.data);
  }, [q.data, settings]);
  const save = useMutation({
    mutationFn: (body: unknown) => put("/settings", body),
    onSuccess: () => {
      setNotice("Saved. Current server permissions apply immediately.");
      queryClient.invalidateQueries();
      setSettings(undefined);
    },
    onError: () => setNotice(""),
  });
  return (
    <>
      <PageHeader
        title="Settings"
        description="Where your data can go, how much Orbit may do on its own, and how much it may spend."
      />
      {q.error && <ErrorNotice error={q.error} />}{" "}
      {settings && (
        <form
          className="panel form section"
          onSubmit={(e) => {
            e.preventDefault();
            const { revision, ...values } = settings;
            save.mutate({ ...values, expected_revision: revision });
          }}
        >
          <h2>How Orbit works</h2>
          <Select
            label="Where may models run?"
            value={settings.installation_mode}
            onChange={(e) =>
              setSettings({ ...settings, installation_mode: e.target.value })
            }
          >
            {["LOCAL_ONLY", "HYBRID", "CLOUD_ONLY"].map((s) => (
              <option value={s} key={s}>
                {label(s)}
              </option>
            ))}
          </Select>
          <p className="muted">
            Local only: only models on your own machine. Hybrid: local when
            possible, cloud services when you allow it. Cloud only: always
            uses online services.
          </p>
          <Select
            label="How much may Orbit do on its own?"
            value={settings.autonomy_mode}
            onChange={(e) =>
              setSettings({ ...settings, autonomy_mode: e.target.value })
            }
          >
            {["CHAT", "OBSERVE", "ASSIST", "TRUSTED_AUTOMATION", "CUSTOM"].map(
              (s) => (
                <option value={s} key={s}>
                  {label(s)}
                </option>
              ),
            )}
          </Select>
          <p className="muted">
            Chat: only answers you. Observe: watches and suggests, changes
            nothing. Assist: can act but asks first. Trusted automation:
            runs approved routines on its own.
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.allow_private_cloud}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  allow_private_cloud: e.target.checked,
                })
              }
            />
            Allow personal context on cloud models
          </label>
          <p className="muted">
            Off means cloud services only see the bare minimum. Your most
            private notes stay on this machine either way, and secrets never
            enter a model.
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.inbox_enabled ?? false}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  inbox_enabled: e.target.checked,
                })
              }
            />
            Turn on the AI Inbox
          </label>
          <p className="muted">
            Off keeps the inbox hidden and nothing is collected. Turn it on
            to gather items in the AI Inbox tab; treat everything there as
            untrusted until you have checked it.
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.sandbox_enabled ?? false}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  sandbox_enabled: e.target.checked,
                })
              }
            />
            Run tools inside a sandbox (AIec)
          </label>
          <p className="muted">
            Off means tools run directly on this machine, still checked by
            policy before they run. Turn it on to route every tool
            interaction through the isolated sandbox instead.
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.agent_may_change_settings ?? false}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  agent_may_change_settings: e.target.checked,
                })
              }
            />
            Let the agent change everyday settings itself
          </label>
          <p className="muted">
            Off means only you can change settings. When on, the agent may
            change everyday preferences, but never keys, identity, or these
            very permissions.
          </p>
          <label className="check">
            <input
              type="checkbox"
              checked={settings.agent_may_manage_mcp ?? false}
              onChange={(e) =>
                setSettings({
                  ...settings,
                  agent_may_manage_mcp: e.target.checked,
                })
              }
            />
            Let the agent manage its own tool connections
          </label>
          <p className="muted">
            Off means only you add or remove tool connections. When on, the
            agent may connect tools it needs, always inside the sandbox.
          </p>
          <button disabled={save.isPending}>Save</button>
        </form>
      )}
      <UpdaterSection />
      <SourcesSection />
      <GrantsSection />
      <BudgetsSection />
      <DesktopObservationSection />
      <McpSection />
      <SkillsSection />
      <QuestionsSection />
      <DocsSection />
      <TabVisibility />
      <ThemePicker />
      <PushToggle />
      <UpdateNotice />
      <section className="panel form">
        <h2>Safety rules</h2>
        <p className="muted">
          Risky actions need your say-so in <Link to="/approvals">Approvals</Link> before
          they run. Blocked things stay blocked, and anything needing a safe
          sandbox waits for one.
        </p>
      </section>
      {save.error && <ErrorNotice error={save.error} />}{" "}
      {notice && <p role="status">{notice}</p>}
      <PasswordSecurity />
      <ApiTokens />
    </>
  );
}
function UpdaterSection() {
  const client = useQueryClient();
  const [state, setState] = useState("");
  const check = useMutation({
    mutationFn: () => api<{ update_available: boolean; latest_version: string; digest: string; notes: string }>("/updates/check?channel=stable&current=web-0.1.0"),
    onSuccess: (d) => setState(d.update_available ? `New version ready: ${d.latest_version}.` : `You are up to date (latest seen: ${d.latest_version}).`),
    onError: () => setState(""),
  });
  const releases = useQuery({ queryKey: ["updates-releases"], queryFn: () => api<{ items: RecordData[] }>("/updates/releases") });
  const apply = useMutation({
    mutationFn: (version: string) => post<{ applied: boolean; version: string; restart_required: boolean }>("/updates/apply", { version, confirm: true }),
    onSuccess: (d) => { setState(`Version ${d.version} is staged. Restart Orbit to start using it.`); client.invalidateQueries({ queryKey: ["updates-releases"] }); },
  });
  return (
    <section className="panel form">
      <h2>Updates</h2>
      <p className="muted">
        Check for a new release, then request it. Requesting stages the
        version only — Orbit never installs or restarts itself. You restart
        when ready.
      </p>
      <div className="actions"><button disabled={check.isPending} onClick={() => check.mutate()}>Check for updates</button></div>
      {state && <p role="status">{state}</p>}
      {check.data?.notes ? <p className="muted">{text(check.data.notes)}</p> : null}
      {check.error && <ErrorNotice error={check.error} retry={() => check.reset()} />}
      {releases.data && (releases.data.items ?? []).length > 0 && (
        <table>
          <thead><tr><th scope="col">Version</th><th scope="col">Notes</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {(releases.data.items ?? []).map((row) => (
              <tr key={String(row.version)}>
                <th scope="row">{text(row.version)}</th>
                <td>{text(row.notes) || "—"}</td>
                <td><div className="actions"><button className="secondary" disabled={apply.isPending} onClick={() => apply.mutate(String(row.version))}>Request this version</button></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {apply.error && <ErrorNotice error={apply.error} retry={() => apply.reset()} />}
    </section>
  );
}
function BudgetsSection() {
  const client = useQueryClient();
  const budgets = useQuery({
    queryKey: ["settings-budgets"],
    queryFn: () => api<RecordData>("/budgets"),
  });
  const [taskUsd, setTaskUsd] = useState("");
  const [dayUsd, setDayUsd] = useState("");
  const [monthUsd, setMonthUsd] = useState("");
  const [seeded, setSeeded] = useState(false);
  useEffect(() => {
    if (budgets.data && !seeded) {
      setTaskUsd(String(budgets.data.task_usd ?? ""));
      setDayUsd(String(budgets.data.day_usd ?? ""));
      setMonthUsd(String(budgets.data.month_usd ?? ""));
      setSeeded(true);
    }
  }, [budgets.data, seeded]);
  const save = useMutation({
    mutationFn: () =>
      put("/budgets", {
        task_usd: Number(taskUsd),
        day_usd: Number(dayUsd),
        month_usd: Number(monthUsd),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["settings-budgets"] }),
  });
  return (
    <section className="panel form">
      <h2>Spending limits</h2>
      <p className="muted">
        Caps on what Orbit may spend on models, per task, per day, and per
        month. Work stops before it spends past these.
      </p>
      {budgets.isPending && <p role="status">Loading limits…</p>}
      {budgets.error && (
        <ErrorNotice error={budgets.error} retry={() => budgets.refetch()} />
      )}
      {budgets.data && (
        <form
          aria-label="Spending limits"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Input
            label="Per task (USD)"
            inputMode="decimal"
            value={taskUsd}
            onChange={(e) => setTaskUsd(e.target.value)}
          />
          <Input
            label="Per day (USD)"
            inputMode="decimal"
            value={dayUsd}
            onChange={(e) => setDayUsd(e.target.value)}
          />
          <Input
            label="Per month (USD)"
            inputMode="decimal"
            value={monthUsd}
            onChange={(e) => setMonthUsd(e.target.value)}
          />
          {save.error && (
            <ErrorNotice error={save.error} retry={() => save.reset()} />
          )}
          <div className="actions">
            <button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save limits"}
            </button>
          </div>
        </form>
      )}
      <p className="muted">
        Quiet hours live on each rule: open{" "}
        <Link to="/automations">Automations</Link>, pick a rule, and set when
        it may run.
      </p>
    </section>
  );
}
function GrantsSection() {
  const client = useQueryClient();
  const grants = useQuery({
    queryKey: ["settings-grants-list"],
    queryFn: () => api<{ items: RecordData[] }>("/grants?limit=50"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => remove(`/grants/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["settings-grants-list"] }),
  });
  const rows = grants.data?.items ?? [];
  return (
    <section className="panel form">
      <h2>Permissions given</h2>
      <p className="muted">
        Tools Orbit may use without asking again. Revoking one means the
        next use waits in <Link to="/approvals">Approvals</Link>.
      </p>
      {grants.isPending && <p role="status">Loading permissions…</p>}
      {grants.error && (
        <ErrorNotice error={grants.error} retry={() => grants.refetch()} />
      )}
      {!grants.isPending && !grants.error && rows.length === 0 && (
        <p className="muted">No standing permissions. Everything asks first.</p>
      )}
      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th scope="col">Tool</th>
              <th scope="col">Scope</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.tool_name)}</th>
                <td>{text(row.scope_key) || "—"}</td>
                <td>
                  <div className="actions">
                    <button
                      className="danger"
                      disabled={revoke.isPending}
                      onClick={() => revoke.mutate(String(row.id))}
                    >
                      Revoke
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {revoke.error && (
        <ErrorNotice error={revoke.error} retry={() => revoke.reset()} />
      )}
    </section>
  );
}
function SourcesSection() {
  const calendar = useQuery({
    queryKey: ["settings-calendar-sources"],
    queryFn: () => api<{ items: RecordData[] }>("/calendar/sources"),
  });
  const computers = useQuery({
    queryKey: ["settings-computers"],
    queryFn: () => api<{ items: RecordData[] }>("/computers"),
  });
  const providers = useQuery({
    queryKey: ["settings-providers"],
    queryFn: () => api<{ items: RecordData[] }>("/providers"),
  });
  const calendars = calendar.data?.items ?? [];
  const nodes = computers.data?.items ?? [];
  const models = providers.data?.items ?? [];
  return (
    <section className="panel form">
      <h2>Sources and capabilities</h2>
      <p className="muted">
        Where Orbit reads from and what it can do with. Manage each list
        where it lives.
      </p>
      {calendar.isPending || computers.isPending || providers.isPending ? (
        <p role="status">Loading sources…</p>
      ) : calendar.error || computers.error || providers.error ? (
        <ErrorNotice
          error={(calendar.error ?? computers.error ?? providers.error)!}
          retry={() => {
            calendar.refetch();
            computers.refetch();
            providers.refetch();
          }}
        />
      ) : (
        <dl>
          <dt>Calendars</dt>
          <dd>
            {calendars.length
              ? calendars.map((c) => text(c.name)).filter(Boolean).join(" · ")
              : "None connected"}{" "}
            · <Link to="/calendar">Calendar</Link>
          </dd>
          <dt>Computers</dt>
          <dd>
            {nodes.length
              ? `${nodes.length} enrolled`
              : "None enrolled"}{" "}
            · <Link to="/computers">Computers</Link>
          </dd>
          <dt>Model providers</dt>
          <dd>
            {models.length
              ? `${models.length} configured`
              : "None configured"}{" "}
            · <Link to="/models">Models</Link>
          </dd>
        </dl>
      )}
    </section>
  );
}

function McpSection() {
  const conns = useQuery({ queryKey: ["settings-mcp"], queryFn: () => api<{ items: RecordData[] }>("/mcp/connections") });
  const grants = useQuery({ queryKey: ["settings-grants"], queryFn: () => api<{ items: RecordData[] }>("/grants?limit=50") });
  const items = conns.data?.items ?? [];
  const grantCount = grants.data?.items.length ?? 0;
  return (
    <section className="panel form">
      <h2>Tool connections</h2>
      <p className="muted">
        Manage connections in <Link to="/connections/mcp">Connections</Link>.{" "}
        {items.length ? `${items.length} connected.` : "Nothing connected yet."}{" "}
        {grantCount ? `${grantCount} standing approval${grantCount === 1 ? "" : "s"} let tools act without asking each time — see Approvals to revoke.` : "No standing approvals: every risky tool call asks you first in Approvals."}
      </p>
      {conns.error ? <ErrorNotice error={conns.error} retry={() => conns.refetch()} /> : null}
    </section>
  );
}
function SkillsSection() {
  const client = useQueryClient();
  const skills = useQuery({ queryKey: ["settings-skills"], queryFn: () => api<{ items: RecordData[] }>("/skills") });
  const installs = useQuery({ queryKey: ["settings-installs"], queryFn: () => api<{ items: RecordData[] }>("/marketplace/installs") });
  const [open, setOpen] = useState<string | null>(null);
  const detail = useQuery({
    queryKey: ["settings-skill", open],
    queryFn: () => api<RecordData>(`/skills/${encodeURIComponent(open ?? "")}`),
    enabled: open !== null,
  });
  const toggle = useMutation({
    mutationFn: ({ name, enabled }: { name: string; enabled: boolean }) => post(`/skills/${encodeURIComponent(name)}/enabled`, { enabled }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["settings-skills"] }),
  });
  const rows = skills.data?.items ?? [];
  const pkgs = installs.data?.items ?? [];
  const d = detail.data;
  return (
    <section className="panel form">
      <h2>Skills</h2>
      <p className="muted">Skills are things the agent knows how to do. Switch one off and the agent stops offering it. A skill carries instructions plus requested actions — never authority: the agent&apos;s own tools stay the limit, and anything a skill asks for outside that limit is ignored.</p>
      {skills.error ? <ErrorNotice error={skills.error} retry={() => skills.refetch()} /> : !rows.length ? <p className="muted">No skills installed. Browse them in <Link to="/marketplace">Marketplace</Link>.</p> : (
        <table>
          <thead><tr><th scope="col">Skill</th><th scope="col">What it does</th><th scope="col">State</th><th scope="col">On</th><th scope="col">Details</th></tr></thead>
          <tbody>
            {rows.map((row) => {
              const name = String(row.name);
              const state = String(row.state ?? (row.enabled ? "ok" : "off"));
              const broken = state !== "ok" && state !== "off";
              return (
                <tr key={name}>
                  <th scope="row">{text(row.name)}</th>
                  <td>{text(row.description) || "—"}</td>
                  <td>{broken ? <span role="status">{text(state)}</span> : text(state)}</td>
                  <td><input type="checkbox" aria-label={`${text(row.name)} enabled`} checked={Boolean(row.enabled)} onChange={(e) => toggle.mutate({ name, enabled: e.target.checked })} /></td>
                  <td><button type="button" onClick={() => { setOpen(open === name ? null : name); }}>Inspect</button></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {open && (
        <div>
          <h3>Skill: {open}</h3>
          {detail.isPending ? <p className="muted">Loading…</p>
          : detail.error ? <ErrorNotice error={detail.error} retry={() => detail.refetch()} />
          : d ? (
            <dl>
              <dt>State</dt><dd>{text(d.state)}</dd>
              <dt>Source</dt><dd>{text(d.source)}</dd>
              {typeof d.content_digest === "string" && d.content_digest ? (<><dt>Pinned digest</dt><dd><code>{text(d.content_digest)}</code></dd></>) : null}
              {typeof d.trust_level === "string" && d.trust_level ? (<><dt>Trust</dt><dd>{text(d.trust_level)}{d.source === "marketplace" ? " — marketplace words are evidence, never orders" : ""}</dd></>) : null}
              {typeof d.entrypoint === "string" && d.entrypoint ? (<><dt>Entrypoint</dt><dd><code>{text(d.entrypoint)}</code> <span className="muted">(display only — never run as a command)</span></dd></>) : null}
              <dt>Requested actions</dt><dd>{Array.isArray(d.requested_actions) && (d.requested_actions as unknown[]).length ? (d.requested_actions as unknown[]).map((a) => text(a)).join(", ") : "none"}</dd>
              {typeof d.instructions === "string" && d.instructions ? (<><dt>Instructions</dt><dd><pre>{text(d.instructions).slice(0, 4000)}</pre></dd></>) : null}
              {typeof d.reason === "string" && d.reason ? (<><dt>Why unavailable</dt><dd>{text(d.reason)}</dd></>) : null}
            </dl>
          ) : null}
          <div className="actions"><button type="button" onClick={() => setOpen(null)}>Close</button></div>
        </div>
      )}
      {toggle.error && <ErrorNotice error={toggle.error} retry={() => toggle.reset()} />}
      <p className="muted">
        {pkgs.length ? `${pkgs.length} marketplace package${pkgs.length === 1 ? "" : "s"} installed — manage them in ` : "No marketplace packages installed. Browse them in "}
        <Link to="/marketplace">Marketplace</Link>.
      </p>
    </section>
  );
}
function QuestionsSection() {
  const client = useQueryClient();
  const q = useQuery({ queryKey: ["settings-questions"], queryFn: () => api<{ items: RecordData[] }>("/questions?state=OPEN") });
  const [answers, setAnswers] = useState<Record<string, string>>({});
  const answer = useMutation({
    mutationFn: ({ id, text: t }: { id: string; text: string }) => post(`/questions/${id}/answer`, { answer: t }),
    onSuccess: () => { setAnswers({}); client.invalidateQueries({ queryKey: ["settings-questions"] }); },
  });
  const rows = q.data?.items ?? [];
  return (
    <section className="panel form">
      <h2>Agent questions</h2>
      <p className="muted">When the agent is stuck it asks here. Answer in plain words and it carries on.</p>
      {q.error ? <ErrorNotice error={q.error} retry={() => q.refetch()} /> : !rows.length ? <p className="muted">No open questions. Nothing needs you.</p> : (
        <ul>
          {rows.map((row) => {
            const id = String(row.id);
            return (
              <li key={id}>
                <p>{text(row.question)}</p>
                {Array.isArray(row.options) && (row.options as unknown[]).length > 0 && (
                  <p className="muted">Suggestions: {(row.options as unknown[]).map((o) => text(o)).join(" · ")}</p>
                )}
                <div className="actions">
                  <Input label={`Answer to: ${text(row.question).slice(0, 40)}`} value={answers[id] ?? ""} onChange={(e) => setAnswers((a) => ({ ...a, [id]: e.target.value }))} placeholder="Type your answer" maxLength={2000} />
                  <button disabled={!(answers[id] ?? "").trim() || answer.isPending} onClick={() => answer.mutate({ id, text: (answers[id] ?? "").trim() })}>Send answer</button>
                </div>
              </li>
            );
          })}
        </ul>
      )}
      {answer.error && <ErrorNotice error={answer.error} retry={() => answer.reset()} />}
    </section>
  );
}
const DOC_PAGES = [["overview", "What Orbit is"], ["settings", "Settings explained"], ["memory", "How memory works"], ["tools", "What the agent can do"]] as const;
function DocsSection() {
  return (
    <section className="panel form">
      <h2>Guides</h2>
      <p className="muted">Short guides, same words the agent reads.</p>
      <ul>
        {DOC_PAGES.map(([page, title]) => (
          <li key={page}><Link to={`/docs/${page}`}>{title}</Link></li>
        ))}
      </ul>
    </section>
  );
}
function ApiTokens() {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const tokens = useQuery({ queryKey: ["api-tokens"], queryFn: () => api<{ items: RecordData[] }>("/tokens") });
  const create = useMutation({ mutationFn: () => post<RecordData>("/tokens", { name }), onSuccess: () => { setName(""); client.invalidateQueries({ queryKey: ["api-tokens"] }); } });
  const revoke = useMutation({ mutationFn: (id: string) => post(`/tokens/${id}/revoke`), onSuccess: () => client.invalidateQueries({ queryKey: ["api-tokens"] }) });
  const items = tokens.data?.items ?? [];
  const fresh = create.data;
  return (
    <section className="panel form">
      <h2>API tokens</h2>
      <p className="muted">Tokens for the CLI and scripts. Same access as your login. The secret shows once — copy it now.</p>
      {tokens.error ? (<ErrorNotice error={tokens.error} retry={() => tokens.refetch()} />) : !items.length ? (<p className="muted">No tokens yet.</p>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">Last used</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.name)}</th>
                <td>{timestamp(row.last_used)}</td>
                <td><div className="actions"><button className="danger" disabled={revoke.isPending} onClick={() => revoke.mutate(String(row.id))}>Revoke</button></div></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {(create.error ?? revoke.error) && (<ErrorNotice error={(create.error ?? revoke.error) as Error} retry={() => { create.reset(); revoke.reset(); }} />)}
      {fresh && typeof (fresh as RecordData).token === "string" && (<p role="status"><code>{text((fresh as RecordData).token)}</code> — copy now, Orbit never shows it again.</p>)}
      <form aria-label="Mint API token" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <Input label="Token name" value={name} onChange={(e) => setName(e.target.value)} required maxLength={64} placeholder="laptop" />
        <div className="actions"><button type="submit" disabled={!name.trim() || create.isPending}>Mint token</button></div>
      </form>
    </section>
  );
}
function PasswordSecurity() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [done, setDone] = useState("");
  const change = useMutation({
    mutationFn: () => post<{ changed: boolean }>("/auth/change-password", { current_password: current, new_password: next }),
    onSuccess: () => { setCurrent(""); setNext(""); setDone("Password changed. Other sessions signed out."); },
  });
  const mint = useMutation({
    mutationFn: () => post<{ recovery_code: string; expires_at: string }>("/auth/recovery-code/mint"),
    onSuccess: (d) => setCode(d.recovery_code),
  });
  return (
    <section className="panel form">
      <h2>Password and recovery</h2>
      <p className="muted">Change your password here. Keep the one-time recovery code somewhere safe — it is the only way back in if you forget your password. It works once and expires in 24 hours.</p>
      {done && <p role="status">{done}</p>}
      {(change.error ?? mint.error) && <ErrorNotice error={(change.error ?? mint.error) as Error} retry={() => { change.reset(); mint.reset(); }} />}
      <form aria-label="Change password" onSubmit={(e) => { e.preventDefault(); change.mutate(); }}>
        <Input label="Current password" type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
        <Input label="New password (12+ characters)" type="password" autoComplete="new-password" required minLength={12} value={next} onChange={(e) => setNext(e.target.value)} />
        <div className="actions"><button type="submit" disabled={!current || next.length < 12 || change.isPending}>Change password</button></div>
      </form>
      <div className="actions"><button className="secondary" disabled={mint.isPending} onClick={() => mint.mutate()}>Show a new recovery code</button></div>
      {code && <p role="status"><code>{code}</code> — copy it now, Orbit never shows it again.</p>}
      <p className="muted">Locked out entirely? Run <code>orbit-server recovery-code</code> on the server, then use Forgot password on the sign-in page.</p>
    </section>
  );
}
