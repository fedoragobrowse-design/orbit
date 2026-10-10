import { useEffect, useState } from "react";
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
  text,
  timestamp,
  type RecordData,
  type Session,
} from "./api";
import { enablePush } from "./push";
import { useDraft } from "./App";
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
    refetchInterval: 5000,
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
    </>
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
  revision: number;
};
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
          <button disabled={save.isPending}>Save</button>
        </form>
      )}
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
