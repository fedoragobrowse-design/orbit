import { useEffect, useState } from "react";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
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
} from "./api";
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
  const ready = useQuery({
    queryKey: ["ready"],
    queryFn: () => api<RecordData>("/ready"),
  });
  const health = useQuery({
    queryKey: ["health"],
    queryFn: () => api<RecordData>("/health"),
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
  return (
    <>
      <PageHeader
        title="Your workspace"
        description="Review changes, continue your work, or ask Orbit."
      />
      <div className="home-grid">
        <div className="home-primary">
          <section className="panel attention">
            <h2>Needs your attention</h2>
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
          <section className="recent">
            <h2>Recent activity</h2>
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
          <section className="panel systems">
            <h2>Connections and health</h2>
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
          <section className="panel projects">
            <h2>Your projects</h2>
            <p className="muted">
              <Link to="/memory">Memory</Link> lists projects and what Orbit
              remembers. Recent file and message events appear under{" "}
              <Link to="/activity">Activity</Link> instead.
            </p>
          </section>
        </div>
      </div>
    </>
  );
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
function RetentionSettings() {
  const settings = useQuery({
    queryKey: ["retention"],
    queryFn: () => api<RecordData>("/retention"),
  });
  const [form, setForm] = useState<Record<string, string>>({});
  const save = useMutation({
    mutationFn: (body: Record<string, number>) => put<RecordData>("/retention", body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["retention"] }),
  });
  if (settings.isPending)
    return (
      <section className="panel form">
        <h2>Retention</h2>
        <p role="status">Loading retention…</p>
      </section>
    );
  if (settings.error)
    return (
      <section className="panel form">
        <h2>Retention</h2>
        <ErrorNotice error={settings.error} retry={() => settings.refetch()} />
      </section>
    );
  const current = settings.data ?? {};
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    const body: Record<string, number> = {};
    for (const name of [
      "event_body_days",
      "conversation_body_days",
      "runtime_artifact_days",
      "connector_cache_days",
    ]) {
      const raw = form[name] ?? (current[name] != null ? String(current[name]) : "");
      const value = Math.floor(Number(raw));
      if (Number.isFinite(value) && value >= 1) body[name] = value;
    }
    save.mutate(body);
  };
  return (
    <section className="panel form">
      <h2>Retention</h2>
      <p className="muted">
        Pending approvals and runtime evidence are protected from ordinary
        cleanup.
      </p>
      <form onSubmit={submit}>
        {[
          "event_body_days",
          "conversation_body_days",
          "runtime_artifact_days",
          "connector_cache_days",
        ].map((name) => (
          <label key={name}>
            {name.replaceAll("_", " ")}
            <input
              type="number"
              min={1}
              value={form[name] ?? (current[name] != null ? String(current[name]) : "")}
              onChange={(e) => setForm({ ...form, [name]: e.target.value })}
            />
          </label>
        ))}
        {save.error && (
          <ErrorNotice error={save.error} retry={() => save.reset()} />
        )}
        <button disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save retention"}
        </button>
      </form>
    </section>
  );
}
type SettingsData = {
  installation_mode: string;
  autonomy_mode: string;
  allow_private_cloud: boolean;
  revision: number;
};
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
        description="Privacy, autonomy, budgets, and retention belong to you."
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
            label="Installation mode"
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
          <Select
            label="Autonomy"
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
            Allow PRIVATE context on cloud providers
          </label>
          <p className="muted">
            HIGHLY_PRIVATE stays local. SECRET never enters a model. Trusted
            Automation still requires specific low-risk grants; high-impact
            actions do not become automatic.
          </p>
          <button disabled={save.isPending}>Save privacy and autonomy</button>
        </form>
      )}
      <RetentionSettings />
      <section className="panel form">
        <h2>Policies and budgets</h2>
        <p className="muted">
          <Link to="/approvals">Approvals</Link> enforce the standing policy:
          denials win, and approval plus sandbox requirements accumulate.
          Standing rules are managed through the policy crate by the owner —
          there is no separate rules API in this build.
        </p>
      </section>
      {save.error && <ErrorNotice error={save.error} />}{" "}
      {notice && <p role="status">{notice}</p>}
    </>
  );
}
