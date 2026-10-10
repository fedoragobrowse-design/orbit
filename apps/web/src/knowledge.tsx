import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  label,
  post,
  put,
  text,
  timestamp,
  type Page,
  type RecordData,
} from "./api";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Field,
  Input,
  Json,
  PageHeader,
  Resource,
  Select,
  Status,
  Textarea,
} from "./ui";

export function Memory() {
  const { id } = useParams();
  return (
    <>
      <PageHeader
        title="Memory"
        description="What Orbit remembers across conversations."
      />
      {id ? <MemoryDetail id={id} /> : <MemoryList />}
      <Projects />
      <Retention />
    </>
  );
}

function MemoryList() {
  return (
    <section className="section" aria-label="Memories">
      <div className="panel">
        <h2>Memories</h2>
        <Resource
          path="/memory"
          empty={
            <Empty title="Nothing remembered yet">
              Facts Orbit learns on your behalf appear here. You can verify,
              supersede, or forget any of them.
            </Empty>
          }
        >
          {(items) => (
            <table>
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Type</th>
                  <th scope="col">Status</th>
                  <th scope="col">Privacy</th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">
                      <Link className="safe-link" to={`/memory/${row.id}`}>
                        {text(row.subject)}
                      </Link>
                    </th>
                    <td>{label(row.type)}</td>
                    <td><Status value={row.status} /></td>
                    <td>{label(row.privacy_class)}</td>
                    <td>{timestamp(row.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Resource>
      </div>
    </section>
  );
}

function MemoryDetail({ id }: { id: string }) {
  const client = useQueryClient();
  const record = useQuery({
    queryKey: ["memory", id],
    queryFn: () => api<RecordData>(`/memory/${id}`),
  });
  const history = useQuery({
    queryKey: ["memory", id, "history"],
    queryFn: () => api<RecordData[]>(`/memory/${id}/history`),
  });
  const [forgetting, setForgetting] = useState(false);
  const [superseding, setSuperseding] = useState(false);
  const invalidate = () => client.invalidateQueries({ queryKey: ["memory"] });
  const verify = useMutation({
    mutationFn: (revision: number) =>
      post<RecordData>(`/memory/${id}/verify`, {
        expected_revision: revision,
      }),
    onSuccess: invalidate,
  });
  const forget = useMutation({
    mutationFn: () => post<RecordData>(`/memory/${id}/forget`),
    onSuccess: invalidate,
  });
  if (record.isPending)
    return (
      <section className="panel section">
        <p role="status">Loading…</p>
      </section>
    );
  if (record.error)
    return (
      <section className="panel section">
        <ErrorNotice error={record.error} retry={() => record.refetch()} />
      </section>
    );
  const row = record.data!;
  const revision = Number(row.revision ?? 0);
  const error = verify.error ?? forget.error;
  return (
    <article className="panel section">
      <header className="page-heading">
        <div>
          <h2>{text(row.subject)}</h2>
          <p className="muted">
            {label(row.type)} · <Status value={row.status} />
          </p>
        </div>
        <small>Updated {timestamp(row.updated_at)}</small>
      </header>
      <h3>What Orbit believes</h3>
      <Json value={row.value} />
      <p>
        <small>
          Confidence {text(row.confidence)}, privacy {label(row.privacy_class)},
          revision {text(row.revision)}.
          {row.valid_until
            ? ` Valid until ${timestamp(row.valid_until)}.`
            : ""}
        </small>
      </p>
      <div className="actions">
        <button
          disabled={verify.isPending}
          onClick={() => verify.mutate(revision)}
        >
          {verify.isPending ? "Verifying…" : "Verify"}
        </button>
        <button className="secondary" onClick={() => setSuperseding(true)}>
          Supersede
        </button>
        <button className="danger" onClick={() => setForgetting(true)}>
          Forget
        </button>
        <Link className="safe-link" to="/memory">
          All memories
        </Link>
      </div>
      {error && <ErrorNotice error={error} retry={() => forget.reset()} />}
      {forgetting && (
        <Confirm
          title="Forget this memory?"
          action="Forget"
          pending={forget.isPending}
          onClose={() => setForgetting(false)}
          onConfirm={() => {
            forget.mutate();
            setForgetting(false);
          }}
        >
          <p>
            Orbit will stop using this fact. The record is marked forgotten and
            kept only for audit.
          </p>
        </Confirm>
      )}
      {superseding && (
        <SupersedeForm
          id={id}
          revision={revision}
          onDone={() => setSuperseding(false)}
        />
      )}
      <h3>History</h3>
      {history.isPending && <p role="status">Loading history…</p>}
      {history.error && (
        <ErrorNotice error={history.error} retry={() => history.refetch()} />
      )}
      {history.data && !history.data.length && (
        <Empty title="No earlier revisions">This memory has not changed yet.</Empty>
      )}
      {history.data && history.data.length > 0 && (
        <ul className="list">
          {history.data.map((entry, index) => (
            <li key={text(entry.id) || index}>
              {timestamp(entry.created_at)} · {text(entry.subject)} ·{" "}
              <Status value={entry.status} />
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function SupersedeForm({
  id,
  revision,
  onDone,
}: {
  id: string;
  revision: number;
  onDone: () => void;
}) {
  const client = useQueryClient();
  const [subject, setSubject] = useState("");
  const [value, setValue] = useState("{}");
  const supersede = useMutation({
    mutationFn: () =>
      post<RecordData>(`/memory/${id}/supersede`, {
        subject,
        value: JSON.parse(value),
        expected_revision: revision,
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["memory"] });
      onDone();
    },
  });
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        supersede.mutate();
      }}
    >
      <Field label="Subject" hint="Replaces the current subject.">
        <input
          required
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
        />
      </Field>
      <Field label="Value" hint="Any JSON value. It must parse before it is sent.">
        <textarea rows={5} required value={value} onChange={(e) => setValue(e.target.value)} />
      </Field>
      {supersede.error && (
        <ErrorNotice error={supersede.error} retry={() => supersede.reset()} />
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={supersede.isPending}>
          {supersede.isPending ? "Saving…" : "Supersede"}
        </button>
      </div>
    </form>
  );
}

function Projects() {
  const projects = useQuery({
    queryKey: ["projects"],
    queryFn: () => api<Page>("/projects?limit=50"),
  });
  if (projects.isPending)
    return (
      <section className="panel section">
        <p role="status">Loading projects…</p>
      </section>
    );
  if (projects.error)
    return (
      <section className="panel section">
        <ErrorNotice error={projects.error} retry={() => projects.refetch()} />
      </section>
    );
  const items = projects.data?.items ?? [];
  return (
    <section className="section" aria-label="Project notebooks">
      <div className="panel">
        <h2>Project notebooks</h2>
        {!items.length ? (
          <Empty title="No project notebooks">
            A project notebook collects the tasks, decisions, and documents
            Orbit gathered for one project.
          </Empty>
        ) : (
          <ul className="list">
            {items.map((item, index) => {
              const record = (item.record ?? item) as RecordData;
              const related = Array.isArray(item.related) ? item.related : [];
              return (
                <li className="row" key={text(record.id) || index}>
                  <div className="row-main">
                    <h3>{text(record.subject)}</h3>
                    <p>
                      <small>
                        {related.length
                          ? `${related.length} related ${related.length === 1 ? "entry" : "entries"}`
                          : "No related entries yet"}
                      </small>
                    </p>
                  </div>
                  <div className="row-meta">
                    <Link className="safe-link" to={`/memory/${text(record.id)}`}>
                      Open
                    </Link>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </section>
  );
}

function Retention() {
  const client = useQueryClient();
  const retention = useQuery({
    queryKey: ["retention"],
    queryFn: () => api<RecordData>("/retention"),
  });
  const [form, setForm] = useState<Record<string, string> | null>(null);
  const save = useMutation({
    mutationFn: (values: Record<string, string>) =>
      put<RecordData>("/retention", {
        event_body_days: Number(values.event_body_days),
        conversation_body_days: Number(values.conversation_body_days),
        runtime_artifact_days: Number(values.runtime_artifact_days),
        connector_cache_days: Number(values.connector_cache_days),
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["retention"] }),
  });
  if (retention.isPending)
    return (
      <section className="panel section">
        <p role="status">Loading retention…</p>
      </section>
    );
  if (retention.error)
    return (
      <section className="panel section">
        <ErrorNotice
          error={retention.error}
          retry={() => retention.refetch()}
        />
      </section>
    );
  const current = retention.data!;
  const fields = [
    "event_body_days",
    "conversation_body_days",
    "runtime_artifact_days",
    "connector_cache_days",
  ];
  const values =
    form ?? Object.fromEntries(fields.map((f) => [f, String(current[f] ?? 1)]));
  return (
    <section className="section" aria-label="Retention">
      <div className="panel">
        <h2>Retention</h2>
        <p>
          <small>
            How long Orbit keeps each kind of body before deleting it. Every
            window must be at least one day.
          </small>
        </p>
        <form
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate(values);
          }}
        >
          {fields.map((field) => (
            <Field key={field} label={label(field)}>
              <input
                type="number"
                min={1}
                required
                value={values[field]}
                onChange={(e) => setForm({ ...values, [field]: e.target.value })}
              />
            </Field>
          ))}
          {save.error && (
            <ErrorNotice error={save.error} retry={() => save.reset()} />
          )}
          <div className="actions">
            <button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : "Save retention"}
            </button>
          </div>
        </form>
      </div>
    </section>
  );
}

const SCHEDULE_TYPES: Record<string, true> = { SCHEDULE_TRIGGER: true, TIMER_TRIGGER: true };
function AutomationManager() {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const toggle = useMutation({
    mutationFn: ({
      id,
      enabled,
      expected_revision,
    }: {
      id: string;
      enabled: boolean;
      expected_revision: number;
    }) => post<RecordData>(`/automations/${id}/enable`, { enabled, expected_revision }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["/automations"] }),
  });
  const removeAutomation = useMutation({
    mutationFn: (id: string) =>
      api<void>(`/automations/${id}`, { method: "DELETE" }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["/automations"] }),
  });
  return (
    <section className="section" aria-label="Automations">
      <div className="panel">
        <h2>Automations</h2>
        <Resource
          path="/automations"
          empty={
            <Empty title="No automations yet">
              Create a schedule or file-event routine below.
            </Empty>
          }
        >
          {(items) => (
            <table>
              <thead>
                <tr>
                  <th scope="col">Instructions</th>
                  <th scope="col">Trigger</th>
                  <th scope="col">Next run</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">{text(row.instructions).slice(0, 80)}</th>
                    <td>{text((row.trigger as RecordData)?.kind ?? row.trigger)}</td>
                    <td>{timestamp(row.next_run)}</td>
                    <td>
                      <Status value={row.enabled} />
                    </td>
                    <td>
                      <button
                        className="secondary"
                        disabled={toggle.isPending}
                        onClick={() =>
                          toggle.mutate({
                            id: String(row.id),
                            enabled: !row.enabled,
                            expected_revision: Number(row.revision ?? 0),
                          })
                        }
                      >
                        {row.enabled ? "Disable" : "Enable"}
                      </button>{" "}
                      <button
                        className="danger"
                        disabled={removeAutomation.isPending}
                        onClick={() => removeAutomation.mutate(String(row.id))}
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Resource>
        {(toggle.error || removeAutomation.error) && (
          <ErrorNotice
            error={(toggle.error ?? removeAutomation.error)!}
            retry={() => {
              toggle.reset();
              removeAutomation.reset();
            }}
          />
        )}
        {open ? (
          <NewAutomation onDone={() => setOpen(false)} />
        ) : (
          <div className="actions">
            <button className="secondary" onClick={() => setOpen(true)}>
              Add automation
            </button>
            <NewBriefShortcut />
          </div>
        )}
      </div>
    </section>
  );
}
/// One click to schedule the daily brief: a 07:00 cron whose instructions say
/// to read the brief page and nudge the owner. The scheduler fires it like any
/// other cron; nothing new runs server-side.
function NewBriefShortcut() {
  const client = useQueryClient();
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/automations", {
        trigger: { kind: "cron", expression: "0 7 * * *", timezone: "UTC" },
        notification_behavior: "IN_APP",
        instructions: "Morning brief: summarize pending approvals, unread notifications and open tasks from the Home brief panel.",
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["/automations"] }),
  });
  return <>
    <button className="secondary" disabled={create.isPending} onClick={() => create.mutate()}>
      {create.isPending ? "Adding…" : "Add daily morning brief (07:00)"}
    </button>
    {create.error && <ErrorNotice error={create.error} retry={() => create.reset()} />}
  </>;
}

function NewAutomation({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    kind: "timer",
    expression: "",
    runAt: "",
    eventType: "EMAIL_RECEIVED",
    notify: "NONE",
    instructions: "",
  });
  const templates = [
    { name: "Weekly review", kind: "cron", expression: "0 9 * * 1", notify: "IN_APP", instructions: "Weekly review: list what shipped, what is stuck, and what needs my decision. Read Home brief, open tasks and pending approvals." },
    { name: "Bill reminders", kind: "event", eventType: "EMAIL_RECEIVED", notify: "PUSH", instructions: "When a bill arrives, queue a summary and remind me before it is due. Never pay or reply without my approval." },
    { name: "File watcher", kind: "event", eventType: "EMAIL_RECEIVED", notify: "EMAIL_DIGEST", instructions: "Watch for shared-file notifications and add a digest entry summarizing what changed." },
  ] as const;
  const create = useMutation({
    mutationFn: () => {
      const trigger =
        form.kind === "cron"
          ? { kind: "cron", expression: form.expression, timezone: "UTC" }
          : form.kind === "timer"
            ? {
                kind: "timer",
                run_at: form.runAt
                  ? new Date(form.runAt).toISOString()
                  : new Date(Date.now() + 3600_000).toISOString(),
              }
            : { kind: "event", event_type: form.eventType };
      return post<RecordData>("/automations", {
        trigger,
        notification_behavior: form.notify,
        instructions: form.instructions,
      });
    },
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["/automations"] });
      onDone();
    },
  });
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate();
      }}
    >
      <Select
        label="Start from a template (optional)"
        value=""
        onChange={(e) => {
          const t = templates[Number(e.target.value)];
          if (t) setForm({ ...form, kind: t.kind, expression: "expression" in t ? t.expression : "", eventType: "eventType" in t ? t.eventType : form.eventType, notify: t.notify, instructions: t.instructions });
        }}
      >
        <option value="">Blank automation…</option>
        {templates.map((t, i) => <option key={t.name} value={String(i)}>{t.name}</option>)}
      </Select>
      <Select
        label="Trigger kind"
        value={form.kind}
        onChange={(e) => setForm({ ...form, kind: e.target.value })}
      >
        <option value="timer">One-shot timer</option>
        <option value="cron">Cron schedule</option>
        <option value="event">Event trigger</option>
      </Select>
      {form.kind === "cron" && (
        <Input
          label="Cron expression (UTC)"
          required
          placeholder="0 9 * * *"
          value={form.expression}
          onChange={(e) => setForm({ ...form, expression: e.target.value })}
        />
      )}
      {form.kind === "timer" && (
        <Input
          label="Run at (defaults to one hour from now)"
          type="datetime-local"
          value={form.runAt}
          onChange={(e) => setForm({ ...form, runAt: e.target.value })}
        />
      )}
      {form.kind === "event" && (
        <Select
          label="Event type"
          value={form.eventType}
          onChange={(e) => setForm({ ...form, eventType: e.target.value })}
        >
          <option value="EMAIL_RECEIVED">Email received</option>
          <option value="FILE_CREATED">File created</option>
          <option value="TASK_COMPLETED">Task completed</option>
        </Select>
      )}
      <Select
        label="Also tell me"
        value={form.notify}
        onChange={(e) => setForm({ ...form, notify: e.target.value })}
      >
        <option value="NONE">In the app only when I look</option>
        <option value="IN_APP">Save a notification for me</option>
        <option value="PUSH">Push to my devices too</option>
        <option value="EMAIL_DIGEST">Add to my daily digest</option>
      </Select>
      <Textarea
        label="Instructions"
        required
        value={form.instructions}
        onChange={(e) => setForm({ ...form, instructions: e.target.value })}
      />
      {create.error && (
        <ErrorNotice error={create.error} retry={() => create.reset()} />
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save automation"}
        </button>
      </div>
    </form>
  );
}

export function Automations() {
  return (
    <>
      <PageHeader
        title="Automations"
        description="Recurring work Orbit runs on a schedule."
      />
      <AutomationManager />

      <section className="section" aria-label="Schedule activity">
        <div className="panel">
          <h2>Schedule activity</h2>
          <Resource
            path="/events"
            empty={
              <div className="empty">
                <h3>No schedule activity yet</h3>
                <p>
                  No SCHEDULE_TRIGGER or TIMER_TRIGGER events have been
                  recorded.
                </p>
              </div>
            }
          >
            {(items: RecordData[]) => {
              const scheduled = items.filter(
                (item) => SCHEDULE_TYPES[text(item.event_type)],
              );
              if (!scheduled.length) {
                return (
                  <div className="empty">
                    <h3>No schedule activity on this page</h3>
                    <p>
                      This page of events holds no SCHEDULE_TRIGGER or
                      TIMER_TRIGGER entries. Later pages may.
                    </p>
                  </div>
                );
              }
              return (
                <ul className="list">
                  {scheduled.map((item) => (
                    <li className="row" key={String(item.id)}>
                      <div className="row-main">
                        <h3>{label(item.event_type) || "Scheduled event"}</h3>
                        <p>
                          <small>
                            {text(item.id)} · {text(item.occurred_at)}
                          </small>
                        </p>
                      </div>
                      <div className="row-meta">
                        <Status value={item.event_type} />
                      </div>
                    </li>
                  ))}
                </ul>
              );
            }}
          </Resource>
        </div>
      </section>
    </>
  );
}