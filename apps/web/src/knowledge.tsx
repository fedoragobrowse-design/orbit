import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  label,
  post,
  put,
  remove,
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

export function DocPage() {
  const { page } = useParams();
  const name = (page ?? "").trim();
  const titles: Record<string, string> = { overview: "What Orbit is", settings: "Settings explained", memory: "How memory works", tools: "What the agent can do" };
  const q = useQuery({ queryKey: ["doc", name], queryFn: () => api<{ page: string; content: string }>(`/docs/${encodeURIComponent(name)}`), enabled: !!name });
  return (
    <>
      <PageHeader title={titles[name] ?? "Guide"} description="The same words the agent reads. Plain text, no surprises." />
      {q.isPending && <p role="status">Loading guide…</p>}
      {q.error && <ErrorNotice error={q.error} retry={() => q.refetch()} />}
      {q.data && <section className="panel"><pre style={{ whiteSpace: "pre-wrap" }}>{q.data.content}</pre></section>}
      <p className="muted"><Link to="/settings">Back to Settings</Link></p>
    </>
  );
}

function MemoryList() {
  const client = useQueryClient();
  const [typeFilter, setTypeFilter] = useState("all");
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const forget = useMutation({
    mutationFn: (id: string) => remove(`/memory/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["/memory"] }),
  });
  const closeDelete = () => {
    if (!forget.isPending) setDeleting(null);
  };
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
          {(items) => {
            const verified = items.filter((r) => text(r.status) === "VERIFIED").length;
            const types: Record<string, number> = {};
            for (const r of items) {
              const t = label(r.type) || "Untyped";
              types[t] = (types[t] ?? 0) + 1;
            }
            const typeNames = Object.keys(types).sort();
            const shown =
              typeFilter === "all"
                ? items
                : items.filter((r) => label(r.type) === typeFilter);
            return (
              <>
                <p className="memory-summary" role="status">
                  Remembering <strong>{items.length}</strong>{" "}
                  {items.length === 1 ? "thing" : "things"}
                  {verified > 0 && (
                    <> · {verified} verified</>
                  )}
                  {typeNames.length > 0 && (
                    <> · {typeNames.map((t) => `${types[t]} ${t.toLowerCase()}`).join(" · ")}</>
                  )}
                </p>
                {typeNames.length > 1 && (
                  <div className="memory-folders" role="group" aria-label="Filter by type">
                    <button
                      type="button"
                      className={typeFilter === "all" ? "memory-folder-active" : ""}
                      onClick={() => setTypeFilter("all")}
                    >
                      All ({items.length})
                    </button>
                    {typeNames.map((t) => (
                      <button
                        type="button"
                        key={t}
                        className={typeFilter === t ? "memory-folder-active" : ""}
                        onClick={() => setTypeFilter(t)}
                      >
                        {t} ({types[t]})
                      </button>
                    ))}
                  </div>
                )}
                {shown.length === 0 ? (
                  <Empty title="Nothing of this type">
                    No memories filed under {typeFilter} yet.
                  </Empty>
                ) : (
                  <ul className="memory-files">
                    {shown.map((row) => (
                      <li key={row.id} className="memory-file">
                        <Link className="safe-link memory-file-name" to={`/memory/${row.id}`}>
                          {text(row.subject) || "Untitled memory"}
                        </Link>
                        <span className="memory-file-meta">
                          {label(row.type)} · <Status value={row.status} /> ·{" "}
                          {label(row.privacy_class)} · {timestamp(row.updated_at)}
                        </span>
                        <div className="actions">
                          <button
                            type="button"
                            className="danger"
                            onClick={() => setDeleting(row)}
                          >
                            Delete
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </>
            );
          }}
        </Resource>
        {forget.error && (
          <ErrorNotice error={forget.error} retry={() => forget.reset()} />
        )}
        {deleting && (
          <Confirm
            title="Delete this memory?"
            action="Delete"
            pending={forget.isPending}
            onClose={closeDelete}
            onConfirm={() => {
              forget.mutate(String(deleting.id), {
                onSuccess: () => setDeleting(null),
              });
            }}
          >
            <p>
              {text(deleting.subject) || "This memory"} will be forgotten. Orbit
              stops using it and keeps only an audit stub. This cannot be
              undone.
            </p>
          </Confirm>
        )}
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
    queryFn: () =>
      api<{ record: RecordData; history: RecordData[]; conflicts: RecordData[] }>(
        `/memory/${id}/history`,
      ),
  });
  const [forgetting, setForgetting] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [superseding, setSuperseding] = useState(false);
  const invalidate = () => {
    client.invalidateQueries({ queryKey: ["memory"] });
    client.invalidateQueries({ queryKey: ["/memory"] });
  };
  const verify = useMutation({
    mutationFn: (version: number) =>
      post<RecordData>(`/memory/${id}/verify`, {
        expected_revision: version,
      }),
    onSuccess: invalidate,
  });
  const forget = useMutation({
    mutationFn: () => post<RecordData>(`/memory/${id}/forget`),
    onSuccess: invalidate,
  });
  const removeMemory = useMutation({
    mutationFn: () => remove(`/memory/${id}`),
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
  const version = Number(row.version ?? 0);
  const error = verify.error ?? forget.error ?? removeMemory.error;
  const versions = history.data?.history ?? [];
  return (
    <article className="panel section">
      <header className="page-heading">
        <div>
          <h2>{text(row.subject) || "Untitled memory"}</h2>
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
          version {text(row.version)}.
          {row.valid_until
            ? ` Valid until ${timestamp(row.valid_until)}.`
            : ""}
        </small>
      </p>
      <div className="actions">
        <button
          disabled={verify.isPending}
          onClick={() => verify.mutate(version)}
        >
          {verify.isPending ? "Verifying…" : "Verify"}
        </button>
        <button className="secondary" onClick={() => setSuperseding(true)}>
          Supersede
        </button>
        <button className="danger" onClick={() => setForgetting(true)}>
          Forget
        </button>
        <button
          className="danger"
          disabled={removeMemory.isPending}
          onClick={() => setDeleting(true)}
        >
          {removeMemory.isPending ? "Deleting…" : "Delete"}
        </button>
        <Link className="safe-link" to="/memory">
          All memories
        </Link>
      </div>
      {error && (
        <ErrorNotice
          error={error}
          retry={() => {
            verify.reset();
            forget.reset();
            removeMemory.reset();
          }}
        />
      )}
      {forgetting && (
        <Confirm
          title="Forget this memory?"
          action="Forget"
          pending={forget.isPending}
          onClose={() => setForgetting(false)}
          onConfirm={() => {
            forget.mutate(undefined, { onSuccess: () => setForgetting(false) });
          }}
        >
          <p>
            Orbit will stop using this fact. The record is marked forgotten and
            kept only for audit.
          </p>
        </Confirm>
      )}
      {deleting && (
        <Confirm
          title="Delete this memory?"
          action="Delete"
          pending={removeMemory.isPending}
          onClose={() => {
            if (!removeMemory.isPending) setDeleting(false);
          }}
          onConfirm={() => {
            removeMemory.mutate(undefined, {
              onSuccess: () => setDeleting(false),
            });
          }}
        >
          <p>
            Orbit stops using this fact and keeps only an audit stub. This
            cannot be undone.
          </p>
        </Confirm>
      )}
      {superseding && (
        <SupersedeForm
          id={id}
          revision={version}
          onDone={() => setSuperseding(false)}
        />
      )}
      <h3>History</h3>
      {history.isPending && <p role="status">Loading history…</p>}
      {history.error && (
        <ErrorNotice error={history.error} retry={() => history.refetch()} />
      )}
      {history.data && versions.length === 0 && (
        <Empty title="No earlier revisions">This memory has not changed yet.</Empty>
      )}
      {versions.length > 0 && (
        <ul className="list">
          {versions.map((entry, index) => (
            <li key={text((entry as RecordData).id) || index}>
              {timestamp((entry as RecordData).created_at)} ·{" "}
              {text((entry as RecordData).subject)} ·{" "}
              <Status value={(entry as RecordData).status} />
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
const RULE_CASES = [
  { value: "email", label: "Email — new mail in an account", eventType: "SOURCE_CHANGED", sourceType: "email", hint: "e.g. inbox account id" },
  { value: "calendar", label: "Calendar — upcoming event due", eventType: "CALENDAR_DUE", sourceType: "calendar", hint: "e.g. calendar id" },
  { value: "file", label: "Files — a watched folder changes", eventType: "SOURCE_CHANGED", sourceType: "file", hint: "e.g. folder path or root id" },
  { value: "browser", label: "Browser — a watched page changes", eventType: "SOURCE_CHANGED", sourceType: "browser", hint: "e.g. watched page id" },
  { value: "desktop", label: "Desktop — a device event fires", eventType: "SOURCE_CHANGED", sourceType: "desktop", hint: "e.g. node id" },
] as const;
const BEHAVIORS = [
  { value: "OFF", label: "Off — keep the rule but never run it" },
  { value: "SUGGEST", label: "Suggest — file a suggestion I review" },
  { value: "ASK", label: "Ask — ask me before acting" },
  { value: "AUTO", label: "Act with permissions — act inside my grants and budget" },
] as const;
function triggerLabel(trigger: unknown): string {
  if (typeof trigger !== "object" || trigger === null) return text(trigger);
  const t = trigger as RecordData;
  const kind = text(t.kind);
  if (kind !== "event") return kind || text(trigger);
  const et = text(t.event_type);
  const src = text((t as RecordData).source) || text((t as RecordData).source_id);
  return src ? `${et} · ${src}` : et;
}
function ruleBehavior(policyScope: unknown): string {
  if (typeof policyScope !== "object" || policyScope === null) return "—";
  const b = text((policyScope as RecordData).behavior);
  return b || "—";
}
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
                  <th scope="col">Behavior</th>
                  <th scope="col">Next run</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id} id={`automation-${String(row.id)}`}>
                    <th scope="row">{text(row.instructions).slice(0, 80)}</th>
                    <td>{triggerLabel(row.trigger)}</td>
                    <td>
                      <Status value={ruleBehavior(row.policy_scope)} />
                    </td>
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
  const agents = useQuery({ queryKey: ["rule-agents"], queryFn: () => api<{ items: RecordData[] }>("/agents?limit=100").then((r) => r.items ?? []) });
  const [form, setForm] = useState({
    kind: "timer",
    expression: "",
    runAt: "",
    eventType: "EMAIL_RECEIVED",
    ruleCase: "email" as string,
    sourceId: "",
    behavior: "ASK" as string,
    agentId: "",
    cooldown: "3600",
    maxRuns: "10",
    budgetUsd: "1.00",
    confidence: "0.7",
    quietStart: "",
    quietEnd: "",
    notify: "NONE",
    instructions: "",
  });
  const templates = [
    { name: "Weekly review", kind: "cron", expression: "0 9 * * 1", notify: "IN_APP", instructions: "Weekly review: list what shipped, what is stuck, and what needs my decision. Read Home brief, open tasks and pending approvals." },
    { name: "Bill reminders", kind: "event", eventType: "EMAIL_RECEIVED", notify: "PUSH", instructions: "When a bill arrives, queue a summary and remind me before it is due. Never pay or reply without my approval." },
    { name: "File watcher", kind: "event", eventType: "EMAIL_RECEIVED", notify: "EMAIL_DIGEST", instructions: "Watch for shared-file notifications and add a digest entry summarizing what changed." },
  ] as const;
  const ruleCase = RULE_CASES.find((c) => c.value === form.ruleCase) ?? RULE_CASES[0];
  const needsAgent = form.kind === "rule" && form.behavior === "AUTO";
  const create = useMutation({
    mutationFn: () => {
      if (form.kind !== "rule") {
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
      }
      const sourceId = form.sourceId.trim();
      const trigger = { kind: "event", event_type: ruleCase.eventType, source_type: ruleCase.sourceType, source_id: sourceId };
      const policyScope: Record<string, unknown> = {
        behavior: form.behavior,
        source_scopes: [`${ruleCase.sourceType}:${sourceId}`],
      };
      const cooldown = Number(form.cooldown);
      if (Number.isFinite(cooldown) && form.cooldown.trim() !== "") policyScope.cooldown_seconds = Math.max(0, Math.floor(cooldown));
      const maxRuns = Number(form.maxRuns);
      if (Number.isFinite(maxRuns) && form.maxRuns.trim() !== "") policyScope.max_runs_per_day = Math.max(1, Math.floor(maxRuns));
      const budget = Number(form.budgetUsd);
      if (Number.isFinite(budget) && form.budgetUsd.trim() !== "") policyScope.max_daily_micro_usd = Math.max(0, Math.round(budget * 1_000_000));
      const confidence = Number(form.confidence);
      if (Number.isFinite(confidence) && form.confidence.trim() !== "") policyScope.minimum_confidence = Math.min(1, Math.max(0, confidence));
      if (form.quietStart.trim() !== "" && form.quietEnd.trim() !== "") {
        policyScope.quiet_hours = { start: form.quietStart.trim(), end: form.quietEnd.trim(), timezone: "UTC" };
      }
      if (form.behavior === "AUTO") {
        policyScope.action_scopes = [{ tool: "*", scope_key: `${ruleCase.sourceType}:${sourceId}`, scope_revision: 1 }];
      }
      return post<RecordData>("/automations", {
        trigger,
        agent_id: form.agentId.trim() !== "" ? form.agentId.trim() : undefined,
        policy_scope: policyScope,
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
        <option value="rule">Proactive rule (email/calendar/file/browser/desktop)</option>
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
      {form.kind === "rule" && (
        <>
          <Select
            label="What should Orbit watch?"
            value={form.ruleCase}
            onChange={(e) => setForm({ ...form, ruleCase: e.target.value })}
          >
            {RULE_CASES.map((c) => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </Select>
          <Input
            label={`Exact source (${ruleCase.hint})`}
            required
            placeholder={ruleCase.hint}
            value={form.sourceId}
            onChange={(e) => setForm({ ...form, sourceId: e.target.value })}
          />
          <Select
            label="When it matches, Orbit should…"
            value={form.behavior}
            onChange={(e) => setForm({ ...form, behavior: e.target.value })}
          >
            {BEHAVIORS.map((b) => (
              <option key={b.value} value={b.value}>{b.label}</option>
            ))}
          </Select>
          <p className="muted">
            <small>
              New rules are saved <strong>disabled</strong>. Enable the rule after
              reviewing — Act-with-permissions additionally needs an agent, a
              grant, and a budget below.
            </small>
          </p>
          {(form.behavior === "ASK" || form.behavior === "AUTO") && (
            <Select
              label={needsAgent ? "Agent (required for Act-with-permissions)" : "Agent (optional)"}
              value={form.agentId}
              required={needsAgent}
              onChange={(e) => setForm({ ...form, agentId: e.target.value })}
            >
              <option value="">No agent — notify only</option>
              {(agents.data ?? []).map((a) => (
                <option key={String(a.id)} value={String(a.id)}>{text(a.name) || text(a.id)}</option>
              ))}
            </Select>
          )}
          <Input
            label="Quiet hours start (HH:MM UTC, optional)"
            placeholder="22:00"
            value={form.quietStart}
            onChange={(e) => setForm({ ...form, quietStart: e.target.value })}
          />
          <Input
            label="Quiet hours end (HH:MM UTC, optional)"
            placeholder="07:00"
            value={form.quietEnd}
            onChange={(e) => setForm({ ...form, quietEnd: e.target.value })}
          />
          <Input
            label="Cooldown between runs (seconds)"
            type="number"
            min={0}
            value={form.cooldown}
            onChange={(e) => setForm({ ...form, cooldown: e.target.value })}
          />
          <Input
            label="Max runs per day"
            type="number"
            min={1}
            value={form.maxRuns}
            onChange={(e) => setForm({ ...form, maxRuns: e.target.value })}
          />
          <Input
            label="Max spend per day (USD)"
            type="number"
            min={0}
            step="0.01"
            value={form.budgetUsd}
            onChange={(e) => setForm({ ...form, budgetUsd: e.target.value })}
          />
          <Input
            label="Minimum confidence (0–1)"
            type="number"
            min={0}
            max={1}
            step="0.05"
            value={form.confidence}
            onChange={(e) => setForm({ ...form, confidence: e.target.value })}
          />
        </>
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