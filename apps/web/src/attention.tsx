import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ApiError,
  api,
  label,
  post,
  text,
  timestamp,
  type RecordData,
} from "./api";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Evidence,
  Field,
  Input,
  Json,
  Modal,
  PageHeader,
  Select,
  Status,
} from "./ui";

/// Attention list: proactive candidates backed by
/// GET /api/v1/proactive/candidates, with a notifications-backed fallback
/// while the pipeline lands. Every card names its why-now, exact
/// source/evidence, proposed action, permission mode, estimated cost and
/// execution target. Dismiss/snooze touch the candidate only; muting a
/// rule, pausing globally and revoking a grant stay one link away.

type ProposedAction = {
  kind: string;
  title: string;
  reason: string;
  severity: string;
  confidence: number | null;
  mode: string;
  cost: string;
  executionTarget: string;
  detail: RecordData;
};

type AttentionCandidate = {
  id: string;
  ruleId: string;
  fireKey: string;
  state: string;
  summary: string;
  evidenceRefs: string[];
  action: ProposedAction;
  taskId: string;
  snoozedUntil: string;
  revision: number;
  correlationId: string;
  raw: RecordData;
};

function str(row: { [key: string]: unknown }, ...keys: string[]): string {
  for (const key of keys) {
    const value = text(row[key]);
    if (value) return value;
  }
  return "";
}

function strList(row: { [key: string]: unknown }, ...keys: string[]): string[] {
  for (const key of keys) {
    const value = row[key];
    if (Array.isArray(value)) return value.map(text).filter(Boolean);
    if (typeof value === "string" && value) return [value];
  }
  return [];
}

function num(value: unknown): number | null {
  const n = typeof value === "number" ? value : Number(text(value));
  return Number.isFinite(n) ? n : null;
}

function asAction(value: unknown, host?: RecordData): ProposedAction {
  const row: Partial<RecordData> =
    value && typeof value === "object" && !Array.isArray(value)
      ? { ...(value as Partial<RecordData>) }
      : {};
  const combined: RecordData = { id: "", ...(host ?? {}), ...row };
  const {
    kind,
    mode,
    cost,
    execution_target,
    executionTarget,
    reason,
    title,
    severity,
    confidence,
    summary,
    evidence_refs,
    evidenceRefs,
    sources,
    ...rest
  } = row;
  void kind;
  void mode;
  void cost;
  void execution_target;
  void executionTarget;
  void reason;
  void title;
  void severity;
  void confidence;
  void summary;
  void evidence_refs;
  void evidenceRefs;
  void sources;
  const detail: RecordData = { id: str(row, "id"), ...rest };
  return {
    kind: str(row, "kind") || "suggest_task",
    title: str(row, "title") || str(combined, "title", "summary"),
    reason: str(row, "reason") || str(combined, "reason", "summary"),
    severity: str(row, "severity", "label") || "ACTION_REQUIRED",
    confidence: num(row.confidence ?? combined.confidence),
    mode: str(row, "mode", "permission_mode").toUpperCase() || str(combined, "mode", "permission_mode").toUpperCase() || "SUGGEST",
    cost: str(row, "cost", "estimated_cost") || "—",
    executionTarget: str(row, "execution_target", "executionTarget", "target") || "—",
    detail,
  };
}

function asCandidate(row: RecordData): AttentionCandidate {
  const action = asAction(row.proposed_action ?? row.action, row);
  const evidence = row.evidence_refs ?? row.evidenceRefs ?? row.sources ?? action.detail.evidence_refs;
  const summary =
    text(row.summary ?? row.why_now) ||
    action.title ||
    (action.kind === "notify" && action.reason ? action.reason : "") ||
    text(row.title) ||
    "A rule raised this for review.";
  return {
    id: text(row.id),
    ruleId: text(row.automation_id ?? row.rule_id ?? row.automationId),
    fireKey: text(row.fire_key),
    state: text(row.state).toUpperCase() || "PENDING",
    summary,
    evidenceRefs: Array.isArray(evidence)
      ? evidence.map(text).filter(Boolean)
      : [],
    action,
    taskId: text(row.task_id),
    snoozedUntil: text(row.snoozed_until),
    revision: Number(row.revision ?? 0),
    correlationId: text(row.correlation_id),
    raw: row,
  };
}

const OPEN_STATES: Record<string, true> = {
  PENDING: true,
  SUGGESTED: true,
  AWAITING_APPROVAL: true,
  RUNNING: true,
  FAILED: true,
};

function modeNote(mode: string): string {
  switch (mode) {
    case "AUTO":
      return "Auto submits through a standing grant. Approving once runs this suggestion without changing the rule.";
    case "ASK":
      return "Ask parks for your decision. Nothing runs until you approve it here.";
    default:
      return "Suggest is draft-only. Nothing runs on its own.";
  }
}

function kindFamily(kind: string): "calendar" | "mail" | "files" | "ha" | "notify" | "needs_review" | "suggest_task" | "note" {
  const k = kind.toLowerCase().replaceAll("-", "_");
  if (k.includes("calendar") || k.includes("meeting") || k.includes("prep")) return "calendar";
  if (k.includes("mail") || k.includes("email") || k.includes("draft")) return "mail";
  if (k.includes("file") || k.includes("change") || k.includes("summary")) return "files";
  if (k.includes("ha") || k.includes("home") || k.includes("hass") || k.includes("service")) return "ha";
  if (k === "notify") return "notify";
  if (k === "needs_review" || k === "needs review") return "needs_review";
  if (k === "suggest_task" || k === "suggest task") return "suggest_task";
  return "note";
}

function ActionDetail({ action }: { action: ProposedAction }) {
  const detail = action.detail;
  switch (kindFamily(action.kind)) {
    case "calendar": {
      const event = str(detail, "event_title", "title", "summary");
      const starts = str(detail, "starts_at", "start", "time", "when");
      const where = str(detail, "location", "where");
      const attendees = strList(detail, "attendees", "attendees_list", "guests");
      const agenda = str(detail, "agenda", "notes", "brief");
      return (
        <dl>
          {!!event && (<><dt>Meeting</dt><dd>{event}</dd></>)}
          {!!starts && (<><dt>Starts</dt><dd>{starts}</dd></>)}
          {!!where && (<><dt>Where</dt><dd>{where}</dd></>)}
          {attendees.length > 0 && (<><dt>Attendees</dt><dd>{attendees.join(", ")}</dd></>)}
          {!!agenda && (<><dt>Prep notes</dt><dd>{agenda}</dd></>)}
          {!event && !starts && !agenda && <Json value={detail} />}
        </dl>
      );
    }
    case "mail": {
      const to = str(detail, "to", "recipients", "recipient");
      const subject = str(detail, "subject");
      const body = str(detail, "body", "draft", "text");
      return (
        <>
          <dl>
            {!!to && (<><dt>To</dt><dd>{to}</dd></>)}
            {!!subject && (<><dt>Subject</dt><dd>{subject}</dd></>)}
          </dl>
          {!!body && <p>{body}</p>}
          <p className="muted">
            Approval happens before anything is sent. Dismissing drops this
            draft; the rule stays on.
          </p>
          {!to && !subject && !body && <Json value={detail} />}
        </>
      );
    }
    case "files": {
      const files = strList(detail, "affected_files", "files", "paths", "changed");
      return (
        <>
          {files.length > 0 ? (
            <p className="source-chips" aria-label="Changed files">
              {files.map((f) => (
                <span key={f} className="source-chip">{f}</span>
              ))}
            </p>
          ) : (
            <Json value={detail} />
          )}
        </>
      );
    }
    case "ha": {
      const entity = str(detail, "entity_id", "entity", "target");
      const service = str(detail, "service", "action_name", "command");
      const state = str(detail, "state", "target_state", "value");
      return (
        <>
          <dl>
            {!!entity && (<><dt>Entity</dt><dd><code>{entity}</code></dd></>)}
            {!!service && (<><dt>Service</dt><dd><code>{service}</code></dd></>)}
            {!!state && (<><dt>Change to</dt><dd>{state}</dd></>)}
          </dl>
          <p className="muted">
            Confirm here to call the service. Nothing touches your home until
            you approve.
          </p>
          {!entity && !service && <Json value={detail} />}
        </>
      );
    }
    case "notify": {
      const age = str(detail, "age_hours", "age");
      const state = str(detail, "state", "task_state");
      return (
        <>
          <dl>
            {!!age && (<><dt>Idle for</dt><dd>{age} hours</dd></>)}
            {!!state && (<><dt>Task state</dt><dd>{label(state)}</dd></>)}
          </dl>
          {!age && !state && <Json value={detail} />}
        </>
      );
    }
    case "needs_review": {
      const synthesis = str(detail, "synthesis");
      return (
        <>
          {!!detail.quarantined && (
            <p>
              <Status value="REVIEW" /> Held for review — treat the content as
              untrusted until checked.
            </p>
          )}
          {!!synthesis && (
            <dl>
              <dt>Synthesis</dt>
              <dd>{synthesis}</dd>
            </dl>
          )}
          <Json value={detail} />
        </>
      );
    }
    case "suggest_task": {
      return Object.keys(detail).length ? <Json value={detail} /> : (
        <p className="muted">A task suggestion with no extra fields.</p>
      );
    }
    default:
      return Object.keys(detail).length ? <Json value={detail} /> : (
        <p className="muted">No further detail was attached.</p>
      );
  }
}

function EvidenceChips({ refs }: { refs: string[] }) {
  if (!refs.length) return <span className="muted">No source refs attached.</span>;
  return (
    <span className="source-chips" aria-label="Exact sources">
      {refs.map((ref) => (
        <span key={ref} className="source-chip" title={ref}>
          {ref.length > 48 ? `…${ref.slice(-47)}` : ref}
        </span>
      ))}
    </span>
  );
}

function SnoozeModal({
  candidate,
  onClose,
}: {
  candidate: AttentionCandidate;
  onClose: () => void;
}) {
  const client = useQueryClient();
  const [choice, setChoice] = useState("morning");
  const [custom, setCustom] = useState("");
  const snooze = useMutation({
    mutationFn: (until: string) =>
      post<RecordData>(`/proactive/candidates/${candidate.id}/snooze`, {
        expected_revision: candidate.revision,
        snoozed_until: until,
      }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["attention"] });
      onClose();
    },
  });
  function tomorrowMorning(): string {
    const d = new Date();
    d.setDate(d.getDate() + 1);
    d.setHours(8, 0, 0, 0);
    return d.toISOString();
  }
  function confirm() {
    const until =
      choice === "custom"
        ? new Date(custom).toISOString()
        : choice === "hour"
          ? new Date(Date.now() + 3600_000).toISOString()
          : choice === "week"
            ? new Date(Date.now() + 7 * 86400_000).toISOString()
            : tomorrowMorning();
    snooze.mutate(until);
  }
  return (
    <Modal title="Snooze this suggestion" onClose={onClose} pending={snooze.isPending}>
      <p className="muted">
        Snoozing hides this candidate only. The rule keeps running and can
        raise new ones.
      </p>
      <Field label="Snooze for">
        <select value={choice} onChange={(e) => setChoice(e.target.value)}>
          <option value="hour">An hour</option>
          <option value="morning">Until tomorrow morning</option>
          <option value="week">A week</option>
          <option value="custom">Pick a time…</option>
        </select>
      </Field>
      {choice === "custom" && (
        <Input
          label="Snooze until"
          type="datetime-local"
          required
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
        />
      )}
      {snooze.error && <ErrorNotice error={snooze.error} retry={() => snooze.reset()} />}
      <div className="actions">
        <button
          disabled={snooze.isPending || (choice === "custom" && !custom)}
          onClick={confirm}
        >
          {snooze.isPending ? "Snoozing…" : "Snooze candidate"}
        </button>
      </div>
    </Modal>
  );
}

function CandidateCard({ candidate }: { candidate: AttentionCandidate }) {
  const client = useQueryClient();
  const [approving, setApproving] = useState(false);
  const [snoozing, setSnoozing] = useState(false);
  const [dismissing, setDismissing] = useState(false);
  const [evidenceOpen, setEvidenceOpen] = useState(false);
  const invalidate = () => client.invalidateQueries({ queryKey: ["attention"] });
  const approve = useMutation({
    mutationFn: () =>
      post<RecordData>(`/proactive/candidates/${candidate.id}/approve`, {
        expected_revision: candidate.revision,
      }),
    onSuccess: () => {
      invalidate();
      setApproving(false);
    },
  });
  const dismiss = useMutation({
    mutationFn: () =>
      post<RecordData>(`/proactive/candidates/${candidate.id}/dismiss`, {
        expected_revision: candidate.revision,
      }),
    onSuccess: () => {
      invalidate();
      setDismissing(false);
    },
  });
  const actionable = !!OPEN_STATES[candidate.state] && candidate.state !== "RUNNING";
  return (
    <article className="row" aria-label={candidate.summary}>
      <div className="row-main">
        <h3>{candidate.summary}</h3>
        <div className="row-meta">
          <Status value={candidate.state} />
          <Status value={candidate.action.severity || "ACTION_REQUIRED"} />
          <span className="source-chip" title={modeNote(candidate.action.mode)}>
            {label(candidate.action.kind)} · {candidate.action.mode}
          </span>
          {candidate.action.confidence !== null && (
            <span>Confidence {Math.round(candidate.action.confidence * 100)}%</span>
          )}
          <span>Cost {candidate.action.cost}</span>
          <span>Target {candidate.action.executionTarget}</span>
          <span>{timestamp(candidate.raw.created_at)}</span>
        </div>
        {!!candidate.action.reason && candidate.action.reason !== candidate.summary && (
          <p>{candidate.action.reason}</p>
        )}
        <p className="muted">{modeNote(candidate.action.mode)}</p>
        <h4>Proposed action</h4>
        <ActionDetail action={candidate.action} />
        <h4>Sources</h4>
        <p>
          <EvidenceChips refs={candidate.evidenceRefs} />
        </p>
        <div className="row-meta">
          {!!candidate.ruleId && (
            <Link className="safe-link" to={`/automations?rule=${candidate.ruleId}`}>
              Rule {candidate.ruleId.slice(0, 8)}
            </Link>
          )}
          {!!candidate.taskId && (
            <Link className="safe-link" to={`/tasks/${candidate.taskId}`}>
              Open task
            </Link>
          )}
          {!!candidate.snoozedUntil && (
            <span>Snoozed until {timestamp(candidate.snoozedUntil)}</span>
          )}
        </div>
        <Evidence
          correlationId={candidate.correlationId}
          evidence={candidate.action.detail}
        />
        {(approve.error || dismiss.error) && (
          <ErrorNotice
            error={(approve.error ?? dismiss.error)!}
            retry={() => {
              approve.reset();
              dismiss.reset();
            }}
          />
        )}
      </div>
      <div className="item-actions">
        {actionable && (
          <button disabled={approve.isPending} onClick={() => setApproving(true)}>
            Approve once
          </button>
        )}
        {actionable && (
          <button
            className="secondary"
            onClick={() => setSnoozing(true)}
          >
            Snooze
          </button>
        )}
        <button className="secondary" onClick={() => setEvidenceOpen(true)}>
          Open evidence
        </button>
        {!!candidate.ruleId && (
          <Link className="safe-link" to={`/automations?rule=${candidate.ruleId}`}>
            Edit rule
          </Link>
        )}
        {actionable && (
          <button
            className="quiet"
            disabled={dismiss.isPending}
            onClick={() => setDismissing(true)}
          >
            Dismiss
          </button>
        )}
      </div>
      <div className="row-meta">
        {!!candidate.ruleId && (
          <Link className="safe-link" to={`/automations?rule=${candidate.ruleId}`}>
            Mute rule
          </Link>
        )}
        <Link className="safe-link" to="/ops">
          Pause everything
        </Link>
        <Link className="safe-link" to="/approvals">
          Revoke grant
        </Link>
      </div>
      {approving && (
        <Modal
          title="Approve this once?"
          onClose={() => setApproving(false)}
          pending={approve.isPending}
        >
          <p>{candidate.summary}</p>
          <dl>
            <dt>Permission mode</dt>
            <dd>{candidate.action.mode} — {modeNote(candidate.action.mode)}</dd>
            <dt>Estimated cost</dt>
            <dd>{candidate.action.cost}</dd>
            <dt>Execution target</dt>
            <dd>{candidate.action.executionTarget}</dd>
          </dl>
          {kindFamily(candidate.action.kind) === "mail" && (
            <p>
              This approval sends the draft above. Nothing has been sent yet.
            </p>
          )}
          {kindFamily(candidate.action.kind) === "ha" && (
            <p>
              This approval calls the service above. Nothing has run yet.
            </p>
          )}
          {approve.error && (
            <ErrorNotice error={approve.error} retry={() => approve.reset()} />
          )}
          <div className="actions">
            <button disabled={approve.isPending} onClick={() => approve.mutate()}>
              {approve.isPending ? "Approving…" : "Approve once"}
            </button>
          </div>
        </Modal>
      )}
      {snoozing && (
        <SnoozeModal candidate={candidate} onClose={() => setSnoozing(false)} />
      )}
      {dismissing && (
        <Confirm
          title="Dismiss this suggestion?"
          action="Dismiss"
          pending={dismiss.isPending}
          onClose={() => setDismissing(false)}
          onConfirm={() => dismiss.mutate()}
        >
          <p>
            Dismissing drops this candidate only. The rule stays on and can
            raise new suggestions later.
          </p>
          {dismiss.error && (
            <ErrorNotice error={dismiss.error} retry={() => dismiss.reset()} />
          )}
        </Confirm>
      )}
      {evidenceOpen && (
        <Modal title="Evidence" onClose={() => setEvidenceOpen(false)}>
          <p>{candidate.summary}</p>
          <h3>Exact sources</h3>
          <p>
            <EvidenceChips refs={candidate.evidenceRefs} />
          </p>
          <Evidence
            correlationId={candidate.correlationId}
            evidence={candidate.raw}
          />
          <div className="actions">
            {!!candidate.taskId && (
              <Link className="safe-link" to={`/tasks/${candidate.taskId}`}>
                Open task
              </Link>
            )}
            {!!candidate.ruleId && (
              <Link className="safe-link" to={`/automations?rule=${candidate.ruleId}`}>
                Edit rule
              </Link>
            )}
          </div>
        </Modal>
      )}
    </article>
  );
}

/// Notifications-backed fallback while the candidate pipeline lands.
function NoticeCard({ row }: { row: RecordData }) {
  return (
    <article className="row">
      <div className="row-main">
        <h3>{text(row.title)}</h3>
        <div className="row-meta">
          <Status value={row.severity} />
          <span>{timestamp(row.created_at)}</span>
        </div>
        <p>{text(row.body)}</p>
        {!!row.task_id && (
          <Link className="safe-link" to={`/tasks/${text(row.task_id)}`}>
            Open task
          </Link>
        )}
        <Evidence correlationId={text(row.correlation_id)} />
      </div>
    </article>
  );
}

async function fetchAttention(): Promise<{
  source: "candidates" | "notifications";
  items: RecordData[];
}> {
  try {
    const page = await api<{ items: RecordData[] }>(
      "/proactive/candidates?limit=100",
    );
    return { source: "candidates", items: page.items ?? [] };
  } catch (error) {
    if (
      error instanceof ApiError &&
      [404, 405, 422, 501].includes(error.status)
    ) {
      const page = await api<{ items: RecordData[] }>("/notifications?limit=50");
      return { source: "notifications", items: page.items ?? [] };
    }
    throw error;
  }
}

export function Attention() {
  const [filter, setFilter] = useState("open");
  const list = useQuery({
    queryKey: ["attention"],
    queryFn: fetchAttention,
  });
  const source = list.data?.source ?? "candidates";
  const rows = list.data?.items ?? [];
  const candidates = rows.map(asCandidate);
  const visible =
    source === "candidates"
      ? candidates.filter((c) => {
          if (filter === "all") return true;
          if (filter === "snoozed") return c.state === "SNOOZED";
          if (filter === "finished")
            return c.state === "DONE" || c.state === "DISMISSED";
          return !!OPEN_STATES[c.state];
        })
      : rows.filter(
          (r) => filter === "all" || (!r.acknowledged_at && !r.dismissed_at),
        );
  const openCount = candidates.filter((c) => !!OPEN_STATES[c.state]).length;
  return (
    <>
      <PageHeader
        title="Attention"
        description="Proactive suggestions with their evidence. Nothing here runs without the permission its mode already granted."
      />
      <section className="panel section" aria-label="How suggestions run">
        <h2>How suggestions run</h2>
        <p>
          Suggest drafts only · Ask parks for your decision · Auto submits
          through a standing grant. Mail is never sent, and Home Assistant
          services never run, without your approval on the card.
        </p>
        <p className="muted">
          <Link className="safe-link" to="/automations">
            Rules
          </Link>{" "}
          ·{" "}
          <Link className="safe-link" to="/approvals">
            Approvals and grants
          </Link>{" "}
          ·{" "}
          <Link className="safe-link" to="/ops">
            Pause everything
          </Link>
        </p>
      </section>
      <section className="panel section" aria-label="Suggestions">
        <h2>
          Suggestions{source === "candidates" && openCount > 0
            ? ` · ${openCount} open`
            : ""}
        </h2>
        {list.isPending && <p role="status">Loading…</p>}
        {list.error && (
          <ErrorNotice error={list.error} retry={() => list.refetch()} />
        )}
        {list.data && source === "notifications" && (
          <p className="muted">
            The candidate pipeline is not reachable yet, so this list shows
            notifications instead. Dismiss and snooze arrive with candidates.
          </p>
        )}
        {list.data && (
          <>
            <Select
              label="Show"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="open">Open</option>
              <option value="snoozed">Snoozed</option>
              <option value="finished">Finished</option>
              <option value="all">Everything</option>
            </Select>
            {visible.length === 0 ? (
              <Empty title="All caught up">
                New suggestions land here when a rule fires.{" "}
                <Link to="/automations">Review the rules</Link>.
              </Empty>
            ) : source === "candidates" ? (
              (visible as AttentionCandidate[]).map((c) => (
                <CandidateCard key={c.id} candidate={c} />
              ))
            ) : (
              (visible as RecordData[]).map((r) => (
                <NoticeCard key={text(r.id)} row={r} />
              ))
            )}
          </>
        )}
      </section>
    </>
  );
}
