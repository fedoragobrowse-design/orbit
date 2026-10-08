import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  api,
  label,
  post,
  queryClient,
  text,
  timestamp,
  type RecordData,
} from "./api";
import { useDraft } from "./App";
import {
  Empty,
  ErrorNotice,
  Evidence,
  PageHeader,
  Resource,
  Status,
  Textarea,
} from "./ui";

function payloadOf(row: RecordData): RecordData {
  return (row.payload ?? {}) as RecordData;
}

function conversationTitle(row: RecordData): string {
  const payload = payloadOf(row);
  const titled = text(payload.title);
  if (titled) return titled;
  const body = text(payload.text).trim();
  if (!body) return "Message";
  return body.length > 80 ? `${body.slice(0, 80)}…` : body;
}

function messageTitle(draft: string): string {
  const firstLine = draft.trim().split("\n")[0] ?? "";
  return firstLine.length > 80 ? `${firstLine.slice(0, 80)}…` : firstLine;
}

function relatedTo(
  rows: RecordData[],
  eventId: string,
  correlationId: string,
): RecordData[] {
  return rows.filter(
    (t) =>
      text(t.event_id) === eventId ||
      (!!correlationId && !!text(t.correlation_id) && text(t.correlation_id) === correlationId),
  );
}

function RelatedTasks({
  eventId,
  correlationId,
}: {
  eventId: string;
  correlationId: string;
}) {
  return (
    <Resource
      path="/tasks"
      empty={
        <p>
          No tasks recorded for this message yet. The backend queues a
          notification task for each message; check back shortly.
        </p>
      }
    >
      {(rows) => {
        const related = relatedTo(rows, eventId, correlationId);
        if (!related.length)
          return (
            <p>
              No tasks recorded for this message yet. The backend queues a
              notification task for each message; check back shortly.
            </p>
          );
        return related.map((t) => (
          <article className="row" key={t.id}>
            <div className="row-main">
              <Link to={`/tasks/${t.id}`}>{text(t.title) || "Task"}</Link>
              <div className="row-meta">
                <Status value={t.state} />
                <span>{timestamp(t.updated_at)}</span>
              </div>
              {!!t.wait_reason && <p>{label(t.wait_reason)}</p>}
              <Evidence
                correlationId={text(t.correlation_id)}
                evidence={t.evidence}
              />
            </div>
          </article>
        ));
      }}
    </Resource>
  );
}

export function Chat() {
  const [params, setParams] = useSearchParams();
  const conversation = params.get("conversation");
  const [draft, setDraft] = useDraft(`chat-${conversation ?? "new"}`);

  const detail = useQuery({
    queryKey: ["event", conversation],
    queryFn: () => api<RecordData>(`/events/${conversation}`),
    enabled: !!conversation,
  });

  const send = useMutation({
    mutationFn: () =>
      post<{ id: string }>("/events", {
        event_type: "USER_MESSAGE",
        payload: { text: draft.trim(), title: messageTitle(draft) },
        source_event_key: `web-chat-${crypto.randomUUID()}`,
        privacy_class: "PRIVATE",
      }),
    onSuccess: (r) => {
      setDraft("");
      setParams({ conversation: r.id });
      queryClient.invalidateQueries();
    },
  });

  const correlationId = text(detail.data?.correlation_id);
  const payload = detail.data ? payloadOf(detail.data) : null;

  return (
    <>
      <PageHeader
        title={(detail.data && conversationTitle(detail.data)) || "Chat"}
        description="An assistant that works within your permissions, with a task record for every request."
      />
      <div className="detail-grid">
        <section>
          <div className="chat-log" aria-live="polite">
            {!conversation && (
              <Empty title="What would you like to work on?">
                Send a message to create a USER_MESSAGE event. The backend
                queues a notification task for it, which you can inspect under
                Tasks.
              </Empty>
            )}
            {detail.isPending && conversation && (
              <p role="status">Loading conversation…</p>
            )}
            {detail.error && (
              <ErrorNotice
                error={detail.error}
                retry={() => detail.refetch()}
              />
            )}
            {detail.data && payload && (
              <article className="message user">
                <header>
                  <strong>You</strong>
                  <span>{timestamp(detail.data.timestamp)}</span>
                </header>
                <div>{text(payload.text)}</div>
                <Evidence
                  correlationId={correlationId}
                  evidence={detail.data.classification}
                />
              </article>
            )}
          </div>
          {conversation && (
            <section className="panel section">
              <h2>Related tasks</h2>
              <RelatedTasks
                eventId={conversation}
                correlationId={correlationId}
              />
            </section>
          )}
          <form
            className="composer"
            onSubmit={(e) => {
              e.preventDefault();
              send.mutate();
            }}
          >
            <p className="muted">General Assistant only in this build.</p>
            <Textarea
              label="Message Orbit"
              required
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
            <div className="actions">
              <button disabled={send.isPending || !draft.trim()}>
                {send.isPending ? "Sending…" : "Send message"}
              </button>
              <Link className="safe-link" to="/tasks">
                View tasks
              </Link>
            </div>
            <p className="muted">
              Attachments need the Milestone 3 upload API, not served by this
              backend. Each sent message creates a USER_MESSAGE event; the
              backend queues a notification task and notification for it.
            </p>
            {send.error && <ErrorNotice error={send.error} />}
          </form>
        </section>
        <aside>
          <section className="panel section">
            <h2>Conversations</h2>
            <Link className="safe-link" to="/chat">
              New conversation
            </Link>
            <Resource
              path="/events"
              empty={<p>No conversations yet.</p>}
            >
              {(rows) => {
                const conversations = rows.filter(
                  (r) => text(r.event_type) === "USER_MESSAGE",
                );
                if (!conversations.length)
                  return <p>No conversations yet.</p>;
                return conversations.map((r) => (
                  <div className="summary-line" key={r.id}>
                    <Link to={`/chat?conversation=${r.id}`}>
                      {conversationTitle(r)}
                    </Link>
                  </div>
                ));
              }}
            </Resource>
          </section>
          <section className="panel">
            <h2>Task trace</h2>
            {conversation ? (
              <RelatedTasks
                eventId={conversation}
                correlationId={correlationId}
              />
            ) : (
              <p>
                Each sent message creates a durable task. The trace for the
                open conversation will appear here.
              </p>
            )}
          </section>
        </aside>
      </div>
    </>
  );
}

const PLANNED_AGENTS = [
  {
    name: "General Assistant",
    note: "Default assistant for chat messages. Needs the Milestone 3 agent runtime API.",
  },
  {
    name: "File Agent",
    note: "Planned file helper. Needs the Milestone 6 file agent API.",
  },
  {
    name: "Email Agent",
    note: "Planned mail helper. Mail accounts exist, but the helper needs the Milestone 3 agent runtime API.",
  },
];

export function Agents() {
  return (
    <>
      <PageHeader
        title="Agents"
        description="Bounded assistants with explicit tools, model roles, and memory access."
      />
      <section className="panel section">
        <h2>Not available in this build</h2>
        <p>
          Agents need the Milestone 3 agent API — not served by this backend.
        </p>
        <h3>What you can do now</h3>
        <ul>
          <li>
            <Link className="safe-link" to="/chat">
              Send a message
            </Link>{" "}
            — creates a USER_MESSAGE event plus a notification task.
          </li>
          <li>
            <Link className="safe-link" to="/tasks">
              Track it in Tasks
            </Link>{" "}
            — inspect state, checkpoints, evidence, and recovery.
          </li>
        </ul>
      </section>
      <section className="panel section">
        <h2>Planned agents</h2>
        <ul>
          {PLANNED_AGENTS.map((a) => (
            <li key={a.name}>
              <strong>{a.name}.</strong> {a.note}
            </li>
          ))}
        </ul>
      </section>
    </>
  );
}
