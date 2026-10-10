import { useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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
  Input,
  PageHeader,
  Resource,
  Select,
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
function ThreadReplies({
  eventId,
  correlationId,
}: {
  eventId: string;
  correlationId: string;
}) {
  return (
    <>
      <Resource
        path="/events"
        empty={<span className="muted">Thinking…</span>}
      >
        {(rows) => {
          const replies = rows.filter(
            (r) =>
              text(r.event_type) === "AGENT_MESSAGE" &&
              (text(payloadOf(r).reply_to) === eventId ||
                (!!correlationId &&
                  !!text(r.correlation_id) &&
                  text(r.correlation_id) === correlationId)),
          );
          if (!replies.length) return null;
          return replies.map((r) => {
            const payload = payloadOf(r);
            const status = text(payload.status);
            const body = text(payload.text);
            return (
              <article className="message assistant" key={r.id}>
                {status === "REPLIED" && body ? (
                  <div>{body}</div>
                ) : status === "FAILED_REPLY" ? (
                  <div className="assistant-failed">
                    Couldn&apos;t get a reply: {text(payload.error) || "model unavailable"}. Check Models — a FAST model must be enabled.
                  </div>
                ) : (
                  <div className="muted">Thinking…</div>
                )}
                <span className="chat-time">
                  {timestamp(r.timestamp)}
                  {!!text(payload.model) && (
                    <span className="assistant-model"> · {text(payload.model)}</span>
                  )}
                </span>
              </article>
            );
          });
        }}
      </Resource>
      <Resource
        path="/tasks"
        empty={<span className="muted">Working on it — replies appear here.</span>}
      >
        {(rows) => {
          const related = relatedTo(rows, eventId, correlationId);
          if (!related.length) return null;
          return related.map((t) => {
            const outcome = text(t.outcome);
            const waiting = text(t.wait_reason);
            return (
              <article className="message assistant" key={t.id}>
                <div>
                  {outcome ||
                    (waiting
                      ? `Waiting: ${label(waiting)} — approve under Approvals.`
                      : `${text(t.title) || "Task"} (${label(t.state)})`)}
                </div>
                <span className="chat-time">
                  {timestamp(t.updated_at)}{" "}
                  <Link to={`/tasks/${t.id}`}>task</Link>
                </span>
                <Evidence
                  correlationId={text(t.correlation_id)}
                  evidence={t.evidence}
                />
              </article>
            );
          });
        }}
      </Resource>
    </>
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
  const logRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [conversation, detail.data, correlationId]);

  return (
    <div className="chat-shell">
      <aside className="chat-sidebar">
        <Link className="safe-link chat-new" to="/chat">
          + New chat
        </Link>
        <Resource path="/events" empty={<p>No chats yet.</p>}>
          {(rows) => {
            const conversations = rows.filter(
              (r) => text(r.event_type) === "USER_MESSAGE",
            );
            if (!conversations.length) return <p>No chats yet.</p>;
            return conversations.slice(0, 30).map((r) => (
              <div
                className={
                  r.id === conversation
                    ? "summary-line chat-active"
                    : "summary-line"
                }
                key={r.id}
              >
                <Link to={`/chat?conversation=${r.id}`}>
                  {conversationTitle(r)}
                </Link>
              </div>
            ));
          }}
        </Resource>
      </aside>
      <section className="chat-main">
        <div className="chat-log" aria-live="polite" ref={logRef}>
          {!conversation && (
            <Empty title="What can I do for you?">
              Just talk — questions get answered straight away. When you ask
              Orbit to do something (send, schedule, remind, write, fix), it
              starts a task and reports back here.
            </Empty>
          )}
          {detail.isPending && conversation && (
            <p role="status">Loading conversation…</p>
          )}
          {detail.error && (
            <ErrorNotice error={detail.error} retry={() => detail.refetch()} />
          )}
          {detail.data && payload && (
            <article className="message user">
              <div>{text(payload.text)}</div>
              <span className="chat-time">
                {timestamp(detail.data.timestamp)}
              </span>
            </article>
          )}
          {conversation && (
            <ThreadReplies
              eventId={conversation}
              correlationId={correlationId}
            />
          )}
        </div>
        <form
          className="composer chat-composer"
          onSubmit={(e) => {
            e.preventDefault();
            send.mutate();
          }}
        >
          <Textarea
            label="Message Orbit"
            required
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                if (draft.trim() && !send.isPending) send.mutate();
              }
            }}
          />
          <div className="actions">
            <button disabled={send.isPending || !draft.trim()}>
              {send.isPending ? "Sending…" : "Send"}
            </button>
          </div>
          {send.error && <ErrorNotice error={send.error} />}
        </form>
      </section>
    </div>
  );
}

const AGENT_ROLES = ["FAST", "PRIVATE", "REASONING", "CODING", "VISION", "EMBEDDING"];

function NewAgent({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    purpose: "",
    instructions: "",
    allowed_tools: "",
    model_role: "FAST",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/agents", {
        agent: {
          name: form.name,
          purpose: form.purpose || form.name,
          instructions: form.instructions || form.purpose || form.name,
          allowed_tools: form.allowed_tools
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean),
          model_role: form.model_role,
          context_strategy: {
            include_memory: true,
            history_messages: 20,
            max_context_characters: 16000,
          },
          limits: {
            max_model_calls: 10,
            max_tool_calls: 20,
            max_active_seconds: 600,
            max_tokens: 32000,
            max_retries: 2,
            max_subagent_depth: 0,
          },
          autonomy_constraints: [],
          memory_permissions: { read_types: [], write_types: [], project_ids: [] },
          sandbox_required: false,
        },
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["/agents"] });
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
      <Input
        label="Name"
        required
        value={form.name}
        onChange={(e) => setForm({ ...form, name: e.target.value })}
      />
      <Textarea
        label="Purpose"
        value={form.purpose}
        onChange={(e) => setForm({ ...form, purpose: e.target.value })}
      />
      <Textarea
        label="Instructions"
        value={form.instructions}
        onChange={(e) => setForm({ ...form, instructions: e.target.value })}
      />
      <Input
        label="Allowed tools (comma-separated)"
        placeholder="files.read, email.send"
        value={form.allowed_tools}
        onChange={(e) => setForm({ ...form, allowed_tools: e.target.value })}
      />
      <Select
        label="Model role"
        value={form.model_role}
        onChange={(e) => setForm({ ...form, model_role: e.target.value })}
      >
        {AGENT_ROLES.map((option) => (
          <option key={option} value={option}>
            {label(option)}
          </option>
        ))}
      </Select>
      {create.error && <ErrorNotice error={create.error} retry={() => create.reset()} />}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save agent"}
        </button>
      </div>
    </form>
  );
}

export function Agents() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <PageHeader
        title="Agents"
        description="Bounded assistants with explicit tools, model roles, and memory access."
      />
      <section className="section" aria-label="Agents">
        <div className="panel">
          <h2>Agents</h2>
          <Resource
            path="/agents"
            empty={
              <Empty title="No agents yet">
                Define a bounded assistant with explicit tools and limits.
              </Empty>
            }
          >
            {(items) => (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Model role</th>
                    <th scope="col">Tools</th>
                    <th scope="col">Enabled</th>
                    <th scope="col">Rev</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={row.id}>
                      <th scope="row">{text(row.name)}</th>
                      <td>{label(row.model_role)}</td>
                      <td>{text(row.allowed_tools)}</td>
                      <td>
                        <Status value={row.enabled} />
                      </td>
                      <td>{text(row.revision)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Resource>
          {open ? (
            <NewAgent onDone={() => setOpen(false)} />
          ) : (
            <button className="secondary" onClick={() => setOpen(true)}>
              Add agent
            </button>
          )}
        </div>
      </section>
    </>
  );
}
