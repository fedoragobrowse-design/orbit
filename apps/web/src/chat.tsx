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
import { useDraft } from "./nav";
import {
  Empty,
  ErrorNotice,
  Input,
  PageHeader,
  Resource,
  Select,
  Status,
  Textarea,
} from "./ui";

function attachmentId(f: unknown): string | null {
  if (typeof f === "string") return f;
  const id = (f as RecordData).id;
  return typeof id === "string" ? id : null;
}
function attachmentName(f: unknown): string {
  if (typeof f === "string") return f;
  return text((f as RecordData).name ?? f);
}
function looksLikeImage(f: unknown): boolean {
  if (typeof f !== "object" || f === null) return false;
  const mime = String((f as RecordData).mime_type ?? "");
  if (mime.startsWith("image/")) return true;
  return /\.(png|jpe?g|gif|webp)$/i.test(attachmentName(f));
}
function ChatImage({ id, name }: { id: string; name: string }) {
  return (
    <figure className="chat-image">
      <img loading="lazy" src={`/api/v1/files/${id}/content`} alt={name || "Attached image"} />
      <figcaption>
        <small>
          {name || "Attached image"} — untrusted, never runs as code.
        </small>
      </figcaption>
    </figure>
  );
}
function renderRich(content: string, attachments: unknown): React.ReactNode {
  const parts: React.ReactNode[] = [];
  const files = Array.isArray(attachments) ? (attachments as unknown[]) : [];
  const fence = /```(\w*)\n([\s\S]*?)```/g;
  let last = 0;
  let i = 0;
  let m: RegExpExecArray | null;
  const pushText = (t: string) => {
    if (!t) return;
    const lines = t.split("\n");
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      const tool = line.match(/^\u{1F527}\s*(`?)([^`\n]+)\1\s*[-—–]\s*(.+)$/u) ?? line.match(/^(?:Used|Called|Ran)\s+(tool|MCP|code)\s+[`"“”']?([^`"“”'\n]+)[`"“”']?\s*[-—–:]\s*(.+)$/i);
      if (tool) {
        const kind = tool[1].includes("\u{1F527}") || /tool/i.test(tool[1]) ? "tool" : /mcp/i.test(tool[1] ?? tool[2] ?? "") ? "mcp" : "code";
        parts.push(
          <p key={`t-${i++}`} className={`rich-run rich-${kind}`}>
            <span className="rich-badge">{kind === "tool" ? "Tool" : kind === "mcp" ? "MCP" : "Code"}</span>
            <code>{(tool[2] ?? "").trim()}</code>
            <span className="rich-note">{(tool[3] ?? "").trim()}</span>
          </p>,
        );
        continue;
      }
      if (/^\s*[-*]\s+\[[ xX]\]/.test(line)) {
        parts.push(
          <p key={`c-${i++}`} className="rich-check">
            <span aria-hidden="true">{/\[xX\]/.test(line.slice(0, 8)) ? "☑" : "☐"}</span> {line.replace(/^\s*[-*]\s+\[[ xX]\]\s*/, "")}
          </p>,
        );
        continue;
      }
      parts.push(<span key={`p-${i++}`}>{line}{li < lines.length - 1 ? <br /> : null}</span>);
    }
  };
  while ((m = fence.exec(content)) !== null) {
    pushText(content.slice(last, m.index));
    parts.push(
      <pre key={`f-${i++}`} className="rich-code">
        {!!m[1] && <span className="rich-lang">{m[1]}</span>}
        <code>{m[2].replace(/\n$/, "")}</code>
      </pre>,
    );
    last = m.index + m[0].length;
  }
  pushText(content.slice(last));
  if (!files.length) return <>{parts}</>;
  const images = files.filter((f) => attachmentId(f) && looksLikeImage(f));
  const rest = files.filter((f) => !(attachmentId(f) && looksLikeImage(f)));
  return (
    <>
      {parts}
      {!!images.length && (
        <div className="chat-images">
          {images.map((f, fi) => (
            <ChatImage key={fi} id={attachmentId(f) ?? ""} name={attachmentName(f)} />
          ))}
        </div>
      )}
      {!!rest.length && (
        <ul className="rich-files">
          {rest.map((f, fi) => (
            <li key={fi}>📎 {attachmentName(f)}</li>
          ))}
        </ul>
      )}
    </>
  );
}

type ChatMsg = {
  id: string;
  task_id?: unknown;
  role: string;
  content: string;
  created_at?: unknown;
  sequence?: number;
};
type RunDelta = { id: number; task_id?: unknown; kind: string; payload: { text?: unknown; role?: unknown } };
type RunSource = { kind: string; reference: string; trust?: unknown; source_id?: unknown; source_version?: unknown; turn?: unknown; cited?: unknown; tombstone?: unknown; label?: unknown };
function sourceHref(s: RunSource): string | null {
  // Citation links resolve the exact pinned version the receipt recorded:
  // memory detail, file range, mail ID, browser URL+snapshot. Targets that
  // cannot deep-link (chat turns, agent revisions, skills) render as plain
  // chips — deletion leaves a tombstone, never removes the receipt row.
  const ref = s.reference || "";
  const id = text(s.source_id);
  if (s.kind === "memory" && id) return `/memory/${id}`;
  if (s.kind === "file" && id) return `/connections/api?file=${encodeURIComponent(id)}`;
  if (s.kind === "mail" && id) return `/connections/email`;
  if (s.kind === "browser") return `/browser`;
  if (ref.startsWith("message:")) return null;
  if (ref.startsWith("agent:")) return null;
  return null;
}
function SourceChips({ taskId }: { taskId: string }) {
  const runs = useQuery({
    queryKey: ["chat-sources", taskId],
    queryFn: () => api<{ children: { sources: RunSource[] }[]; items?: { sources: RunSource[] }[] }>(`/tasks/${taskId}/runs`),
    staleTime: 60000,
  });
  // Explicit parent linkage only: `children` holds runs whose dispatch
  // persisted this task as parent. `items` is a legacy fallback for stale
  // cached responses — never synthesized.
  const sources = (runs.data?.children ?? runs.data?.items ?? []).flatMap((r) => r.sources ?? []).slice(0, 6);
  if (!sources.length) return null;
  return (
    <p className="source-chips" aria-label="What this answer used">
      {sources.map((s, i) => {
        const href = sourceHref(s);
        const tombstone = s.tombstone === true;
        const untrusted = text(s.trust) !== "" && text(s.trust) !== "OwnerAuthenticated" && text(s.trust) !== "OWNER_AUTHENTICATED" && text(s.trust) !== "System" && text(s.trust) !== "SYSTEM";
        // Provided as context unless the model cites the pin; deleted pins
        // keep a tombstone chip so the receipt stays auditable. The title
        // names the exact pinned version the chip resolves.
        const pin = text(s.source_version) !== "" ? `${s.reference} (version ${text(s.source_version)})` : s.reference;
        const title = tombstone ? `Deleted — source removed, receipt kept (${pin})` : `${text(s.label) || (s.cited === true ? "Cited by model" : "Provided as context")} — ${pin}`;
        const name =
          s.kind === "memory" ? "Saved memory"
          : s.kind === "file" ? "Attached file"
          : s.kind === "chat" ? "Your message"
          : s.kind === "mail" ? "Mail message"
          : s.kind === "browser" ? "Browser snapshot"
          : s.reference.startsWith("orbit-memory:") ? "Saved memory"
          : s.reference.startsWith("attachment:") ? "Attached file"
          : s.reference.startsWith("message:") ? "Your message"
          : s.kind || "Source";
        const inner = (
          <>
            {name}
            {tombstone ? <> · deleted</> : untrusted ? <> · untrusted</> : null}
          </>
        );
        return (
          <span key={i} className="source-chip" title={title}>
            {href && !tombstone ? <Link to={href}>{inner}</Link> : inner}
          </span>
        );
      })}
    </p>
  );
}
// Helper lineage: delegates this run spawned, read from the same explicit
// `children` linkage the tasks view groups by. Empty when the run spawned
// no helpers — that renders nothing, never a placeholder row.
function HelperLineage({ taskId }: { taskId: string }) {
  const runs = useQuery({
    queryKey: ["chat-helpers", taskId],
    queryFn: () => api<{ parent_task_id?: unknown; children: { task_id: unknown; title?: unknown; state?: unknown }[]; items?: { task_id: unknown; title?: unknown; state?: unknown }[] }>(`/tasks/${taskId}/runs`),
    staleTime: 60000,
  });
  const children = runs.data?.children ?? runs.data?.items ?? [];
  if (!children.length) return null;
  return (
    <p className="muted" aria-label="Delegated helpers">
      Delegated to{" "}
      {children.map((c, i) => (
        <span key={String(c.task_id)}>
          {i > 0 ? ", " : ""}
          <Link className="safe-link" to={`/tasks/${text(c.task_id)}`}>
            {text(c.title) || text(c.task_id)}
          </Link>
          {text(c.state) ? ` (${text(c.state)})` : ""}
        </span>
      ))}.
    </p>
  );
}
function TypingBubble() {
  return (
    <article className="message assistant" aria-live="polite">
      <div className="assistant-typing" role="status">
        <span className="typing-dot" />
        <span className="typing-dot" />
        <span className="typing-dot" />
        <span className="typing-label">Responding…</span>
      </div>
    </article>
  );
}
 function ConversationStream({ conversation, taskId }: { conversation: string; taskId: string | null }) {
  const [streamed, setStreamed] = useState<ChatMsg[]>([]);
  const [deltas, setDeltas] = useState<RunDelta[]>([]);
  const [done, setDone] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const history = useQuery({
    queryKey: ["chat-history", conversation],
    queryFn: () => api<{ items: ChatMsg[]; last_sequence: number | null }>(`/chat/messages?conversation_id=${conversation}&limit=100`),
    enabled: !!conversation,
  });
  useEffect(() => {
    setStreamed([]);
    setDeltas([]);
    setDone(null);
    setFailed(false);
    if (!conversation) return;
    // run_events ids double as the SSE cursor: the server replays from
    // Last-Event-ID, so a reconnect resumes without missing or duplicating.
    const src = new EventSource(`/api/v1/chat/stream?conversation_id=${conversation}`);
    src.addEventListener("message", (e) => {
      try {
        const m = JSON.parse((e as MessageEvent).data) as ChatMsg;
        setStreamed((prev) => (prev.some((p) => p.id === m.id) ? prev : [...prev, m]));
      } catch { /* partial frame */ }
    });
    const onDelta = (e: Event) => {
      try {
        const d = JSON.parse((e as MessageEvent).data) as RunDelta & { payload: { text?: unknown } };
        if (d.kind === "TEXT_DELTA" && typeof d.payload?.text === "string") {
          setDeltas((prev) => [...prev, d as RunDelta]);
        }
      } catch { /* partial frame */ }
    };
    for (const name of ["delta", "tool_started", "tool_result", "status", "usage"]) {
      src.addEventListener(name, onDelta);
    }
    src.addEventListener("done", (e) => {
      try {
        const d = JSON.parse((e as MessageEvent).data) as { state: string };
        setDone(d.state);
        if (d.state === "FAILED" || d.state === "TIMED_OUT") setFailed(true);
      } catch {
        setDone("DONE");
      }
      src.close();
    });
    src.onerror = () => {
      src.close();
    };
    return () => src.close();
  }, [conversation, taskId]);
  // Sequence-ordered pages: the server returns every page oldest-first, so
  // merge history and live rows by (sequence, id) — never by timestamp.
  const seen: Record<string, true> = {};
  for (const m of streamed) seen[m.id] = true;
  const older = (history.data?.items ?? []).filter((m) => !seen[m.id]);
  const all = [...older, ...streamed].sort((a, b) => (typeof a.sequence === "number" ? a.sequence : Number.MAX_SAFE_INTEGER) - (typeof b.sequence === "number" ? b.sequence : Number.MAX_SAFE_INTEGER) || (a.id < b.id ? -1 : 1));
  // Live partial reply: TEXT_DELTA chunks for the open turn reduce in order
  // into one in-place bubble keyed by the latest assistant message's task.
  const openTask = taskId ?? (all.length && all[all.length - 1]?.role === "user" ? text(all[all.length - 1]?.task_id) || null : null);
  const partial = openTask ? deltas.filter((d) => text(d.task_id) === openTask).map((d) => text(d.payload?.text)).join("") : "";
  const showPartial = !done && partial.length > 0 && (all.length === 0 || all[all.length - 1]?.role !== "assistant" || text(all[all.length - 1]?.task_id) !== (openTask ?? ""));
  const waiting = !done && !showPartial && (taskId !== null || all.length === 0 || all[all.length - 1]?.role === "user");
  return (
    <>
      {history.isPending && <p role="status">Loading conversation…</p>}
      {history.error && <ErrorNotice error={history.error} retry={() => history.refetch()} />}
      {all.map((m) => (
        <article className={m.role === "user" ? "message user" : "message assistant"} key={m.id}>
          <div className={m.role === "assistant" ? "assistant-streamed" : undefined}>{renderRich(m.content, (m as unknown as RecordData).attachments)}</div>
          {m.role === "assistant" && !!m.task_id && <SourceChips taskId={text(m.task_id)} />}
          {m.role === "assistant" && !!m.task_id && <HelperLineage taskId={text(m.task_id)} />}
          <span className="chat-time">
            {timestamp(m.created_at)}{" "}
            {!!m.task_id && <Link to={`/tasks/${text(m.task_id)}`}>task</Link>}
          </span>
        </article>
      ))}
      {showPartial && (
        <article className="message assistant" aria-live="polite">
          <div className="assistant-streamed">{renderRich(partial, undefined)}</div>
        </article>
      )}
      {waiting && !failed && <TypingBubble />}
      {failed && (
        <article className="message assistant">
          <div className="assistant-failed">
            Couldn&apos;t get a reply — the run failed. Check Models (a FAST model must be enabled) or retry.
          </div>
        </article>
      )}
    </>
  );
}
export function Chat() {
  const [params, setParams] = useSearchParams();
  const conversation = params.get("conversation");
  const [chatModel, setChatModel] = useState(() => localStorage.getItem("orbit.chat.model") ?? "");
  const [chatRole, setChatRole] = useState(() => localStorage.getItem("orbit.chat.role") ?? "FAST");
  const [agentId, setAgentId] = useState(() => localStorage.getItem("orbit.chat.agent") ?? "");
  const [draft, setDraft] = useDraft(`chat-${conversation ?? "new"}`);
  const [taskId, setTaskId] = useState<string | null>(null);
  const [images, setImages] = useState<{ id: string; name: string }[]>([]);
  const [imageError, setImageError] = useState("");
  const [uploadingImage, setUploadingImage] = useState(false);
  async function attachImage(picked: File | null) {
    if (!picked) return;
    setImageError("");
    setUploadingImage(true);
    try {
      const form = new FormData();
      form.append("file", picked, picked.name);
      const stored = await api<RecordData>(
        `/files/import?kind=image&filename=${encodeURIComponent(picked.name || "image")}`,
        { method: "POST", body: form },
      );
      const id = String(stored.id ?? "");
      if (!id) throw new Error("Image upload did not return an id.");
      setImages((prev) => [...prev, { id, name: text(stored.name) || picked.name }]);
    } catch (e) {
      setImageError(e instanceof Error ? e.message : "Image upload failed.");
    } finally {
      setUploadingImage(false);
    }
  }
  const convos = useQuery({
    queryKey: ["chat-convos"],
    queryFn: () => api<{ items: RecordData[] }>("/chat/conversations"),
  });
  const send = useMutation({
    mutationFn: () =>
      post<{ conversation_id: string; task_id: string }>("/chat/messages", {
        ...(conversation ? { conversation_id: conversation } : {}),
        ...(agentId ? { agent_id: agentId } : {}),
        message: draft.trim(),
        ...(images.length ? { images: images.map((im) => im.id) } : {}),
      }),
    onSuccess: (r) => {
      setDraft("");
      setImages([]);
      setTaskId(r.task_id);
      setParams({ conversation: r.conversation_id });
      void queryClient.invalidateQueries({ queryKey: ["chat-convos"] });
    },
  });
  const logRef = useRef<HTMLDivElement>(null);
  const log = logRef.current;
  useEffect(() => {
    log?.scrollTo({ top: log.scrollHeight });
  }, [conversation, taskId, log]);
  return (
    <div className="chat-shell">
      <aside className="chat-sidebar">
        <Link className="safe-link chat-new" to="/chat">
          + New chat
        </Link>
        {convos.isPending && <p role="status">Loading…</p>}
        {convos.error && <ErrorNotice error={convos.error} retry={() => convos.refetch()} />}
        {(convos.data?.items ?? []).slice(0, 30).map((r) => (
          <div
            className={r.id === conversation ? "summary-line chat-active" : "summary-line"}
            key={String(r.id)}
          >
            <Link to={`/chat?conversation=${r.id}`}>
              {text(r.title) || "Conversation"}
            </Link>
          </div>
        ))}
        {convos.data && !(convos.data.items ?? []).length && <p>No chats yet.</p>}
      </aside>
      <section className="chat-main">
        <div className="chat-log" aria-live="polite" ref={logRef}>
          {!conversation ? (
            <Empty title="What can I do for you?">
              Just talk — the thread keeps context, so follow-ups build on
              what came before. When you ask Orbit to do something (send,
              schedule, remind, write, fix), it starts a task and reports
              back here.
            </Empty>
          ) : (
            <ConversationStream conversation={conversation} taskId={taskId} />
          )}
        </div>
        <ChatPickers
          chatModel={chatModel}
          setChatModel={(v) => { setChatModel(v); localStorage.setItem("orbit.chat.model", v); }}
          chatRole={chatRole}
          setChatRole={(v) => { setChatRole(v); localStorage.setItem("orbit.chat.role", v); }}
          agentId={agentId}
          setAgentId={(v) => { setAgentId(v); localStorage.setItem("orbit.chat.agent", v); }}
        />
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
            <label className="attach-image">
              Attach image
              <input
                type="file"
                accept="image/*"
                hidden
                disabled={uploadingImage}
                onChange={(e) => { void attachImage(e.target.files?.[0] ?? null); e.target.value = ""; }}
              />
            </label>
            <button disabled={send.isPending || !draft.trim()}>
              {send.isPending ? "Sending…" : "Send"}
            </button>
          </div>
          {!!images.length && (
            <ul className="chat-attached">
              {images.map((im) => (
                <li key={im.id}>
                  🖼 {im.name}{" "}
                  <button type="button" onClick={() => setImages((prev) => prev.filter((p) => p.id !== im.id))}>
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          )}
          {uploadingImage && <p role="status">Uploading image…</p>}
          {imageError && <ErrorNotice error={imageError} retry={() => setImageError("")} />}
          {send.error && <ErrorNotice error={send.error} />}
        </form>
      </section>
    </div>
  );
}
function ChatPickers({ chatModel, setChatModel, chatRole, setChatRole, agentId, setAgentId }: { chatModel: string; setChatModel: (v: string) => void; chatRole: string; setChatRole: (v: string) => void; agentId: string; setAgentId: (v: string) => void }) {
  const agents = useQuery({ queryKey: ["chat-agents"], queryFn: () => api<{ items: RecordData[] }>("/agents?limit=100").then((r) => r.items ?? []) });
  const models = useQuery({ queryKey: ["models"], queryFn: () => api<{ items: RecordData[] }>("/models?limit=100").then((r) => r.items ?? []) });
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => api<{ items: RecordData[] }>("/providers?limit=100").then((r) => r.items ?? []) });
  const providerOf = (id: string) => (providers.data ?? []).find((r) => String(r.id) === id);
  const keyBadge = (m: RecordData) => {
    if (m.enabled === false) return "disabled";
    const p = providerOf(String(m.provider_id ?? ""));
    if (p && p.enabled === false) return "provider off";
    if (p && p.local === true) return "local, no key needed";
    return p && (p as RecordData).secret_set ? "key set" : "no key — add in Models";
  };
  const providerName = (id: string) => { const p = providerOf(id); return p ? String(p.name ?? p.id) : ""; };
  const items = models.data ?? [];
  return (
    <div className="chat-pickers">
      <Select label="Model (optional — auto when blank)" value={chatModel} onChange={(e) => setChatModel(e.target.value)}>
        <option value="">Auto (role default)</option>
        {items.slice(0, 100).map((m) => (
          <option key={String(m.id)} value={String(m.id)}>{`${providerName(String(m.provider_id ?? ""))} — ${String(m.name ?? m.model ?? m.id)} (${keyBadge(m)})`}</option>
        ))}
      </Select>
      <Select label="Agent (optional — default when blank)" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
        <option value="">Default agent</option>
        {(agents.data ?? []).slice(0, 100).map((a) => (
          <option key={String(a.id)} value={String(a.id)}>{text(a.name) || "Agent"}</option>
        ))}
      </Select>
      <Select label="Function" value={chatRole} onChange={(e) => setChatRole(e.target.value)}>
        {AGENT_ROLES.map((option) => (
          <option key={option} value={option}>{label(option)}</option>
        ))}
      </Select>
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
    skills: "",
    model_role: "FAST",
  });
  const skills = useQuery({ queryKey: ["agent-skills"], queryFn: () => api<{ items: RecordData[] }>("/skills").then((r) => r.items ?? []) });
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
          skills: form.skills
            .split(",")
            .map((s) => s.trim().toLowerCase())
            .filter((s) => s && /^[a-z0-9-]+$/.test(s)),
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
      <Input
        label="Skills (comma-separated, lowercase)"
        placeholder="hello-skill"
        value={form.skills}
        onChange={(e) => setForm({ ...form, skills: e.target.value })}
      />
      {skills.data && skills.data.length > 0 && (
        <p className="muted">
          Available: {skills.data.map((k) => `${text(k.name)}${k.state && k.state !== "ok" ? ` (${text(k.state)})` : ""}`).join(" · ")}
        </p>
      )}
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
                    <th scope="col">Skills</th>
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
                      <td>{text((row as unknown as Record<string, unknown>).skills)}</td>
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
