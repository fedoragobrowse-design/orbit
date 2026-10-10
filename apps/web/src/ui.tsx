import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { AlertCircle, RefreshCw } from "lucide-react";
import {
  api,
  ApiError,
  label,
  text,
  timestamp,
  type Page,
  type RecordData,
} from "./api";
export function ErrorNotice({
  error,
  retry,
}: {
  error: unknown;
  retry?: () => void;
}) {
  return (
    <div className="notice error" role="alert">
      <AlertCircle size={20} />
      <div>
        <strong>
          {error instanceof ApiError ? label(error.code) : "Request failed"}
        </strong>
        <p>
          {error instanceof Error
            ? error.message
            : "The request could not be completed."}
        </p>
        {error instanceof ApiError && error.requestId && (
          <small>Request reference: {error.requestId}</small>
        )}
        {retry && (
          <button className="secondary" onClick={retry}>
            <RefreshCw size={16} />
            Try again
          </button>
        )}
      </div>
    </div>
  );
}
export function Empty({
  title,
  children,
}: {
  title: string;
  children: ReactNode;
}) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      <p>{children}</p>
    </div>
  );
}
export function Status({ value }: { value: unknown }) {
  const s = text(value);
  return (
    <span
      className={`status ${/FAILED|DENIED|UNKNOWN|FORBIDDEN|OFFLINE|UNRESOLVED/.test(s) ? "bad" : /WAITING|PENDING|EXPIRED|REVIEW/.test(s) ? "pending" : /COMPLETED|ACTIVE|ONLINE|APPROVED|DESTROYED|CONNECTED/.test(s) ? "good" : ""}`}
    >
      {label(value) || "Unknown"}
    </span>
  );
}
export function Field({
  label: caption,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{caption}</label>
      <div id={id}>{children}</div>
      {hint && <small>{hint}</small>}
    </div>
  );
}
export function Input({
  label: caption,
  ...props
}: React.InputHTMLAttributes<HTMLInputElement> & { label: string }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{caption}</label>
      <input id={id} {...props} />
    </div>
  );
}
export function Select({
  label: caption,
  children,
  ...props
}: React.SelectHTMLAttributes<HTMLSelectElement> & { label: string }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{caption}</label>
      <select id={id} {...props}>
        {children}
      </select>
    </div>
  );
}
export function Textarea({
  label: caption,
  ...props
}: React.TextareaHTMLAttributes<HTMLTextAreaElement> & { label: string }) {
  const id = useId();
  return (
    <div className="field">
      <label htmlFor={id}>{caption}</label>
      <textarea id={id} {...props} />
    </div>
  );
}
export function PageHeader({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children?: ReactNode;
}) {
  return (
    <header className="page-heading">
      <div>
        <h1>{title}</h1>
        {description && <p>{description}</p>}
      </div>
      {children}
    </header>
  );
}
export function Json({ value }: { value: unknown }) {
  return <pre className="json">{text(value)}</pre>;
}
export function Evidence({
  correlationId,
  evidence,
}: {
  correlationId?: string;
  evidence?: unknown;
}) {
  const [open, setOpen] = useState(false);
  const q = useQuery({
    queryKey: ["why", correlationId],
    queryFn: () =>
      api<{ correlation_id: string; events: RecordData[]; tasks: RecordData[]; activity: RecordData[]; notifications: RecordData[] }>(
        `/why/${encodeURIComponent(correlationId!)}`,
      ),
    enabled: open && !!correlationId,
  });
  const timeline = q.data;
  return (
    <details
      className="evidence"
      onToggle={(e) => setOpen(e.currentTarget.open)}
    >
      <summary>Why this happened</summary>
      <p className="muted">
        Recorded sources and decisions, not private model reasoning.
      </p>
      {q.isPending && correlationId && <p role="status">Loading evidence…</p>}
      {q.error && <ErrorNotice error={q.error} retry={() => q.refetch()} />}
      {timeline && (
        <>
          {timeline.tasks.map((row) => (
            <p key={String(row.id)}><small>Task <Link to={`/tasks/${row.id}`}>{text(row.title)}</Link> · {label(row.state)}{row.wait_reason ? ` — ${text(row.wait_reason)}` : ""}</small></p>
          ))}
          {timeline.notifications.map((row) => (
            <p key={String(row.id)}><small>Notice {text(row.title)} · {label(row.severity)}</small></p>
          ))}
          {timeline.events.map((row) => (
            <p key={String(row.id)}><small>Trigger {text(row.event_type)} · {timestamp(row.timestamp)}</small></p>
          ))}
        </>
      )}
      <ol>
        {(timeline?.activity ?? []).map((row) => (
          <li key={row.id}>
            <Link to={`/activity/${row.id}`}>{label(row.operation)}</Link>
            <span>{text(row.reason)}</span>
            <small>{timestamp(row.timestamp)}</small>
            {!!row.metadata && <Json value={row.metadata} />}
          </li>
        ))}
      </ol>
      {evidence !== undefined && <Json value={evidence} />}{" "}
      {!correlationId && evidence === undefined && (
        <p>No supporting record was returned. Permission is not implied.</p>
      )}
      {correlationId && timeline && timeline.activity.length === 0 && timeline.tasks.length === 0 && timeline.events.length === 0 && timeline.notifications.length === 0 && (
        <p>No recorded evidence is available for this correlation.</p>
      )}
    </details>
  );
}
export function Confirm({
  title,
  children,
  onConfirm,
  onClose,
  pending = false,
  action = "Confirm",
}: {
  title: string;
  children: ReactNode;
  onConfirm: () => void;
  onClose: () => void;
  pending?: boolean;
  action?: string;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const previous = useRef<HTMLElement | null>(null);
  useEffect(() => {
    previous.current = document.activeElement as HTMLElement;
    ref.current?.showModal();
    return () => previous.current?.focus();
  }, []);
  return (
    <dialog
      ref={ref}
      onCancel={(e) => {
        e.preventDefault();
        if (!pending) onClose();
      }}
    >
      <h2>{title}</h2>
      {children}
      <div className="actions">
        <button className="secondary" disabled={pending} onClick={onClose}>
          Keep unchanged
        </button>
        <button className="danger" disabled={pending} onClick={onConfirm}>
          {pending ? "Working…" : action}
        </button>
      </div>
    </dialog>
  );
}
export function Resource({
  path,
  empty,
  children,
}: {
  path: string;
  empty: ReactNode;
  children: (items: RecordData[]) => ReactNode;
}) {
  const [cursor, setCursor] = useState<string | null>(null);
  const q = useQuery({
    queryKey: [path, cursor],
    queryFn: () =>
      api<Page>(
        path +
          (path.includes("?") ? "&" : "?") +
          (cursor ? `cursor=${encodeURIComponent(cursor)}&` : "") +
          "limit=50",
      ),
  });
  return (
    <>
      {q.isPending && <p role="status">Loading…</p>}
      {q.error && (
        <ErrorNotice error={q.error} retry={() => q.refetch()} />
      )}{" "}
      {q.data && (q.data.items.length ? children(q.data.items) : empty)}
      {q.data?.next_cursor && (
        <button
          className="secondary"
          onClick={() => setCursor(q.data!.next_cursor)}
        >
          Next page
        </button>
      )}
      {cursor && (
        <button className="quiet" onClick={() => setCursor(null)}>
          Return to first page
        </button>
      )}
    </>
  );
}
