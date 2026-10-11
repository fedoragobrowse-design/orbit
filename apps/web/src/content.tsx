import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Input,
  PageHeader,
  Select,
  Status,
  Textarea,
} from "./ui";
import {
  api,
  ApiError,
  label,
  post,
  remove,
  text,
  timestamp,
  type RecordData,
} from "./api";

type ItemList = { items: RecordData[] };

export function ImportForm({
  heading,
  description,
  placeholder,
  actionLabel,
  payloadKey,
  endpoint,
  queryKey,
}: {
  heading: string;
  description: string;
  placeholder: string;
  actionLabel: string;
  payloadKey: string;
  endpoint: string;
  queryKey: string[];
}) {
  const client = useQueryClient();
  const [raw, setRaw] = useState("");
  const [outcome, setOutcome] = useState("");
  const [problem, setProblem] = useState<Error | null>(null);
  const run = useMutation({
    mutationFn: (body: Record<string, unknown>) =>
      post<RecordData>(endpoint, body),
    onSuccess: (data) => {
      const held =
        data.quarantined === undefined
          ? ""
          : `, ${text(data.quarantined)} held for review`;
      setOutcome(
        `Saved ${text(data.imported)}; skipped ${text(data.skipped)}${held}.`,
      );
      setProblem(null);
      setRaw("");
      void client.invalidateQueries({ queryKey });
    },
    onError: (error: unknown) => {
      setOutcome("");
      setProblem(error instanceof Error ? error : new Error("Import failed."));
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      setOutcome("");
      setProblem(
        new Error("That is not valid JSON. Paste a JSON array like the example below."),
      );
      return;
    }
    if (!Array.isArray(parsed)) {
      setOutcome("");
      setProblem(new Error("Paste a JSON array of objects."));
      return;
    }
    run.mutate({ [payloadKey]: parsed });
  }
  return (
    <section className="panel form section" aria-label={heading}>
      <h2>{heading}</h2>
      <p className="muted">{description}</p>
      <form onSubmit={submit}>
        <Textarea
          label="Rows to import (JSON array)"
          rows={6}
          value={raw}
          placeholder={placeholder}
          onChange={(e) => setRaw(e.target.value)}
        />
        <button disabled={run.isPending || !raw.trim()}>
          {run.isPending ? "Importing…" : actionLabel}
        </button>
      </form>
      {outcome && <p role="status">{outcome}</p>}
      {problem && <ErrorNotice error={problem} />}
    </section>
  );
}

export function Notes() {
  const client = useQueryClient();
  const list = useQuery({
    queryKey: ["notes"],
    queryFn: () => api<ItemList>("/api/v1/notes?limit=100"),
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [draftTitle, setDraftTitle] = useState("");
  const [draftBody, setDraftBody] = useState("");
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const [showImport, setShowImport] = useState(false);
  function refresh() {
    void client.invalidateQueries({ queryKey: ["notes"] });
  }
  const create = useMutation({
    mutationFn: (input: { title: string; body: string }) =>
      post<RecordData>("/api/v1/notes", input),
    onSuccess: (row) => {
      setDraftTitle("");
      setDraftBody("");
      setSelected(String(row.id));
      refresh();
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: { id: string; title: string; body: string }) =>
      api<RecordData>(`/api/v1/notes/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({ title: input.title, body: input.body }),
      }),
    onSuccess: refresh,
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/notes/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (selected === id) {
        setSelected(null);
        setDraftTitle("");
        setDraftBody("");
      }
      refresh();
    },
  });
  const items = list.data?.items ?? [];
  const active = items.find((r) => String(r.id) === selected) ?? null;
  function pick(row: RecordData) {
    setSelected(String(row.id));
    setDraftTitle(text(row.title));
    setDraftBody(text(row.body));
  }
  function newNote() {
    setSelected(null);
    setDraftTitle("");
    setDraftBody("");
  }
  const dirty =
    active !== null &&
    (draftTitle !== text(active.title) || draftBody !== text(active.body));
  return (
    <>
      <PageHeader
        title="Notes"
        description="Short notes to yourself. They stay on this machine unless you share them."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <div className="notes-shell">
        <aside className="notes-list" aria-label="All notes">
          <button onClick={newNote}>+ New note</button>
          {list.isPending && <p role="status">Loading…</p>}
          {items.length === 0 && !list.isPending ? (
            <Empty title="No notes yet">Start one on the right.</Empty>
          ) : (
            <ul>
              {items.map((row) => {
                const id = String(row.id);
                return (
                  <li key={id}>
                    <button
                      type="button"
                      className={selected === id ? "notes-active" : ""}
                      onClick={() => pick(row)}
                    >
                      <span className="notes-item-title">{text(row.title) || "Untitled"}</span>
                      <span className="notes-item-meta">{timestamp(row.updated_at)}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </aside>
        <section className="panel form notes-editor" aria-label={active ? "Edit note" : "New note"}>
          <h2>{active ? "Edit note" : "New note"}</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (active) saveEdit.mutate({ id: String(active.id), title: draftTitle, body: draftBody });
              else create.mutate({ title: draftTitle, body: draftBody });
            }}
          >
            <Input
              label="Title"
              value={draftTitle}
              maxLength={256}
              onChange={(e) => setDraftTitle(e.target.value)}
            />
            <Textarea
              label="Body"
              rows={12}
              value={draftBody}
              onChange={(e) => setDraftBody(e.target.value)}
            />
            <div className="actions">
              <button disabled={create.isPending || saveEdit.isPending || (!active && !draftTitle.trim() && !draftBody.trim())}>
                {active ? (saveEdit.isPending ? "Saving…" : dirty ? "Save changes" : "Saved") : create.isPending ? "Saving…" : "Save note"}
              </button>
              {active && (
                <button type="button" className="danger" onClick={() => setDeleting(active)}>
                  Delete
                </button>
              )}
            </div>
          </form>
          {(create.error ?? saveEdit.error) && <ErrorNotice error={(create.error ?? saveEdit.error) as Error} />}
        </section>
      </div>
      <p>
        <button type="button" className="secondary" onClick={() => setShowImport((v) => !v)}>
          {showImport ? "Hide import" : "Import a batch"}
        </button>
      </p>
      {showImport && (
        <ImportForm
          heading="Import notes"
          description="Paste a JSON array. Each entry needs a title and a body."
          placeholder='[{"title":"Shopping","body":"milk, eggs"}]'
          actionLabel="Import notes"
          payloadKey="notes"
          endpoint="/api/v1/notes/import"
          queryKey={["notes"]}
        />
      )}
      {deleting && (
        <Confirm
          title="Delete this note?"
          action="Delete"
          pending={destroy.isPending}
          onClose={() => setDeleting(null)}
          onConfirm={() => destroy.mutate(String(deleting.id))}
        >
          <p>“{text(deleting.title) || "Untitled"}” will be gone for good.</p>
          {destroy.error && <ErrorNotice error={destroy.error} />}
        </Confirm>
      )}
    </>
  );
}

export function Inbox() {
  const client = useQueryClient();
  const [filter, setFilter] = useState("open");
  const path =
    filter === "handled"
      ? "/api/v1/inbox?limit=100&handled=true"
      : filter === "all"
        ? "/api/v1/inbox?limit=100"
        : "/api/v1/inbox?limit=100&handled=false";
  const list = useQuery({
    queryKey: ["inbox", filter],
    queryFn: () => api<ItemList>(path),
    retry: false,
  });
  const handle = useMutation({
    mutationFn: (id: string) => post<RecordData>(`/api/v1/inbox/${id}/handle`),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["inbox"] });
    },
  });
  const disabled =
    list.error instanceof ApiError && list.error.status === 422;
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="AI Inbox"
        description="Things collected for you to sort through. Treat every entry as untrusted until you have checked it."
      />
      {disabled ? (
        <section className="panel form section" aria-label="Inbox turned off">
          <h2>The inbox is turned off</h2>
          <p>
            Turn it on in <Link to="/settings">Settings</Link> to start
            collecting items here. Nothing is gathered while it stays off.
          </p>
        </section>
      ) : (
        <>
          {list.error && (
            <ErrorNotice error={list.error} retry={() => list.refetch()} />
          )}
          <section className="panel form section" aria-label="Filter inbox">
            <Select
              label="Show"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            >
              <option value="open">Open items</option>
              <option value="handled">Handled items</option>
              <option value="all">Everything</option>
            </Select>
          </section>
          <section className="section" aria-label="Inbox items">
            <div className="panel">
              <h2>Inbox</h2>
              {list.isPending && <p role="status">Loading…</p>}
              {handle.error && <ErrorNotice error={handle.error} />}
              {list.data &&
                (items.length ? (
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Title</th>
                        <th scope="col">Source</th>
                        <th scope="col">Trust</th>
                        <th scope="col">State</th>
                        <th scope="col">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {items.map((row) => (
                        <tr key={String(row.id)}>
                          <th scope="row">
                            {text(row.title) || "Untitled"}
                            {row.quarantined ? (
                              <div>
                                <span className="status bad">
                                  Held for review
                                </span>
                              </div>
                            ) : null}
                            <div className="muted">{text(row.body).slice(0, 160)}</div>
                          </th>
                          <td>{text(row.source) || "—"}</td>
                          <td>{label(row.trust) || "Untrusted external"}</td>
                          <td>
                            <Status value={row.handled ? "HANDLED" : "NEW"} />
                          </td>
                          <td>
                            {!row.handled && (
                              <button
                                className="secondary"
                                disabled={handle.isPending}
                                onClick={() => handle.mutate(String(row.id))}
                              >
                                Mark handled
                              </button>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <Empty title="Inbox clear">
                    New items land here once something is sent to the inbox.
                  </Empty>
                ))}
            </div>
          </section>
          <ImportForm
            heading="Import into the inbox"
            description="Paste a JSON array. Each entry can carry a source, a title, and a body. Anything that looks like an instruction is held for review."
            placeholder='[{"source":"email","title":"Hello","body":"Just saying hi"}]'
            actionLabel="Import items"
            payloadKey="items"
            endpoint="/api/v1/inbox/import"
            queryKey={["inbox"]}
          />
        </>
      )}
    </>
  );
}
