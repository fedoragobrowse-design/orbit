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
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [editing, setEditing] = useState<RecordData | null>(null);
  const [editTitle, setEditTitle] = useState("");
  const [editBody, setEditBody] = useState("");
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  function refresh() {
    void client.invalidateQueries({ queryKey: ["notes"] });
  }
  const create = useMutation({
    mutationFn: (input: { title: string; body: string }) =>
      post<RecordData>("/api/v1/notes", input),
    onSuccess: () => {
      setTitle("");
      setBody("");
      refresh();
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: { id: string; title: string; body: string }) =>
      api<RecordData>(`/api/v1/notes/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({ title: input.title, body: input.body }),
      }),
    onSuccess: () => {
      setEditing(null);
      refresh();
    },
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/notes/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (editing && String(editing.id) === id) setEditing(null);
      refresh();
    },
  });
  function startEdit(row: RecordData) {
    setEditing(row);
    setEditTitle(text(row.title));
    setEditBody(text(row.body));
  }
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Notes"
        description="Short notes to yourself. They stay on this machine unless you share them."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <section className="panel form section" aria-label="New note">
        <h2>New note</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ title, body });
          }}
        >
          <Input
            label="Title"
            value={title}
            maxLength={256}
            onChange={(e) => setTitle(e.target.value)}
          />
          <Textarea
            label="Body"
            rows={4}
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
          <button disabled={create.isPending}>
            {create.isPending ? "Saving…" : "Save note"}
          </button>
        </form>
        {create.error && <ErrorNotice error={create.error} />}
      </section>
      <section className="section" aria-label="Saved notes">
        <div className="panel">
          <h2>Saved notes</h2>
          {list.isPending && <p role="status">Loading…</p>}
          {list.data &&
            (items.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Title</th>
                    <th scope="col">Updated</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={String(row.id)}>
                      <th scope="row">{text(row.title) || "Untitled"}</th>
                      <td>{timestamp(row.updated_at)}</td>
                      <td>
                        <div className="actions">
                          <button
                            className="secondary"
                            onClick={() => startEdit(row)}
                          >
                            Edit
                          </button>
                          <button
                            className="danger"
                            onClick={() => setDeleting(row)}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <Empty title="No notes yet">
                Write one above, or import a batch below.
              </Empty>
            ))}
        </div>
      </section>
      {editing && (
        <section className="panel form section" aria-label="Edit note">
          <h2>Edit note</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveEdit.mutate({
                id: String(editing.id),
                title: editTitle,
                body: editBody,
              });
            }}
          >
            <Input
              label="Title"
              value={editTitle}
              maxLength={256}
              onChange={(e) => setEditTitle(e.target.value)}
            />
            <Textarea
              label="Body"
              rows={6}
              value={editBody}
              onChange={(e) => setEditBody(e.target.value)}
            />
            <div className="actions">
              <button disabled={saveEdit.isPending}>
                {saveEdit.isPending ? "Saving…" : "Save changes"}
              </button>
              <button
                type="button"
                className="secondary"
                onClick={() => setEditing(null)}
              >
                Cancel
              </button>
            </div>
          </form>
          {saveEdit.error && <ErrorNotice error={saveEdit.error} />}
        </section>
      )}
      <ImportForm
        heading="Import notes"
        description="Paste a JSON array. Each entry needs a title and a body."
        placeholder='[{"title":"Shopping","body":"milk, eggs"}]'
        actionLabel="Import notes"
        payloadKey="notes"
        endpoint="/api/v1/notes/import"
        queryKey={["notes"]}
      />
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
