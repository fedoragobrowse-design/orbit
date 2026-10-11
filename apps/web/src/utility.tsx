import { useState } from "react";
import type { QueryClient } from "@tanstack/react-query";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Input,
  PageHeader,
  Status,
  Textarea,
} from "./ui";
import {
  api,
  label,
  post,
  remove,
  text,
  timestamp,
  type RecordData,
} from "./api";
import { ImportForm } from "./content";

type ItemList = { items: RecordData[] };

function refreshKey(client: QueryClient, key: string[]) {
  void client.invalidateQueries({ queryKey: key });
}

export function Reminders() {
  const client = useQueryClient();
  const list = useQuery({
    queryKey: ["reminders"],
    queryFn: () => api<ItemList>("/api/v1/reminders?limit=100"),
  });
  const [title, setTitle] = useState("");
  const [when, setWhen] = useState("");
  const [editing, setEditing] = useState<RecordData | null>(null);
  const [editTitle, setEditTitle] = useState("");
  const [editWhen, setEditWhen] = useState("");
  const [editDone, setEditDone] = useState(false);
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const create = useMutation({
    mutationFn: (input: { title: string; remind_at: string | null }) =>
      post<RecordData>("/api/v1/reminders", input),
    onSuccess: () => {
      setTitle("");
      setWhen("");
      refreshKey(client, ["reminders"]);
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: {
      id: string;
      title: string;
      remind_at: string | null;
      done: boolean;
    }) =>
      api<RecordData>(`/api/v1/reminders/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          title: input.title,
          remind_at: input.remind_at,
          done: input.done,
        }),
      }),
    onSuccess: () => {
      setEditing(null);
      refreshKey(client, ["reminders"]);
    },
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/reminders/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (editing && String(editing.id) === id) setEditing(null);
      refreshKey(client, ["reminders"]);
    },
  });
  function startEdit(row: RecordData) {
    setEditing(row);
    setEditTitle(text(row.title));
    setEditWhen(text(row.remind_at).slice(0, 16));
    setEditDone(row.done === true);
  }
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Reminders"
        description="Things to do, with an optional date and time."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <section className="panel form section" aria-label="New reminder">
        <h2>New reminder</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({
              title,
              remind_at: when ? new Date(when).toISOString() : null,
            });
          }}
        >
          <Input
            label="Title"
            value={title}
            maxLength={280}
            required
            onChange={(e) => setTitle(e.target.value)}
          />
          <Input
            label="Remind at (optional)"
            type="datetime-local"
            value={when}
            onChange={(e) => setWhen(e.target.value)}
          />
          <button disabled={create.isPending || !title.trim()}>
            {create.isPending ? "Saving…" : "Save reminder"}
          </button>
        </form>
        {create.error && <ErrorNotice error={create.error} />}
      </section>
      <section className="section" aria-label="Saved reminders">
        <div className="panel">
          <h2>Saved reminders</h2>
          {list.isPending && <p role="status">Loading…</p>}
          {list.data &&
            (items.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Title</th>
                    <th scope="col">When</th>
                    <th scope="col">State</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={String(row.id)}>
                      <th scope="row">{text(row.title)}</th>
                      <td>{row.remind_at ? timestamp(row.remind_at) : "—"}</td>
                      <td>
                        <Status value={row.done ? "DONE" : "OPEN"} />
                      </td>
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
              <Empty title="No reminders yet">
                Add one above, or import a batch below.
              </Empty>
            ))}
        </div>
      </section>
      {editing && (
        <section className="panel form section" aria-label="Edit reminder">
          <h2>Edit reminder</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveEdit.mutate({
                id: String(editing.id),
                title: editTitle,
                remind_at: editWhen ? new Date(editWhen).toISOString() : null,
                done: editDone,
              });
            }}
          >
            <Input
              label="Title"
              value={editTitle}
              maxLength={280}
              required
              onChange={(e) => setEditTitle(e.target.value)}
            />
            <Input
              label="Remind at (optional)"
              type="datetime-local"
              value={editWhen}
              onChange={(e) => setEditWhen(e.target.value)}
            />
            <label className="check">
              <input
                type="checkbox"
                checked={editDone}
                onChange={(e) => setEditDone(e.target.checked)}
              />
              Done
            </label>
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
        heading="Import reminders"
        description="Paste a JSON array. Each entry needs a title; remind_at is an optional date like 2026-11-01T09:00:00Z."
        placeholder='[{"title":"Call the dentist","remind_at":"2026-11-01T09:00:00Z"}]'
        actionLabel="Import reminders"
        payloadKey="items"
        endpoint="/api/v1/reminders/import"
        queryKey={["reminders"]}
      />
      {deleting && (
        <Confirm
          title="Delete this reminder?"
          action="Delete"
          pending={destroy.isPending}
          onClose={() => setDeleting(null)}
          onConfirm={() => destroy.mutate(String(deleting.id))}
        >
          <p>“{text(deleting.title)}” will be gone for good.</p>
          {destroy.error && <ErrorNotice error={destroy.error} />}
        </Confirm>
      )}
    </>
  );
}

export function Contacts() {
  const client = useQueryClient();
  const list = useQuery({
    queryKey: ["contacts"],
    queryFn: () => api<ItemList>("/api/v1/contacts?limit=100"),
  });
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [phone, setPhone] = useState("");
  const [notes, setNotes] = useState("");
  const [editing, setEditing] = useState<RecordData | null>(null);
  const [draft, setDraft] = useState({ name: "", email: "", phone: "", notes: "" });
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const create = useMutation({
    mutationFn: (input: {
      name: string;
      email: string;
      phone: string;
      notes: string;
    }) => post<RecordData>("/api/v1/contacts", input),
    onSuccess: () => {
      setName("");
      setEmail("");
      setPhone("");
      setNotes("");
      refreshKey(client, ["contacts"]);
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: {
      id: string;
      name: string;
      email: string;
      phone: string;
      notes: string;
    }) =>
      api<RecordData>(`/api/v1/contacts/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: input.name,
          email: input.email,
          phone: input.phone,
          notes: input.notes,
        }),
      }),
    onSuccess: () => {
      setEditing(null);
      refreshKey(client, ["contacts"]);
    },
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/contacts/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (editing && String(editing.id) === id) setEditing(null);
      refreshKey(client, ["contacts"]);
    },
  });
  function startEdit(row: RecordData) {
    setEditing(row);
    setDraft({
      name: text(row.name),
      email: text(row.email),
      phone: text(row.phone),
      notes: text(row.notes),
    });
  }
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Contacts"
        description="People and places you want to keep track of."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <section className="panel form section" aria-label="New contact">
        <h2>New contact</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ name, email, phone, notes });
          }}
        >
          <Input
            label="Name"
            value={name}
            maxLength={200}
            required
            onChange={(e) => setName(e.target.value)}
          />
          <Input
            label="Email (optional)"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <Input
            label="Phone (optional)"
            type="tel"
            value={phone}
            onChange={(e) => setPhone(e.target.value)}
          />
          <Textarea
            label="Notes (optional)"
            rows={3}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
          />
          <button disabled={create.isPending || !name.trim()}>
            {create.isPending ? "Saving…" : "Save contact"}
          </button>
        </form>
        {create.error && <ErrorNotice error={create.error} />}
      </section>
      <section className="section" aria-label="Saved contacts">
        <div className="panel">
          <h2>Saved contacts</h2>
          {list.isPending && <p role="status">Loading…</p>}
          {list.data &&
            (items.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Email</th>
                    <th scope="col">Phone</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={String(row.id)}>
                      <th scope="row">{text(row.name)}</th>
                      <td>{text(row.email) || "—"}</td>
                      <td>{text(row.phone) || "—"}</td>
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
              <Empty title="No contacts yet">
                Add one above, or import a batch below.
              </Empty>
            ))}
        </div>
      </section>
      {editing && (
        <section className="panel form section" aria-label="Edit contact">
          <h2>Edit contact</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveEdit.mutate({ id: String(editing.id), ...draft });
            }}
          >
            <Input
              label="Name"
              value={draft.name}
              maxLength={200}
              required
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
            />
            <Input
              label="Email (optional)"
              type="email"
              value={draft.email}
              onChange={(e) => setDraft({ ...draft, email: e.target.value })}
            />
            <Input
              label="Phone (optional)"
              type="tel"
              value={draft.phone}
              onChange={(e) => setDraft({ ...draft, phone: e.target.value })}
            />
            <Textarea
              label="Notes (optional)"
              rows={3}
              value={draft.notes}
              onChange={(e) => setDraft({ ...draft, notes: e.target.value })}
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
        heading="Import contacts"
        description="Paste a JSON array. Each entry needs a name; email, phone, and notes are optional."
        placeholder='[{"name":"Sam Rivera","email":"sam@example.com","phone":"555-0100"}]'
        actionLabel="Import contacts"
        payloadKey="items"
        endpoint="/api/v1/contacts/import"
        queryKey={["contacts"]}
      />
      {deleting && (
        <Confirm
          title="Delete this contact?"
          action="Delete"
          pending={destroy.isPending}
          onClose={() => setDeleting(null)}
          onConfirm={() => destroy.mutate(String(deleting.id))}
        >
          <p>“{text(deleting.name)}” will be gone for good.</p>
          {destroy.error && <ErrorNotice error={destroy.error} />}
        </Confirm>
      )}
    </>
  );
}

export function Bookmarks() {
  const client = useQueryClient();
  const list = useQuery({
    queryKey: ["bookmarks"],
    queryFn: () => api<ItemList>("/api/v1/bookmarks?limit=100"),
  });
  const [url, setUrl] = useState("");
  const [title, setTitle] = useState("");
  const [editing, setEditing] = useState<RecordData | null>(null);
  const [editUrl, setEditUrl] = useState("");
  const [editTitle, setEditTitle] = useState("");
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const create = useMutation({
    mutationFn: (input: { url: string; title: string }) =>
      post<RecordData>("/api/v1/bookmarks", input),
    onSuccess: () => {
      setUrl("");
      setTitle("");
      refreshKey(client, ["bookmarks"]);
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: { id: string; url: string; title: string }) =>
      api<RecordData>(`/api/v1/bookmarks/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({ url: input.url, title: input.title }),
      }),
    onSuccess: () => {
      setEditing(null);
      refreshKey(client, ["bookmarks"]);
    },
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/bookmarks/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (editing && String(editing.id) === id) setEditing(null);
      refreshKey(client, ["bookmarks"]);
    },
  });
  function startEdit(row: RecordData) {
    setEditing(row);
    setEditUrl(text(row.url));
    setEditTitle(text(row.title));
  }
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Bookmarks"
        description="Pages worth finding again. Links must start with http:// or https://."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <section className="panel form section" aria-label="New bookmark">
        <h2>New bookmark</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ url, title });
          }}
        >
          <Input
            label="Link"
            type="url"
            value={url}
            placeholder="https://example.com"
            required
            onChange={(e) => setUrl(e.target.value)}
          />
          <Input
            label="Title (optional)"
            value={title}
            maxLength={280}
            onChange={(e) => setTitle(e.target.value)}
          />
          <button disabled={create.isPending || !url.trim()}>
            {create.isPending ? "Saving…" : "Save bookmark"}
          </button>
        </form>
        {create.error && <ErrorNotice error={create.error} />}
      </section>
      <section className="section" aria-label="Saved bookmarks">
        <div className="panel">
          <h2>Saved bookmarks</h2>
          {list.isPending && <p role="status">Loading…</p>}
          {list.data &&
            (items.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Title</th>
                    <th scope="col">Link</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={String(row.id)}>
                      <th scope="row">{text(row.title) || "Untitled"}</th>
                      <td>
                        <a
                          className="safe-link"
                          href={text(row.url)}
                          target="_blank"
                          rel="noreferrer"
                        >
                          {text(row.url)}
                        </a>
                      </td>
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
              <Empty title="No bookmarks yet">
                Add one above, or import a batch below.
              </Empty>
            ))}
        </div>
      </section>
      {editing && (
        <section className="panel form section" aria-label="Edit bookmark">
          <h2>Edit bookmark</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveEdit.mutate({
                id: String(editing.id),
                url: editUrl,
                title: editTitle,
              });
            }}
          >
            <Input
              label="Link"
              type="url"
              value={editUrl}
              required
              onChange={(e) => setEditUrl(e.target.value)}
            />
            <Input
              label="Title (optional)"
              value={editTitle}
              maxLength={280}
              onChange={(e) => setEditTitle(e.target.value)}
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
        heading="Import bookmarks"
        description="Paste a JSON array. Each entry needs a link starting with http:// or https://; titles are optional."
        placeholder='[{"url":"https://example.com","title":"Example"}]'
        actionLabel="Import bookmarks"
        payloadKey="items"
        endpoint="/api/v1/bookmarks/import"
        queryKey={["bookmarks"]}
      />
      {deleting && (
        <Confirm
          title="Delete this bookmark?"
          action="Delete"
          pending={destroy.isPending}
          onClose={() => setDeleting(null)}
          onConfirm={() => destroy.mutate(String(deleting.id))}
        >
          <p>“{text(deleting.title) || text(deleting.url)}” will be gone for good.</p>
          {destroy.error && <ErrorNotice error={destroy.error} />}
        </Confirm>
      )}
    </>
  );
}

export function Clips() {
  const client = useQueryClient();
  const list = useQuery({
    queryKey: ["clips"],
    queryFn: () => api<ItemList>("/api/v1/clips?limit=100"),
  });
  const [source, setSource] = useState("");
  const [clipText, setClipText] = useState("");
  const [editing, setEditing] = useState<RecordData | null>(null);
  const [editSource, setEditSource] = useState("");
  const [editText, setEditText] = useState("");
  const [deleting, setDeleting] = useState<RecordData | null>(null);
  const create = useMutation({
    mutationFn: (input: { source: string; text: string }) =>
      post<RecordData>("/api/v1/clips", input),
    onSuccess: () => {
      setSource("");
      setClipText("");
      refreshKey(client, ["clips"]);
    },
  });
  const saveEdit = useMutation({
    mutationFn: (input: { id: string; source: string; text: string }) =>
      api<RecordData>(`/api/v1/clips/${input.id}`, {
        method: "PATCH",
        body: JSON.stringify({ source: input.source, text: input.text }),
      }),
    onSuccess: () => {
      setEditing(null);
      refreshKey(client, ["clips"]);
    },
  });
  const destroy = useMutation({
    mutationFn: (id: string) => remove(`/api/v1/clips/${id}`),
    onSuccess: (_data, id) => {
      setDeleting(null);
      if (editing && String(editing.id) === id) setEditing(null);
      refreshKey(client, ["clips"]);
    },
  });
  function startEdit(row: RecordData) {
    setEditing(row);
    setEditSource(text(row.source));
    setEditText(text(row.text));
  }
  const items = list.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Clips"
        description="Snippets you pasted or saved from elsewhere. Treat them as untrusted until you have checked them."
      />
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      <section className="panel form section" aria-label="New clip">
        <h2>New clip</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            create.mutate({ source, text: clipText });
          }}
        >
          <Input
            label="Where is it from? (optional)"
            value={source}
            maxLength={512}
            onChange={(e) => setSource(e.target.value)}
          />
          <Textarea
            label="Clip text"
            rows={5}
            value={clipText}
            required
            onChange={(e) => setClipText(e.target.value)}
          />
          <button disabled={create.isPending || !clipText.trim()}>
            {create.isPending ? "Saving…" : "Save clip"}
          </button>
        </form>
        {create.error && <ErrorNotice error={create.error} />}
      </section>
      <section className="section" aria-label="Saved clips">
        <div className="panel">
          <h2>Saved clips</h2>
          {list.isPending && <p role="status">Loading…</p>}
          {list.data &&
            (items.length ? (
              <table>
                <thead>
                  <tr>
                    <th scope="col">Clip</th>
                    <th scope="col">Source</th>
                    <th scope="col">Trust</th>
                    <th scope="col">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((row) => (
                    <tr key={String(row.id)}>
                      <th scope="row">
                        {text(row.text).slice(0, 200)}
                        {row.quarantined ? (
                          <div>
                            <span className="status bad">
                              Held for review
                            </span>
                          </div>
                        ) : null}
                      </th>
                      <td>{text(row.source) || "—"}</td>
                      <td>{label(row.quarantined ? "QUARANTINED" : "UNTRUSTED_EXTERNAL")}</td>
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
              <Empty title="No clips yet">
                Paste one above, or import a batch below.
              </Empty>
            ))}
        </div>
      </section>
      {editing && (
        <section className="panel form section" aria-label="Edit clip">
          <h2>Edit clip</h2>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              saveEdit.mutate({
                id: String(editing.id),
                source: editSource,
                text: editText,
              });
            }}
          >
            <Input
              label="Where is it from? (optional)"
              value={editSource}
              maxLength={512}
              onChange={(e) => setEditSource(e.target.value)}
            />
            <Textarea
              label="Clip text"
              rows={6}
              value={editText}
              required
              onChange={(e) => setEditText(e.target.value)}
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
        heading="Import clips"
        description="Paste a JSON array. Each entry needs clip text; the source is optional. Anything that looks like an instruction is held for review."
        placeholder='[{"source":"article","text":"A paragraph worth keeping"}]'
        actionLabel="Import clips"
        payloadKey="items"
        endpoint="/api/v1/clips/import"
        queryKey={["clips"]}
      />
      {deleting && (
        <Confirm
          title="Delete this clip?"
          action="Delete"
          pending={destroy.isPending}
          onClose={() => setDeleting(null)}
          onConfirm={() => destroy.mutate(String(deleting.id))}
        >
          <p>This clip will be gone for good.</p>
          {destroy.error && <ErrorNotice error={destroy.error} />}
        </Confirm>
      )}
    </>
  );
}
