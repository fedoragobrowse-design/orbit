import { useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  api,
  label,
  post,
  remove,
  text,
  timestamp,
  type RecordData,
} from "./api";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Field,
  Json,
  PageHeader,
  Status,
} from "./ui";

const tabs = [
  { to: "runtimes", label: "Runtimes" },
  { to: "computers", label: "Computers" },
  { to: "mcp", label: "MCP" },
  { to: "calendars", label: "Calendars" },
  { to: "github", label: "GitHub" },
  { to: "home-assistant", label: "Home Assistant" },
  { to: "api", label: "API" },
] as const;

function gated(title: string, reason: string, extra?: React.ReactNode) {
  return (
    <div className="panel">
      <h2>{title}</h2>
      <p>
        <strong>Not available in this build.</strong> {reason}
      </p>
      {extra}
    </div>
  );
}

function Runtimes() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const connections = useQuery({
    queryKey: ["connections"],
    queryFn: () => api<{ items: RecordData[] }>("/runtimes/connections"),
  });
  const invalidate = () => client.invalidateQueries({ queryKey: ["connections"] });
  const test = useMutation({
    mutationFn: (id: string) => post<RecordData>(`/runtimes/connections/${id}/test`),
    onSuccess: invalidate,
  });
  const removeConnection = useMutation({
    mutationFn: (id: string) => remove(`/runtimes/connections/${id}`),
    onSuccess: invalidate,
  });
  if (connections.isPending)
    return (
      <div className="panel">
        <p role="status">Loading connections…</p>
      </div>
    );
  if (connections.error)
    return (
      <div className="panel">
        <ErrorNotice error={connections.error} retry={() => connections.refetch()} />
      </div>
    );
  const items = connections.data?.items ?? [];
  const error = test.error ?? removeConnection.error;
  return (
    <div className="panel">
      <h2>Runtimes</h2>
      <p>
        <small>
          Each connection points at one AIec control plane. Orbit admits only
          the addresses you list and keeps the tenant key in the secret store.
        </small>
      </p>
      {!items.length ? (
        <Empty title="No runtime connections yet">
          Add one so Orbit can reach an AIec control plane.
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Origin</th>
              <th scope="col">Admitted</th>
              <th scope="col">Image</th>
              <th scope="col">Status</th>
              <th scope="col">Last test</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.name)}</th>
                <td>{text(row.origin)}</td>
                <td>
                  {Array.isArray(row.admitted_addresses)
                    ? row.admitted_addresses.map((a) => text(a)).join(", ") || "—"
                    : "—"}
                </td>
                <td>{text(row.image)}</td>
                <td>
                  <Status value={row.status} />
                </td>
                <td>{timestamp(row.last_test)}</td>
                <td>
                  <div className="actions">
                    <button
                      className="secondary"
                      disabled={test.isPending}
                      onClick={() => test.mutate(String(row.id))}
                    >
                      Test
                    </button>
                    <button
                      className="danger"
                      onClick={() => setRemoving(String(row.id))}
                    >
                      Remove
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {error && (
        <ErrorNotice error={error} retry={() => removeConnection.reset()} />
      )}
      {removing && (
        <Confirm
          title="Remove this connection?"
          action="Remove"
          pending={removeConnection.isPending}
          onClose={() => setRemoving(null)}
          onConfirm={() => {
            removeConnection.mutate(removing);
            setRemoving(null);
          }}
        >
          <p>
            Orbit will no longer be able to start machines on this control
            plane. The stored credential stays in the secret store until you
            remove the secret.
          </p>
        </Confirm>
      )}
      {adding ? (
        <NewConnection onDone={() => setAdding(false)} />
      ) : (
        <button className="secondary" onClick={() => setAdding(true)}>
          Add runtime connection
        </button>
      )}
    </div>
  );
}

function NewConnection({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    origin: "",
    admitted_addresses: "",
    credential: "",
    image: "",
    disk_mb: "10240",
    lifetime_seconds: "3600",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/runtimes/connections", {
        name: form.name,
        origin: form.origin,
        admitted_addresses: form.admitted_addresses
          .split(",")
          .map((a) => a.trim())
          .filter(Boolean),
        credential: form.credential,
        image: form.image,
        disk_mb: Number(form.disk_mb),
        lifetime_seconds: Number(form.lifetime_seconds),
        enabled: true,
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["connections"] });
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
      <Field label="Name">
        <input
          required
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
      </Field>
      <Field label="Origin" hint="The control plane base URL.">
        <input
          required
          placeholder="https://aiec.internal:9443"
          value={form.origin}
          onChange={(e) => setForm({ ...form, origin: e.target.value })}
        />
      </Field>
      <Field
        label="Admitted addresses"
        hint="Comma separated. Nothing outside this list is dialled."
      >
        <input
          required
          placeholder="10.0.0.5, 10.0.0.6"
          value={form.admitted_addresses}
          onChange={(e) =>
            setForm({ ...form, admitted_addresses: e.target.value })
          }
        />
      </Field>
      <Field label="Tenant API key" hint="Write-only. Stored, never returned.">
        <input
          type="password"
          required
          value={form.credential}
          onChange={(e) => setForm({ ...form, credential: e.target.value })}
        />
      </Field>
      <Field label="Image" hint="The machine image Orbit starts.">
        <input
          required
          value={form.image}
          onChange={(e) => setForm({ ...form, image: e.target.value })}
        />
      </Field>
      <Field label="Disk MB">
        <input
          type="number"
          min={1}
          required
          value={form.disk_mb}
          onChange={(e) => setForm({ ...form, disk_mb: e.target.value })}
        />
      </Field>
      <Field label="Lifetime seconds">
        <input
          type="number"
          min={1}
          required
          value={form.lifetime_seconds}
          onChange={(e) => setForm({ ...form, lifetime_seconds: e.target.value })}
        />
      </Field>
      {create.error && (
        <ErrorNotice error={create.error} retry={() => create.reset()} />
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save connection"}
        </button>
      </div>
    </form>
  );
}
export function Connections() {
  return (
    <>
      <PageHeader
        title="Connections"
        description="Where Orbit reaches the rest of your setup."
      />
      <nav className="tabs" aria-label="Connection categories">
        {tabs.map((tab) => (
          <NavLink
            key={tab.to}
            to={tab.to}
            className={({ isActive }) => (isActive ? "active" : "")}
          >
            {tab.label}
          </NavLink>
        ))}
      </nav>
      <Routes>
        <Route index element={<Navigate to="runtimes" replace />} />
        <Route path="runtimes" element={<Runtimes />} />
        <Route path="email" element={<Email />} />
        <Route
          path="computers"
          element={gated(
            "Computers",
            "Computer nodes let Orbit work alongside your machines. Node pairing needs the Node API (Milestone 6), not yet served by this backend.",
            <p>
              <Link className="safe-link" to="/computers">
                Open the Computers page
              </Link>{" "}
              for the full status.
            </p>,
          )}
        />
        <Route
          path="mcp"
          element={gated(
            "MCP",
            "MCP tool connections need the Milestone 10 MCP API, not served by this backend.",
            <p>
              <Link className="safe-link" to="/approvals">
                Tools registered so far are listed under Approvals
              </Link>
              .
            </p>,
          )}
        />
        <Route
          path="calendars"
          element={gated(
            "Calendars",
            "Native calendar connections (OAuth calendar access) are not served by this backend.",
          )}
        />
        <Route
          path="github"
          element={gated(
            "GitHub",
            "Native GitHub connections (OAuth) are not served by this backend.",
          )}
        />
        <Route
          path="home-assistant"
          element={gated(
            "Home Assistant",
            "Native Home Assistant connections are not served by this backend.",
          )}
        />
        <Route
          path="api"
          element={gated(
            "API",
            "API access (OAuth apps and tokens) is not served by this backend.",
          )}
        />
        <Route
          path="*"
          element={
            <div className="panel">
              <h2>Unknown category</h2>
              <p>No such connection category in this build.</p>
            </div>
          }
        />
      </Routes>
    </>
  );
}

function Email() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<string | null>(null);
  const accounts = useQuery({
    queryKey: ["email-accounts"],
    queryFn: () => api<{ items: RecordData[] }>("/email/accounts"),
  });
  const invalidate = () =>
    client.invalidateQueries({ queryKey: ["email-accounts"] });
  const run = useMutation({
    mutationFn: ({ id, action }: { id: string; action: "test" | "sync" }) =>
      post<RecordData>(`/email/accounts/${id}/${action}`),
    onSuccess: invalidate,
  });
  const removeAccount = useMutation({
    mutationFn: (id: string) => remove(`/email/accounts/${id}`),
    onSuccess: invalidate,
  });
  if (accounts.isPending)
    return (
      <div className="panel">
        <p role="status">Loading accounts…</p>
      </div>
    );
  if (accounts.error)
    return (
      <div className="panel">
        <ErrorNotice error={accounts.error} retry={() => accounts.refetch()} />
      </div>
    );
  const items = accounts.data?.items ?? [];
  const error = run.error ?? removeAccount.error;
  return (
    <div className="panel">
      <h2>Email</h2>
      <p>
        <small>
          Orbit polls the mailboxes you name and can draft replies. Sending
          still needs your approval.
        </small>
      </p>
      {!items.length ? (
        <Empty title="No mail accounts yet">
          Add an IMAP and SMTP pair to let Orbit read and draft mail.
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">From</th>
              <th scope="col">Mailboxes</th>
              <th scope="col">Enabled</th>
              <th scope="col">Last sync</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => {
              const config = (row.config ?? {}) as RecordData;
              return (
                <tr key={String(row.id)}>
                  <th scope="row">{text(row.name)}</th>
                  <td>{text(config.from_address)}</td>
                  <td>
                    {Array.isArray(config.mailboxes)
                      ? (config.mailboxes as unknown[]).map(text).join(", ")
                      : "—"}
                  </td>
                  <td>
                    <Status value={row.enabled} />
                  </td>
                  <td>{timestamp(row.last_sync)}</td>
                  <td>
                    <div className="actions">
                      <button
                        className="secondary"
                        disabled={run.isPending}
                        onClick={() =>
                          run.mutate({ id: String(row.id), action: "test" })
                        }
                      >
                        Test
                      </button>
                      <button
                        className="secondary"
                        disabled={run.isPending}
                        onClick={() =>
                          run.mutate({ id: String(row.id), action: "sync" })
                        }
                      >
                        Sync
                      </button>
                      <button
                        className="danger"
                        onClick={() => setRemoving(String(row.id))}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {error && (
        <ErrorNotice error={error} retry={() => removeAccount.reset()} />
      )}
      {removing && (
        <Confirm
          title="Remove this mail account?"
          action="Remove"
          pending={removeAccount.isPending}
          onClose={() => setRemoving(null)}
          onConfirm={() => {
            removeAccount.mutate(removing);
            setRemoving(null);
          }}
        >
          <p>
            Orbit stops polling these mailboxes. Stored mail credentials stay
            in the secret store.
          </p>
        </Confirm>
      )}
      {adding ? (
        <NewEmailAccount onDone={() => setAdding(false)} />
      ) : (
        <button className="secondary" onClick={() => setAdding(true)}>
          Add mail account
        </button>
      )}
    </div>
  );
}

function NewEmailAccount({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    from_address: "",
    imap_host: "",
    imap_port: "993",
    smtp_host: "",
    smtp_port: "465",
    mailboxes: "INBOX",
    username: "",
    password: "",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/email/accounts", {
        name: form.name,
        config: {
          imap_host: form.imap_host,
          imap_port: Number(form.imap_port),
          smtp_host: form.smtp_host,
          smtp_port: Number(form.smtp_port),
          from_address: form.from_address,
          mailboxes: form.mailboxes
            .split(",")
            .map((m) => m.trim())
            .filter(Boolean),
        },
        imap_credential: { username: form.username, password: form.password },
        smtp_credential: { username: form.username, password: form.password },
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["email-accounts"] });
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
      <Field label="Name">
        <input
          required
          value={form.name}
          onChange={(e) => setForm({ ...form, name: e.target.value })}
        />
      </Field>
      <Field label="From address">
        <input
          type="email"
          required
          placeholder="you@example.com"
          value={form.from_address}
          onChange={(e) => setForm({ ...form, from_address: e.target.value })}
        />
      </Field>
      <Field label="IMAP host">
        <input
          required
          value={form.imap_host}
          onChange={(e) => setForm({ ...form, imap_host: e.target.value })}
        />
      </Field>
      <Field label="IMAP port">
        <input
          type="number"
          min={1}
          required
          value={form.imap_port}
          onChange={(e) => setForm({ ...form, imap_port: e.target.value })}
        />
      </Field>
      <Field label="SMTP host">
        <input
          required
          value={form.smtp_host}
          onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
        />
      </Field>
      <Field label="SMTP port">
        <input
          type="number"
          min={1}
          required
          value={form.smtp_port}
          onChange={(e) => setForm({ ...form, smtp_port: e.target.value })}
        />
      </Field>
      <Field label="Mailboxes" hint="Comma separated. At most 20.">
        <input
          required
          value={form.mailboxes}
          onChange={(e) => setForm({ ...form, mailboxes: e.target.value })}
        />
      </Field>
      <Field label="Username">
        <input
          required
          autoComplete="username"
          value={form.username}
          onChange={(e) => setForm({ ...form, username: e.target.value })}
        />
      </Field>
      <Field label="Password" hint="Write-only. Stored, never returned.">
        <input
          type="password"
          required
          autoComplete="current-password"
          value={form.password}
          onChange={(e) => setForm({ ...form, password: e.target.value })}
        />
      </Field>
      {create.error && (
        <ErrorNotice error={create.error} retry={() => create.reset()} />
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save account"}
        </button>
      </div>
    </form>
  );
}

export function Computers() {
  return (
    <>
      <PageHeader
        title="Computers"
        description="Machines paired with your Orbit."
      />
      <div className="notice info" role="note">
        <div>
          <p>
            <strong>Not available in this build.</strong> Computer nodes need
            the Node API (Milestone 6) — not served by this backend.
          </p>
          <p>
            <small>
              No machines are paired, so this page lists nothing. Pairing a
              machine — including macOS machines via the OMP node agent —
              becomes possible once the Node API lands; see the Orbit node
              pairing docs then for the enrolment steps.
            </small>
          </p>
        </div>
      </div>
    </>
  );
}

export function Files() {
  return (
    <>
      <PageHeader title="Files" description="Files Orbit can see." />
      <div className="notice info" role="note">
        <div>
          <p>
            <strong>Not available in this build.</strong> Files need the
            Files API (Milestone 6) — not served by this backend.
          </p>
          <p>
            <small>
              File browsing is version-gated: the backend exposes no file
              listing in this build, so this page lists nothing rather than
              guessing at your files.
            </small>
          </p>
        </div>
      </div>
    </>
  );
}
