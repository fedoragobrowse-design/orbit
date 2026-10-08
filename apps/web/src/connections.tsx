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
  Input,
  Json,
  PageHeader,
  Status,
} from "./ui";

const tabs = [
  { to: "/connections/runtimes", label: "Runtimes" },
  { to: "/connections/email", label: "Email" },
  { to: "/connections/computers", label: "Computers" },
  { to: "/connections/mcp", label: "MCP" },
  { to: "/connections/calendars", label: "Calendars" },
  { to: "/connections/github", label: "GitHub" },
  { to: "/connections/home-assistant", label: "Home Assistant" },
  { to: "/connections/api", label: "API" },
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
          element={
            <div className="panel">
              <h2>Computers</h2>
              <p>
                Nodes pair and enrol from the{" "}
                <Link className="safe-link" to="/computers">
                  Computers page
                </Link>{" "}
                — pairing codes and revocation live there.
              </p>
            </div>
          }
        />
        <Route path="mcp" element={<McpConnections />} />
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
function McpConnections() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const connections = useQuery({
    queryKey: ["mcp-connections"],
    queryFn: () => api<{ items: RecordData[] }>("/mcp/connections"),
  });
  const invalidate = () =>
    client.invalidateQueries({ queryKey: ["mcp-connections"] });
  const removeConnection = useMutation({
    mutationFn: (id: string) => remove(`/mcp/connections/${id}`),
    onSuccess: invalidate,
  });
  if (connections.isPending)
    return (
      <div className="panel">
        <p role="status">Loading MCP connections…</p>
      </div>
    );
  if (connections.error)
    return (
      <div className="panel">
        <ErrorNotice
          error={connections.error}
          retry={() => connections.refetch()}
        />
      </div>
    );
  const items = connections.data?.items ?? [];
  return (
    <div className="panel">
      <h2>MCP</h2>
      <p>
        <small>
          MCP servers expose tools through a connection Orbit admits first.
          Tool calls still need your approval.
        </small>
      </p>
      {!items.length ? (
        <Empty title="No MCP connections yet">
          Add a server origin to discover its tools.
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Status</th>
              <th scope="col">Enabled</th>
              <th scope="col">Last discovery</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.name)}</th>
                <td>
                  <Status value={row.status} />
                </td>
                <td>
                  <Status value={row.enabled} />
                </td>
                <td>{timestamp(row.last_discovery)}</td>
                <td>
                  <button
                    className="danger"
                    disabled={removeConnection.isPending}
                    onClick={() => removeConnection.mutate(String(row.id))}
                  >
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {removeConnection.error && (
        <ErrorNotice
          error={removeConnection.error}
          retry={() => removeConnection.reset()}
        />
      )}
      <p>
        <Link className="safe-link" to="/approvals">
          Tools registered so far are listed under Approvals
        </Link>
        .
      </p>
      {adding ? (
        <NewMcpConnection onDone={() => setAdding(false)} />
      ) : (
        <button className="secondary" onClick={() => setAdding(true)}>
          Add MCP connection
        </button>
      )}
    </div>
  );
}

function NewMcpConnection({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({ name: "", origin: "" });
  const create = useMutation({
    mutationFn: () => post<RecordData>("/mcp/connections", form),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["mcp-connections"] });
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
      <Input
        label="Server origin"
        required
        placeholder="https://mcp.example.com"
        value={form.origin}
        onChange={(e) => setForm({ ...form, origin: e.target.value })}
      />
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
  const client = useQueryClient();
  const nodes = useQuery({
    queryKey: ["computers"],
    queryFn: () => api<{ items: RecordData[] }>("/computers"),
  });
  const invalidate = () => client.invalidateQueries({ queryKey: ["computers"] });
  const pairing = useMutation({
    mutationFn: () => post<RecordData>("/computers/pairing-codes"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => post<RecordData>(`/computers/${id}/revoke`),
    onSuccess: invalidate,
  });
  if (nodes.isPending)
    return (
      <>
        <PageHeader
          title="Computers"
          description="Machines paired with your Orbit."
        />
        <div className="panel">
          <p role="status">Loading machines…</p>
        </div>
      </>
    );
  if (nodes.error)
    return (
      <>
        <PageHeader
          title="Computers"
          description="Machines paired with your Orbit."
        />
        <div className="panel">
          <ErrorNotice error={nodes.error} retry={() => nodes.refetch()} />
        </div>
      </>
    );
  const items = nodes.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Computers"
        description="Machines paired with your Orbit."
      />
      <div className="panel">
        <h2>Paired machines</h2>
        {!items.length ? (
          <Empty title="No machines paired yet">
            Create a one-use pairing code, then enrol the node agent on the
            machine — including macOS machines via the OMP node agent.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Connected</th>
                <th scope="col">Last seen</th>
                <th scope="col">Roots</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={String(row.id)}>
                  <th scope="row">{text(row.display_name)}</th>
                  <td>
                    <Status value={row.connected} />
                  </td>
                  <td>{timestamp(row.last_seen)}</td>
                  <td>
                    {Array.isArray(row.roots)
                      ? row.roots.map((r) => text((r as RecordData).display_name)).join(", ") || "—"
                      : "—"}
                  </td>
                  <td>
                    <button
                      className="danger"
                      disabled={revoke.isPending}
                      onClick={() => revoke.mutate(String(row.id))}
                    >
                      Revoke
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {revoke.error && (
          <ErrorNotice error={revoke.error} retry={() => revoke.reset()} />
        )}
      </div>
      <div className="panel">
        <h2>Pair a machine</h2>
        <p>
          <small>
            Codes are one-use and expire after ten minutes. The node presents
            the code over verified TLS when it enrols.
          </small>
        </p>
        {pairing.data ? (
          <div>
            <p>
              Pairing code: <strong>{text(pairing.data.code)}</strong>
            </p>
            <p>
              <small>
                Expires in {text(pairing.data.expires_in_seconds)} seconds.
                Creating another code invalidates this one.
              </small>
            </p>
          </div>
        ) : (
          <button
            className="secondary"
            disabled={pairing.isPending}
            onClick={() => pairing.mutate()}
          >
            {pairing.isPending ? "Creating…" : "Create pairing code"}
          </button>
        )}
        {pairing.error && (
          <ErrorNotice error={pairing.error} retry={() => pairing.reset()} />
        )}
      </div>
    </>
  );
}

export function Files() {
  const [nodeId, setNodeId] = useState("");
  const [rootId, setRootId] = useState("");
  const [path, setPath] = useState("");
  const [browse, setBrowse] = useState<{
    node_id: string;
    root_id: string;
    relative_path: string;
  } | null>(null);
  const nodes = useQuery({
    queryKey: ["computers"],
    queryFn: () => api<{ items: RecordData[] }>("/computers"),
  });
  const listing = useQuery({
    queryKey: ["files", browse],
    enabled: browse !== null,
    queryFn: () =>
      api<RecordData>(
        `/files/list?node_id=${encodeURIComponent(browse!.node_id)}&root_id=${encodeURIComponent(browse!.root_id)}${browse!.relative_path ? `&relative_path=${encodeURIComponent(browse!.relative_path)}` : ""}`,
      ),
  });
  const nodeItems = nodes.data?.items ?? [];
  const selected = nodeItems.find((n) => String(n.id) === nodeId);
  const roots = Array.isArray(selected?.roots)
    ? (selected.roots as RecordData[])
    : [];
  return (
    <>
      <PageHeader title="Files" description="Files Orbit can see." />
      <div className="panel">
        <h2>Browse files</h2>
        <p>
          <small>
            Reads go through the paired node over its live channel, scoped to
            the roots you approved for that machine.
          </small>
        </p>
        {!nodeItems.length ? (
          <Empty title="No machines paired yet">
            Pair a machine on the Computers page first — file browsing needs
            a live node with approved roots.
          </Empty>
        ) : (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              setBrowse({ node_id: nodeId, root_id: rootId, relative_path: path });
            }}
          >
            <Field label="Machine">
              <select
                required
                value={nodeId}
                onChange={(e) => {
                  setNodeId(e.target.value);
                  setRootId("");
                }}
              >
                <option value="">Choose a machine…</option>
                {nodeItems.map((n) => (
                  <option key={String(n.id)} value={String(n.id)}>
                    {text(n.display_name)}
                  </option>
                ))}
              </select>
            </Field>
            {!!roots.length && (
              <Field label="Root">
                <select
                  required
                  value={rootId}
                  onChange={(e) => setRootId(e.target.value)}
                >
                  <option value="">Choose a root…</option>
                  {roots.map((r) => (
                    <option key={String(r.id)} value={String(r.id)}>
                      {text(r.display_name)}
                    </option>
                  ))}
                </select>
              </Field>
            )}
            <Input
              label="Subdirectory (optional)"
              placeholder="documents"
              value={path}
              onChange={(e) => setPath(e.target.value)}
            />
            <div className="actions">
              <button type="submit" disabled={!nodeId || !rootId}>
                List files
              </button>
            </div>
          </form>
        )}
      </div>
      {browse && (
        <div className="panel">
          <h2>Listing</h2>
          {listing.isPending && <p role="status">Loading…</p>}
          {listing.error && (
            <ErrorNotice error={listing.error} retry={() => listing.refetch()} />
          )}
          {listing.data && <Json value={listing.data} />}
        </div>
      )}
    </>
  );
}
