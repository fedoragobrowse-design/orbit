import { useEffect, useState } from "react";
import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import {
  api,
  label,
  post,
  put,
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
  Modal,
  PageHeader,
  Select,
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

function OAuthClientSection({ connector, title }: { connector: string; title: string }) {
  const client = useQueryClient();
  const status = useQuery({
    queryKey: ["oauth-clients"],
    queryFn: () => api<{ items: RecordData[] }>("/oauth/clients"),
  });
  const [form, setForm] = useState({ client_id: "", client_secret: "" });
  const [editing, setEditing] = useState(false);
  const save = useMutation({
    mutationFn: () =>
      put<RecordData>(`/oauth/clients/${connector}`, {
        client_id: form.client_id,
        client_secret: form.client_secret,
      }),
    onSuccess: async () => {
      setForm({ client_id: "", client_secret: "" });
      setEditing(false);
      await client.invalidateQueries({ queryKey: ["oauth-clients"] });
    },
  });
  const forget = useMutation({
    mutationFn: () => remove(`/oauth/clients/${connector}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["oauth-clients"] }),
  });
  const entry = status.data?.items.find((item) => item.connector === connector);
  return (
    <div className="panel">
      <h2>{title} credentials</h2>
      {status.isPending ? (
        <p role="status">Loading client status…</p>
      ) : status.error ? (
        <ErrorNotice error={status.error} retry={() => status.refetch()} />
      ) : entry?.configured ? (
        <p role="status">
          Client stored (…{text(entry.client_id_suffix)}). OAuth sign-in stays
          unavailable in this build — credentials are pending verification.
        </p>
      ) : (
        <p role="status">
          No client stored. OAuth sign-in stays unavailable in this build.
        </p>
      )}
      {entry?.configured && !editing ? (
        <div className="actions">
          <button className="secondary" onClick={() => setEditing(true)}>
            Replace credentials
          </button>{" "}
          <button
            className="danger"
            disabled={forget.isPending}
            onClick={() => forget.mutate()}
          >
            {forget.isPending ? "Removing…" : "Remove"}
          </button>
        </div>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            save.mutate();
          }}
        >
          <Input
            label="Client ID"
            required
            autoComplete="off"
            value={form.client_id}
            onChange={(e) => setForm({ ...form, client_id: e.target.value })}
          />
          <Input
            label="Client secret"
            type="password"
            required
            autoComplete="new-password"
            value={form.client_secret}
            onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
          />
          {save.error && <ErrorNotice error={save.error} retry={() => save.reset()} />}
          {forget.error && <ErrorNotice error={forget.error} retry={() => forget.reset()} />}
          <div className="actions">
            {entry?.configured ? (
              <>
                <button type="button" className="secondary" onClick={() => setEditing(false)}>
                  Cancel
                </button>{" "}
              </>
            ) : null}
            <button type="submit" disabled={save.isPending || !form.client_id || !form.client_secret}>
              {save.isPending ? "Saving…" : "Save credentials"}
            </button>
          </div>
        </form>
      )}
      <p>
        <small>
          Write-only: the secret is sealed into the secret store and never
          shown back. OAuth sign-in is not wired up yet, so storing a client
          does not enable sign-in.
        </small>
      </p>
    </div>
  );
}

function OAuthConnectors() {
  return (
    <>
      <OAuthClientSection connector="google" title="Google" />
      <OAuthClientSection connector="outlook" title="Outlook" />
      <OAuthClientSection connector="github" title="GitHub" />
    </>
  );
}

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
        <Route path="calendars" element={<Calendars />} />
        <Route path="github" element={<GithubConnections />} />
        <Route path="home-assistant" element={<HaConnections />} />
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
function BuiltInServices() {
  const ha = useQuery({
    queryKey: ["builtin-ha"],
    queryFn: () => api<{ items: RecordData[] }>("/ha/connections"),
  });
  const haCount = ha.data?.items?.length ?? -1;
  const services = [
    {
      name: "orbit-control",
      blurb: "Settings, questions, skills, agent docs. Trusted — owner data only.",
      state: "Active",
    },
    {
      name: "orbit-data",
      blurb: "Memory, mail, calendar, file reads. Everything it returns is marked untrusted.",
      state: "Active",
    },
    {
      name: "ha-control",
      blurb:
        haCount > 0
          ? "Home Assistant actions: read states, call services. Every action needs your confirm."
          : "Home Assistant actions. Connect Home Assistant first — this service stays off until then.",
      state: haCount > 0 ? "Active" : "Off — no Home Assistant",
    },
  ];
  return (
    <section aria-label="Built-in services">
      <h3>Built-in services</h3>
      <ul className="memory-files">
        {services.map((s) => (
          <li key={s.name}>
            <span className="notes-item-title">{s.name}</span>
            <span className="notes-item-meta">
              <Status value={s.state.startsWith("Active") ? "Connected" : "Unavailable"} /> {s.state} · {s.blurb}
            </span>
          </li>
        ))}
      </ul>
    </section>
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
      <BuiltInServices />
      <h3>External connections</h3>
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

function monthCells(year: number, month: number): (Date | null)[] {
  const first = new Date(year, month, 1);
  const startPad = (first.getDay() + 6) % 7;
  const daysIn = new Date(year, month + 1, 0).getDate();
  const cells: (Date | null)[] = [];
  for (let i = 0; i < startPad; i++) cells.push(null);
  for (let d = 1; d <= daysIn; d++) cells.push(new Date(year, month, d));
  while (cells.length % 7 !== 0) cells.push(null);
  return cells;
}
function toLocalInput(d: Date): string {
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
}
function Calendars() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [showFeeds, setShowFeeds] = useState(false);
  const now = new Date();
  const [year, setYear] = useState(now.getFullYear());
  const [month, setMonth] = useState(now.getMonth());
  const [day, setDay] = useState<string | null>(null);
  const [eventOpen, setEventOpen] = useState(false);
  const [form, setForm] = useState({ title: "", starts: "", ends: "" });
  const from = new Date(year, month, 1).toISOString();
  const to = new Date(year, month + 1, 1).toISOString();
  const sources = useQuery({ queryKey: ["calendar-sources"], queryFn: () => api<{ items: RecordData[] }>("/calendar/sources") });
  const events = useQuery({ queryKey: ["calendar-month", year, month], queryFn: () => api<{ items: RecordData[] }>(`/calendar/events?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}&limit=200`) });
  const invalidate = () => { client.invalidateQueries({ queryKey: ["calendar-sources"] }); client.invalidateQueries({ queryKey: ["calendar-month", year, month] }); client.invalidateQueries({ queryKey: ["calendar-today"] }); };
  const sync = useMutation({ mutationFn: (id: string) => post<RecordData>(`/calendar/sources/${id}/sync`), onSuccess: invalidate });
  const removeSource = useMutation({ mutationFn: (id: string) => remove(`/calendar/sources/${id}`), onSuccess: invalidate });
  const addEvent = useMutation({
    mutationFn: () => post<RecordData>("/calendar/events", {
      title: form.title,
      starts_at: new Date(form.starts).toISOString(),
      ends_at: form.ends ? new Date(form.ends).toISOString() : undefined,
    }),
    onSuccess: () => { setForm({ title: "", starts: "", ends: "" }); setEventOpen(false); invalidate(); },
  });
  if (sources.isPending) return (<div className="panel"><p role="status">Loading calendars…</p></div>);
  if (sources.error) return (<div className="panel"><ErrorNotice error={sources.error} retry={() => sources.refetch()} /></div>);
  const items = sources.data?.items ?? [];
  const rows = events.data?.items ?? [];
  const byDay: Record<string, RecordData[]> = {};
  for (const r of rows) {
    const s = text(r.starts_at);
    if (!s) continue;
    const d = new Date(s);
    const k = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
    byDay[k] = [...(byDay[k] ?? []), r];
  }
  const cells = monthCells(year, month);
  const monthName = new Date(year, month, 1).toLocaleString(undefined, { month: "long", year: "numeric" });
  const step = (d: number) => {
    const n = new Date(year, month + d, 1);
    setYear(n.getFullYear());
    setMonth(n.getMonth());
    setDay(null);
  };
  const openDay = (d: Date) => {
    setDay(`${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`);
    setForm((f) => ({ ...f, starts: f.starts || toLocalInput(new Date(d.getFullYear(), d.getMonth(), d.getDate(), 9, 0)) }));
  };
  const dayRows = day ? (byDay[day] ?? []) : [];
  return (
    <div className="panel">
      <h2>Calendar</h2>
      <p><small>Your own events plus anything synced from feeds. Local events stay here — feed events are read-only.</small></p>
      <div className="cal-head">
        <button type="button" className="secondary" onClick={() => step(-1)} aria-label="Previous month">‹</button>
        <strong>{monthName}</strong>
        <button type="button" className="secondary" onClick={() => step(1)} aria-label="Next month">›</button>
        <button type="button" className="secondary" onClick={() => { const t = new Date(); setYear(t.getFullYear()); setMonth(t.getMonth()); setDay(null); }}>Today</button>
      </div>
      {events.isPending && <p role="status">Loading events…</p>}
      {events.error && <ErrorNotice error={events.error} retry={() => events.refetch()} />}
      <div className="cal-grid" role="grid" aria-label={monthName}>
        {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => (<span key={d} className="cal-dow">{d}</span>))}
        {cells.map((d, i) => {
          if (!d) return <span key={i} className="cal-empty" />;
          const k = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
          const evs = byDay[k] ?? [];
          const isToday = d.toDateString() === new Date().toDateString();
          return (
            <button type="button" key={i} className={`cal-day${isToday ? " cal-today" : ""}${day === k ? " cal-selected" : ""}`} onClick={() => openDay(d)}>
              <span className="cal-num">{d.getDate()}</span>
              {evs.slice(0, 3).map((r) => (<span key={String(r.id)} className="cal-chip">{text(r.title) || "Untitled"}</span>))}
              {evs.length > 3 && <span className="cal-more">+{evs.length - 3} more</span>}
            </button>
          );
        })}
      </div>
      {day && (
        <section className="cal-day-panel" aria-label="Selected day">
          <h3>{dayRows.length ? `${dayRows.length} event${dayRows.length === 1 ? "" : "s"}` : "No events this day"}</h3>
          {dayRows.length > 0 && (
            <ul className="cal-day-list">
              {dayRows.map((r) => (
                <li key={String(r.id)}>
                  <strong>{text(r.title) || "Untitled"}</strong>
                  <span className="muted"> {timestamp(r.starts_at)}{text(r.ends_at) ? ` – ${timestamp(r.ends_at)}` : ""}{text(r.source) && text(r.source) !== "local" ? ` · from ${text(r.source)}` : ""}</span>
                </li>
              ))}
            </ul>
          )}
          <div className="actions">
            <button onClick={() => { addEvent.reset(); setEventOpen(true); }}>Add event</button>
            <button type="button" className="secondary" onClick={() => setDay(null)}>Close</button>
          </div>
        </section>
      )}
      {eventOpen && (
        <Modal title="Add event" onClose={() => setEventOpen(false)} pending={addEvent.isPending}>
          <form
            className="grid"
            onSubmit={(e) => { e.preventDefault(); addEvent.mutate(); }}
          >
            <Input label="Event title" required value={form.title} maxLength={280} onChange={(e) => setForm({ ...form, title: e.target.value })} placeholder="Dentist" />
            <Input label="Starts" type="datetime-local" required value={form.starts} onChange={(e) => setForm({ ...form, starts: e.target.value })} />
            <Input label="Ends (optional)" type="datetime-local" value={form.ends} onChange={(e) => setForm({ ...form, ends: e.target.value })} />
            <div className="actions">
              <button disabled={addEvent.isPending || !form.title.trim() || !form.starts}>{addEvent.isPending ? "Adding…" : "Add event"}</button>
            </div>
          </form>
          {addEvent.error && <ErrorNotice error={addEvent.error} retry={() => addEvent.reset()} />}
        </Modal>
      )}
      <p>
        <button type="button" className="secondary" onClick={() => setShowFeeds((v) => !v)}>
          {showFeeds ? "Hide feeds" : `Feeds (${items.length})`}
        </button>
      </p>
      {showFeeds && (
        <>
          {!items.length ? (<Empty title="No feeds yet">Add an ICS feed or CalDAV server to pull shared events in.</Empty>) : (
            <table>
              <thead><tr><th scope="col">Name</th><th scope="col">Kind</th><th scope="col">Enabled</th><th scope="col">Actions</th></tr></thead>
              <tbody>
                {items.map((row) => (
                  <tr key={String(row.id)}>
                    <th scope="row">{text(row.name)}</th>
                    <td>{text((row.configuration as RecordData | undefined)?.kind)}</td>
                    <td><Status value={row.enabled} /></td>
                    <td>
                      <div className="actions">
                        <button className="secondary" disabled={sync.isPending} onClick={() => sync.mutate(String(row.id))}>Sync</button>
                        <button className="danger" disabled={removeSource.isPending} onClick={() => removeSource.mutate(String(row.id))}>Remove</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {(sync.error ?? removeSource.error) && (<ErrorNotice error={(sync.error ?? removeSource.error) as Error} retry={() => { sync.reset(); removeSource.reset(); }} />)}
          {adding ? (<NewCalendarSource onDone={() => { setAdding(false); invalidate(); }} />) : (<button className="secondary" onClick={() => setAdding(true)}>Add feed</button>)}
        </>
      )}
    </div>
  );
}
function NewCalendarSource({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({ name: "", kind: "ics", url: "", username: "", password: "" });
  const create = useMutation({ mutationFn: () => post<RecordData>("/calendar/sources", { name: form.name, kind: form.kind, url: form.url, username: form.username || undefined, password: form.password || undefined }), onSuccess: async () => { await client.invalidateQueries({ queryKey: ["calendar-sources"] }); onDone(); } });
  const update = (k: string) => (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <form aria-label="Add calendar" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <Input label="Name" value={form.name} onChange={update("name")} required maxLength={64} />
      <label>Kind<select value={form.kind} onChange={update("kind")}><option value="ics">Public feed (ICS)</option><option value="caldav">Calendar server (CalDAV)</option></select></label>
      <Input label="Feed or server URL" value={form.url} onChange={update("url")} required maxLength={512} placeholder="https://example.invalid/calendar.ics" />
      <Input label="Username (CalDAV only)" value={form.username} onChange={update("username")} maxLength={512} />
      <Input label="Password (CalDAV only)" value={form.password} onChange={update("password")} maxLength={512} />
      {create.error && (<ErrorNotice error={create.error} retry={() => create.reset()} />)}
      <div className="actions"><button type="submit" disabled={create.isPending}>Add calendar</button><button type="button" className="secondary" onClick={onDone}>Cancel</button></div>
    </form>
  );
}
function HaConnections() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const conns = useQuery({ queryKey: ["ha-connections"], queryFn: () => api<{ items: RecordData[] }>("/ha/connections") });
  const states = useQuery({ queryKey: ["ha-states"], queryFn: () => api<{ items: RecordData[] }>("/ha/states") });
  const invalidate = () => { client.invalidateQueries({ queryKey: ["ha-connections"] }); client.invalidateQueries({ queryKey: ["ha-states"] }); };
  const sync = useMutation({ mutationFn: (id: string) => post<RecordData>(`/ha/connections/${id}/sync`), onSuccess: invalidate });
  const removeConn = useMutation({ mutationFn: (id: string) => post(`/ha/connections/${id}/remove`), onSuccess: invalidate });
  if (conns.isPending) return (<div className="panel"><p role="status">Loading Home Assistant…</p></div>);
  if (conns.error) return (<div className="panel"><ErrorNotice error={conns.error} retry={() => conns.refetch()} /></div>);
  const items = conns.data?.items ?? [];
  const rows = states.data?.items ?? [];
  return (
    <div className="panel">
      <h2>Home Assistant</h2>
      <p><small>Orbit polls the states endpoint with a token you paste. The token is stored sealed and never shown again.</small></p>
      {!items.length ? (<Empty title="No Home Assistant yet">Add your Home Assistant address and a long-lived token.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">Address</th><th scope="col">Last sync</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.name)}</th>
                <td>{text(row.base_url)}</td>
                <td>{timestamp(row.last_sync)}</td>
                <td>
                  <div className="actions">
                    <button className="secondary" disabled={sync.isPending} onClick={() => sync.mutate(String(row.id))}>Sync</button>
                    <button className="danger" disabled={removeConn.isPending} onClick={() => removeConn.mutate(String(row.id))}>Remove</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {(sync.error ?? removeConn.error) && (<ErrorNotice error={(sync.error ?? removeConn.error) as Error} retry={() => { sync.reset(); removeConn.reset(); }} />)}
      {adding ? (<NewHaConnection onDone={() => setAdding(false)} />) : (<button className="secondary" onClick={() => setAdding(true)}>Add Home Assistant</button>)}
      <h3>Latest states</h3>
      {!rows.length ? (<Empty title="No states yet">Sync to pull the current states.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Entity</th><th scope="col">State</th><th scope="col">Seen</th></tr></thead>
          <tbody>
            {rows.slice(0, 20).map((row) => (<tr key={String(row.id)}><th scope="row">{text(row.entity_id)}</th><td>{text(row.state)}</td><td>{timestamp(row.observed_at)}</td></tr>))}
          </tbody>
        </table>
      )}
    </div>
  );
}
function NewHaConnection({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({ name: "", base_url: "", token: "" });
  const create = useMutation({ mutationFn: () => post<RecordData>("/ha/connections", form), onSuccess: async () => { await client.invalidateQueries({ queryKey: ["ha-connections"] }); onDone(); } });
  const update = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <form aria-label="Add Home Assistant" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <Input label="Name" value={form.name} onChange={update("name")} required maxLength={64} />
      <Input label="Address" value={form.base_url} onChange={update("base_url")} required maxLength={512} placeholder="http://homeassistant.local:8123" />
      <Input label="Long-lived token" value={form.token} onChange={update("token")} required maxLength={8192} />
      {create.error && (<ErrorNotice error={create.error} retry={() => create.reset()} />)}
      <div className="actions"><button type="submit" disabled={create.isPending}>Add Home Assistant</button><button type="button" className="secondary" onClick={onDone}>Cancel</button></div>
    </form>
  );
}
function GithubConnections() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const conns = useQuery({ queryKey: ["github-connections"], queryFn: () => api<{ items: RecordData[] }>("/github/connections") });
  const invalidate = () => client.invalidateQueries({ queryKey: ["github-connections"] });
  const sync = useMutation({ mutationFn: (id: string) => post<RecordData>(`/github/connections/${id}/sync`), onSuccess: invalidate });
  const removeConn = useMutation({ mutationFn: (id: string) => post(`/github/connections/${id}/remove`), onSuccess: invalidate });
  if (conns.isPending) return (<div className="panel"><p role="status">Loading GitHub…</p></div>);
  if (conns.error) return (<div className="panel"><ErrorNotice error={conns.error} retry={() => conns.refetch()} /></div>);
  const items = conns.data?.items ?? [];
  return (
    <div className="panel">
      <h2>GitHub</h2>
      <p><small>Paste a personal token to read your notifications. The token is stored sealed and never shown again. OAuth sign-in stays unavailable in this build.</small></p>
      <OAuthClientSection connector="github" title="GitHub OAuth client (stored only)" />
      {!items.length ? (<Empty title="No GitHub token yet">Add a personal token to sync notifications.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">Last sync</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => (
              <tr key={String(row.id)}>
                <th scope="row">{text(row.name)}</th>
                <td>{timestamp(row.last_sync)}</td>
                <td>
                  <div className="actions">
                    <button className="secondary" disabled={sync.isPending} onClick={() => sync.mutate(String(row.id))}>Sync</button>
                    <button className="danger" disabled={removeConn.isPending} onClick={() => removeConn.mutate(String(row.id))}>Remove</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {(sync.error ?? removeConn.error) && (<ErrorNotice error={(sync.error ?? removeConn.error) as Error} retry={() => { sync.reset(); removeConn.reset(); }} />)}
      {adding ? (<NewGithubConnection onDone={() => setAdding(false)} />) : (<button className="secondary" onClick={() => setAdding(true)}>Add GitHub token</button>)}
    </div>
  );
}
function NewGithubConnection({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({ name: "", token: "" });
  const create = useMutation({ mutationFn: () => post<RecordData>("/github/connections", form), onSuccess: async () => { await client.invalidateQueries({ queryKey: ["github-connections"] }); onDone(); } });
  const update = (k: string) => (e: React.ChangeEvent<HTMLInputElement>) => setForm((f) => ({ ...f, [k]: e.target.value }));
  return (
    <form aria-label="Add GitHub token" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
      <Input label="Name" value={form.name} onChange={update("name")} required maxLength={64} />
      <Input label="Personal token" value={form.token} onChange={update("token")} required maxLength={8192} />
      {create.error && (<ErrorNotice error={create.error} retry={() => create.reset()} />)}
      <div className="actions"><button type="submit" disabled={create.isPending}>Add GitHub token</button><button type="button" className="secondary" onClick={onDone}>Cancel</button></div>
    </form>
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
function mailSubject(m: RecordData): string {
  const meta = (m.metadata ?? {}) as RecordData;
  return text(meta.subject) || "(no subject)";
}
function mailFrom(m: RecordData): string {
  const meta = (m.metadata ?? {}) as RecordData;
  return text(meta.from) || text(meta.sender) || "Unknown sender";
}
function MailReader({ accounts }: { accounts: RecordData[] }) {
  const [account, setAccount] = useState<string>("");
  const [selected, setSelected] = useState<string | null>(null);
  const list = useQuery({
    queryKey: ["mail-list", account],
    queryFn: () => api<{ items: RecordData[] }>(`/email/messages?limit=50${account ? `&account_id=${account}` : ""}`),
    enabled: accounts.length > 0,
  });
  const detail = useQuery({
    queryKey: ["mail-detail", selected],
    queryFn: () => api<RecordData>(`/email/messages/${selected}`),
    enabled: !!selected,
  });
  if (!accounts.length) return null;
  const items = list.data?.items ?? [];
  const row = detail.data ?? null;
  const rowMeta = row ? ((row.metadata ?? {}) as RecordData & { to?: unknown }) : null;
  const attachments = Array.isArray(row?.attachments) ? (row.attachments as RecordData[]) : [];
  return (
    <section className="mail-shell" aria-label="Inbox">
      <div className="mail-toolbar">
        <Select label="Account" value={account} onChange={(e) => { setAccount(e.target.value); setSelected(null); }}>
          <option value="">All accounts</option>
          {accounts.map((a) => (<option key={String(a.id)} value={String(a.id)}>{text(a.name)}</option>))}
        </Select>
      </div>
      <div className="mail-panes">
        <aside className="mail-list" aria-label="Messages">
          {list.isPending && <p role="status">Loading mail…</p>}
          {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
          {list.data && items.length === 0 && (
            <Empty title="Inbox zero — or never synced">Hit Sync on the account above, then come back.</Empty>
          )}
          <ul>
            {items.map((m) => {
              const id = String(m.id);
              return (
                <li key={id}>
                  <button type="button" className={selected === id ? "mail-active" : ""} onClick={() => setSelected(id)}>
                    <span className="mail-subject">{mailSubject(m)}</span>
                    <span className="mail-meta">{mailFrom(m)} · {text(m.mailbox)} · {timestamp(m.received_at)}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        </aside>
        <article className="mail-reader" aria-label={row ? "Message" : "No message selected"}>
          {!selected ? (
            <Empty title="Pick a message">The reading pane lives here — plain text only, never remote images.</Empty>
          ) : detail.isPending ? (
            <p role="status">Loading message…</p>
          ) : detail.error ? (
            <ErrorNotice error={detail.error} retry={() => detail.refetch()} />
          ) : row ? (
            <>
              <h3>{mailSubject(row)}</h3>
              <p className="muted">
                From {mailFrom(row)} · {timestamp(row.received_at)} · {text(row.mailbox)}
                {text(row.trust_level) && text(row.trust_level) !== "OWNER_AUTHENTICATED" && (<> · <Status value={row.trust_level} /></>)}
              </p>
              {rowMeta && text(rowMeta.to) && <p className="muted">To {text(rowMeta.to)}</p>}
              <pre className="mail-body">{text(row.body_text) || "(empty body)"}</pre>
              {attachments.length > 0 && (
                <ul className="mail-attachments">
                  {attachments.map((a, i) => (<li key={i}>{text(a.name)} · {text(a.mime)}</li>))}
                </ul>
              )}
            </>
          ) : null}
        </article>
      </div>
    </section>
  );
}

function Email() {
  const client = useQueryClient();
  const [adding, setAdding] = useState(false);
  const [confirm, setConfirm] = useState<{ kind: "revoke" | "purge"; id: string; name: string } | null>(null);
  const accounts = useQuery({ queryKey: ["email-accounts"], queryFn: () => api<{ items: RecordData[] }>("/email/accounts") });
  const checkpoints = useQuery({ queryKey: ["email-checkpoints"], queryFn: () => api<{ items: RecordData[] }>("/email/checkpoints") });
  const invalidate = () => { client.invalidateQueries({ queryKey: ["email-accounts"] }); client.invalidateQueries({ queryKey: ["email-checkpoints"] }); };
  const run = useMutation({ mutationFn: ({ id, action }: { id: string; action: "test" | "sync" }) => post<RecordData>(`/email/accounts/${id}/${action}`), onSuccess: invalidate });
  const toggle = useMutation({ mutationFn: (row: RecordData) => api<RecordData>(`/email/accounts/${String(row.id)}`, { method: "PATCH", body: JSON.stringify({ enabled: !(row.enabled as boolean), expected_revision: row.revision as number }) }), onSuccess: invalidate });
  const removeAccount = useMutation({ mutationFn: (id: string) => remove(`/email/accounts/${id}`), onSuccess: invalidate });
  const purgeAccount = useMutation({ mutationFn: (id: string) => remove(`/email/accounts/${id}/purge`), onSuccess: invalidate });
  if (accounts.isPending) return (<div className="panel"><p role="status">Loading accounts…</p></div>);
  if (accounts.error) return (<div className="panel"><ErrorNotice error={accounts.error} retry={() => accounts.refetch()} /></div>);
  const items = accounts.data?.items ?? [];
  const points = checkpoints.data?.items ?? [];
  const error = run.error ?? toggle.error ?? removeAccount.error ?? purgeAccount.error ?? checkpoints.error;
  const busy = run.isPending || toggle.isPending || removeAccount.isPending || purgeAccount.isPending;
  const checkpointSummary = (id: string) => {
    const rows = points.filter((p) => String(p.account_id) === id);
    if (checkpoints.isPending) return "Loading…";
    if (!rows.length) return "Never synced";
    const high = Math.max(...rows.map((p) => Number(p.last_uid ?? 0)));
    return `${rows.length} mailbox${rows.length === 1 ? "" : "es"} · highest UID ${Number.isFinite(high) ? high : 0}`;
  };
  const pending = confirm?.kind === "revoke" ? removeAccount.isPending : purgeAccount.isPending;
  return (
    <div className="panel">
      <h2>Email</h2>
      <p><small>Orbit polls the mailboxes you name and can draft replies. Sending still needs your approval. Pausing stops polling; revoking disconnects but keeps stored mail; purging deletes the account and its stored messages and drafts.</small></p>
      {!items.length ? (<Empty title="No mail accounts yet">Add an IMAP and SMTP pair to let Orbit read and draft mail.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">From</th><th scope="col">Scopes (mailboxes)</th><th scope="col">Enabled</th><th scope="col">Last sync</th><th scope="col">Checkpoints</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => {
              const config = (row.config ?? {}) as RecordData;
              const mailboxes = Array.isArray(config.mailboxes) ? (config.mailboxes as unknown[]).map(text) : [];
              const id = String(row.id);
              return (
                <tr key={id}>
                  <th scope="row">{text(row.name)}</th>
                  <td>{text(config.from_address)}</td>
                  <td>{mailboxes.length ? mailboxes.join(", ") : "—"}</td>
                  <td><Status value={row.enabled} /></td>
                  <td>{timestamp(row.last_sync)}</td>
                  <td><small>{checkpointSummary(id)}</small></td>
                  <td>
                    <div className="actions">
                      <button className="secondary" disabled={busy} onClick={() => run.mutate({ id, action: "test" })}>Test</button>
                      <button className="secondary" disabled={busy} onClick={() => run.mutate({ id, action: "sync" })}>Sync</button>
                      <button className="secondary" disabled={busy} onClick={() => toggle.mutate(row)}>{row.enabled ? "Pause" : "Resume"}</button>
                      <button className="danger" disabled={busy} onClick={() => setConfirm({ kind: "revoke", id, name: text(row.name) })}>Revoke</button>
                      <button className="danger" disabled={busy} onClick={() => setConfirm({ kind: "purge", id, name: text(row.name) })}>Purge</button>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {error && (<ErrorNotice error={error} retry={() => { run.reset(); toggle.reset(); removeAccount.reset(); purgeAccount.reset(); checkpoints.refetch(); }} />)}
      {confirm && (
        <Confirm title={confirm.kind === "revoke" ? `Revoke ${confirm.name || "this mail account"}?` : `Purge ${confirm.name || "this mail account"} and its stored mail?`} action={confirm.kind === "revoke" ? "Revoke" : "Purge"} pending={pending} onClose={() => setConfirm(null)} onConfirm={() => { (confirm.kind === "revoke" ? removeAccount : purgeAccount).mutate(confirm.id); setConfirm(null); }}>
          {confirm.kind === "revoke" ? (<p>Orbit stops polling these mailboxes and disconnects its credentials. Stored messages and drafts are kept.</p>) : (<p>This deletes the account plus its stored messages and drafts. This cannot be undone.</p>)}
        </Confirm>
      )}
      {adding ? (<NewEmailAccount onDone={() => setAdding(false)} />) : (<button className="secondary" onClick={() => setAdding(true)}>Add mail account</button>)}
      <MailReader accounts={items} />
      <TriageRules />
    </div>
  );
}
/// Inbox triage: substring rules that label incoming mail and queue a summary
/// task. Drafts are never sent — a summary task only prepares text the owner
/// approves through the normal drafts flow.
function TriageRules() {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", from: "", subject: "", label: "", summarize: true });
  const rules = useQuery({ queryKey: ["triage-rules"], queryFn: () => api<{ items: RecordData[] }>("/email/triage-rules") });
  const invalidate = () => client.invalidateQueries({ queryKey: ["triage-rules"] });
  const create = useMutation({
    mutationFn: () => post<RecordData>("/email/triage-rules", {
      name: form.name,
      matcher: { ...(form.from ? { from_contains: form.from } : {}), ...(form.subject ? { subject_contains: form.subject } : {}) },
      action: { ...(form.label ? { label: form.label } : {}), summarize: form.summarize },
    }),
    onSuccess: () => { invalidate(); setOpen(false); setForm({ name: "", from: "", subject: "", label: "", summarize: true }); },
  });
  const toggle = useMutation({
    mutationFn: (row: RecordData) => api<RecordData>(`/email/triage-rules/${String(row.id)}`, { method: "PATCH", body: JSON.stringify({ enabled: !(row.enabled as boolean) }) }),
    onSuccess: invalidate,
  });
  const removeRule = useMutation({ mutationFn: (id: string) => remove(`/email/triage-rules/${id}`), onSuccess: invalidate });
  const items = rules.data?.items ?? [];
  return (
    <section aria-label="Inbox triage rules">
      <h3>Sort incoming mail for me</h3>
      <p><small>The first matching rule wins. Matches label the stored message and queue a summary for you — drafts are never sent without your approval.</small></p>
      {rules.isPending ? (<p role="status">Loading rules…</p>) : items.length === 0 ? (<Empty title="No triage rules">Add one below — e.g. subject contains “invoice” → label “bills”.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">When</th><th scope="col">Then</th><th scope="col">On</th><th scope="col">Actions</th></tr></thead>
          <tbody>
            {items.map((row) => {
              const matcher = (row.matcher ?? {}) as RecordData;
              const action = (row.action ?? {}) as RecordData;
              const when = [matcher.from_contains ? `from “${text(matcher.from_contains)}”` : "", matcher.subject_contains ? `subject “${text(matcher.subject_contains)}”` : "", matcher.topic ? `topic “${text(matcher.topic)}”` : ""].filter(Boolean).join(" + ") || "—";
              const then = [action.label ? `label “${text(action.label)}”` : "", action.summarize ? "summarize" : "", action.draft_reply ? "draft reply" : ""].filter(Boolean).join(" + ") || "—";
              return (
                <tr key={String(row.id)}>
                  <th scope="row">{text(row.name)}</th>
                  <td><small>{when}</small></td>
                  <td><small>{then}</small></td>
                  <td><Status value={row.enabled} /></td>
                  <td><div className="actions">
                    <button className="secondary" disabled={toggle.isPending} onClick={() => toggle.mutate(row)}>{row.enabled ? "Pause" : "Resume"}</button>
                    <button className="danger" disabled={removeRule.isPending} onClick={() => removeRule.mutate(String(row.id))}>Delete</button>
                  </div></td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
      {(rules.error ?? create.error ?? toggle.error ?? removeRule.error) && (<ErrorNotice error={(rules.error ?? create.error ?? toggle.error ?? removeRule.error) as Error} retry={() => { rules.refetch(); create.reset(); toggle.reset(); removeRule.reset(); }} />)}
      {open ? (
        <form className="grid" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
          <Input label="Rule name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Bills" />
          <Input label="From contains" value={form.from} onChange={(e) => setForm({ ...form, from: e.target.value })} placeholder="billing@" />
          <Input label="Subject contains" value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} placeholder="invoice" />
          <Input label="Label to apply" value={form.label} onChange={(e) => setForm({ ...form, label: e.target.value })} placeholder="bills" />
          <label className="check"><input type="checkbox" checked={form.summarize} onChange={(e) => setForm({ ...form, summarize: e.target.checked })} /> Queue a summary task for me</label>
          <div className="actions">
            <button className="secondary" type="submit" disabled={create.isPending || (!form.from && !form.subject)}>{create.isPending ? "Adding…" : "Add rule"}</button>
            <button className="secondary" type="button" onClick={() => setOpen(false)}>Cancel</button>
          </div>
        </form>
      ) : (<button className="secondary" onClick={() => setOpen(true)}>Add triage rule</button>)}
    </section>
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

function computerAge(lastSeen: unknown) {
  const seen = new Date(text(lastSeen));
  if (Number.isNaN(seen.getTime())) return "never seen";
  const minutes = Math.max(0, Math.round((Date.now() - seen.getTime()) / 60000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? "" : "s"} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? "" : "s"} ago`;
  const days = Math.round(hours / 24);
  return `${days} day${days === 1 ? "" : "s"} ago`;
}
export function Computers() {
  const client = useQueryClient();
  const nodes = useQuery({
    queryKey: ["computers-tab"],
    queryFn: () => api<{ items: RecordData[] }>("/computers/tab"),
  });
  const invalidate = () =>
    client.invalidateQueries({ queryKey: ["computers-tab"] });
  const pairing = useMutation({
    mutationFn: () => post<RecordData>("/computers/pairing-codes"),
  });
  const revoke = useMutation({
    mutationFn: (id: string) => post<RecordData>(`/computers/${id}/revoke`),
    onSuccess: invalidate,
  });
  const items = nodes.data?.items ?? [];
  const [pairedCodeId, setPairedCodeId] = useState("");
  const [pairedCount, setPairedCount] = useState<number | null>(null);
  const [copied, setCopied] = useState("");
  const [sharePath, setSharePath] = useState("");
  const code = text(pairing.data?.code ?? "");
  const codeId = text(pairing.data?.id ?? "");
  const origin = typeof window === "undefined" ? "" : window.location.origin;
  const daemonCommand = code
    ? `orbit-computer-node pair --server ${origin} --code ${code}`
    : "";
  const fresh = pairedCount === null ? [] : items.slice(pairedCount);
  const freshLive = fresh.find((row) => Boolean(row.live)) ?? null;
  const shareTarget = sharePath.trim() || "Documents";
  const shareArg =
    shareTarget.startsWith("/") || shareTarget.startsWith("~")
      ? shareTarget
      : `~/${shareTarget}`;
  const shareCommand = `orbit-computer-node roots add ${shareArg}`;
  const copyText = async (value: string, which: string) => {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
      setCopied(which);
    } catch {
      setCopied(`failed:${which}`);
    }
  };
  useEffect(() => {
    if (pairing.data && pairedCodeId !== codeId) {
      setPairedCodeId(codeId);
      setPairedCount(items.length);
      setCopied("");
    }
  }, [pairing.data, codeId, pairedCodeId, items.length]);
  useEffect(() => {
    if (!pairing.data || freshLive) return;
    const timer = setInterval(() => {
      void client.invalidateQueries({ queryKey: ["computers-tab"] });
    }, 4000);
    return () => clearInterval(timer);
  }, [pairing.data, freshLive, client]);
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
                <th scope="col">Status</th>
                <th scope="col">Last seen</th>
                <th scope="col">System</th>
                <th scope="col">Agent</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={String(row.id)}>
                  <th scope="row">{text(row.display_name)}</th>
                  <td>
                    {row.live ? (
                      <span className="status good">Live</span>
                    ) : (
                      <span className="status bad">Dead</span>
                    )}
                  </td>
                  <td>{computerAge(row.last_seen)}</td>
                  <td>
                    {[text(row.os), text(row.arch)].filter(Boolean).join(" · ") || "—"}
                  </td>
                  <td>{text(row.version) || "—"}</td>
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
        <h2>Pair this machine</h2>
        <p>
          <small>
            Codes are one-use and expire after ten minutes. The node presents
            the code over verified TLS when it enrols.
          </small>
        </p>
        {pairing.data ? (
          <div>
            <p>
              Pairing code: <strong>{code}</strong>{" "}
              <button
                type="button"
                className="secondary"
                onClick={() => void copyText(code, "code")}
              >
                {copied === "code" ? "Copied" : "Copy code"}
              </button>
            </p>
            <p>
              <small>
                Expires in {text(pairing.data.expires_in_seconds)} seconds.
                Creating another code invalidates this one.
              </small>
            </p>
            <p>On the machine, run this one command:</p>
            <p>
              <code>{daemonCommand}</code>{" "}
              <button
                type="button"
                className="secondary"
                onClick={() => void copyText(daemonCommand, "command")}
              >
                {copied === "command" ? "Copied" : "Copy command"}
              </button>
            </p>
            {copied.startsWith("failed:") && (
              <p role="status">
                <small>
                  Copy did not work in this browser — select the text and copy
                  it by hand.
                </small>
              </p>
            )}
            {freshLive ? (
              <div>
                <p role="status">
                  {text(freshLive.display_name)} is paired and live.
                </p>
                <Input
                  label="Folder to share (relative path)"
                  placeholder="Documents"
                  value={sharePath}
                  onChange={(e) => setSharePath(e.target.value)}
                />
                <p>
                  <small>
                    Sharing stays read-only unless you pick otherwise on the
                    machine. Nothing is shared until you run the command below
                    there.
                  </small>
                </p>
                <p>On the machine, share the folder:</p>
                <p>
                  <code>{shareCommand}</code>{" "}
                  <button
                    type="button"
                    className="secondary"
                    onClick={() => void copyText(shareCommand, "share")}
                  >
                    {copied === "share" ? "Copied" : "Copy command"}
                  </button>
                </p>
                <div className="actions">
                  <button
                    type="button"
                    className="secondary"
                    disabled={pairing.isPending}
                    onClick={() => pairing.mutate()}
                  >
                    Pair another machine
                  </button>
                </div>
              </div>
            ) : (
              <p role="status">
                <small>
                  Waiting for the machine to pair… this list updates on its
                  own once the node enrols.
                </small>
              </p>
            )}
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
              try { localStorage.setItem("orbit.files.context", JSON.stringify({ node_id: nodeId, root_id: rootId })); } catch { /* private mode: header files search stays memory-only */ }
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
      <StoredFiles />
      <Documents />
    </>
  );
}
function Documents() {
  const client = useQueryClient();
  const uploads = useQuery({ queryKey: ["uploads"], queryFn: () => api<{ items: RecordData[] }>("/uploads") });
  const [file, setFile] = useState<File | null>(null);
  const send = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose a PDF first.");
      const buf = await file.arrayBuffer();
      const res = await fetch(`/api/v1/uploads?${new URLSearchParams({ filename: file.name })}`, { method: "POST", body: buf, headers: { "Content-Type": "application/pdf" }, credentials: "same-origin" });
      if (!res.ok) throw new Error(`Upload failed (${res.status}).`);
      return res.json() as Promise<RecordData>;
    },
    onSuccess: () => { setFile(null); client.invalidateQueries({ queryKey: ["uploads"] }); },
  });
  const items = uploads.data?.items ?? [];
  return (
    <div className="panel">
      <h2>Documents</h2>
      <p><small>PDFs only, up to 50 MB. Orbit stores the original bytes and indexes the text so memory can find it. Anything else is rejected.</small></p>
      {uploads.error ? (<ErrorNotice error={uploads.error} retry={() => uploads.refetch()} />) : !items.length ? (<Empty title="No documents yet">Upload a PDF to make it searchable.</Empty>) : (
        <table>
          <thead><tr><th scope="col">Name</th><th scope="col">Size</th><th scope="col">Added</th></tr></thead>
          <tbody>
            {items.map((row) => (<tr key={String(row.id)}><th scope="row">{text(row.name)}</th><td>{text(row.size)}</td><td>{timestamp(row.created_at)}</td></tr>))}
          </tbody>
        </table>
      )}
      <form aria-label="Upload document" onSubmit={(e) => { e.preventDefault(); send.mutate(); }}>
        <label>PDF<input type="file" accept="application/pdf,.pdf" onChange={(e) => setFile(e.target.files?.[0] ?? null)} /></label>
        {send.error && (<ErrorNotice error={send.error} retry={() => send.reset()} />)}
        {send.data && (<p role="status"><small>Stored {text((send.data as RecordData).name)} — {text((send.data as RecordData).chars)} characters indexed.</small></p>)}
        <div className="actions"><button type="submit" disabled={!file || send.isPending}>Upload PDF</button></div>
      </form>
    </div>
  );
}
export function HomeAssistant() {
  const client = useQueryClient();
  const [connectionId, setConnectionId] = useState("");
  const entities = useQuery({
    queryKey: ["ha-entities"],
    queryFn: () => api<{ items: RecordData[] }>("/ha/entities?limit=100"),
  });
  const conns = useQuery({
    queryKey: ["ha-connections"],
    queryFn: () => api<{ items: RecordData[] }>("/ha/connections"),
  });
  const sync = useMutation({
    mutationFn: () =>
      post<RecordData>("/ha/sync", { connection_id: connectionId }),
    onSuccess: () => {
      client.invalidateQueries({ queryKey: ["ha-entities"] });
    },
  });
  const items = entities.data?.items ?? [];
  const options = conns.data?.items ?? [];
  return (
    <>
      <PageHeader
        title="Home Assistant"
        description="Devices and sensors from your home."
      />
      <div className="panel">
        <h2>Sync states</h2>
        <p>
          <small>
            Pick the connection to pull fresh states from. States arrive
            marked untrusted, and Orbit never switches anything on or off
            without your approval.
          </small>
        </p>
        {conns.isPending ? (
          <p role="status">Loading connections…</p>
        ) : conns.error ? (
          <ErrorNotice error={conns.error} retry={() => conns.refetch()} />
        ) : !options.length ? (
          <Empty title="No Home Assistant connection yet">
            Add one under Connections, then sync here.
          </Empty>
        ) : (
          <form
            onSubmit={(event) => {
              event.preventDefault();
              sync.mutate();
            }}
          >
            <Select
              label="Connection"
              required
              value={connectionId}
              onChange={(e) => setConnectionId(e.target.value)}
            >
              <option value="">Choose a connection…</option>
              {options.map((row) => (
                <option key={String(row.id)} value={String(row.id)}>
                  {text(row.name) || text(row.base_url)}
                </option>
              ))}
            </Select>
            <div className="actions">
              <button type="submit" disabled={!connectionId || sync.isPending}>
                {sync.isPending ? "Syncing…" : "Sync now"}
              </button>
            </div>
          </form>
        )}
        {sync.error && (
          <ErrorNotice error={sync.error} retry={() => sync.reset()} />
        )}
        {sync.data && (
          <p role="status">Synced — stored {text(sync.data.stored)} states.</p>
        )}
      </div>
      <div className="panel">
        <h2>Entities</h2>
        {entities.isPending ? (
          <p role="status">Loading entities…</p>
        ) : entities.error ? (
          <ErrorNotice error={entities.error} retry={() => entities.refetch()} />
        ) : !items.length ? (
          <Empty title="No entities yet">
            Sync a connection above to pull the current states.
          </Empty>
        ) : (
          <table>
            <thead>
              <tr>
                <th scope="col">Entity</th>
                <th scope="col">State</th>
                <th scope="col">Last seen</th>
                <th scope="col">Source</th>
              </tr>
            </thead>
            <tbody>
              {items.map((row) => (
                <tr key={String(row.id)}>
                  <th scope="row">{text(row.entity_id)}</th>
                  <td>{text(row.state)}</td>
                  <td>{timestamp(row.last_seen)}</td>
                  <td>
                    <span className="status pending">Untrusted</span>{" "}
                    <small>{label(row.trust_level)}</small>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </>
  );
}
function fileIcon(mime: string): string {
  if (mime.startsWith("image/")) return "🖼";
  if (mime.startsWith("video/")) return "🎬";
  if (mime.startsWith("audio/")) return "🎵";
  if (mime === "application/pdf") return "📕";
  if (mime.startsWith("text/")) return "📄";
  return "📦";
}
function fileSize(n: unknown): string {
  const v = Number(n ?? 0);
  if (!Number.isFinite(v) || v <= 0) return "—";
  if (v < 1024) return `${v} B`;
  if (v < 1048576) return `${(v / 1024).toFixed(1)} KB`;
  return `${(v / 1048576).toFixed(1)} MB`;
}
function StoredFiles() {
  const client = useQueryClient();
  const [kind, setKind] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [notice, setNotice] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const stored = useQuery({
    queryKey: ["stored-files", kind],
    queryFn: () =>
      api<{ items: RecordData[] }>(
        `/files${kind ? `?kind=${encodeURIComponent(kind)}` : ""}`,
      ),
  });
  const send = useMutation({
    mutationFn: (picked: File) => {
      const form = new FormData();
      form.append("file", picked, picked.name);
      return api<RecordData>(
        `/files/import?filename=${encodeURIComponent(picked.name || "upload.bin")}`,
        { method: "POST", body: form },
      );
    },
    onSuccess: (data) => {
      setFile(null);
      setNotice(
        data.quarantined
          ? `Stored ${text(data.name)} — held for review as untrusted content.`
          : `Stored ${text(data.name)}.`,
      );
      client.invalidateQueries({ queryKey: ["stored-files"] });
    },
  });
  const preview = useQuery({
    queryKey: ["file-preview", selected],
    queryFn: () => api<RecordData>(`/files/${selected}`),
    enabled: !!selected,
  });
  const items = stored.data?.items ?? [];
  const row = preview.data ?? items.find((r) => String(r.id) === selected) ?? null;
  const folders: [string, string][] = [
    ["", "Everything"],
    ["image/", "Images"],
    ["video/", "Video"],
    ["audio/", "Audio"],
    ["text/", "Text"],
    ["application/pdf", "PDFs"],
  ];
  return (
    <div className="panel">
      <h2>Stored files</h2>
      <p>
        <small>
          Anything you import here is treated as untrusted. Orbit reads it
          when you ask, and anything that looks like an instruction to the
          assistant is held for review first.
        </small>
      </p>
      <form
        aria-label="Import file"
        onSubmit={(event) => {
          event.preventDefault();
          if (file) {
            setNotice("");
            send.mutate(file);
          }
        }}
      >
        <Input
          label="File to import"
          type="file"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
        />
        {send.error && (
          <ErrorNotice error={send.error} retry={() => send.reset()} />
        )}
        {notice && <p role="status">{notice}</p>}
        <div className="actions">
          <button type="submit" disabled={!file || send.isPending}>
            {send.isPending ? "Importing…" : "Import file"}
          </button>
        </div>
      </form>
      <div className="memory-folders" role="group" aria-label="Filter by kind">
        {folders.map(([v, label]) => (
          <button
            type="button"
            key={v || "all"}
            className={kind === v ? "memory-folder-active" : ""}
            onClick={() => { setKind(v); setSelected(null); }}
          >
            {label}
          </button>
        ))}
      </div>
      {stored.isPending ? (
        <p role="status">Loading stored files…</p>
      ) : stored.error ? (
        <ErrorNotice error={stored.error} retry={() => stored.refetch()} />
      ) : !items.length ? (
        <Empty title="No stored files yet">
          Import a file above to keep it with your Orbit.
        </Empty>
      ) : (
        <div className="notes-shell">
          <ul className="memory-files" aria-label="Files">
            {items.map((r) => {
              const id = String(r.id);
              const mime = String(r.mime_type ?? "");
              return (
                <li key={id}>
                  <button
                    type="button"
                    className={selected === id ? "notes-active" : ""}
                    onClick={() => setSelected(id)}
                    style={{ width: "100%", textAlign: "left", background: "none", border: "1px solid transparent", borderRadius: "8px", padding: "8px 10px", cursor: "pointer", color: "inherit" }}
                  >
                    <span className="notes-item-title">{fileIcon(mime)} {text(r.name)}</span>
                    <span className="notes-item-meta">
                      {fileSize(r.size)} · {r.quarantined ? "Held for review" : "Clear"} · {timestamp(r.created_at)}
                    </span>
                  </button>
                </li>
              );
            })}
          </ul>
          <section className="panel form" aria-label={row ? "File detail" : "No file selected"}>
            {!row ? (
              <Empty title="Pick a file">Details and preview live here.</Empty>
            ) : (
              <>
                <h3>{text(row.name)}</h3>
                <p className="muted">
                  {text(row.mime_type)} · {fileSize(row.size)} · {timestamp(row.created_at)}
                  {" · "}{row.quarantined ? "Held for review" : "Clear"} {label(row.trust_level)}
                </p>
                {String(row.mime_type ?? "").startsWith("image/") && (
                  <img loading="lazy" src={`/api/v1/files/${row.id}/content`} alt={text(row.name) || "Stored image"} style={{ maxWidth: "100%", borderRadius: "8px" }} />
                )}
                {preview.isPending && <p role="status">Loading detail…</p>}
                {preview.error && <ErrorNotice error={preview.error} retry={() => preview.refetch()} />}
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
