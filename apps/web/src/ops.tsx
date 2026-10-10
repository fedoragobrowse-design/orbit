import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post, text } from "./api";
import { Empty, ErrorNotice, Input, Json, PageHeader } from "./ui";
type Status = { frozen: boolean };
type Dry = { enabled: boolean; trigger: unknown; preview: { next_run: string | null; missed_would_coalesce: number }; would_dispatch: { consumer: string; task_title: string; checkpoint_phase: string } };
type FileHit = { name: string; path: string; size: number };
export function Ops() {
 const client = useQueryClient();
 const status = useQuery({ queryKey: ["ops", "status"], queryFn: () => api<Status>("/ops/status") });
 const [aid, setAid] = useState("");const [dry, setDry] = useState<Dry | null>(null);
 const [artifact, setArtifact] = useState("");const [made, setMade] = useState<{ artifact_id: string; byte_size: number; chunks: number } | null>(null);
 const [note, setNote] = useState("");
 const twist = useMutation({
  mutationFn: (frozen: boolean) => post<Status>(frozen ? "/ops/resume" : "/ops/kill"),
  onSuccess: () => { client.invalidateQueries({ queryKey: ["ops", "status"] });setNote(""); },
 });
 const snap = useMutation({
  mutationFn: () => post<{ artifact_id: string; byte_size: number; chunks: number }>("/ops/backup"),
  onSuccess: (r) => { setMade(r);setNote(""); },
 });
 const heal = useMutation({
  mutationFn: () => post<{ restored: string }>("/ops/restore", { artifact_id: artifact }),
  onSuccess: (r) => { setNote(`Restored ${r.restored}.`);setArtifact(""); },
 });
 const preview = useMutation({
  mutationFn: () => api<Dry>(`/automations/${aid}/dry-run`, { method: "POST" }),
  onSuccess: (r) => setDry(r),
 });
 const frozen = status.data?.frozen ?? false;
 const fail = twist.error ?? snap.error ?? heal.error ?? preview.error ?? null;
 return <>
  <PageHeader title="Ops" description="Kill switch, dry runs and encrypted backups." />
  {status.isPending && <p role="status">Loading…</p>}
  {status.error && <ErrorNotice error={status.error} retry={() => status.refetch()} />}
  {fail && <ErrorNotice error={fail} />}
  {note && <p role="status">{note}</p>}
  {status.data && <>
   <section className="panel">
    <h2>{frozen ? "Read-only mode engaged" : "System writable"}</h2>
    <p>{frozen ? "Guarded mutations reject with 403. Reads stay open." : "Mutations allowed."}</p>
    <div className="actions">
     <button className={frozen ? undefined : "danger"} disabled={twist.isPending} onClick={() => twist.mutate(frozen)}>
      {frozen ? "Resume writes" : "Engage kill switch"}
     </button>
    </div>
   </section>
   <section className="panel">
    <h2>Automation dry-run</h2>
    <form onSubmit={(e) => { e.preventDefault();if (aid) preview.mutate(); }}>
     <Input label="Automation id" value={aid} onChange={(e) => setAid(e.target.value)} placeholder="automation id" />
     <div className="actions"><button className="secondary" disabled={preview.isPending}>Dry-run</button></div>
    </form>
    {dry && <Json value={{ enabled: dry.enabled, next_run: dry.preview.next_run, missed_would_coalesce: dry.preview.missed_would_coalesce, would_dispatch: dry.would_dispatch }} />}
   </section>
   <section className="panel">
    <h2>Encrypted backup</h2>
    <div className="actions"><button className="secondary" disabled={snap.isPending} onClick={() => snap.mutate()}>Take backup</button></div>
    {made && <p>Artifact <code>{made.artifact_id}</code> · {made.byte_size} bytes in {made.chunks} chunk(s).</p>}
    <form onSubmit={(e) => { e.preventDefault();if (artifact) heal.mutate(); }}>
     <Input label="Artifact id to restore" value={artifact} onChange={(e) => setArtifact(e.target.value)} placeholder="artifact id" />
     <div className="actions"><button className="secondary" disabled={heal.isPending}>Restore</button></div>
    </form>
   </section>
  </>}
 </>;
}
/// Global search box: one POST to /api/v1/search returns memory, tasks,
/// events, notifications and mail; files search when the Files page has
/// recorded a browse context (node + root) in localStorage.
type Row = Record<string, unknown>;
type Envelope = { memory: Row[]; tasks: Row[]; events: Row[]; notifications: Row[]; mail: Row[]; files_note: string };
export function GlobalSearch() {
 const [q, setQ] = useState("");const [hits, setHits] = useState<Envelope | null>(null);const [files, setFiles] = useState<FileHit[] | null>(null);const [hint, setHint] = useState("");
 async function run() {
  setHint("");setFiles(null);
  try { setHits(await api<Envelope>("/search", { method: "POST", body: JSON.stringify({ query: q, limit: 12 }) })); } catch { setHits({ memory: [], tasks: [], events: [], notifications: [], mail: [], files_note: "" }); }
  const raw = localStorage.getItem("orbit.files.context");
  if (!raw) return;
  try {
   const c = JSON.parse(raw) as { node_id: string; root_id: string };
   const r = await api<{ results: FileHit[] }>(`/computers/${c.node_id}/files/search?root_ids=${encodeURIComponent(c.root_id)}&query=${encodeURIComponent(q)}&limit=12`);
   setFiles(r.results);
  } catch { setHint("Files search unavailable for the saved computer."); }
 }
 return <div className="search">
  <form className="row" onSubmit={(e) => { e.preventDefault();if (q) run(); }}>
   <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search memory, tasks, mail…" aria-label="Global search" />
   <button className="secondary" type="submit">Search</button>
  </form>
  {hits && <>
   {hits.memory.length > 0 && <div className="list"><p><small>Memory</small></p>{hits.memory.map((m, i) => <div className="row" key={text(m.id) || `m${i}`}><span>{text(m.type)} · {text(m.subject)}</span></div>)}</div>}
   {hits.tasks.length > 0 && <div className="list"><p><small>Tasks</small></p>{hits.tasks.map((t, i) => <div className="row" key={text(t.id) || `t${i}`}><span>{text(t.title)}</span><code>{text(t.state)}</code></div>)}</div>}
   {hits.mail.length > 0 && <div className="list"><p><small>Mail</small></p>{hits.mail.map((m, i) => <div className="row" key={text(m.id) || `e${i}`}><code>{text(m.metadata).slice(0, 80)}</code></div>)}</div>}
   {hits.events.length > 0 && <div className="list"><p><small>Events</small></p>{hits.events.map((v, i) => <div className="row" key={text(v.id) || `v${i}`}><span>{text(v.event_type)}</span></div>)}</div>}
   {hits.notifications.length > 0 && <div className="list"><p><small>Notifications</small></p>{hits.notifications.map((n, i) => <div className="row" key={text(n.id) || `n${i}`}><span>{text(n.title)}</span></div>)}</div>}
   {hits.memory.length + hits.tasks.length + hits.mail.length + hits.events.length + hits.notifications.length === 0 && <Empty title="No hits">Try different words.</Empty>}
   {hits.files_note && !localStorage.getItem("orbit.files.context") && <p><small>{hits.files_note}</small></p>}
  </>}
  {files && <div className="list">{files.length === 0 ? <Empty title="No file hits">Try different words.</Empty> : files.map((f) => <div className="row" key={f.path}><span>{text(f.name)}</span><code>{text(f.path)}</code></div>)}</div>}
  {hint && <p><small>{hint}</small></p>}
 </div>;
}
