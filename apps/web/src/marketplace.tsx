import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Package, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, post, remove, text, timestamp, type RecordData } from "./api";
import { Confirm, Empty, ErrorNotice, Field, Json, PageHeader, Status } from "./ui";
type Preview = { manifest: RecordData; digest_valid: boolean; signature_valid: boolean; capabilities: RecordData; over_broad: string[]; index_source: string };
function Capabilities({ caps }: { caps: RecordData }) {
  const net = (caps.network ?? {}) as RecordData;
  const fs = (caps.filesystem ?? {}) as RecordData;
  const hosts = Array.isArray(net.hosts) ? (net.hosts as unknown[]).map(String) : [];
  const scopes = Array.isArray(fs.scopes) ? (fs.scopes as unknown[]).map(String) : [];
  const secrets = Array.isArray(caps.secrets) ? (caps.secrets as unknown[]).map(String) : [];
  const tools = Array.isArray(caps.tools) ? (caps.tools as unknown[]).map(String) : [];
  return (
    <dl className="caps">
      <div><dt>Network egress</dt><dd>{net.egress ? `yes — ${hosts.join(", ") || "unbounded"}` : "none"}</dd></div>
      <div><dt>Filesystem</dt><dd>{scopes.join(", ") || "—"}{fs.read_only === false ? " (writable)" : " (read-only)"}</dd></div>
      <div><dt>Secrets</dt><dd>{secrets.join(", ") || "none"}</dd></div>
      <div><dt>Host tools</dt><dd>{tools.join(", ") || "none"}</dd></div>
    </dl>
  );
}
function InstallFlow({ initialName, autoPreview, onInstalled }: { initialName: string; autoPreview: boolean; onInstalled: () => void }) {
  const client = useQueryClient();
  const [name, setName] = useState(initialName);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [accepted, setAccepted] = useState(false);
  const [devUnsigned, setDevUnsigned] = useState(false);
  const fetchPreview = useMutation({
    mutationFn: () => post<Preview>("/marketplace/preview", { name: name.trim() }),
    onSuccess: (data) => { setPreview(data); setAccepted(false); setDevUnsigned(false); },
  });
  const install = useMutation({
    mutationFn: () => {
      if (!preview) throw new Error("Preview a package first.");
      return post<RecordData>("/marketplace/install", { name: preview.manifest.name, approved_capabilities: preview.capabilities, accept_trust_level: accepted, ...(devUnsigned ? { allow_unsigned: true } : {}) });
    },
    onSuccess: async () => { await client.invalidateQueries({ queryKey: ["marketplace"] }); await client.invalidateQueries({ queryKey: ["marketplace-search"] }); setPreview(null); setAccepted(false); setDevUnsigned(false); onInstalled(); },
  });
  const autoStarted = useRef(false);
  useEffect(() => {
    if (autoPreview && !autoStarted.current && initialName.trim()) {
      autoStarted.current = true;
      fetchPreview.mutate();
    }
  }, []);
  const error = fetchPreview.error ?? install.error;
  return (
    <div className="panel">
      <h2>Install a package</h2>
      <p><small>Manifests are fetched from the Orbit-MarketPlace repo index and verified here: sha256 digest recomputed first, then the ed25519 signature — but the signing key ships inside the manifest itself, so a passing check is self-asserted, never registry trust. Installs run sandbox-only and are recorded as self-asserted. Install needs your explicit approval below.</small></p>
      <form onSubmit={(e) => { e.preventDefault(); fetchPreview.mutate(); }}>
        <Field label="Package name" hint="Lowercase kebab-case, e.g. hello-skill.">
          <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="hello-skill" />
        </Field>
        <div className="actions"><button type="submit" className="secondary" disabled={fetchPreview.isPending}>{fetchPreview.isPending ? "Fetching…" : "Preview manifest"}</button></div>
      </form>
      {preview && (
        <div className="preview">
          <h3>{text(preview.manifest.name)} {text(preview.manifest.version)}</h3>
          <p>{text(preview.manifest.description)}</p>
          <p><small>Source: {text(preview.index_source)}</small></p>
          <p>
            {preview.digest_valid ? <span className="ok"><ShieldCheck size={14} /> digest recomputed</span> : <span className="bad"><ShieldAlert size={14} /> digest mismatch</span>}{" "}
            {preview.signature_valid ? <span className="ok"><ShieldCheck size={14} /> signature valid</span> : <span className="bad"><ShieldAlert size={14} /> unsigned or invalid</span>}{" "}
            <Status value={preview.manifest.trust_level} />
          </p>
          <h4>Requested capabilities</h4>
          <Capabilities caps={preview.capabilities} />
          {preview.over_broad.length > 0 && (
            <div className="warning" role="alert">
              <p><strong><ShieldAlert size={14} /> Over-broad capabilities — review before approving:</strong></p>
              <ul>{preview.over_broad.map((f) => <li key={f}>{f}</li>)}</ul>
            </div>
          )}
          <label className="consent">
            <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
            I reviewed these capabilities and the {text(preview.manifest.trust_level)} trust level, and approve this install.
          </label>
          {!preview.signature_valid && (
            <label className="consent">
              <input type="checkbox" checked={devUnsigned} onChange={(e) => setDevUnsigned(e.target.checked)} />
              Dev install: accept this self-asserted (unsigned) package. Recorded as self-asserted trust.
            </label>
          )}
          <div className="actions">
            <button disabled={!accepted || install.isPending} onClick={() => install.mutate()}>{install.isPending ? "Installing…" : "Approve and install (sandbox-only)"}</button>
          </div>
        </div>
      )}
      {error && <ErrorNotice error={error} retry={() => { fetchPreview.reset(); install.reset(); }} />}
    </div>
  );
}
function Registries() {
  const client = useQueryClient();
  const [name, setName] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const list = useQuery({ queryKey: ["marketplace-registries"], queryFn: () => api<{ items: RecordData[] }>("/marketplace/registries") });
  const add = useMutation({
    mutationFn: () => post<RecordData>("/marketplace/registries", { name: name.trim(), base_url: baseUrl.trim() }),
    onSuccess: async () => { await client.invalidateQueries({ queryKey: ["marketplace-registries"] }); setName(""); setBaseUrl(""); },
  });
  const drop = useMutation({
    mutationFn: (registry: string) => remove(`/marketplace/registries/${encodeURIComponent(registry)}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["marketplace-registries"] }),
  });
  const error = add.error ?? drop.error;
  return (
    <div className="panel">
      <h2>Marketplaces</h2>
      <p><small>Your own indexes, same manifest format as the built-in one. Adding checks the address serves a manifest schema file before saving it. Removing one never touches installed packages.</small></p>
      <form onSubmit={(e) => { e.preventDefault(); add.mutate(); }}>
        <Field label="Name" hint="Lowercase kebab-case, e.g. team-index.">
          <input required value={name} onChange={(e) => setName(e.target.value)} placeholder="team-index" />
        </Field>
        <Field label="Index address" hint="https address of the index root, e.g. https://market.example.com.">
          <input required value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://market.example.com" inputMode="url" />
        </Field>
        <div className="actions"><button type="submit" className="secondary" disabled={add.isPending}>{add.isPending ? "Adding…" : "Add marketplace"}</button></div>
      </form>
      {list.data && (
        list.data.items.length ? (
          <ul>{list.data.items.map((r) => (
            <li key={String(r.name)}>{text(r.name)} — {text(r.base_url)}{" "}
              <button className="danger" disabled={drop.isPending} onClick={() => drop.mutate(String(r.name))}>Remove</button>
            </li>
          ))}</ul>
        ) : (
          <p><small>No extra marketplaces yet — the built-in index above always stays.</small></p>
        )
      )}
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      {error && <ErrorNotice error={error} retry={() => { add.reset(); drop.reset(); }} />}
    </div>
  );
}
export function Marketplace() {
  const client = useQueryClient();
  const [installTarget, setInstallTarget] = useState<string | null>(null);
  const [removing, setRemoving] = useState<string | null>(null);
  const installs = useQuery({ queryKey: ["marketplace"], queryFn: () => api<{ items: RecordData[] }>("/marketplace/installs") });
  const search = useQuery({ queryKey: ["marketplace-search"], queryFn: () => api<{ items: RecordData[]; index_source: string }>("/marketplace/search?limit=20") });
  const uninstall = useMutation({
    mutationFn: (pkg: string) => remove(`/marketplace/installs/${encodeURIComponent(pkg)}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["marketplace"] }),
  });
  if (installs.isPending) return <div className="panel"><p role="status">Loading marketplace…</p></div>;
  if (installs.error) return <div className="panel"><ErrorNotice error={installs.error} retry={() => installs.refetch()} /></div>;
  const items = installs.data?.items ?? [];
  return (
    <>
      <PageHeader title="Marketplace" description="Signed community packages. Every install is digest- and signature-verified, capability-approved, and runs sandbox-only." />
      {!items.length ? (
        <Empty title="No packages installed yet">Preview a package below — its capabilities show before anything is installed.</Empty>
      ) : (
        <div className="panel">
          <h2><Package size={16} /> Installed packages</h2>
          <table>
            <thead><tr><th scope="col">Package</th><th scope="col">Version</th><th scope="col">Trust</th><th scope="col">Execution</th><th scope="col">Installed</th><th scope="col">Capabilities</th><th scope="col">Actions</th></tr></thead>
            <tbody>
              {items.map((row) => (
                <tr key={String(row.name)}>
                  <th scope="row">{text(row.name)}</th>
                  <td>{text(row.version)}</td>
                  <td><Status value={row.trust_level} /></td>
                  <td>sandbox-only</td>
                  <td>{timestamp(row.installed_at)}</td>
                  <td><details><summary>capabilities</summary><Json value={row.capabilities} /></details></td>
                  <td><div className="actions"><button className="danger" onClick={() => setRemoving(String(row.name))}>Remove</button></div></td>
                </tr>
              ))}
            </tbody>
          </table>
          {uninstall.error && <ErrorNotice error={uninstall.error} retry={() => uninstall.reset()} />}
        </div>
      )}
      {search.data && (
        <div className="panel">
          <h2>Available packages</h2>
          <p><small>Source: {text(search.data.index_source)}. Each description below comes from that package's own manifest file. Installed packages run only via the sandbox path — never in-process.</small></p>
          {search.data.items.length ? (
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(240px, 1fr))", gap: "16px" }}>
              {search.data.items.map((e) => {
                const pkg = String(e.name ?? "");
                const installed = e.installed === true;
                const missing = e.unavailable === true;
                return (
                  <article key={pkg} style={{ border: "1px solid var(--line)", borderRadius: "12px", padding: "16px", background: "#fff", display: "flex", flexDirection: "column", gap: "8px" }}>
                    <h3 style={{ margin: 0 }}>{text(e.name)}</h3>
                    <p style={{ margin: 0 }}><small>Version {text(e.version) || "unknown"}</small></p>
                    <p style={{ margin: 0 }}>{text(e.description) || (missing ? "Package file not found in the repo index." : "No description yet.")}</p>
                    <p style={{ margin: 0 }}><small><Status value={e.trust_level} />{installed ? " — installed" : ""}</small></p>
                    <div className="actions" style={{ marginTop: "auto" }}>
                      {missing || installed
                        ? <button className="secondary" disabled>{missing ? "Unavailable" : "Installed"}</button>
                        : <button onClick={() => setInstallTarget(pkg)}>Install</button>}
                    </div>
                  </article>
                );
              })}
            </div>
          ) : (
            <p>No packages found in the repo index.</p>
          )}
        </div>
      )}
      {removing && (
        <Confirm title={`Remove ${removing}?`} action="Remove" pending={uninstall.isPending} onClose={() => setRemoving(null)} onConfirm={() => { uninstall.mutate(removing); setRemoving(null); }}>
          <p>The package stops being available to the sandbox path. This is recorded in the audit log.</p>
        </Confirm>
      )}
      {installTarget ? <InstallFlow key={installTarget} initialName={installTarget} autoPreview onInstalled={() => setInstallTarget(null)} /> : <button className="secondary" onClick={() => setInstallTarget("hello-skill")}>Install a package</button>}
      <Registries />
    </>
  );
}
