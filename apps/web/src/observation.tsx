import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Eye, PauseCircle } from "lucide-react";
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
import { Confirm, Empty, ErrorNotice, Field, Modal, PageHeader, Status } from "./ui";

export type Consent = RecordData & {
  node_id: string;
  node_name: string;
  source_app: string;
  mode: string;
  revision: number;
  retention_hours: number;
  expires_at: string | null;
  consent_expired: boolean;
  node_revoked: boolean;
  node_state: string | null;
};

export type ObservationStatus = {
  observing: boolean;
  consents: Consent[];
};

export function useObservationStatus(enabled = true) {
  return useQuery({
    queryKey: ["observation-status"],
    queryFn: () => api<ObservationStatus>("/observation/status"),
    enabled,
    refetchInterval: 30_000,
  });
}

function modeClass(mode: string): "good" | "pending" | "bad" | "" {
  if (mode === "GRANTED") return "good";
  if (mode === "PAUSED") return "pending";
  return "bad";
}

export function ObservationIndicator() {
  const status = useObservationStatus(true);
  const client = useQueryClient();
  const [confirmPause, setConfirmPause] = useState<Consent | null>(null);
  const pause = useMutation({
    mutationFn: (c: Consent) =>
      post<Consent>(`/computers/${c.node_id}/observation/consents/${c.id}/pause`, {
        expected_revision: c.revision,
      }),
    onSuccess: () => {
      setConfirmPause(null);
      void client.invalidateQueries({ queryKey: ["observation-status"] });
      void client.invalidateQueries({ queryKey: ["observation"] });
    },
  });
  if (status.isPending || status.error || !status.data) return null;
  const active = status.data.consents.filter(
    (c) => c.mode === "GRANTED" && !c.consent_expired && !c.node_revoked,
  );
  if (!active.length) return null;
  const first = active[0];
  return (
    <>
      <div className="observing-banner" role="status">
        <Eye size={18} aria-hidden="true" />
        <div className="observing-banner-main">
          <strong>
            Observing {active.length === 1 ? text(first.node_name) : `${active.length} machines`}
            {active.length === 1 && first.source_app ? ` · ${text(first.source_app)}` : ""}
          </strong>
          <span className="muted">
            {active.length === 1
              ? `Kept ${first.retention_hours === 0 ? "until you delete it" : `${first.retention_hours}h`}.`
              : "Screen observation is on. Open details to review each machine."}{" "}
            <Link to="/settings#desktop-observation">Details</Link>
          </span>
        </div>
        <button
          className="secondary"
          disabled={pause.isPending}
          onClick={() =>
            active.length === 1 ? setConfirmPause(first) : undefined
          }
          hidden={active.length !== 1}
        >
          <PauseCircle size={16} /> Pause
        </button>
        {active.length !== 1 && (
          <Link className="observing-banner-link" to="/settings#desktop-observation">
            Review and pause
          </Link>
        )}
      </div>
      {confirmPause && (
        <Confirm
          title={`Pause observation of ${text(confirmPause.source_app)}?`}
          action="Pause observation"
          pending={pause.isPending}
          onClose={() => {
            if (!pause.isPending) {
              setConfirmPause(null);
              pause.reset();
            }
          }}
          onConfirm={() => pause.mutate(confirmPause)}
        >
          <p>
            Orbit stops capturing {text(confirmPause.source_app)} on{" "}
            {text(confirmPause.node_name)} right away. Anything already kept
            stays until its expiry; grant again when you want to resume.
          </p>
          {pause.error && <ErrorNotice error={pause.error} retry={() => pause.reset()} />}
        </Confirm>
      )}
      {pause.error && !confirmPause && (
        <ErrorNotice error={pause.error} retry={() => pause.reset()} />
      )}
    </>
  );
}

type GrantDraft = { source_app: string; retention_hours: number; expires_at: string };

function retentionLabel(hours: number): string {
  if (hours === 0) return "Keep until I delete it";
  if (hours === 24) return "24 hours (recommended)";
  return `${hours} hours`;
}

export function DesktopObservationSection() {
  const client = useQueryClient();
  const status = useObservationStatus(true);
  const nodes = useQuery({
    queryKey: ["observation-nodes"],
    queryFn: () => api<{ items: RecordData[] }>("/computers"),
  });
  const [grantNode, setGrantNode] = useState("");
  const [draft, setDraft] = useState<GrantDraft>({
    source_app: "",
    retention_hours: 24,
    expires_at: "",
  });
  const [narrow, setNarrow] = useState<Consent | null>(null);
  const [confirm, setConfirm] = useState<{ consent: Consent; action: "revoke" } | null>(null);
  const [inspect, setInspect] = useState<Consent | null>(null);
  const invalidate = () => {
    void client.invalidateQueries({ queryKey: ["observation-status"] });
    void client.invalidateQueries({ queryKey: ["observation"] });
  };
  const grant = useMutation({
    mutationFn: () =>
      post<Consent>(`/computers/${grantNode}/observation/consents`, {
        source_app: draft.source_app.trim(),
        retention_hours: draft.retention_hours,
        expires_at: draft.expires_at ? new Date(draft.expires_at).toISOString() : undefined,
      }),
    onSuccess: () => {
      setDraft({ source_app: "", retention_hours: 24, expires_at: "" });
      invalidate();
    },
  });
  const transition = useMutation({
    mutationFn: ({ consent, path }: { consent: Consent; path: string }) =>
      post<Consent>(
        `/computers/${consent.node_id}/observation/consents/${consent.id}/${path}`,
        { expected_revision: consent.revision },
      ),
    onSuccess: () => {
      setConfirm(null);
      invalidate();
    },
  });
  const narrowSave = useMutation({
    mutationFn: (body: {
      source_app?: string;
      retention_hours?: number;
      expires_at?: string | null;
      clear_expires_at?: boolean;
    }) =>
      put<Consent>(
        `/computers/${narrow!.node_id}/observation/consents/${narrow!.id}`,
        { ...body, expected_revision: narrow!.revision },
      ),
    onSuccess: () => {
      setNarrow(null);
      invalidate();
    },
  });
  const pauseNode = useMutation({
    mutationFn: (nodeId: string) => post(`/computers/${nodeId}/observation/pause`),
    onSuccess: invalidate,
  });
  const consents = status.data?.consents ?? [];
  const nodeItems = nodes.data?.items ?? [];
  return (
    <section className="panel form section" id="desktop-observation" aria-label="Desktop observation">
      <h2>Desktop observation</h2>
      <p className="muted">
        Off unless you turn it on, one window or app at a time. Granting here
        only permits capture — the machine itself still asks you to pick the
        window through its system screen-sharing dialog, and Orbit can only
        narrow, pause, or revoke from here, never start capture remotely. What
        is captured: OCR text from the windows you allow. What is kept: that
        text for 24 hours by default, or until you delete it if you choose
        explicit keep. Phones can review and pause, but only this screen can
        grant, resume, narrow, revoke, or delete.
      </p>
      {status.error && <ErrorNotice error={status.error} retry={() => status.refetch()} />}
      {status.isPending ? (
        <p role="status">Loading observation consents…</p>
      ) : consents.length === 0 ? (
        <Empty title="Desktop observation is off">
          Nothing is being watched. Grant consent for one window on one machine
          below — capture only starts after you also pick that window on the
          machine itself.
        </Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Machine</th>
              <th scope="col">Window</th>
              <th scope="col">Consent</th>
              <th scope="col">Machine reports</th>
              <th scope="col">Kept</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {consents.map((c) => (
              <tr key={String(c.id)}>
                <th scope="row">{text(c.node_name)}</th>
                <td>{text(c.source_app)}</td>
                <td>
                  <span className={`status ${modeClass(text(c.mode))}`}>
                    {c.consent_expired ? "Expired — grant again" : label(c.mode)}
                  </span>
                  {c.node_revoked && (
                    <span className="status bad">Machine revoked</span>
                  )}
                </td>
                <td>
                  <Status value={c.node_state ?? "UNKNOWN"} />
                </td>
                <td>
                  {c.retention_hours === 0
                    ? "Until you delete it"
                    : `${c.retention_hours}h${c.expires_at ? ` · consent ends ${timestamp(c.expires_at)}` : ""}`}
                </td>
                <td>
                  <div className="actions">
                    {c.mode === "GRANTED" && !c.consent_expired && (
                      <button
                        className="secondary mini"
                        disabled={transition.isPending}
                        onClick={() => transition.mutate({ consent: c, path: "pause" })}
                      >
                        Pause
                      </button>
                    )}
                    {c.mode === "PAUSED" && (
                      <button
                        className="secondary mini"
                        disabled={transition.isPending}
                        onClick={() => transition.mutate({ consent: c, path: "resume" })}
                      >
                        Resume
                      </button>
                    )}
                    {(c.mode === "GRANTED" || c.mode === "PAUSED") && (
                      <>
                        <button
                          className="secondary mini"
                          onClick={() => setNarrow(c)}
                        >
                          Narrow
                        </button>
                        <button
                          className="secondary mini"
                          onClick={() => setInspect(c)}
                        >
                          Inspect
                        </button>
                      </>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {transition.error && (
        <ErrorNotice error={transition.error} retry={() => transition.reset()} />
      )}
      {pauseNode.error && (
        <ErrorNotice error={pauseNode.error} retry={() => pauseNode.reset()} />
      )}
      {consents.some((c) => c.mode === "GRANTED" && !c.consent_expired && !c.node_revoked) && (
        <div className="actions">
          {Object.values(
            consents
              .filter((c) => c.mode === "GRANTED")
              .reduce<Record<string, Consent>>((byNode, c) => {
                byNode[String(c.node_id)] ??= c;
                return byNode;
              }, {}),
          ).map((c) => (
            <button
              key={String(c.node_id)}
              className="secondary"
              disabled={pauseNode.isPending}
              onClick={() => pauseNode.mutate(String(c.node_id))}
            >
              Pause all on {text(c.node_name)}
            </button>
          ))}
        </div>
      )}
      <h3>Grant consent for a window</h3>
      <div className="form-grid">
        <Field label="Machine">
          <select
            value={grantNode}
            onChange={(e) => setGrantNode(e.target.value)}
            aria-label="Machine"
          >
            <option value="">Choose a machine…</option>
            {nodeItems.map((n) => (
              <option key={String(n.id)} value={String(n.id)}>
                {text(n.display_name)}
              </option>
            ))}
          </select>
        </Field>
        <Field
          label="Window or app"
          hint="Exactly what you will pick in the machine's screen-sharing dialog, e.g. a browser window title."
        >
          <input
            value={draft.source_app}
            maxLength={128}
            placeholder="e.g. Firefox — Project notes"
            onChange={(e) => setDraft({ ...draft, source_app: e.target.value })}
            aria-label="Window or app"
          />
        </Field>
        <Field label="Keep captured text" hint="OCR text expires automatically unless you choose keep.">
          <select
            value={draft.retention_hours}
            onChange={(e) => setDraft({ ...draft, retention_hours: Number(e.target.value) })}
            aria-label="Keep captured text"
          >
            {[1, 24, 72, 168, 0].map((h) => (
              <option value={h} key={h}>
                {retentionLabel(h)}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Consent ends (optional)" hint="Leave empty for no consent expiry. Expired consents stop and need a fresh grant.">
          <input
            type="datetime-local"
            value={draft.expires_at}
            onChange={(e) => setDraft({ ...draft, expires_at: e.target.value })}
            aria-label="Consent ends"
          />
        </Field>
      </div>
      <div className="actions">
        <button
          disabled={grant.isPending || !grantNode || !draft.source_app.trim()}
          onClick={() => grant.mutate()}
        >
          Grant consent
        </button>
      </div>
      <p className="muted">
        If the machine cannot do system screen capture, granting fails with
        DESKTOP_CAPTURE_UNAVAILABLE — there is no silent fallback.
      </p>
      {grant.error && <ErrorNotice error={grant.error} retry={() => grant.reset()} />}
      {nodes.error && <ErrorNotice error={nodes.error} retry={() => nodes.refetch()} />}
      {narrow && (
        <NarrowDialog
          consent={narrow}
          pending={narrowSave.isPending}
          saveError={narrowSave.error}
          onClose={() => {
            if (!narrowSave.isPending) {
              setNarrow(null);
              narrowSave.reset();
            }
          }}
          onSave={(body) => narrowSave.mutate(body)}
        />
      )}
      {confirm && (
        <Confirm
          title={`Revoke observation of ${text(confirm.consent.source_app)}?`}
          action="Revoke consent"
          pending={transition.isPending}
          onClose={() => {
            if (!transition.isPending) {
              setConfirm(null);
              transition.reset();
            }
          }}
          onConfirm={() => transition.mutate({ consent: confirm.consent, path: "revoke" })}
        >
          <p>
            Capture of {text(confirm.consent.source_app)} on{" "}
            {text(confirm.consent.node_name)} stops and this consent ends for
            good. Kept text stays until its expiry — delete it below if you
            want it gone now. To watch again later, grant fresh consent.
          </p>
        </Confirm>
      )}
      {inspect && (
        <ObservationInspector consent={inspect} onClose={() => setInspect(null)} />
      )}
      <ObservationInspectorStandalone />
    </section>
  );
}

function NarrowDialog({
  consent,
  pending,
  saveError,
  onClose,
  onSave,
}: {
  consent: Consent;
  pending: boolean;
  saveError: unknown;
  onClose: () => void;
  onSave: (body: {
    source_app?: string;
    retention_hours?: number;
    expires_at?: string | null;
    clear_expires_at?: boolean;
  }) => void;
}) {
  const [sourceApp, setSourceApp] = useState(text(consent.source_app));
  const [retention, setRetention] = useState(String(consent.retention_hours));
  const [expiresAt, setExpiresAt] = useState(
    consent.expires_at ? consent.expires_at.slice(0, 16) : "",
  );
  const [clearExpiry, setClearExpiry] = useState(false);
  return (
    <Modal title={`Narrow ${text(consent.source_app)}`} onClose={onClose} pending={pending}>
      <Field label="Window or app">
        <input
          value={sourceApp}
          maxLength={128}
          onChange={(e) => setSourceApp(e.target.value)}
          aria-label="Window or app"
        />
      </Field>
      <Field label="Keep captured text">
        <select
          value={retention}
          onChange={(e) => setRetention(e.target.value)}
          aria-label="Keep captured text"
        >
          {[1, 24, 72, 168, 0].map((h) => (
            <option value={h} key={h}>
              {retentionLabel(h)}
            </option>
          ))}
        </select>
      </Field>
      <Field label="Consent ends">
        <input
          type="datetime-local"
          value={expiresAt}
          disabled={clearExpiry}
          onChange={(e) => setExpiresAt(e.target.value)}
          aria-label="Consent ends"
        />
      </Field>
      {consent.expires_at && (
        <label className="check">
          <input
            type="checkbox"
            checked={clearExpiry}
            onChange={(e) => setClearExpiry(e.target.checked)}
          />
          Remove consent end (no expiry)
        </label>
      )}
      {saveError ? <ErrorNotice error={saveError} /> : null}
      <div className="actions">
        <button
          disabled={pending || !sourceApp.trim()}
          onClick={() =>
            onSave({
              source_app: sourceApp.trim() === text(consent.source_app) ? undefined : sourceApp.trim(),
              retention_hours:
                Number(retention) === consent.retention_hours ? undefined : Number(retention),
              expires_at:
                !clearExpiry && expiresAt
                  ? new Date(expiresAt).toISOString()
                  : undefined,
              clear_expires_at: clearExpiry || undefined,
            })
          }
        >
          {pending ? "Working…" : "Save changes"}
        </button>
      </div>
    </Modal>
  );
}

export function ObservationInspector({
  consent,
  onClose,
}: {
  consent: Consent;
  onClose: () => void;
}) {
  const [sourceId, setSourceId] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const [cursor, setCursor] = useState(0);
  const params = new URLSearchParams();
  params.set("source_type", "desktop");
  params.set("source_id", sourceId.trim() || String(consent.node_id));
  if (since) params.set("since", new Date(since).toISOString());
  if (until) params.set("until", new Date(until).toISOString());
  params.set("limit", "30");
  params.set("cursor", String(cursor));
  const list = useQuery({
    queryKey: ["observation", String(consent.id), params.toString()],
    queryFn: () => api<{ items: RecordData[]; next_cursor: number | null }>(`/observations?${params}`),
  });
  const client = useQueryClient();
  const del = useMutation({
    mutationFn: (id: string) => remove(`/observations/${id}`),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["observation"] });
    },
  });
  const delBulk = useMutation({
    mutationFn: () =>
      api<{ deleted: number }>(
        `/observations?source_type=desktop&source_id=${encodeURIComponent(String(consent.node_id))}`,
        { method: "DELETE" },
      ),
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["observation"] });
    },
  });
  const items = list.data?.items ?? [];
  return (
    <Modal title={`Kept from ${text(consent.source_app)}`} onClose={onClose}>
      <p className="muted">
        Everything Orbit kept from {text(consent.source_app)} on{" "}
        {text(consent.node_name)}, newest first. Each row shows when it expires —
        delete anything you do not want kept.
      </p>
      <div className="toolbar">
        <Field label="Filter by source">
          <input
            value={sourceId}
            placeholder="Window or app id"
            onChange={(e) => {
              setSourceId(e.target.value);
              setCursor(0);
            }}
            aria-label="Filter by source"
          />
        </Field>
        <Field label="Since">
          <input
            type="datetime-local"
            value={since}
            onChange={(e) => {
              setSince(e.target.value);
              setCursor(0);
            }}
            aria-label="Since"
          />
        </Field>
        <Field label="Until">
          <input
            type="datetime-local"
            value={until}
            onChange={(e) => {
              setUntil(e.target.value);
              setCursor(0);
            }}
            aria-label="Until"
          />
        </Field>
      </div>
      {list.isPending && <p role="status">Loading kept observations…</p>}
      {list.error && <ErrorNotice error={list.error} retry={() => list.refetch()} />}
      {list.data && items.length === 0 && (
        <Empty title="Nothing kept from this window">
          Either nothing was captured yet, or everything already expired or was
          deleted. Pick a wider time range above to be sure.
        </Empty>
      )}
      {items.length > 0 && (
        <ul className="list">
          {items.map((row) => (
            <li className="row" key={String(row.id)}>
              <div className="row-main">
                <h3>{timestamp(row.observed_at)}</h3>
                <p className="muted">
                  Source {text(row.source_id)} · expires{" "}
                  {row.expires_at ? timestamp(row.expires_at) : "never (explicit keep)"}
                </p>
                <details className="evidence">
                  <summary>Record contents</summary>
                  <pre className="json">{text(row.record ?? row)}</pre>
                </details>
              </div>
              <button
                className="secondary mini"
                disabled={del.isPending}
                onClick={() => del.mutate(String(row.id))}
              >
                Delete
              </button>
            </li>
          ))}
        </ul>
      )}
      {(list.data?.next_cursor ?? null) !== null && (
        <div className="actions">
          <button className="secondary" onClick={() => setCursor(list.data!.next_cursor!)}>
            Next page
          </button>
          {cursor > 0 && (
            <button className="quiet" onClick={() => setCursor(0)}>
              Return to first page
            </button>
          )}
        </div>
      )}
      {del.error && <ErrorNotice error={del.error} retry={() => del.reset()} />}
      <div className="actions">
        <button
          className="danger"
          disabled={delBulk.isPending}
          onClick={() => delBulk.mutate()}
        >
          {delBulk.isPending ? "Working…" : "Delete everything from this machine"}
        </button>
      </div>
      {delBulk.data && <p role="status">Deleted {delBulk.data.deleted} records.</p>}
      {delBulk.error && <ErrorNotice error={delBulk.error} retry={() => delBulk.reset()} />}
    </Modal>
  );
}

function ObservationInspectorStandalone() {
  const [sourceType, setSourceType] = useState("desktop");
  const [sourceId, setSourceId] = useState("");
  const [before, setBefore] = useState("");
  const client = useQueryClient();
  const delBulk = useMutation({
    mutationFn: () => {
      const params = new URLSearchParams();
      if (sourceType.trim()) params.set("source_type", sourceType.trim());
      if (sourceId.trim()) params.set("source_id", sourceId.trim());
      if (before) params.set("before", new Date(before).toISOString());
      return api<{ deleted: number }>(`/observations?${params}`, { method: "DELETE" });
    },
    onSuccess: () => {
      void client.invalidateQueries({ queryKey: ["observation"] });
    },
  });
  return (
    <div className="destructive">
      <h3>Delete kept observations</h3>
      <p className="muted">
        Remove what Orbit kept, by source and time — for example everything
        from one machine, or everything observed before a date. At least one
        filter is required; there is no delete-everything button.
      </p>
      <div className="form-grid">
        <Field label="Source type">
          <input
            value={sourceType}
            onChange={(e) => setSourceType(e.target.value)}
            aria-label="Source type"
          />
        </Field>
        <Field label="Source id (machine or window)">
          <input
            value={sourceId}
            placeholder="Machine id, or leave empty"
            onChange={(e) => setSourceId(e.target.value)}
            aria-label="Source id"
          />
        </Field>
        <Field label="Observed before">
          <input
            type="datetime-local"
            value={before}
            onChange={(e) => setBefore(e.target.value)}
            aria-label="Observed before"
          />
        </Field>
      </div>
      <div className="actions">
        <button
          className="danger"
          disabled={
            delBulk.isPending ||
            (!sourceType.trim() && !sourceId.trim() && !before)
          }
          onClick={() => delBulk.mutate()}
        >
          {delBulk.isPending ? "Working…" : "Delete matching records"}
        </button>
      </div>
      {delBulk.data && <p role="status">Deleted {delBulk.data.deleted} records.</p>}
      {delBulk.error && <ErrorNotice error={delBulk.error} retry={() => delBulk.reset()} />}
    </div>
  );
}
