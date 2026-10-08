import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  api,
  label,
  post,
  put,
  remove,
  text,
  timestamp,
  type Page,
  type RecordData,
} from "./api";
import {
  Confirm,
  Empty,
  ErrorNotice,
  Evidence,
  Field,
  Json,
  PageHeader,
  Resource,
  Status,
} from "./ui";

export function Approvals() {
  const { id } = useParams();
  return (
    <>
      <PageHeader
        title="Approvals"
        description="You decide before external data changes or isolated computation starts."
      />
      {id ? <ApprovalDetail id={id} /> : <ApprovalList />}
      <Grants />
      <Policy />
      <Registry />
    </>
  );
}

function ApprovalList() {
  return (
    <Resource
      path="/approvals"
      empty={
        <Empty title="No actions waiting">
          Nothing is waiting for your decision right now.
        </Empty>
      }
    >
      {(items) => (
        <table>
          <thead>
            <tr>
              <th scope="col">Tool</th>
              <th scope="col">Task</th>
              <th scope="col">Sandbox</th>
              <th scope="col">Created</th>
              <th scope="col">Decision</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <th scope="row">
                  <Link className="safe-link" to={`/approvals/${row.id}`}>
                    {text(row.tool_name) || "Review"}
                  </Link>
                </th>
                <td>
                  <Link className="safe-link" to={`/tasks/${text(row.task_id)}`}>
                    {text(row.task_id)}
                  </Link>
                </td>
                <td><Status value={row.requires_sandbox} /></td>
                <td>{timestamp(row.created_at)}</td>
                <td>
                  <ApproveReject approval={row} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Resource>
  );
}

function ApproveReject({ approval }: { approval: RecordData }) {
  const client = useQueryClient();
  const [rejecting, setRejecting] = useState(false);
  const invalidate = () =>
    client.invalidateQueries({ queryKey: ["approvals"] });
  const approve = useMutation({
    mutationFn: () =>
      post<RecordData>(`/approvals/${approval.id}/approve`, {
        expected_revision: approval.revision,
      }),
    onSuccess: invalidate,
  });
  const reject = useMutation({
    mutationFn: () =>
      post<RecordData>(`/approvals/${approval.id}/reject`, {
        expected_revision: approval.revision,
      }),
    onSuccess: invalidate,
  });
  const error = approve.error ?? reject.error;
  return (
    <>
      <div className="actions">
        <button
          disabled={approve.isPending}
          onClick={() => approve.mutate()}
        >
          {approve.isPending ? "Approving…" : "Approve"}
        </button>
        <button
          className="secondary"
          disabled={reject.isPending}
          onClick={() => setRejecting(true)}
        >
          Reject
        </button>
      </div>
      {rejecting && (
        <Confirm
          title="Reject this action?"
          action="Reject"
          pending={reject.isPending}
          onClose={() => setRejecting(false)}
          onConfirm={() => {
            reject.mutate();
            setRejecting(false);
          }}
        >
          <p>
            Orbit will refuse the pending call. The task can still be retried
            later.
          </p>
        </Confirm>
      )}
      {error && <ErrorNotice error={error} retry={() => reject.reset()} />}
    </>
  );
}

function ApprovalDetail({ id }: { id: string }) {
  const approval = useQuery({
    queryKey: ["approval", id],
    queryFn: () => api<RecordData>(`/approvals/${id}`),
  });
  if (approval.isPending)
    return (
      <section className="panel section">
        <p role="status">Loading…</p>
      </section>
    );
  if (approval.error)
    return (
      <section className="panel section">
        <ErrorNotice error={approval.error} retry={() => approval.refetch()} />
      </section>
    );
  const record = approval.data!;
  return (
    <article className="panel section">
      <header className="page-heading">
        <div>
          <h2>{text(record.tool_name) || "Pending action"}</h2>
          <p className="muted">{label(record.state)}</p>
        </div>
        <small>Created {timestamp(record.created_at)}</small>
      </header>
      <p>
        This call has not run. Orbit will not touch external data or start
        isolated computation until you decide.
      </p>
      <Evidence
        correlationId={text(record.correlation_id)}
        evidence={record.snapshot ?? record.evidence}
      />
      <h3>Arguments</h3>
      <Json value={record.preview ?? record.snapshot} />
      <div className="actions">
        <ApproveReject approval={record} />
        <Link className="safe-link" to={`/tasks/${text(record.task_id)}`}>
          Open task
        </Link>
        <Link className="safe-link" to="/approvals">
          All approvals
        </Link>
      </div>
    </article>
  );
}

function Grants() {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const revoke = useMutation({
    mutationFn: (id: string) => remove(`/grants/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["grants"] }),
  });
  return (
    <section className="section" aria-label="Scope grants">
      <div className="panel">
        <h2>Scope grants</h2>
        <Resource
          path="/grants"
          empty={
            <Empty title="No standing grants">
              Grants let a tool act inside a bounded scope without asking each
              time.
            </Empty>
          }
        >
          {(items) => (
            <table>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">Scope</th>
                  <th scope="col">Max risk</th>
                  <th scope="col">Granted</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">{text(row.tool_name)}</th>
                    <td>{text(row.scope_key)}</td>
                    <td>{label(row.max_risk)}</td>
                    <td>{timestamp(row.created_at)}</td>
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
        </Resource>
        {revoke.error && (
          <ErrorNotice error={revoke.error} retry={() => revoke.reset()} />
        )}
        {open ? (
          <NewGrant onDone={() => setOpen(false)} />
        ) : (
          <button className="secondary" onClick={() => setOpen(true)}>
            Grant a scope
          </button>
        )}
      </div>
    </section>
  );
}

function NewGrant({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    tool_name: "",
    scope_key: "",
    scope_revision: "1",
    max_risk: "LOW",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/grants", {
        tool_name: form.tool_name,
        scope_key: form.scope_key,
        scope_revision: Number(form.scope_revision),
        max_risk: form.max_risk,
        autonomy_modes: [],
        parameter_bounds: {},
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["grants"] });
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
      <Field label="Tool name" hint="The registered tool this grant applies to.">
        <input
          required
          value={form.tool_name}
          onChange={(e) => setForm({ ...form, tool_name: e.target.value })}
        />
      </Field>
      <Field label="Scope key" hint="The exact object the tool may act on.">
        <input
          required
          value={form.scope_key}
          onChange={(e) => setForm({ ...form, scope_key: e.target.value })}
        />
      </Field>
      <Field label="Scope revision">
        <input
          type="number"
          min={0}
          required
          value={form.scope_revision}
          onChange={(e) => setForm({ ...form, scope_revision: e.target.value })}
        />
      </Field>
      <Field label="Max risk">
        <select
          value={form.max_risk}
          onChange={(e) => setForm({ ...form, max_risk: e.target.value })}
        >
          {["LOW", "MEDIUM", "HIGH"].map((option) => (
            <option key={option} value={option}>
              {label(option)}
            </option>
          ))}
        </select>
      </Field>
      {create.error && (
        <ErrorNotice error={create.error} retry={() => create.reset()} />
      )}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Grant"}
        </button>
      </div>
    </form>
  );
}

function Policy() {
  const client = useQueryClient();
  const policy = useQuery({
    queryKey: ["policy"],
    queryFn: () => api<RecordData>("/policy"),
  });
  const [draft, setDraft] = useState<string | null>(null);
  const save = useMutation({
    mutationFn: (rules: unknown) =>
      put<RecordData>("/policy", {
        rules,
        expected_revision: policy.data!.revision,
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["policy"] }),
  });
  if (policy.isPending)
    return (
      <section className="panel section">
        <p role="status">Loading policy…</p>
      </section>
    );
  if (policy.error)
    return (
      <section className="panel section">
        <ErrorNotice error={policy.error} retry={() => policy.refetch()} />
      </section>
    );
  const current = policy.data!;
  const value = draft ?? JSON.stringify(current.rules ?? [], null, 2);
  return (
    <section className="section" aria-label="Policy">
      <div className="panel">
        <h2>Policy</h2>
        <p>
          <small>
            Every rule needs a tool_pattern. Ceilings:{" "}
            {text(current.max_tool_calls)} tool calls,{" "}
            {text(current.max_active_seconds)} active seconds. Revision{" "}
            {text(current.revision)}.
          </small>
        </p>
        <Field
          label="Rules"
          hint="JSON array. Saving sends expected_revision, so a concurrent edit is refused rather than overwritten."
        >
          <textarea
            rows={8}
            value={value}
            onChange={(e) => setDraft(e.target.value)}
          />
        </Field>
        {save.error && <ErrorNotice error={save.error} retry={() => save.reset()} />}
        <div className="actions">
          <button
            disabled={save.isPending}
            onClick={() => {
              try {
                save.mutate(JSON.parse(value));
              } catch {
                // A parse failure must not reach the API; the draft stays editable.
                setDraft(value);
              }
            }}
          >
            {save.isPending ? "Saving…" : "Save policy"}
          </button>
        </div>
      </div>
    </section>
  );
}

function Registry() {
  const [cursor, setCursor] = useState<string | null>(null);
  const calls = useQuery({
    queryKey: ["tool-calls", cursor],
    queryFn: () =>
      api<Page>(
        `/tool-calls?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
      ),
  });
  return (
    <section className="section" aria-label="Tool calls">
      <div className="panel">
        <h2>Recent tool calls</h2>
        <RegisteredTools />
        {calls.isPending && <p role="status">Loading tool calls…</p>}
        {calls.error && (
          <ErrorNotice error={calls.error} retry={() => calls.refetch()} />
        )}
        {calls.data &&
          (calls.data.items.length ? (
            <table>
              <thead>
                <tr>
                  <th scope="col">Tool</th>
                  <th scope="col">State</th>
                  <th scope="col">When</th>
                </tr>
              </thead>
              <tbody>
                {calls.data.items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">{text(row.tool_name)}</th>
                    <td>{label(row.state)}</td>
                    <td>{timestamp(row.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <Empty title="No tool calls yet">
              Calls appear here once an agent runs a tool.
            </Empty>
          ))}
          <button
            className="secondary"
            onClick={() => setCursor(calls.data!.next_cursor)}
          >
            Next page
          </button>
        {cursor && (
          <button className="quiet" onClick={() => setCursor(null)}>
            First page
          </button>
        )}
      </div>
    </section>
  );
}

function RegisteredTools() {
  const tools = useQuery({
    queryKey: ["tools"],
    queryFn: () => api<Page>("/tools"),
  });
  if (tools.isPending) return <p role="status">Loading tools…</p>;
  if (tools.error)
    return <ErrorNotice error={tools.error} retry={() => tools.refetch()} />;
  const items = tools.data?.items ?? [];
  if (!items.length)
    return (
      <Empty title="No tools registered">
        Tools appear here once a connector or agent registers one.
      </Empty>
    );
  return (
    <ul className="list">
      {items.map((tool, index) => (
        <li key={text(tool.name) || index}>
          {text(tool.name)}
          {tool.description ? <small> — {text(tool.description)}</small> : null}
        </li>
      ))}
    </ul>
  );
}