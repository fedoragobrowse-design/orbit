import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post, put, remove, text, timestamp, label, type Page, type RecordData } from "./api";
import { Empty, ErrorNotice, Field, Input, PageHeader, Resource, Select, Status } from "./ui";

type Settings = { installation_mode?: unknown };

const PROVIDER_KINDS = [
  "OLLAMA",
  "OPENAI",
  "ANTHROPIC",
  "GEMINI",
  "OPENAI_COMPATIBLE",
  "AIEC",
];

export function Models() {
  const [kind, setKind] = useState("");
  const providers = useQuery({
    queryKey: ["providers", kind],
    queryFn: () => api<Page>("/providers?limit=100"),
  });

  return (
    <>
      <PageHeader
        title="Models"
        description="Choose which language model answers on your behalf."
      />
      <Providers />
      <section className="section" aria-label="Models">
        <div className="panel">
          <h2>Models</h2>
          <ModelsTable providers={providers.data?.items ?? []} />
          <NewModel />
        </div>
      </section>
      <section className="section" aria-label="Spend">
        <div className="panel">
          <h2>Spend</h2>
          <Budgets />
          <ModelCalls />
        </div>
      </section>
      <InstallationMode />
    </>
  );
}

function InstallationMode() {
  const settings = useQuery({
    queryKey: ["settings-installation-mode"],
    queryFn: () => api<Settings>("/settings"),
  });
  return (
    <section className="section" aria-label="Current install mode">
      <div className="panel">
        <h2>Current install mode</h2>
        {settings.isPending && <p role="status">Loading…</p>}
        {settings.error && (
          <ErrorNotice error={settings.error} retry={() => settings.refetch()} />
        )}
        {settings.data && (
          <p>
            Installation mode: <Status value={settings.data.installation_mode} />
          </p>
        )}
      </div>
    </section>
  );
}

function Providers() {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const removeProvider = useMutation({
    mutationFn: (id: string) => remove(`/providers/${id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["providers"] }),
  });
  return (
    <section className="section" aria-label="Providers">
      <div className="panel">
        <h2>Providers</h2>
        <Resource path="/providers" empty={<Empty title="No providers yet">Add the endpoint Orbit should send model requests to.</Empty>}>
          {(items) => (
            <table>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">Kind</th>
                  <th scope="col">Origin</th>
                  <th scope="col">Credential</th>
                  <th scope="col">Enabled</th>
                  <th scope="col">Rev</th>
                  <th scope="col">Actions</th>
                </tr>
              </thead>
              <tbody>
                {items.map((row) => (
                  <tr key={row.id}>
                    <th scope="row">{text(row.name)}</th>
                    <td>{label(row.kind)}</td>
                    <td>{text(row.origin)}</td>
                    <td>{row.secret_set ? "Set" : "None"}</td>
                    <td><Status value={row.enabled} /></td>
                    <td>{text(row.revision)}</td>
                    <td>
                      <button
                        className="danger"
                        disabled={removeProvider.isPending}
                        onClick={() => removeProvider.mutate(String(row.id))}
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Resource>
        {removeProvider.error && <ErrorNotice error={removeProvider.error} retry={() => removeProvider.reset()} />}
        {open ? (
          <NewProvider onDone={() => setOpen(false)} />
        ) : (
          <button className="secondary" onClick={() => setOpen(true)}>
            Add provider
          </button>
        )}
      </div>
    </section>
  );
}

function NewProvider({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [form, setForm] = useState({
    name: "",
    kind: "OLLAMA",
    origin: "",
    local: true,
    credential: "",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/providers", {
        name: form.name,
        kind: form.kind,
        origin: form.origin,
        local: form.local,
        credential: form.credential || undefined,
      }),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ["providers"] });
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
      <Select
        label="Kind"
        value={form.kind}
        onChange={(e) => setForm({ ...form, kind: e.target.value })}
      >
        {PROVIDER_KINDS.map((option) => (
          <option key={option} value={option}>
            {label(option)}
          </option>
        ))}
      </Select>
      <Input
        label="Origin"
        required
        placeholder="http://ollama:11434"
        value={form.origin}
        onChange={(e) => setForm({ ...form, origin: e.target.value })}
      />
      <Field label="Credential" hint="Write-only. Never returned by the API.">
        <input
          type="password"
          value={form.credential}
          onChange={(e) => setForm({ ...form, credential: e.target.value })}
        />
      </Field>
      {create.error && <ErrorNotice error={create.error} retry={() => create.reset()} />}
      <div className="actions">
        <button type="button" className="secondary" onClick={onDone}>
          Cancel
        </button>
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save provider"}
        </button>
      </div>
    </form>
  );
}

function ModelsTable({ providers }: { providers: RecordData[] }) {
  const client = useQueryClient();
  const toggle = useMutation({
    mutationFn: (row: RecordData) =>
      put<RecordData>(`/models/${row.id}`, {
        enabled: !row.enabled,
        expected_revision: row.revision,
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["models"] }),
  });
  return (
    <Resource path="/models" empty={<Empty title="No models yet">Add a model from one of your providers.</Empty>}>
      {(items) => (
        <table>
          <thead>
            <tr>
              <th scope="col">Name</th>
              <th scope="col">Provider</th>
              <th scope="col">Model</th>
              <th scope="col">Roles</th>
              <th scope="col">Context</th>
              <th scope="col">Enabled</th>
              <th scope="col">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <th scope="row">{text(row.name)}</th>
                <td>
                  {text(
                    providers.find((p) => p.id === row.provider_id)?.name ??
                      row.provider_id,
                  )}
                </td>
                <td>{text(row.model) || "—"}</td>
                <td>
                  {Array.isArray(row.roles)
                    ? row.roles.map(label).join(", ")
                    : "—"}
                </td>
                <td>{text(row.context_tokens)}</td>
                <td>
                  <Status value={row.enabled} />
                </td>
                <td>
                  <button
                    className="secondary"
                    disabled={toggle.isPending}
                    onClick={() => toggle.mutate(row)}
                  >
                    {row.enabled ? "Disable" : "Enable"}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Resource>
  );
}

function NewModel() {
  const client = useQueryClient();
  const providers = useQuery({
    queryKey: ["providers", "picker"],
    queryFn: () => api<Page>("/providers?limit=100"),
  });
  const [form, setForm] = useState({
    provider_id: "",
    name: "",
    model: "",
    roles: "CHAT",
    context_tokens: "128000",
  });
  const create = useMutation({
    mutationFn: () =>
      post<RecordData>("/models", {
        provider_id: form.provider_id,
        name: form.name,
        model: form.model,
        roles: form.roles.split(",").map((r) => r.trim()).filter(Boolean),
        context_tokens: Number(form.context_tokens),
        capabilities: {},
      }),
    onSuccess: () => client.invalidateQueries({ queryKey: ["models"] }),
  });
  if (providers.isPending) return <p role="status">Loading providers…</p>;
  if (providers.error) return <ErrorNotice error={providers.error} retry={() => providers.refetch()} />;
  const options = providers.data?.items ?? [];
  if (!options.length)
    return <Empty title="Add a provider first">A model must belong to a provider.</Empty>;
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        create.mutate();
      }}
    >
      <Select
        label="Provider"
        required
        value={form.provider_id || options[0].id}
        onChange={(e) => setForm({ ...form, provider_id: e.target.value })}
      >
        {options.map((option) => (
          <option key={option.id} value={String(option.id)}>
            {text(option.name)}
          </option>
        ))}
      </Select>
      <Input
        label="Name"
        required
        value={form.name}
        onChange={(e) => setForm({ ...form, name: e.target.value })}
      />
      <Input
        label="Model"
        required
        placeholder="llama3.1"
        value={form.model}
        onChange={(e) => setForm({ ...form, model: e.target.value })}
      />
      <Field label="Roles" hint="Comma separated, for example CHAT,PLAN.">
        <input
          value={form.roles}
          onChange={(e) => setForm({ ...form, roles: e.target.value })}
        />
      </Field>
      <Input
        label="Context tokens"
        type="number"
        min={1}
        required
        value={form.context_tokens}
        onChange={(e) => setForm({ ...form, context_tokens: e.target.value })}
      />
      {create.error && <ErrorNotice error={create.error} retry={() => create.reset()} />}
      <div className="actions">
        <button type="submit" disabled={create.isPending}>
          {create.isPending ? "Saving…" : "Save model"}
        </button>
      </div>
    </form>
  );
}

function Budgets() {
  const client = useQueryClient();
  const budget = useQuery({
    queryKey: ["budgets"],
    queryFn: () => api<RecordData>("/budgets"),
  });
  const [form, setForm] = useState<Record<string, string> | null>(null);
  const save = useMutation({
    mutationFn: (body: RecordData) => put<RecordData>("/budgets", body),
    onSuccess: () => client.invalidateQueries({ queryKey: ["budgets"] }),
  });
  if (budget.isPending) return <p role="status">Loading budgets…</p>;
  if (budget.error) return <ErrorNotice error={budget.error} retry={() => budget.refetch()} />;
  const current = budget.data!;
  const fields = ["task_usd", "day_usd", "month_usd", "agent_day_usd"];
  const values = form ?? Object.fromEntries(fields.map((f) => [f, String(current[f] ?? "")]));
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        save.mutate({
          task_usd: Number(values.task_usd),
          day_usd: Number(values.day_usd),
          month_usd: Number(values.month_usd),
          agent_day_usd: Number(values.agent_day_usd),
          max_model_calls: Number(current.max_model_calls ?? 0),
          max_input_tokens: Number(current.max_input_tokens ?? 0),
          max_output_tokens: Number(current.max_output_tokens ?? 0),
        } as unknown as RecordData);
      }}
    >
      {fields.map((field) => (
        <Input
          key={field}
          label={label(field)}
          type="number"
          step="any"
          value={values[field]}
          onChange={(e) => setForm({ ...values, [field]: e.target.value })}
        />
      ))}
      <p>
        <small>
          Ceilings also cap model calls ({text(current.max_model_calls)}), input
          tokens ({text(current.max_input_tokens)}) and output tokens (
          {text(current.max_output_tokens)}).
        </small>
      </p>
      {save.error && <ErrorNotice error={save.error} retry={() => save.reset()} />}
      <div className="actions">
        <button type="submit" disabled={save.isPending}>
          {save.isPending ? "Saving…" : "Save budgets"}
        </button>
      </div>
    </form>
  );
}

function ModelCalls() {
  const client = useQueryClient();
  const [cursor, setCursor] = useState<string | null>(null);
  const calls = useQuery({
    queryKey: ["model-calls", cursor],
    queryFn: () =>
      api<Page>(`/model-calls?limit=50${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
  });
  if (calls.isPending) return <p role="status">Loading model calls…</p>;
  if (calls.error) return <ErrorNotice error={calls.error} retry={() => calls.refetch()} />;
  const items = calls.data?.items ?? [];
  return (
    <>
      <h3>Recent model calls</h3>
      {!items.length ? (
        <Empty title="No model calls yet">Calls appear here once a task reaches a model.</Empty>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Model</th>
              <th scope="col">Task</th>
              <th scope="col">When</th>
            </tr>
          </thead>
          <tbody>
            {items.map((row) => (
              <tr key={row.id}>
                <th scope="row">{text(row.model)}</th>
                <td>{text(row.task_id)}</td>
                <td>{timestamp(row.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {calls.data?.next_cursor && (
        <button className="secondary" onClick={() => setCursor(calls.data!.next_cursor)}>
          Next page
        </button>
      )}
      {cursor && (
        <button className="quiet" onClick={() => setCursor(null)}>
          First page
        </button>
      )}
    </>
  );
}