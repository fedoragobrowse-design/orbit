import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, post, put, remove, text, timestamp, label, type Page, type RecordData } from "./api";
import { Empty, ErrorNotice, Field, Input, PageHeader, Resource, Select, Status } from "./ui";

type Settings = { installation_mode?: unknown };

const PROVIDER_PRESETS: { kind: string; label: string; origin: string; local: boolean }[] = [
  { kind: "OLLAMA", label: "Ollama (local)", origin: "http://ollama:11434", local: true },
  { kind: "OPENAI_COMPATIBLE", label: "OpenAI", origin: "https://api.openai.com/v1", local: false },
  { kind: "ANTHROPIC", label: "Anthropic", origin: "https://api.anthropic.com", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "OpenRouter", origin: "https://openrouter.ai/api/v1", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "Together", origin: "https://api.together.xyz/v1", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "Groq", origin: "https://api.groq.com/openai/v1", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "Mistral", origin: "https://api.mistral.ai/v1", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "DeepSeek", origin: "https://api.deepseek.com/v1", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "xAI", origin: "https://api.x.ai/v1", local: false },
  { kind: "GEMINI", label: "Gemini", origin: "https://generativelanguage.googleapis.com", local: false },
  { kind: "OPENAI_COMPATIBLE", label: "Custom (OpenAI-compatible)", origin: "https://", local: false },
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
      <DecisionModels />
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
/// Which model answers each kind of job. The router picks the enabled model
/// with the lowest priority number carrying the role, so choosing here sets
/// the winner to priority 0 and bumps the rest. FAST is the chat decider:
/// it answers plain chat and classifies what needs a task.
const DECISION_ROLES: { role: string; blurb: string }[] = [
  { role: "FAST", blurb: "Chat replies and quick decisions" },
  { role: "REASONING", blurb: "Hard thinking, plans, judgment calls" },
  { role: "CODING", blurb: "Writing and changing code" },
  { role: "PRIVATE", blurb: "Sensitive text that stays local" },
  { role: "VISION", blurb: "Images and screenshots" },
  { role: "EMBEDDING", blurb: "Memory search" },
];
function DecisionModels() {
  const client = useQueryClient();
  const save = useMutation({
    mutationFn: async ({ role, winner }: { role: string; winner: RecordData }) => {
      const all = await api<{ items: RecordData[] }>("/models?limit=100").then((p) => p.items);
      const rivals = all.filter((m) => m.id !== winner.id && Array.isArray(m.roles) && (m.roles as unknown[]).map(label).includes(role));
      const carried: string[] = Array.isArray(winner.roles) ? (winner.roles as unknown[]).map(label) : [];
      const nextRoles = carried.includes(role) ? carried : [...carried, role];
      await put(`/models/${winner.id}`, { roles: nextRoles, priority: 0, expected_revision: winner.revision });
      for (const rival of rivals) {
        await put(`/models/${rival.id}`, { priority: 100, expected_revision: rival.revision });
      }
    },
    onSuccess: () => client.invalidateQueries({ queryKey: ["models"] }),
  });
  return (
    <section className="section" aria-label="Which model does what">
      <div className="panel">
        <h2>Which model does what</h2>
        <p className="muted">Pick the model that answers each kind of job. Chat and quick decisions use FAST.</p>
        <Resource path="/models" empty={<Empty title="No models yet">Add a provider and a model first.</Empty>}>
          {(items) => (
            <div className="grid">
              {DECISION_ROLES.map(({ role, blurb }) => {
                const carriers = items.filter((m) => Array.isArray(m.roles) && (m.roles as unknown[]).map(label).includes(role));
                const current = [...carriers].sort((a, b) => Number(a.priority ?? 100) - Number(b.priority ?? 100))[0];
                return (
                  <Select key={role} label={`${label(role)} — ${blurb}`} value={String(current?.id ?? "")} onChange={(e) => { const winner = items.find((m) => String(m.id) === e.target.value); if (winner) save.mutate({ role, winner }); }} disabled={save.isPending || !items.length}>
                    {!current && <option value="">No model carries {label(role)} yet</option>}
                    {items.map((m) => (
                      <option key={m.id} value={String(m.id)}>{text(m.name)}{carriers.some((c) => c.id === m.id) ? "" : " (will gain this job)"}</option>
                    ))}
                  </Select>
                );
              })}
            </div>
          )}
        </Resource>
        {save.error && <ErrorNotice error={save.error} retry={() => save.reset()} />}
      </div>
    </section>
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
  const [open, setOpen] = useState(false);
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
                  <ProviderRow key={row.id} row={row} />
                ))}
              </tbody>
            </table>
          )}
        </Resource>
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

function ProviderRow({ row }: { row: RecordData }) {
  const client = useQueryClient();
  const [open, setOpen] = useState(false);
  const [credential, setCredential] = useState("");
  const removeProvider = useMutation({
    mutationFn: () => remove(`/providers/${row.id}`),
    onSuccess: () => client.invalidateQueries({ queryKey: ["providers"] }),
  });
  const rotate = useMutation({
    mutationFn: () =>
      post<RecordData>(`/providers/${row.id}/credential`, {
        credential,
        expected_revision: row.revision,
      }),
    onSuccess: async () => {
      setCredential("");
      setOpen(false);
      await client.invalidateQueries({ queryKey: ["providers"] });
    },
  });
  const test = useMutation({
    mutationFn: () => post<RecordData>(`/providers/${row.id}/test`, {}),
  });
  return (
    <>
      <tr>
        <th scope="row">{text(row.name)}</th>
        <td>{label(row.kind)}</td>
        <td>{text(row.origin)}</td>
        <td>{row.secret_set ? "Set" : "None"}</td>
        <td><Status value={row.enabled} /></td>
        <td>{text(row.revision)}</td>
        <td>
          <button
            className="secondary"
            onClick={() => {
              setCredential("");
              rotate.reset();
              test.reset();
              setOpen(!open);
            }}
          >
            {open ? "Close" : "Key"}
          </button>{" "}
          <button
            className="danger"
            disabled={removeProvider.isPending}
            onClick={() => removeProvider.mutate()}
          >
            Remove
          </button>
        </td>
      </tr>
      {open && (
        <tr>
          <td colSpan={7}>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                rotate.mutate();
              }}
            >
              <Input
                label={`Rotate key for ${text(row.name)}`}
                type="password"
                autoComplete="new-password"
                placeholder="New API key (write-only, never shown again)"
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
              />
              {rotate.error && <ErrorNotice error={rotate.error} retry={() => rotate.reset()} />}
              {rotate.isSuccess && <p role="status">Key saved.</p>}
              {test.data && <p role="status">Test call accepted.</p>}
              {test.error && <ErrorNotice error={test.error} retry={() => test.reset()} />}
              <div className="actions">
                <button type="submit" disabled={rotate.isPending || !credential}>
                  {rotate.isPending ? "Saving…" : "Save key"}
                </button>{" "}
                <button
                  type="button"
                  className="secondary"
                  disabled={test.isPending}
                  onClick={() => test.mutate()}
                >
                  {test.isPending ? "Testing…" : "Test"}
                </button>
              </div>
            </form>
            {String(row.kind) === "OLLAMA" && (<LocalModels id={String(row.id)} name={text(row.name)} />)}
            {removeProvider.error && (
              <ErrorNotice error={removeProvider.error} retry={() => removeProvider.reset()} />
            )}
          </td>
        </tr>
      )}
    </>
  );
}
/// Per-provider spend caps. Same dollars as the global budgets, scoped to the
/// one endpoint; zero means uncapped. The router refuses with "provider model
/// cost budget exhausted" once the day or month cap would be exceeded.
function ProviderBudget({ id, name }: { id: string; name: string }) {
  const budget = useQuery({ queryKey: ["provider-budget", id], queryFn: () => api<RecordData>(`/providers/${id}/budget`) });
  const save = useMutation({
    mutationFn: (body: RecordData) => put<RecordData>(`/providers/${id}/budget`, body),
    onSuccess: () => budget.refetch(),
  });
  const [form, setForm] = useState<{ day: string; month: string } | null>(null);
  if (budget.isPending) return (<p role="status"><small>Loading caps…</small></p>);
  if (budget.error) return (<ErrorNotice error={budget.error} retry={() => budget.refetch()} />);
  const values = form ?? { day: String(budget.data!.day_usd ?? 0), month: String(budget.data!.month_usd ?? 0) };
  return (
    <form
      className="grid"
      aria-label={`Spend caps for ${name}`}
      onSubmit={(e) => {
        e.preventDefault();
        save.mutate({ day_usd: Number(values.day), month_usd: Number(values.month) } as unknown as RecordData);
      }}
    >
      <Input label="Day cap USD (0 = none)" type="number" step="any" value={values.day} onChange={(e) => setForm({ ...values, day: e.target.value })} />
      <Input label="Month cap USD (0 = none)" type="number" step="any" value={values.month} onChange={(e) => setForm({ ...values, month: e.target.value })} />
      {save.error && (<ErrorNotice error={save.error} retry={() => save.reset()} />)}
      <div className="actions">
        <button className="secondary" type="submit" disabled={save.isPending}>{save.isPending ? "Saving…" : "Save caps"}</button>
      </div>
    </form>
  );
}
/// Local model manager (growth D16). Installed list + pull + benchmark for
/// one OLLAMA provider. Unreachable daemon surfaces the server error, never
/// a faked empty list.
function LocalModels({ id, name }: { id: string; name: string }) {
  const client = useQueryClient();
  const installed = useQuery({ queryKey: ["local-models", id], queryFn: () => api<RecordData>(`/providers/${id}/local/models`) });
  const [pullName, setPullName] = useState("");
  const [benchName, setBenchName] = useState("");
  const pull = useMutation({ mutationFn: () => post<RecordData>(`/providers/${id}/local/pull`, { name: pullName }), onSuccess: () => { setPullName(""); client.invalidateQueries({ queryKey: ["local-models", id] }); } });
  const bench = useMutation({ mutationFn: () => post<RecordData>(`/providers/${id}/local/benchmark`, { model: benchName }) });
  const rows = (installed.data?.models as RecordData[] | undefined) ?? [];
  return (
    <section aria-label={`Local models on ${name}`}>
      <h3>Local models</h3>
      {installed.isPending ? (<p role="status"><small>Reading daemon…</small></p>)
        : installed.error ? (<ErrorNotice error={installed.error} retry={() => installed.refetch()} />)
        : !rows.length ? (<p className="muted">Daemon reachable, nothing installed yet.</p>)
        : (<ul>{rows.map((m) => (<li key={text(m.name)}>{text(m.name)}</li>))}</ul>)}
      {(pull.error ?? bench.error) && (<ErrorNotice error={(pull.error ?? bench.error) as Error} retry={() => { pull.reset(); bench.reset(); }} />)}
      {pull.data && (<p role="status">Pull: {text((pull.data as RecordData).status)}.</p>)}
      {bench.data && (<p role="status">Benchmark {text((bench.data as RecordData).model)}: {text((bench.data as RecordData).elapsed_ms)} ms wall{typeof (bench.data as RecordData).daemon_total_ms === "number" ? `, ${text((bench.data as RecordData).daemon_total_ms)} ms daemon` : ""}.</p>)}
      <form className="grid" aria-label={`Pull a model on ${name}`} onSubmit={(e) => { e.preventDefault(); pull.mutate(); }}>
        <Input label="Pull model (e.g. gemma3:4b)" value={pullName} onChange={(e) => setPullName(e.target.value)} required maxLength={256} placeholder="gemma3:4b" />
        <div className="actions"><button className="secondary" type="submit" disabled={!pullName.trim() || pull.isPending}>{pull.isPending ? "Pulling…" : "Pull"}</button></div>
      </form>
      <form className="grid" aria-label={`Benchmark a model on ${name}`} onSubmit={(e) => { e.preventDefault(); bench.mutate(); }}>
        <Input label="Benchmark model" value={benchName} onChange={(e) => setBenchName(e.target.value)} required maxLength={256} placeholder="gemma3:4b" />
        <div className="actions"><button className="secondary" type="submit" disabled={!benchName.trim() || bench.isPending}>{bench.isPending ? "Running…" : "Benchmark"}</button></div>
      </form>
    </section>
  );
}

function NewProvider({ onDone }: { onDone: () => void }) {
  const client = useQueryClient();
  const [preset, setPreset] = useState(0);
  const [form, setForm] = useState({
    name: "",
    kind: PROVIDER_PRESETS[0].kind,
    origin: PROVIDER_PRESETS[0].origin,
    local: PROVIDER_PRESETS[0].local,
    credential: "",
  });
  const pick = (index: number) => {
    const p = PROVIDER_PRESETS[index];
    setPreset(index);
    setForm((f) => ({ ...f, kind: p.kind, origin: p.origin, local: p.local }));
  };
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
      <Select
        label="Provider"
        value={String(preset)}
        onChange={(e) => pick(Number(e.target.value))}
      >
        {PROVIDER_PRESETS.map((p, i) => (
          <option key={p.label} value={String(i)}>
            {p.label}
          </option>
        ))}
      </Select>
      <Input
        label="Name"
        required
        placeholder={PROVIDER_PRESETS[preset].label}
        value={form.name}
        onChange={(e) => setForm({ ...form, name: e.target.value })}
      />
      <Input
        label="Origin"
        required
        placeholder={PROVIDER_PRESETS[preset].origin}
        value={form.origin}
        onChange={(e) => setForm({ ...form, origin: e.target.value })}
      />
      <p className="muted">
        Picking a provider fills in its address; edit it if you self-host.
      </p>
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