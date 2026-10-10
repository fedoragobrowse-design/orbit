import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Link, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Menu,
  X,
  Home as HomeIcon,
  MessageSquare,
  ListTodo,
  Activity as ActivityIcon,
  BookOpen,
  Folder,
  Plug,
  Store,
  ShieldCheck,
  Workflow,
  Cpu,
  Settings as SettingsIcon,
  Users,
  Wrench,
} from "lucide-react";
import { api, post, queryClient, setSession, type Session } from "./api";
import { syncPushSubscription } from "./push";
import { ErrorNotice, Input } from "./ui";
import { Home, Tasks, TaskDetail, Activity, Settings } from "./workspace";
import { Chat, Agents } from "./chat";
import { Approvals } from "./approvals";
import { Memory, Automations } from "./knowledge";
import { Models } from "./models";
import { Marketplace } from "./marketplace";
import { Connections, Computers, Files } from "./connections";
import { Ops, GlobalSearch } from "./ops";
const DraftContext = createContext<{
  drafts: Record<string, string>;
  save: (key: string, value: string) => void;
}>({ drafts: {}, save: () => {} });
export function useDraft(key: string, initial = "") {
  const { drafts, save } = useContext(DraftContext);
  return [drafts[key] ?? initial, (value: string) => save(key, value)] as const;
}
const destinations = [
  [
    "Everyday work",
    [
      ["/", "Home", HomeIcon],
      ["/chat", "Chat", MessageSquare],
      ["/tasks", "Tasks", ListTodo],
      ["/approvals", "Approvals", ShieldCheck],
      ["/memory", "Memory", BookOpen],
      ["/files", "Files", Folder],
      ["/activity", "Activity", ActivityIcon],
    ],
  ],
  [
    "Setup and routines",
    [
      ["/automations", "Automations", Workflow],
      ["/agents", "Agents", Users],
      ["/connections", "Connections", Plug],
      ["/models", "Models", Cpu],
      ["/marketplace", "Marketplace", Store],
      ["/ops", "Ops", Wrench],
      ["/settings", "Settings", SettingsIcon],
    ],
  ],
] as const;
export function App() {
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [menu, setMenu] = useState(false);
  const [online, setOnline] = useState(navigator.onLine);
  const location = useLocation();
  const session = useQuery({
    queryKey: ["session"],
    queryFn: () => api<Session>("/auth/session"),
    retry: false,
  });
  const logout = useMutation({
    mutationFn: () => post("/auth/logout"),
    onSuccess: () => {
      setSession(null);
      setDrafts({});
      queryClient.clear();
      session.refetch();
    },
  });
  useEffect(() => {
    setSession(session.data ?? null);
  }, [session.data]);
  useEffect(() => {
    setMenu(false);
    document.getElementById("main")?.focus();
  }, [location.pathname]);
  useEffect(() => {
    const on = () => setOnline(true),
      off = () => setOnline(false);
    window.addEventListener("online", on);
    window.addEventListener("offline", off);
    return () => {
      window.removeEventListener("online", on);
      window.removeEventListener("offline", off);
    };
  }, []);
  useEffect(() => {
    if (!session.data) return;
    const stream = new EventSource("/api/v1/stream");
    stream.onmessage = () => queryClient.invalidateQueries({ predicate: (q) => q.queryKey[0] !== "session" });
    let cancelled = false;
    if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").then((reg) => { if (!cancelled) void syncPushSubscription(reg); }).catch(() => {});
    return () => { cancelled = true; stream.close(); };
  }, [session.data?.user.id]);
  if (session.isPending)
    return (
      <main className="auth">
        <h1>Orbit</h1>
        <p role="status">Opening your workspace…</p>
      </main>
    );
  if (!session.data)
    return (
      <Auth
        error={session.error}
        onAuthenticated={(s) => {
          setSession(s);
          queryClient.setQueryData(["session"], s);
        }}
      />
    );
  return (
    <DraftContext.Provider
      value={{
        drafts,
        save: (key, value) =>
          setDrafts((current) => ({ ...current, [key]: value })),
      }}
    >
      <a className="skip-link" href="#main">
        Skip to workspace
      </a>
      <header className="mobile-header">
        <Link className="brand" to="/">
          Orbit
        </Link>
        <button
          aria-label={menu ? "Close navigation" : "Open navigation"}
          aria-expanded={menu}
          aria-controls="navigation"
          onClick={() => setMenu(!menu)}
        >
          {menu ? <X size={20} /> : <Menu size={20} />}Menu
        </button>
      </header>
      <div className="shell">
        <aside className={`rail ${menu ? "open" : ""}`}>
          <Link className="brand" to="/">
            Orbit
          </Link>
          <nav id="navigation" aria-label="Main navigation">
            {destinations.map(([group, links]) => (
              <div className="nav-group" key={group}>
                <p>{group}</p>
                {links.map(([path, name, Icon]) => (
                  <NavLink key={path} to={path} end={path === "/"}>
                    <Icon size={18} />
                    {name}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
          <small>{session.data.user.display_name}</small>
          <button disabled={logout.isPending} onClick={() => logout.mutate()}>
            Sign out
          </button>
          {logout.error && <ErrorNotice error={logout.error} />}
        </aside>
        <main id="main" className="main" tabIndex={-1}>
          <GlobalSearch />
          {!online && (
            <div className="offline-banner" role="status">
              You are offline. Saved metadata may be stale; your unsent drafts
              remain here.
            </div>
          )}
          <Routes>
            <Route path="/" element={<Home />} />
            <Route path="/chat" element={<Chat />} />
            <Route path="/agents" element={<Agents />} />
            <Route path="/tasks" element={<Tasks />} />
            <Route path="/tasks/:id" element={<TaskDetail />} />
            <Route path="/activity" element={<Activity />} />
            <Route path="/activity/:id" element={<Activity />} />
            <Route path="/approvals" element={<Approvals />} />
            <Route path="/approvals/:id" element={<Approvals />} />
            <Route path="/memory" element={<Memory />} />
            <Route path="/memory/projects/:id" element={<Memory />} />
            <Route path="/automations" element={<Automations />} />
            <Route path="/models" element={<Models />} />
            <Route path="/marketplace" element={<Marketplace />} />
            <Route path="/connections/*" element={<Connections />} />
            <Route path="/computers" element={<Computers />} />
            <Route path="/files" element={<Files />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/ops" element={<Ops />} />
            <Route
              path="*"
              element={
                <>
                  <h1>Page not found</h1>
                  <Link to="/">Return home</Link>
                </>
              }
            />
          </Routes>
        </main>
      </div>
    </DraftContext.Provider>
  );
}
function Auth({
  error,
  onAuthenticated,
}: {
  error: unknown;
  onAuthenticated: (s: Session) => void;
}) {
  const [setup, setSetup] = useState(false);
  const status = useQuery({
    queryKey: ["auth-status"],
    queryFn: () => api<{ configured: boolean }>("/auth/status"),
    retry: false,
  });
  const needsSetup = status.data?.configured === false;
  const [values, setValues] = useState({
    setup_token: "",
    email: "",
    password: "",
    display_name: "",
  });
  const auth = useMutation({
    mutationFn: async () => {
      await post(
        `/auth/${setup ? "setup" : "login"}`,
        setup ? values : { email: values.email, password: values.password },
      );
      return api<Session>("/auth/session");
    },
    onSuccess: onAuthenticated,
  });
  return (
    <main className="auth panel">
      <span className="brand">Orbit</span>
      <h1>{setup ? "Create your workspace" : "Welcome back"}</h1>
      <p>
        {setup
          ? "Use the one-use setup token from your server to create the owner. Optional models and connections can be added afterward."
          : "Sign in to your personal workspace."}
      </p>
      <div className="auth-tabs">
        <button
          className="secondary"
          aria-pressed={!setup}
          onClick={() => setSetup(false)}
        >
          Sign in
        </button>
        {needsSetup && (
          <button
            className="secondary"
            aria-pressed={setup}
            onClick={() => setSetup(true)}
          >
            First-time setup
          </button>
        )}
      </div>
      <form
        onSubmit={(e) => {
          e.preventDefault();
          auth.mutate();
        }}
      >
        {setup && (
          <>
            <Input
              label="Setup token"
              required
              value={values.setup_token}
              autoComplete="off"
              onChange={(e) =>
                setValues({ ...values, setup_token: e.target.value })
              }
            />
            <Input
              label="Display name"
              required
              value={values.display_name}
              autoComplete="name"
              onChange={(e) =>
                setValues({ ...values, display_name: e.target.value })
              }
            />
          </>
        )}
        <Input
          label="Email"
          type="email"
          required
          autoComplete="username"
          value={values.email}
          onChange={(e) => setValues({ ...values, email: e.target.value })}
        />
        <Input
          label="Password"
          type="password"
          required
          autoComplete={setup ? "new-password" : "current-password"}
          value={values.password}
          onChange={(e) => setValues({ ...values, password: e.target.value })}
        />
        <button disabled={auth.isPending}>
          {auth.isPending ? "Opening…" : setup ? "Create owner" : "Sign in"}
        </button>
        {auth.error && <ErrorNotice error={auth.error} />}
      </form>
      {error instanceof Error &&
        !("status" in error && error.status === 401) && (
          <ErrorNotice error={error} />
        )}{" "}
      {setup && (
        <p className="muted">
          Get your token with <code>orbit-server bootstrap-token</code> on the
          server. Orbit does not expose it through this page.
        </p>
      )}
    </main>
  );
}
