import {
  lazy,
  Suspense,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import { Link, Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  AlarmClock,
  BellRing,
  BookOpen,
  Bookmark,
  Contact,
  CalendarDays,
  Cpu,
  Folder,
  Home as HomeIcon,
  HousePlug,
  ListTodo,
  Mail,
  Menu,
  MessageSquare,
  Monitor,
  Plug,
  Scissors,
  Settings as SettingsIcon,
  ShieldCheck,
  StickyNote,
  Store,
  Users,
  Workflow,
  Wrench,
  X,
  Activity as ActivityIcon,
} from "lucide-react";
import { api, post, queryClient, setSession, type Session } from "./api";
import { syncPushSubscription } from "./push";
import { ErrorNotice, Input } from "./ui";
import { SetupChecklist } from "./setup";
import { ObservationIndicator } from "./observation";
// Tab bundles split per route so the Pi serves a small first paint: the shell
// (Home/Chat/Tasks) loads first, heavier tabs load on navigation.
import { Home, Tasks, TaskDetail, Activity, Settings } from "./workspace";
import { Chat, Agents } from "./chat";
const Approvals = lazy(() => import("./approvals").then((m) => ({ default: m.Approvals })));
const Memory = lazy(() => import("./knowledge").then((m) => ({ default: m.Memory })));
const Automations = lazy(() => import("./knowledge").then((m) => ({ default: m.Automations })));
const DocPage = lazy(() => import("./knowledge").then((m) => ({ default: m.DocPage })));
const Models = lazy(() => import("./models").then((m) => ({ default: m.Models })));
const Marketplace = lazy(() => import("./marketplace").then((m) => ({ default: m.Marketplace })));
const Connections = lazy(() => import("./connections").then((m) => ({ default: m.Connections })));
const Computers = lazy(() => import("./connections").then((m) => ({ default: m.Computers })));
const Files = lazy(() => import("./connections").then((m) => ({ default: m.Files })));
const HomeAssistant = lazy(() => import("./connections").then((m) => ({ default: m.HomeAssistant })));
const Attention = lazy(() => import("./attention").then((m) => ({ default: m.Attention })));
const Notes = lazy(() => import("./content").then((m) => ({ default: m.Notes })));
const Inbox = lazy(() => import("./content").then((m) => ({ default: m.Inbox })));
const Reminders = lazy(() => import("./utility").then((m) => ({ default: m.Reminders })));
const Contacts = lazy(() => import("./utility").then((m) => ({ default: m.Contacts })));
const Bookmarks = lazy(() => import("./utility").then((m) => ({ default: m.Bookmarks })));
const Clips = lazy(() => import("./utility").then((m) => ({ default: m.Clips })));
const BrowserPage = lazy(() => import("./browser").then((m) => ({ default: m.BrowserPage })));
const TerminalPage = lazy(() => import("./terminal").then((m) => ({ default: m.TerminalPage })));
const Ops = lazy(() => import("./ops").then((m) => ({ default: m.Ops })));
const About = lazy(() => import("./ops").then((m) => ({ default: m.About })));
const GlobalSearch = lazy(() => import("./ops").then((m) => ({ default: m.GlobalSearch })));
import { DraftContext, FAMILIES } from "./nav";
function Logo() {
  return (
    <svg width="26" height="26" viewBox="0 0 128 128" aria-hidden="true">
      <circle cx="64" cy="64" r="14" fill="currentColor" />
      <ellipse cx="64" cy="64" rx="52" ry="22" fill="none" stroke="currentColor" strokeWidth="7" transform="rotate(-24 64 64)" />
      <ellipse cx="64" cy="64" rx="52" ry="22" fill="none" stroke="currentColor" strokeWidth="4" opacity="0.45" transform="rotate(38 64 64)" />
      <circle cx="108" cy="38" r="7" fill="currentColor" />
    </svg>
  );
}
function readHidden(): string[] {
  try {
    return JSON.parse(localStorage.getItem("orbit.nav.hidden") ?? "[]");
  } catch {
    return [];
  }
}
function SidebarFamily({ family }: { family: (typeof FAMILIES)[number] }) {
  const [hidden, setHidden] = useState<string[]>(readHidden);
  const [open, setOpen] = useState(() => {
    try {
      return localStorage.getItem(`orbit.nav.${family.id}`) !== "closed";
    } catch {
      return true;
    }
  });
  useEffect(() => {
    const on = () => setHidden(readHidden());
    window.addEventListener("storage", on);
    window.addEventListener("orbit-nav", on);
    return () => {
      window.removeEventListener("storage", on);
      window.removeEventListener("orbit-nav", on);
    };
  }, []);
  const visible = family.links.filter(([path]) => !hidden.includes(path as string));
  if (!visible.length) return null;
  return (
    <div className="nav-group">
      <p
        className="nav-group-label"
        role="button"
        tabIndex={0}
        aria-expanded={open}
        aria-label={`${open ? "Collapse" : "Expand"} ${family.title}`}
        onClick={() => {
          const next = !open;
          setOpen(next);
          try {
            localStorage.setItem(`orbit.nav.${family.id}`, next ? "open" : "closed");
          } catch { /* private mode */ }
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            const next = !open;
            setOpen(next);
            try {
              localStorage.setItem(`orbit.nav.${family.id}`, next ? "open" : "closed");
            } catch { /* private mode */ }
          }
        }}
      >
        <span>{family.title}</span>
        <span className="nav-group-caret" aria-hidden="true">{open ? "–" : "+"}</span>
      </p>
      {open &&
        visible.map(([path, name, Icon]) => (
          <NavLink key={path} to={path as string} end={path === "/"}>
            <Icon size={18} />
            {name}
          </NavLink>
        ))}
    </div>
  );
}
export function App() {
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  useEffect(() => {
    try {
      const vars = JSON.parse(localStorage.getItem("orbit.theme.custom") ?? "{}");
      const name = localStorage.getItem("orbit.theme") ?? "default";
      if (name !== "default" || Object.keys(vars).length) {
        for (const [k, v] of Object.entries(vars)) document.documentElement.style.setProperty(k, v as string);
      }
    } catch { /* private mode */ }
  }, []);
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
      <main className="auth boot-screen">
        <div className="boot-mark" aria-hidden="true">
          <span className="boot-orbit" />
          <span className="boot-orbit boot-orbit-2" />
          <span className="boot-core" />
        </div>
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
          <Logo /> Orbit
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
            <Logo /> Orbit
          </Link>
          <nav id="navigation" aria-label="Main navigation">
            {FAMILIES.map((family) => (
              <SidebarFamily key={family.id} family={family} />
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
          <ObservationIndicator />
          {!online && (
            <div className="offline-banner" role="status">
              You are offline. Saved metadata may be stale; your unsent drafts
              remain here.
            </div>
          )}
          <Suspense fallback={<div className="route-loading" role="status"><span className="route-spinner" aria-hidden="true" /><span>Loading…</span></div>}>
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
            <Route path="/memory/:id" element={<Memory />} />
            <Route path="/notes" element={<Notes />} />
            <Route path="/inbox" element={<Inbox />} />
            <Route path="/reminders" element={<Reminders />} />
            <Route path="/contacts" element={<Contacts />} />
            <Route path="/bookmarks" element={<Bookmarks />} />
            <Route path="/clips" element={<Clips />} />
            <Route path="/automations" element={<Automations />} />
            <Route path="/attention" element={<Attention />} />
            <Route path="/models" element={<Models />} />
            <Route path="/files" element={<Files />} />
            <Route path="/marketplace" element={<Marketplace />} />
            <Route path="/calendar" element={<Navigate to="/connections/calendars" replace />} />
            <Route path="/email" element={<Navigate to="/connections/email" replace />} />
            <Route path="/computers" element={<Computers />} />
            <Route path="/browser" element={<BrowserPage />} />
            <Route path="/terminal" element={<TerminalPage />} />
            <Route path="/home-assistant" element={<HomeAssistant />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="/about" element={<About />} />
            <Route path="/docs/:page" element={<DocPage />} />
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
          </Suspense>
        </main>
      </div>
    </DraftContext.Provider>
  );
}
function SetupEmail({ visible }: { visible: boolean }) {
  if (!visible) return null;
  return (
    <p className="muted">
      Mail is optional — leave this for later, or open Connections → Email
      after setup to connect an inbox. Skipping loses nothing.
    </p>
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
  const [forgot, setForgot] = useState(false);
  const status = useQuery({
    queryKey: ["auth-status"],
    queryFn: () => api<{ configured: boolean }>("/auth/status"),
    retry: false,
  });
  const needsSetup = status.data?.configured === false;
  useEffect(() => { if (needsSetup) setSetup(true); }, [needsSetup]);
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
  const [recoverValues, setRecoverValues] = useState({ email: "", recovery_code: "", new_password: "" });
  const [recovered, setRecovered] = useState(false);
  const recover = useMutation({
    mutationFn: () => post("/auth/recover", { email: recoverValues.email, recovery_code: recoverValues.recovery_code, new_password: recoverValues.new_password }),
    onSuccess: () => { setRecovered(true); setForgot(false); },
  });
  return (
    <main className="auth panel">
      <span className="brand">Orbit</span>
      <h1>{forgot ? "Reset your password" : setup ? "Create your workspace" : "Welcome back"}</h1>
      <p>
        {forgot
          ? "Reset with your one-time recovery code. It works once and expires 24 hours after it is made."
          : setup
            ? "Create the owner account for this server. You only do this once."
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
      {forgot ? (
        <form aria-label="Recover password" onSubmit={(e) => { e.preventDefault(); recover.mutate(); }}>
          <Input label="Email" type="email" required autoComplete="username" value={recoverValues.email} onChange={(e) => setRecoverValues({ ...recoverValues, email: e.target.value })} />
          <Input label="Recovery code" required autoComplete="off" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX" value={recoverValues.recovery_code} onChange={(e) => setRecoverValues({ ...recoverValues, recovery_code: e.target.value })} />
          <Input label="New password (12+ characters)" type="password" required autoComplete="new-password" minLength={12} value={recoverValues.new_password} onChange={(e) => setRecoverValues({ ...recoverValues, new_password: e.target.value })} />
          <ol className="muted">
            <li>Find your code: if you saved one from Settings → Password and recovery, use that.</li>
            <li>No saved code? On the server itself, run <code>docker exec orbit-server-1 orbit-server recovery-code</code> and use the code it prints. (Server access proves you are the owner — that is why this page never emails codes.)</li>
            <li>Type it below exactly as shown, dashes included.</li>
            <li>After reset, every session is signed out — sign in again with the new password, and make a fresh code in Settings.</li>
          </ol>
          <button disabled={recover.isPending || recoverValues.new_password.length < 12}>{recover.isPending ? "Resetting…" : "Reset password"}</button>
          {recover.error && <ErrorNotice error={recover.error} />}
          <div className="actions"><button type="button" className="secondary" onClick={() => setForgot(false)}>Back to sign in</button></div>
        </form>
      ) : (
      <form
        onSubmit={(e) => {
          e.preventDefault();
          auth.mutate();
        }}
      >
        {setup && <SetupChecklist />}
        <SetupEmail visible={setup} />
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
      )}
      {!forgot && !setup && (
        <div className="actions"><button type="button" className="secondary" onClick={() => setForgot(true)}>Forgot password?</button></div>
      )}
      {recovered && <p role="status">Password reset. Sign in with your new password.</p>}
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
