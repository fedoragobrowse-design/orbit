/// First-run capability checklist for the owner-setup form.
///
/// Rendered before any session exists, so every row is static guidance —
/// no authenticated queries. After setup each source settles into one of
/// five states; the legend renders all five so the screen always shows
/// the full vocabulary.
///
/// New owners skip mail, Home Assistant, MCP, and desktop observation and
/// use Files and Chat immediately. Node pairing (TLS + daemon install)
/// stays the Computers-page host-rooted flow; this screen only points
/// at it.

export type SetupSourceState =
  | "connected"
  | "available"
  | "consent-needed"
  | "off"
  | "unsupported";

/// Every state the checklist can show, in legend order.
export const SETUP_STATES: SetupSourceState[] = [
  "connected",
  "available",
  "consent-needed",
  "off",
  "unsupported",
];

const STATE_LABEL: Record<SetupSourceState, string> = {
  connected: "Connected",
  available: "Available",
  "consent-needed": "Consent needed",
  off: "Off",
  unsupported: "Unsupported",
};

const STATE_TONE: Record<SetupSourceState, string> = {
  connected: "good",
  available: "good",
  "consent-needed": "pending",
  off: "",
  unsupported: "bad",
};

export function SetupStatePill({ state }: { state: SetupSourceState }) {
  const tone = STATE_TONE[state];
  return (
    <span className={tone ? `status ${tone}` : "status"}>
      {STATE_LABEL[state]}
    </span>
  );
}

type SetupSource = { name: string; state: SetupSourceState; blurb: string };

const USE_NOW: SetupSource[] = [
  {
    name: "Files",
    state: "available",
    blurb:
      "Your workspace folders. Open Files right after setup — nothing to connect first.",
  },
  {
    name: "Chat",
    state: "available",
    blurb:
      "Ask Orbit anything once a model is set on the Models page. Start here, with Files.",
  },
];

const SKIP_FOR_NOW: SetupSource[] = [
  {
    name: "Mail",
    state: "off",
    blurb:
      "Skip for now. Connect an inbox later under Connections → Email. Skipping loses nothing.",
  },
  {
    name: "Home Assistant",
    state: "off",
    blurb: "Skip for now. Add it later under Connections → Home Assistant.",
  },
  {
    name: "MCP plug-ins",
    state: "off",
    blurb: "Skip for now. Add servers later under Connections → MCP.",
  },
  {
    name: "Desktop observation",
    state: "off",
    blurb:
      "Off until you grant it per window on a paired machine (consent needed there). Machines without portal capture stay unsupported — Orbit never falls back to X11.",
  },
];

const ADD_LATER: SetupSource[] = [
  {
    name: "Computers",
    state: "available",
    blurb:
      "Pair extra machines later from the Computers page: mint a one-use code there, then run the daemon command on the machine over verified TLS.",
  },
];

function SetupGroup({
  title,
  sources,
}: {
  title: string;
  sources: SetupSource[];
}) {
  return (
    <>
      <h3>{title}</h3>
      <ul>
        {sources.map((source) => (
          <li key={source.name}>
            <SetupStatePill state={source.state} />{" "}
            <strong>{source.name}</strong> — {source.blurb}
          </li>
        ))}
      </ul>
    </>
  );
}

export function SetupChecklist() {
  return (
    <section aria-label="What to set up, and what to skip">
      <p className="muted">
        Every source shows one state:{" "}
        {SETUP_STATES.map((state, index) => (
          <span key={state}>
            {index > 0 && ", "}
            <SetupStatePill state={state} />
          </span>
        ))}
        . Start with Files and Chat; everything else can wait.
      </p>
      <SetupGroup title="Use immediately" sources={USE_NOW} />
      <SetupGroup title="Skip for now — connect later" sources={SKIP_FOR_NOW} />
      <SetupGroup title="When you add machines" sources={ADD_LATER} />
    </section>
  );
}
