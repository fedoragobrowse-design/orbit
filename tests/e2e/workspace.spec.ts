import { test, expect } from "@playwright/test";

// Serial M1 journey against the isolated orbit-test deployment
// (tests/e2e/run-server.mjs owns lifecycle; this file never touches a
// personal server and resets only the E2E database via that harness).
//
// Uses the fresh CLI setup token from global-setup (ORBIT_E2E_SETUP_TOKEN)
// to complete first-time setup, then exercises every backed surface.

const PASSWORD = "orbit-e2e-owner-123";

test.describe.configure({ mode: "serial" });

// Playwright hands each test a fresh browser context, so the session cookie
// minted during setup is gone by the second test. Serial order guarantees the
// owner exists by then, so every later test signs back in through the real
// login form. Before setup there is no owner to sign in as, so the flag stays
// false and the onboarding test does the creating.
let ownerCreated = false;

test.beforeEach(async ({ page }) => {
  if (!ownerCreated) return;
  page.on("response", async (r) => {
    if (r.url().includes("/api/v1/auth/"))
      console.log(
        "AUTHDEBUG",
        r.request().method(),
        r.url().split("/api/v1")[1],
        r.status(),
        (await r.text().catch(() => "")).slice(0, 120),
        JSON.stringify(r.request().headers()["x-csrf-token"] ?? null),
      );
  });
  await page.goto("/");
  // The auth screen renders one "Sign in" tab and one "Sign in" submit, so the
  // submit has to be scoped to the form to satisfy strict mode.
  const submit = page
    .locator("form")
    .getByRole("button", { name: "Sign in", exact: true });
  const workspace = page.getByRole("heading", { name: "Your workspace", exact: true });
  await expect(submit.or(workspace).first()).toBeVisible();
  if (await submit.isVisible()) {
    await page.getByLabel("Email").fill("owner@orbit.test");
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await submit.click();
  }
  await expect(workspace, "sign-in lands on Home").toBeVisible({ timeout: 15000 });
});

test("onboarding: setup creates the owner and lands on Home", async ({
  page,
}) => {
  const token = process.env.ORBIT_E2E_SETUP_TOKEN;
  expect(token, "setup token from global-setup").toBeTruthy();
  await page.goto("/");
  await page.getByRole("button", { name: "First-time setup" }).click();
  await page.getByLabel("Setup token").fill(token!);
  await page.getByLabel("Email").fill("owner@orbit.test");
  await page.getByLabel("Display name").fill("Owner");
  await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  await page.getByRole("button", { name: "Create owner" }).click();
  await expect(
    page.getByRole("heading", { name: "Your workspace", exact: true }),
    "owner setup lands on Home",
  ).toBeVisible({ timeout: 15000 });
  // The Home composer only renders post-login (the Auth screen has no such
  // label), so this proves setup really minted the session instead of
  // vacuously matching the Auth screen's own "Create your workspace" h1.
  await expect(
    page.getByLabel("What would you like help with?"),
  ).toBeVisible();
  ownerCreated = true;
});

test("home composer posts a USER_MESSAGE event and shows its task", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Your workspace", exact: true }),
  ).toBeVisible();
  await page.getByLabel("What would you like help with?").fill("e2e hello");
  await page.getByRole("button", { name: "Ask Orbit" }).click();
  // NOTE: onSuccess navigates to /tasks immediately, so the inline
  // "Recorded." marker on Home unmounts on navigation; assert the
  // navigation plus a task row link (the composer-created USER_MESSAGE
  // task) instead.
  await expect(page).toHaveURL(/\/tasks$/);
  await expect(
    page.getByRole("heading", { name: "Tasks", exact: true }),
  ).toBeVisible();
  // Task creation is async (event → classifier → task row, ~1s); the list
  // fetch predates the POST and Resource has no refetch, so poll with
  // reload until the composer-created task appears.
  await expect(async () => {
    await page.reload();
    await expect(
      page.getByRole("link", { name: "Message received" }).first(),
    ).toBeVisible({ timeout: 5000 });
  }, "composer-created task appears in list").toPass({ timeout: 30000 });
});

test("tasks: list shows the created task and detail offers recovery", async ({
  page,
}) => {
  await page.goto("/tasks");
  await expect(page.getByRole("heading", { name: "Tasks", exact: true })).toBeVisible();
  const first = page.getByRole("link", { name: "Message received" }).first();
  await expect(first, "created task listed").toBeVisible();
  await first.click();
  await expect(page).toHaveURL(/\/tasks\//);
  // RUNNING composer task exposes CANCEL ("Cancel task") per the API.
  await expect(
    page.getByRole("button", { name: "Cancel task" }),
    "detail offers recovery",
  ).toBeVisible();
});

test("activity: list renders classified events", async ({ page }) => {
  await page.goto("/activity");
  await expect(page.getByRole("heading", { name: "Activity" })).toBeVisible();
});

 test("chat: composer creates a conversation event", async ({ page }) => {
   await page.goto("/chat");
   await expect(page.getByRole("heading", { name: "Chat" })).toBeVisible();
   await page.getByLabel("Message Orbit").fill("e2e chat hello");
   await page.getByRole("button", { name: "Send message" }).click();
   // onSuccess sets ?conversation=<event id> and the detail query renders
   // the posted message text; that URL + text proves the event persisted.
   await expect(page).toHaveURL(/\/chat\?conversation=/);
  await expect(
    page.getByRole("heading", { name: "e2e chat hello" }),
  ).toBeVisible();
 });

test("settings: privacy form saves with revision", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await page
    .getByRole("button", { name: "Save privacy and autonomy" })
    .click();
  await expect(page.getByText(/saved|revision|Saved/i).first()).toBeVisible();
});

test("still-unavailable surfaces name their gap, not a dead end", async ({
  page,
}) => {
  for (const [url, name] of [
    ["/connections/calendars", "Calendars"],
    ["/connections/github", "GitHub"],
    ["/connections/home-assistant", "Home Assistant"],
    ["/connections/api", "API"],
  ] as const) {
    await page.goto(url);
    await expect(
      page.getByRole("heading", { name, exact: true }),
    ).toBeVisible();
    await expect(page.getByText("Not available in this build")).toBeVisible();
  }
});

test("wired surfaces load real data instead of a gate", async ({ page }) => {
  for (const [url, name] of [
    ["/models", "Models"],
    ["/approvals", "Approvals"],
    ["/memory", "Memory"],
    ["/connections", "Connections"],
    ["/agents", "Agents"],
    ["/computers", "Computers"],
    ["/files", "Files"],
    ["/automations", "Automations"],
  ] as const) {
    await page.goto(url);
    await expect(page.locator("h1", { hasText: name })).toBeVisible();
    await expect(
      page.getByText("Not available in this build"),
    ).toHaveCount(0);
  }
});

 test("models: provider form surfaces backend validation", async ({ page }) => {
   await page.goto("/models");
   await page.getByRole("button", { name: "Add provider" }).click();
   await page.getByLabel("Name").first().fill("e2e-local");
   await page.getByLabel("Kind").selectOption("OLLAMA");
   await page.getByLabel("Origin").fill("http://127.0.0.1:11434");
   await page.getByRole("button", { name: "Save provider" }).click();
   // The backend rejects local providers without an admitted address
   // (422 VALIDATION) in this build; the form surfaces that error instead
   // of a row. Assert the surfaced validation, proving the round-trip.
   await expect(page.getByText(/admitted address/i)).toBeVisible();
 });

test("connections: runtime and email tabs render against real endpoints", async ({
  page,
}) => {
  await page.goto("/connections");
  await expect(page.locator("h1", { hasText: "Connections" })).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Runtimes", exact: true }),
  ).toBeVisible();
  await expect(page.getByText("Not available in this build")).toHaveCount(0);
  await page
    .locator('nav[aria-label="Connection categories"]')
    .getByRole("link", { name: "Email" })
    .click();
  await expect(page).toHaveURL(/\/connections\/email$/);
  await expect(
    page.getByRole("heading", { name: "Email", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Add mail account" }),
  ).toBeVisible();
});

// One login covers all four write paths: the per-email rate gate (10
// attempts/15min) counts every serial sign-in, so separate tests would trip
// it. Same assertions, one session.
test("wired write paths persist (agents, automations, computers, retention)", async ({
  page,
}) => {
  await test.step("agents: create persists a row", async () => {
    await page.goto("/agents");
    await expect(page.locator("h1", { hasText: "Agents" })).toBeVisible();
    await page.getByRole("button", { name: "Add agent" }).click();
    await page.getByLabel("Name").fill("e2e-agent");
    await page.getByLabel("Purpose").fill("e2e purpose");
    await page.getByLabel("Instructions").fill("e2e instructions");
    await page.getByRole("button", { name: "Save agent" }).click();
    await expect(
      page.getByRole("rowheader", { name: "e2e-agent" }),
    ).toBeVisible();
  });

  await test.step("automations: create and toggle persist", async () => {
    await page.goto("/automations");
    await expect(page.locator("h1", { hasText: "Automations" })).toBeVisible();
    await page.getByRole("button", { name: "Add automation" }).click();
    await page.getByLabel("Instructions").fill("e2e automation instructions");
    await page.getByRole("button", { name: "Save automation" }).click();
    const row = page.getByRole("row", {
      name: /e2e automation instructions/,
    });
    await expect(row).toBeVisible();
    await row.getByRole("button", { name: "Disable" }).click();
    await expect(
      row.getByRole("button", { name: "Enable" }),
    ).toBeVisible();
  });

  await test.step("computers: pairing code round-trip", async () => {
    await page.goto("/computers");
    await expect(
      page.getByRole("heading", { name: "Paired machines" }),
    ).toBeVisible();
    await page.getByRole("button", { name: "Create pairing code" }).click();
    await expect(page.getByText("Pairing code:")).toBeVisible();
  });

  await test.step("settings: retention form loads real values", async () => {
    await page.goto("/settings");
    await expect(
      page.getByRole("heading", { name: "Retention" }),
    ).toBeVisible();
    await expect(page.getByText("Not available in this build")).toHaveCount(0);
  });
});
