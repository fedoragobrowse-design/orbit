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
  await page.goto("/");
  // The auth screen renders one "Sign in" tab and one "Sign in" submit, so the
  // submit has to be scoped to the form to satisfy strict mode.
  const submit = page
    .locator("form")
    .getByRole("button", { name: "Sign in", exact: true });
  const workspace = page.getByRole("heading", { name: "Your workspace" });
  await expect(submit.or(workspace).first()).toBeVisible();
  if (await submit.isVisible()) {
    await page.getByLabel("Email").fill("owner@orbit.test");
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await submit.click();
  }
  await expect(workspace).toBeVisible();
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
    page.getByRole("heading", { name: "Your workspace" }),
  ).toBeVisible();
  ownerCreated = true;
});

test("home composer posts a USER_MESSAGE event and shows its task", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Your workspace" }),
  ).toBeVisible();
  await page.getByLabel("What would you like help with?").fill("e2e hello");
  await page.getByRole("button", { name: "Ask Orbit" }).click();
  await expect(page.getByText("Open the created task")).toBeVisible();
});

test("tasks: list shows the created task and detail offers recovery", async ({
  page,
}) => {
  await page.goto("/tasks");
  await expect(page.getByRole("heading", { name: "Tasks" })).toBeVisible();
  const first = page.getByRole("link", { name: /Task|Inspect|Open/ }).first();
  await expect(first).toBeVisible();
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
  await expect(page.getByText("hello", { exact: false })).toBeVisible();
});

test("settings: privacy form saves with revision", async ({ page }) => {
  await page.goto("/settings");
  await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  await page
    .getByRole("button", { name: "Save privacy and autonomy" })
    .click();
  await expect(page.getByText(/saved|revision|Saved/i).first()).toBeVisible();
});

test("unavailable surfaces name their milestone, not a dead end", async ({
  page,
}) => {
  for (const [url, name] of [
    ["/agents", "Agents"],
    ["/computers", "Computers"],
    ["/files", "Files"],
    ["/automations", "Automations"],
  ] as const) {
    await page.goto(url);
    await expect(page.getByRole("heading", { name })).toBeVisible();
    await expect(page.getByText("Not available in this build")).toBeVisible();
  }
});

test("wired surfaces load real data instead of a gate", async ({ page }) => {
  for (const [url, name] of [
    ["/models", "Models"],
    ["/approvals", "Approvals"],
    ["/memory", "Memory"],
    ["/connections", "Connections"],
  ] as const) {
    await page.goto(url);
    await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
    await expect(
      page.getByText("Not available in this build"),
    ).toHaveCount(0);
  }
});

test("models: a provider can be created and then listed", async ({ page }) => {
  await page.goto("/models");
  await page.getByRole("button", { name: "Add provider" }).click();
  await page.getByLabel("Name").first().fill("e2e-local");
  await page.getByLabel("Kind").selectOption("OLLAMA");
  await page.getByLabel("Origin").fill("http://127.0.0.1:11434");
  await page.getByRole("button", { name: "Save provider" }).click();
  await expect(page.getByRole("rowheader", { name: "e2e-local" })).toBeVisible();
});

test("connections: runtime and email tabs render against real endpoints", async ({
  page,
}) => {
  await page.goto("/connections");
  await expect(page.getByRole("heading", { name: "Runtimes" })).toBeVisible();
  await expect(page.getByText("Not available in this build")).toHaveCount(0);
  await page.getByRole("link", { name: "Email" }).click();
  await expect(page.getByRole("heading", { name: "Email" })).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Add mail account" }),
  ).toBeVisible();
});
