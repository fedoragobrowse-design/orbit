# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: workspace.spec.ts >> home composer posts a USER_MESSAGE event and shows its task
- Location: ../../tests/e2e/workspace.spec.ts:57:5

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: getByRole('heading', { name: 'Your workspace' })
Expected: visible
Timeout: 5000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" getByRole('heading', { name: 'Your workspace' }) with timeout 5000ms
  - waiting for getByRole('heading', { name: 'Your workspace' })

```

```yaml
- main:
  - text: Orbit
  - heading "Welcome back" [level=1]
  - paragraph: Sign in to your personal workspace.
  - button "Sign in" [pressed]
  - button "First-time setup"
  - text: Email
  - textbox "Email": owner@orbit.test
  - text: Password
  - textbox "Password": orbit-e2e-owner-123
  - button "Sign in"
  - alert:
    - img
    - strong: Unauthorized
    - paragraph: authentication required
    - text: "Request reference: 79e0c677-8150-41a6-ad69-2891642aa295"
```

# Test source

```ts
  1   | import { test, expect } from "@playwright/test";
  2   | 
  3   | // Serial M1 journey against the isolated orbit-test deployment
  4   | // (tests/e2e/run-server.mjs owns lifecycle; this file never touches a
  5   | // personal server and resets only the E2E database via that harness).
  6   | //
  7   | // Uses the fresh CLI setup token from global-setup (ORBIT_E2E_SETUP_TOKEN)
  8   | // to complete first-time setup, then exercises every backed surface.
  9   | 
  10  | const PASSWORD = "orbit-e2e-owner-123";
  11  | 
  12  | test.describe.configure({ mode: "serial" });
  13  | 
  14  | // Playwright hands each test a fresh browser context, so the session cookie
  15  | // minted during setup is gone by the second test. Serial order guarantees the
  16  | // owner exists by then, so every later test signs back in through the real
  17  | // login form. Before setup there is no owner to sign in as, so the flag stays
  18  | // false and the onboarding test does the creating.
  19  | let ownerCreated = false;
  20  | 
  21  | test.beforeEach(async ({ page }) => {
  22  |   if (!ownerCreated) return;
  23  |   await page.goto("/");
  24  |   // The auth screen renders one "Sign in" tab and one "Sign in" submit, so the
  25  |   // submit has to be scoped to the form to satisfy strict mode.
  26  |   const submit = page
  27  |     .locator("form")
  28  |     .getByRole("button", { name: "Sign in", exact: true });
  29  |   const workspace = page.getByRole("heading", { name: "Your workspace" });
  30  |   await expect(submit.or(workspace).first()).toBeVisible();
  31  |   if (await submit.isVisible()) {
  32  |     await page.getByLabel("Email").fill("owner@orbit.test");
  33  |     await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  34  |     await submit.click();
  35  |   }
> 36  |   await expect(workspace).toBeVisible();
      |                           ^ Error: expect(locator).toBeVisible() failed
  37  | });
  38  | 
  39  | test("onboarding: setup creates the owner and lands on Home", async ({
  40  |   page,
  41  | }) => {
  42  |   const token = process.env.ORBIT_E2E_SETUP_TOKEN;
  43  |   expect(token, "setup token from global-setup").toBeTruthy();
  44  |   await page.goto("/");
  45  |   await page.getByRole("button", { name: "First-time setup" }).click();
  46  |   await page.getByLabel("Setup token").fill(token!);
  47  |   await page.getByLabel("Email").fill("owner@orbit.test");
  48  |   await page.getByLabel("Display name").fill("Owner");
  49  |   await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
  50  |   await page.getByRole("button", { name: "Create owner" }).click();
  51  |   await expect(
  52  |     page.getByRole("heading", { name: "Your workspace" }),
  53  |   ).toBeVisible();
  54  |   ownerCreated = true;
  55  | });
  56  | 
  57  | test("home composer posts a USER_MESSAGE event and shows its task", async ({
  58  |   page,
  59  | }) => {
  60  |   await page.goto("/");
  61  |   await expect(
  62  |     page.getByRole("heading", { name: "Your workspace" }),
  63  |   ).toBeVisible();
  64  |   await page.getByLabel("What would you like help with?").fill("e2e hello");
  65  |   await page.getByRole("button", { name: "Ask Orbit" }).click();
  66  |   await expect(page.getByText("Open the created task")).toBeVisible();
  67  | });
  68  | 
  69  | test("tasks: list shows the created task and detail offers recovery", async ({
  70  |   page,
  71  | }) => {
  72  |   await page.goto("/tasks");
  73  |   await expect(page.getByRole("heading", { name: "Tasks" })).toBeVisible();
  74  |   const first = page.getByRole("link", { name: /Task|Inspect|Open/ }).first();
  75  |   await expect(first).toBeVisible();
  76  | });
  77  | 
  78  | test("activity: list renders classified events", async ({ page }) => {
  79  |   await page.goto("/activity");
  80  |   await expect(page.getByRole("heading", { name: "Activity" })).toBeVisible();
  81  | });
  82  | 
  83  | test("chat: composer creates a conversation event", async ({ page }) => {
  84  |   await page.goto("/chat");
  85  |   await expect(page.getByRole("heading", { name: "Chat" })).toBeVisible();
  86  |   await page.getByLabel("Message Orbit").fill("e2e chat hello");
  87  |   await page.getByRole("button", { name: "Send message" }).click();
  88  |   await expect(page.getByText("hello", { exact: false })).toBeVisible();
  89  | });
  90  | 
  91  | test("settings: privacy form saves with revision", async ({ page }) => {
  92  |   await page.goto("/settings");
  93  |   await expect(page.getByRole("heading", { name: "Settings" })).toBeVisible();
  94  |   await page
  95  |     .getByRole("button", { name: "Save privacy and autonomy" })
  96  |     .click();
  97  |   await expect(page.getByText(/saved|revision|Saved/i).first()).toBeVisible();
  98  | });
  99  | 
  100 | test("unavailable surfaces name their milestone, not a dead end", async ({
  101 |   page,
  102 | }) => {
  103 |   for (const [url, name] of [
  104 |     ["/agents", "Agents"],
  105 |     ["/computers", "Computers"],
  106 |     ["/files", "Files"],
  107 |     ["/automations", "Automations"],
  108 |   ] as const) {
  109 |     await page.goto(url);
  110 |     await expect(page.getByRole("heading", { name })).toBeVisible();
  111 |     await expect(page.getByText("Not available in this build")).toBeVisible();
  112 |   }
  113 | });
  114 | 
  115 | test("wired surfaces load real data instead of a gate", async ({ page }) => {
  116 |   for (const [url, name] of [
  117 |     ["/models", "Models"],
  118 |     ["/approvals", "Approvals"],
  119 |     ["/memory", "Memory"],
  120 |     ["/connections", "Connections"],
  121 |   ] as const) {
  122 |     await page.goto(url);
  123 |     await expect(page.getByRole("heading", { name, exact: true })).toBeVisible();
  124 |     await expect(
  125 |       page.getByText("Not available in this build"),
  126 |     ).toHaveCount(0);
  127 |   }
  128 | });
  129 | 
  130 | test("models: a provider can be created and then listed", async ({ page }) => {
  131 |   await page.goto("/models");
  132 |   await page.getByRole("button", { name: "Add provider" }).click();
  133 |   await page.getByLabel("Name").first().fill("e2e-local");
  134 |   await page.getByLabel("Kind").selectOption("OLLAMA");
  135 |   await page.getByLabel("Origin").fill("http://127.0.0.1:11434");
  136 |   await page.getByRole("button", { name: "Save provider" }).click();
```