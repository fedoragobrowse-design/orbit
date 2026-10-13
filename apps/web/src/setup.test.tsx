/** @vitest-environment jsdom */
import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { SetupChecklist } from "./setup";

test("setup checklist renders every capability state", () => {
  render(<SetupChecklist />);
  for (const label of [
    "Connected",
    "Available",
    "Consent needed",
    "Off",
    "Unsupported",
  ]) {
    expect(
      screen.getAllByText(label).length,
      `state ${label} renders`,
    ).toBeGreaterThan(0);
  }
});

test("setup checklist says to skip mail and start with Files and Chat", () => {
  render(<SetupChecklist />);
  expect(screen.getAllByText("Use immediately").length).toBeGreaterThan(0);
  expect(screen.getAllByText("Skip for now — connect later").length).toBeGreaterThan(0);
  expect(screen.getAllByText(/Connections → Email/).length).toBeGreaterThan(0);
  expect(screen.getAllByText(/verified TLS/).length).toBeGreaterThan(0);
});
