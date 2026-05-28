import { describe, expect, it } from "vitest";

import {
  formatScenarioConfidencePercent,
  generateScenarioConfidencePercent,
  hashScenarioId,
  isValidConfidencePercent,
} from "./scenarioConfidence.js";

describe("scenarioConfidence", () => {
  it("hashScenarioId is stable and non-zero", () => {
    expect(hashScenarioId("SC-001")).toBe(hashScenarioId("SC-001"));
    expect(hashScenarioId("SC-001")).not.toBe(hashScenarioId("SC-002"));
    expect(hashScenarioId("SC-001")).toBeGreaterThan(0);
  });

  it("generateScenarioConfidencePercent is stable per scenario id", () => {
    const a = generateScenarioConfidencePercent("SC-042");
    const b = generateScenarioConfidencePercent("SC-042");
    expect(a).toBe(b);
    expect(isValidConfidencePercent(a)).toBe(true);
  });

  it("generateScenarioConfidencePercent can differ across ids", () => {
    const values = new Set(
      ["SC-001", "SC-002", "SC-003", "SC-004", "SC-005"].map((id) =>
        generateScenarioConfidencePercent(id),
      ),
    );
    expect(values.size).toBeGreaterThan(1);
  });

  it("formatScenarioConfidencePercent appends a percent sign", () => {
    expect(formatScenarioConfidencePercent(20)).toBe("20%");
    expect(formatScenarioConfidencePercent(98)).toBe("98%");
  });
});
