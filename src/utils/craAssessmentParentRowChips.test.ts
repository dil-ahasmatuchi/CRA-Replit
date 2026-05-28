import { describe, expect, it } from "vitest";

import type { MockScenario } from "../data/types.js";
import { parentResultChipsFromScenarios } from "./craAssessmentParentRowChips.js";

function scenarioStub(partial: Partial<MockScenario> & Pick<MockScenario, "id">): MockScenario {
  const cyberRiskId = partial.cyberRiskId ?? "CR-TEST";
  const assetId = partial.assetId ?? "AST-TEST";
  return {
    name: "Test scenario",
    ownerId: "USR-001",
    cyberRiskId,
    assetId,
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 3,
    threatSeverityLabel: "Medium",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 9,
    likelihoodLabel: "Medium",
    cyberRiskScore: 27,
    cyberRiskScoreLabel: "Medium",
    confidencePercent: 50,
    threatIds: [],
    vulnerabilityIds: [],
    scoringRationale: "",
    relationships: {
      cyberRiskId,
      assetId,
      threatIds: [],
      vulnerabilityIds: [],
      controlIds: [],
      mitigationPlanIds: [],
    },
    ...partial,
  };
}

describe("parentResultChipsFromScenarios", () => {
  it("Highest: parent CRS derives from max I/T/V, not max of scenario CRS", () => {
    const s1 = scenarioStub({
      id: "SC-TEST-1",
      impact: 5,
      impactLabel: "Very high",
      threatSeverity: 2,
      threatSeverityLabel: "Low",
      vulnerabilitySeverity: 2,
      vulnerabilitySeverityLabel: "Low",
      likelihood: 4,
      cyberRiskScore: 20,
    });
    const s2 = scenarioStub({
      id: "SC-TEST-2",
      impact: 3,
      impactLabel: "Medium",
      threatSeverity: 5,
      threatSeverityLabel: "Very high",
      vulnerabilitySeverity: 5,
      vulnerabilitySeverityLabel: "Very high",
      likelihood: 25,
      cyberRiskScore: 75,
    });

    const parent = parentResultChipsFromScenarios([s1, s2], "highest");
    const maxScenarioCrs = Math.max(s1.cyberRiskScore, s2.cyberRiskScore);
    expect(Number.parseFloat(parent.cyberRiskScore.numeric)).not.toBe(maxScenarioCrs);
    expect(Number.parseFloat(parent.cyberRiskScore.numeric)).toBe(125);
    expect(Number.parseFloat(parent.likelihood.numeric)).toBe(25);
  });

  it("Average: uses mean I/T/V then same L and CRS derivation", () => {
    const s1 = scenarioStub({
      id: "SC-A-1",
      impact: 4,
      impactLabel: "High",
      threatSeverity: 2,
      threatSeverityLabel: "Low",
      vulnerabilitySeverity: 2,
      vulnerabilitySeverityLabel: "Low",
    });
    const s2 = scenarioStub({
      id: "SC-A-2",
      impact: 2,
      impactLabel: "Low",
      threatSeverity: 4,
      threatSeverityLabel: "High",
      vulnerabilitySeverity: 4,
      vulnerabilitySeverityLabel: "High",
    });
    const parent = parentResultChipsFromScenarios([s1, s2], "average");
    expect(Number.parseFloat(parent.impact.numeric)).toBe(3);
    expect(Number.parseFloat(parent.threat.numeric)).toBe(3);
    expect(Number.parseFloat(parent.vulnerability.numeric)).toBe(3);
    expect(Number.parseFloat(parent.likelihood.numeric)).toBe(9);
    expect(Number.parseFloat(parent.cyberRiskScore.numeric)).toBe(27);
  });
});
