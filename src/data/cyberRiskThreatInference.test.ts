import { describe, expect, it } from "vitest";

import {
  applyCyberRiskThreatInference,
  inferThreatIdsForCyberRisk,
  threatIntersectsRiskAssets,
} from "./cyberRiskThreatInference.js";
import type { MockCyberRisk, MockThreat } from "./types.js";

function threatFixture(partial: Partial<MockThreat> & Pick<MockThreat, "id" | "assetIds">): MockThreat {
  return {
    displayId: "T-0001",
    name: "Threat",
    domain: "Identity & Access Management",
    description: "",
    sources: ["Deliberate"],
    threatActors: [],
    attackVectors: [],
    status: "Active",
    ownerIds: ["USR-001"],
    attachments: [],
    cyberRiskIds: [],
    vulnerabilityIds: [],
    relationships: {
      assetIds: [...partial.assetIds],
      vulnerabilityIds: [],
      cyberRiskIds: [],
      controlIds: [],
      mitigationPlanIds: [],
      scenarioIds: [],
    },
    ...partial,
  } as MockThreat;
}

describe("threatIntersectsRiskAssets", () => {
  it("is true when any threat asset is on the risk", () => {
    const t = threatFixture({ id: "THR-001", assetIds: ["AST-001", "AST-002"] });
    expect(threatIntersectsRiskAssets(t, new Set(["AST-002", "AST-099"]))).toBe(true);
  });

  it("is false when disjoint", () => {
    const t = threatFixture({ id: "THR-001", assetIds: ["AST-001"] });
    expect(threatIntersectsRiskAssets(t, new Set(["AST-099"]))).toBe(false);
  });
});

describe("inferThreatIdsForCyberRisk", () => {
  it("returns empty when risk has no assets", () => {
    const threats = [threatFixture({ id: "THR-001", assetIds: ["AST-001"] })];
    expect(inferThreatIdsForCyberRisk({ id: "CR-001", name: "Risk", assetIds: [], threatIds: [] }, threats)).toEqual(
      [],
    );
  });

  it("keeps existing threat ids that still intersect risk assets", () => {
    const threats = [
      threatFixture({ id: "THR-001", assetIds: ["AST-001"], name: "Alpha" }),
      threatFixture({ id: "THR-002", assetIds: ["AST-099"], name: "Beta" }),
    ];
    const out = inferThreatIdsForCyberRisk(
      {
        id: "CR-005",
        name: "Ignored for keep path",
        assetIds: ["AST-001"],
        threatIds: ["THR-001", "THR-002"],
      },
      threats,
    );
    expect(out).toEqual(["THR-001"]);
  });

  it("infers at least one intersecting threat when threatIds empty", () => {
    const threats = [
      threatFixture({ id: "THR-001", assetIds: ["AST-001"], name: "Account takeover" }),
      threatFixture({ id: "THR-002", assetIds: ["AST-002"], name: "Unrelated" }),
    ];
    const out = inferThreatIdsForCyberRisk(
      {
        id: "CR-003",
        name: "Account takeover enabling access",
        assetIds: ["AST-001", "AST-002"],
        threatIds: [],
      },
      threats,
    );
    expect(out.length).toBeGreaterThanOrEqual(1);
    const riskAssets = new Set(["AST-001", "AST-002"]);
    for (const tid of out) {
      const t = threats.find((x) => x.id === tid)!;
      expect(threatIntersectsRiskAssets(t, riskAssets)).toBe(true);
    }
  });
});

describe("applyCyberRiskThreatInference", () => {
  it("writes threatIds and relationships.threatIds", () => {
    const threats = [threatFixture({ id: "THR-007", assetIds: ["AST-007"], name: "Phishing" })];
    const risk: MockCyberRisk = {
      id: "CR-099",
      name: "Phishing risk",
      ownerId: "USR-001",
      status: "Monitoring",
      orgUnitId: "BU-001",
      likelihood: 5,
      likelihoodLabel: "Low",
      impact: 3,
      impactLabel: "Medium",
      cyberRiskScore: 15,
      cyberRiskScoreLabel: "Very low",
      residualLikelihood: 5,
      residualLikelihoodLabel: "Low",
      residualCyberRiskScore: 15,
      residualCyberRiskScoreLabel: "Very low",
      assetIds: ["AST-007"],
      threatIds: [],
      vulnerabilityIds: [],
      scenarioIds: [],
      mitigationPlanIds: [],
      relationships: {
        assetIds: ["AST-007"],
        threatIds: [],
        vulnerabilityIds: [],
        scenarioIds: [],
        mitigationPlanIds: [],
        assessmentIds: [],
      },
    };
    applyCyberRiskThreatInference(risk, threats);
    expect(risk.threatIds).toEqual(["THR-007"]);
    expect(risk.relationships.threatIds).toEqual(["THR-007"]);
  });
});
