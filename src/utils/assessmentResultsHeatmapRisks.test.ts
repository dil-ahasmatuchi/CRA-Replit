import { describe, expect, it } from "vitest";

import type { MockCyberRisk } from "../data/types.js";
import type { AssessmentCyberResultsRow } from "../pages/craAssessmentScopeRows.js";
import { buildHeatmapCyberRisksForResultsTab } from "./assessmentResultsHeatmapRisks.js";
import { buildCyberRiskHeatmapAggregates } from "./cyberRiskMatrixAggregates.js";

const emptyRel: MockCyberRisk["relationships"] = {
  assetIds: [],
  threatIds: [],
  vulnerabilityIds: [],
  scenarioIds: [],
  mitigationPlanIds: [],
  assessmentIds: [],
};

function baseRisk(
  id: string,
  overrides: Partial<MockCyberRisk> & Pick<MockCyberRisk, "name" | "ownerId" | "orgUnitId">,
): MockCyberRisk {
  const { name, ownerId, orgUnitId, ...restOverrides } = overrides;
  return {
    id,
    name,
    ownerId,
    status: "Monitoring",
    orgUnitId,
    likelihood: 22,
    likelihoodLabel: "Very high",
    impact: 2,
    impactLabel: "Low",
    cyberRiskScore: 10,
    cyberRiskScoreLabel: "Very low",
    residualLikelihood: 22,
    residualLikelihoodLabel: "Very high",
    residualCyberRiskScore: 10,
    residualCyberRiskScoreLabel: "Very low",
    assetIds: [],
    threatIds: [],
    vulnerabilityIds: [],
    scenarioIds: [],
    mitigationPlanIds: [],
    relationships: { ...emptyRel },
    ...restOverrides,
  };
}

function chip(numeric: string, label: string) {
  return { numeric, label, rag: "neu03" as const };
}

describe("buildHeatmapCyberRisksForResultsTab", () => {
  it("overrides library risk so heatmap matches parent table chips", () => {
    const scoped: MockCyberRisk[] = [
      baseRisk("CR-010", { name: "Social engineering", ownerId: "USR-001", orgUnitId: "BU-001" }),
      baseRisk("CR-002", { name: "Ransomware", ownerId: "USR-001", orgUnitId: "BU-001" }),
      baseRisk("CR-001", { name: "Unauthorized access", ownerId: "USR-001", orgUnitId: "BU-001" }),
    ];

    const parents: AssessmentCyberResultsRow[] = [
      {
        id: "CR-010",
        kind: "cyberRisk",
        groupId: "CR-010",
        name: "Social engineering",
        impact: chip("5", "Very high"),
        threat: chip("5", "Very high"),
        vulnerability: chip("5", "Very high"),
        likelihood: chip("25", "Very high"),
        cyberRiskScore: chip("115", "Very high"),
      },
      {
        id: "CR-002",
        kind: "cyberRisk",
        groupId: "CR-002",
        name: "Ransomware",
        impact: chip("5", "Very high"),
        threat: chip("5", "Very high"),
        vulnerability: chip("4", "High"),
        likelihood: chip("20", "High"),
        cyberRiskScore: chip("100", "High"),
      },
      {
        id: "CR-001",
        kind: "cyberRisk",
        groupId: "CR-001",
        name: "Unauthorized access",
        impact: chip("4", "High"),
        threat: chip("5", "Very high"),
        vulnerability: chip("3", "Medium"),
        likelihood: chip("15", "Medium"),
        cyberRiskScore: chip("60", "Medium"),
      },
    ];

    const merged = buildHeatmapCyberRisksForResultsTab(scoped, parents);
    const { grid, legend } = buildCyberRiskHeatmapAggregates(merged, "residual");

    const byLevel = Object.fromEntries(legend.map((l) => [l.level, l.count])) as Record<string, number>;
    expect(byLevel.veryHigh).toBe(1);
    expect(byLevel.high).toBe(1);
    expect(byLevel.medium).toBe(1);
    expect(byLevel.low ?? 0).toBe(0);
    expect(byLevel.veryLow ?? 0).toBe(0);

    // Very high likelihood row (0), impact 5 (col 4) — residual parent chips
    expect(grid[0]![4]).toBe(1);
    // High likelihood row (1), impact 5 — residual parent chips
    expect(grid[1]![4]).toBe(1);
    // Medium likelihood row (2), impact 4 (col 3)
    expect(grid[2]![3]).toBe(1);
  });

  it("preserves inherent likelihood and impact while overlaying residual from parent", () => {
    const scoped: MockCyberRisk[] = [
      baseRisk("CR-002", {
        name: "Ransomware",
        ownerId: "USR-001",
        orgUnitId: "BU-001",
        impact: 5,
        impactLabel: "Very high",
        likelihood: 25,
        likelihoodLabel: "Very high",
        cyberRiskScore: 125,
        cyberRiskScoreLabel: "Very high",
      }),
    ];
    const parents: AssessmentCyberResultsRow[] = [
      {
        id: "CR-002",
        kind: "cyberRisk",
        groupId: "CR-002",
        name: "Ransomware",
        impact: chip("5", "Very high"),
        threat: chip("3", "Medium"),
        vulnerability: chip("3", "Medium"),
        likelihood: chip("9", "Low"),
        cyberRiskScore: chip("45", "Low"),
      },
    ];
    const merged = buildHeatmapCyberRisksForResultsTab(scoped, parents);
    expect(merged[0]!.impact).toBe(5);
    expect(merged[0]!.likelihood).toBe(25);
    expect(merged[0]!.cyberRiskScore).toBe(125);
    expect(merged[0]!.residualLikelihood).toBe(9);
    expect(merged[0]!.residualLikelihoodLabel).toBe("Low");
    expect(merged[0]!.residualCyberRiskScore).toBe(45);
    expect(merged[0]!.residualImpact).toBe(5);

    const inh = buildCyberRiskHeatmapAggregates(merged, "inherent");
    expect(inh.grid[0]![4]).toBe(1);

    const res = buildCyberRiskHeatmapAggregates(merged, "residual");
    expect(res.grid[3]![4]).toBe(1);
  });

  it("falls back to library row when parent chips are incomplete", () => {
    const scoped = [baseRisk("CR-001", { name: "R1", ownerId: "USR-001", orgUnitId: "BU-001" })];
    const rows: AssessmentCyberResultsRow[] = [
      {
        id: "CR-001",
        kind: "cyberRisk",
        groupId: "CR-001",
        name: "R1",
        impact: chip("4", "High"),
        threat: null,
        vulnerability: null,
        likelihood: null,
        cyberRiskScore: null,
      },
    ];
    const merged = buildHeatmapCyberRisksForResultsTab(scoped, rows);
    expect(merged[0]).toEqual(scoped[0]);
  });
});
