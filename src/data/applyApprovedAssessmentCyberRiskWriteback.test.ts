import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { applyApprovedAssessmentCyberRiskWriteback } from "./applyApprovedAssessmentCyberRiskWriteback.js";
import { cyberRisks, getCyberRiskById, replaceCyberRisksFromPersistence } from "./cyberRisks.js";
import {
  applyScenariosGraphRelinks,
  buildScenarioFromGraph,
  deleteScenarioOverridesForIds,
  scenarios,
} from "./scenarios.js";
import { threats as allThreats } from "./threats.js";
import type { MockCyberRisk } from "./types.js";

function cloneRisks(): MockCyberRisk[] {
  return cyberRisks.map((r) => structuredClone(r));
}

/** Same linkage rule as `buildScenarioFromGraph`: asset must be on both risk and threat. */
function pickAssetThreatTupleForRisk(risk: MockCyberRisk): { assetId: string; threatId: string } {
  const threatById = new Map(allThreats.map((t) => [t.id, t]));
  for (const assetId of risk.assetIds) {
    for (const threatId of risk.threatIds) {
      const t = threatById.get(threatId);
      if (t?.assetIds.includes(assetId)) return { assetId, threatId };
    }
  }
  throw new Error(`No (asset, threat) tuple for cyber risk ${risk.id}`);
}

describe("replaceCyberRisksFromPersistence + residualScoresFromAssessment", () => {
  let backup: MockCyberRisk[];

  beforeAll(() => {
    backup = cloneRisks();
  });

  afterEach(() => {
    replaceCyberRisksFromPersistence(backup.map((r) => structuredClone(r)));
  });

  it("does not overwrite residual scores when residualScoresFromAssessment is true", () => {
    const next = cloneRisks();
    const target = next[0]!;
    target.residualScoresFromAssessment = true;
    target.residualCyberRiskScore = 71;
    target.residualLikelihood = 71;
    replaceCyberRisksFromPersistence(next);
    const loaded = cyberRisks.find((r) => r.id === target.id)!;
    expect(loaded.residualCyberRiskScore).toBe(71);
    expect(loaded.residualLikelihood).toBe(71);
    expect(loaded.residualScoresFromAssessment).toBe(true);
  });

  it("recomputes residual from controls when residualScoresFromAssessment is false", () => {
    const next = cloneRisks();
    const target = next[0]!;
    target.residualScoresFromAssessment = false;
    target.residualCyberRiskScore = 71;
    target.residualLikelihood = 71;
    replaceCyberRisksFromPersistence(next);
    const loaded = cyberRisks.find((r) => r.id === target.id)!;
    expect(loaded.residualCyberRiskScore).not.toBe(71);
    expect(loaded.residualLikelihood).not.toBe(71);
  });
});

describe("applyApprovedAssessmentCyberRiskWriteback", () => {
  let risksBackup: MockCyberRisk[];

  beforeAll(() => {
    risksBackup = cloneRisks();
  });

  afterEach(() => {
    const idx = scenarios.findIndex((s) => s.id === "SCA-CRA-WB-TEST-WRITE-CR");
    if (idx >= 0) {
      scenarios.splice(idx, 1);
    }
    deleteScenarioOverridesForIds(["SCA-CRA-WB-TEST-WRITE-CR"]);
    applyScenariosGraphRelinks();
    replaceCyberRisksFromPersistence(risksBackup.map((r) => structuredClone(r)));
  });

  it("writes inherent scores from one assessment-owned scenario", () => {
    const risk = getCyberRiskById("CR-003") ?? cyberRisks[2]!;
    const { assetId, threatId } = pickAssetThreatTupleForRisk(risk);
    const craId = "CRA-WB-TEST";
    const id = "SCA-CRA-WB-TEST-WRITE-CR";

    const built = buildScenarioFromGraph({
      id,
      cyberRiskId: risk.id,
      assetId,
      threatId,
      assessmentId: craId,
    });
    expect(built).not.toBeNull();

    scenarios.push(built!);
    applyScenariosGraphRelinks();

    applyApprovedAssessmentCyberRiskWriteback({
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
      excludedScopeScenarioIds: new Set(),
      scenarioNotApplicableIds: new Set(),
      scenarioScopeAssessmentId: craId,
      scoringType: "inherent",
      scenarioScoreAggregationMethod: "highest",
    });

    const after = getCyberRiskById(risk.id)!;
    expect(after.impact).toBe(built!.impact);
    expect(after.likelihood).toBe(built!.likelihood);
    expect(after.cyberRiskScore).toBe(built!.cyberRiskScore);
    expect(after.residualScoresFromAssessment).toBeFalsy();
  });

  it("writes residual scores and sets residualScoresFromAssessment when scoringType is residual", () => {
    const risk = getCyberRiskById("CR-003") ?? cyberRisks[2]!;
    const { assetId, threatId } = pickAssetThreatTupleForRisk(risk);
    const craId = "CRA-WB-TEST";
    const id = "SCA-CRA-WB-TEST-WRITE-CR";

    const built = buildScenarioFromGraph({
      id,
      cyberRiskId: risk.id,
      assetId,
      threatId,
      assessmentId: craId,
    });
    expect(built).not.toBeNull();

    scenarios.push(built!);
    applyScenariosGraphRelinks();

    applyApprovedAssessmentCyberRiskWriteback({
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
      excludedScopeScenarioIds: new Set(),
      scenarioNotApplicableIds: new Set(),
      scenarioScopeAssessmentId: craId,
      scoringType: "residual",
      scenarioScoreAggregationMethod: "highest",
    });

    const after = getCyberRiskById(risk.id)!;
    expect(after.residualLikelihood).toBe(built!.likelihood);
    expect(after.residualCyberRiskScore).toBe(built!.cyberRiskScore);
    expect(after.residualScoresFromAssessment).toBe(true);
    expect(after.impact).toBe(risksBackup.find((r) => r.id === risk.id)!.impact);
  });
});
