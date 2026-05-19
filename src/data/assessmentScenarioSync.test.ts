import { afterAll, describe, expect, it } from "vitest";
import { assessmentScopedCyberRisks, assessmentScopedScenarios } from "./assessmentScopeRollup.js";
import { getScenariosForPersistence, replaceScenariosFromPersistence } from "./scenarios.js";
import { syncAssessmentOwnedScenarios } from "./assessmentScenarioSync.js";

function findFirstOwnedScenarioIdFor(craId: string, assetId: string): string | undefined {
  return getScenariosForPersistence().find(
    (s) =>
      s.assessmentId === craId &&
      s.assetId === assetId &&
      s.id.startsWith(`SCA-${craId}-`),
  )?.id;
}

describe("syncAssessmentOwnedScenarios", () => {
  const backup = getScenariosForPersistence();

  afterAll(() => {
    replaceScenariosFromPersistence(backup);
  });

  it("adds stable assessment-owned rows for scope and idempotent re-sync updates in place", () => {
    const craId = "CRA-SYNC-TEST-001";
    const risks = assessmentScopedCyberRisks(new Set(["AST-001"]), new Set());
    expect(risks.length).toBeGreaterThan(0);
    const assetId = "AST-001";

    const r1 = syncAssessmentOwnedScenarios({
      craId,
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
    });
    expect(r1.addedIds.length + r1.updatedIds.length).toBeGreaterThan(0);
    const expectedId = findFirstOwnedScenarioIdFor(craId, assetId);
    expect(expectedId).toBeDefined();
    expect(r1.addedIds.includes(expectedId!) || r1.updatedIds.includes(expectedId!)).toBe(true);

    const r2 = syncAssessmentOwnedScenarios({
      craId,
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
    });
    expect(r2.addedIds).toEqual([]);
    expect(r2.removedIds).toEqual([]);

    const scoped = assessmentScopedScenarios(new Set([assetId]), new Set(), new Set(), craId);
    expect(scoped.some((s) => s.id === expectedId && s.assessmentId === craId)).toBe(true);
  });

  it("removes owned rows when tuple leaves scope and skips create when scenario id is excluded", () => {
    const craId = "CRA-SYNC-TEST-002";
    const assetId = "AST-001";

    syncAssessmentOwnedScenarios({
      craId,
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
    });
    const sid = findFirstOwnedScenarioIdFor(craId, assetId);
    expect(sid).toBeDefined();
    expect(getScenariosForPersistence().some((s) => s.id === sid)).toBe(true);

    const removed = syncAssessmentOwnedScenarios({
      craId,
      includedAssetIds: new Set<string>(),
      excludedScopeCyberRiskIds: new Set(),
    });
    expect(removed.removedIds).toContain(sid!);
    expect(getScenariosForPersistence().some((s) => s.id === sid)).toBe(false);

    syncAssessmentOwnedScenarios({
      craId,
      includedAssetIds: new Set([assetId]),
      excludedScopeCyberRiskIds: new Set(),
      excludedScopeScenarioIds: new Set([sid!]),
    });
    expect(getScenariosForPersistence().some((s) => s.id === sid)).toBe(false);
  });
});
