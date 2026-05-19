import {
  assessmentScopedCyberRisks,
  assessmentScopedThreats,
  buildAssessmentOwnedScenarioId,
} from "./assessmentScopeRollup.js";
import type { MockScenario } from "./types.js";
import {
  applyScenariosGraphRelinks,
  buildScenarioFromGraph,
  deleteScenarioOverridesForIds,
  scenarios,
} from "./scenarios.js";

export type AssessmentScenarioSyncResult = {
  craId: string;
  addedIds: string[];
  updatedIds: string[];
  removedIds: string[];
};

type ScenarioTuple = { cyberRiskId: string; assetId: string; threatId: string };

function copyScenarioGraphFieldsOnto(target: MockScenario, source: MockScenario): void {
  const { id, relationships: srcRel, ...srcRest } = source;
  void id;
  Object.assign(target, srcRest);
  Object.assign(target.relationships, srcRel);
}

function assertScenarioIdOwnedByCraOrFree(id: string, craId: string): void {
  const hit = scenarios.find((s) => s.id === id);
  if (hit == null) return;
  if (hit.assessmentId !== craId) {
    throw new Error(
      `assessmentScenarioSync: scenario id "${id}" already exists with a different owner (expected "${craId}", got "${String(hit.assessmentId)}"`,
    );
  }
}

/**
 * Ensures catalog `scenarios` contains exactly the assessment-owned rows for the current scope:
 * add / refresh tuples in scope, remove rows whose tuple left scope.
 * Tuples are every (scoped cyber risk × assessment-scoped threat × shared included asset), matching the asset-based threat closure used elsewhere (not only `risk.threatIds`).
 * Suppressed tuples (`excludedScopeScenarioIds`) are not created if missing; existing rows stay and are refreshed from graph.
 */
export function syncAssessmentOwnedScenarios(args: {
  craId: string;
  includedAssetIds: ReadonlySet<string>;
  excludedScopeCyberRiskIds: ReadonlySet<string>;
  excludedScopeScenarioIds?: ReadonlySet<string>;
  excludedScopeThreatIds?: ReadonlySet<string>;
}): AssessmentScenarioSyncResult {
  const craId = args.craId.trim();
  const excludedScenario = args.excludedScopeScenarioIds ?? new Set<string>();
  const addedIds: string[] = [];
  const updatedIds: string[] = [];
  const removedIds: string[] = [];

  if (craId === "") {
    return { craId, addedIds, updatedIds, removedIds };
  }

  if (args.includedAssetIds.size === 0) {
    for (let i = scenarios.length - 1; i >= 0; i -= 1) {
      const s = scenarios[i]!;
      if (s.assessmentId !== craId) continue;
      scenarios.splice(i, 1);
      removedIds.push(s.id);
    }
    if (removedIds.length > 0) {
      deleteScenarioOverridesForIds(removedIds);
    }
    applyScenariosGraphRelinks();
    return { craId, addedIds, updatedIds, removedIds };
  }

  const tupleById = new Map<string, ScenarioTuple>();

  const included = new Set(args.includedAssetIds);
  const excludedCr = new Set(args.excludedScopeCyberRiskIds);
  const excludedThreat = new Set(args.excludedScopeThreatIds ?? []);

  const scopedRisks = assessmentScopedCyberRisks(included, excludedCr);
  const scopedThreats = assessmentScopedThreats(included, excludedCr, excludedThreat);

  for (const risk of scopedRisks) {
    for (const threat of scopedThreats) {
      for (const assetId of threat.assetIds) {
        if (!risk.assetIds.includes(assetId)) continue;
        if (!included.has(assetId)) continue;
        const id = buildAssessmentOwnedScenarioId(craId, risk.id, assetId, threat.id);
        tupleById.set(id, { cyberRiskId: risk.id, assetId, threatId: threat.id });
      }
    }
  }

  const retainedIds = new Set(tupleById.keys());

  for (let i = scenarios.length - 1; i >= 0; i -= 1) {
    const s = scenarios[i]!;
    if (s.assessmentId !== craId) continue;
    if (retainedIds.has(s.id)) continue;
    scenarios.splice(i, 1);
    removedIds.push(s.id);
  }

  if (removedIds.length > 0) {
    deleteScenarioOverridesForIds(removedIds);
  }

  for (const [id, tuple] of tupleById) {
    const isExcluded = excludedScenario.has(id);
    const existingIdx = scenarios.findIndex((s) => s.id === id);

    if (isExcluded) {
      if (existingIdx === -1) continue;
      const existing = scenarios[existingIdx]!;
      if (existing.assessmentId !== craId) continue;
      const built = buildScenarioFromGraph({
        id,
        cyberRiskId: tuple.cyberRiskId,
        assetId: tuple.assetId,
        threatId: tuple.threatId,
        assessmentId: craId,
      });
      if (built) {
        copyScenarioGraphFieldsOnto(existing, built);
        existing.assessmentId = craId;
        updatedIds.push(id);
      }
      continue;
    }

    assertScenarioIdOwnedByCraOrFree(id, craId);
    const built = buildScenarioFromGraph({
      id,
      cyberRiskId: tuple.cyberRiskId,
      assetId: tuple.assetId,
      threatId: tuple.threatId,
      assessmentId: craId,
    });
    if (!built) continue;

    if (existingIdx === -1) {
      scenarios.push(built);
      addedIds.push(id);
    } else {
      const existing = scenarios[existingIdx]!;
      if (existing.assessmentId != null && existing.assessmentId !== craId) {
        throw new Error(
          `assessmentScenarioSync: scenario id "${id}" is owned by "${existing.assessmentId}", not "${craId}"`,
        );
      }
      copyScenarioGraphFieldsOnto(existing, built);
      existing.assessmentId = craId;
      updatedIds.push(id);
    }
  }

  applyScenariosGraphRelinks();

  return { craId, addedIds, updatedIds, removedIds };
}
