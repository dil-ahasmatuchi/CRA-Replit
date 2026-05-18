import { controls } from "./controls.js";
import { cyberRisks } from "./cyberRisks.js";
import { scenarios } from "./scenarios.js";
import { threats } from "./threats.js";
import {
  isVulnerabilityActiveForAssessment,
  vulnerabilities,
} from "./vulnerabilities.js";
import type { MockControl, MockCyberRisk, MockScenario, MockThreat, MockVulnerability } from "./types.js";

export function includedAssetIdSet(rows: { included: boolean; assetId: string }[]): Set<string> {
  const s = new Set<string>();
  for (const r of rows) {
    if (r.included) s.add(r.assetId);
  }
  return s;
}

/** Cyber risks touching any included asset (before user exclusions). */
export function candidateScopedCyberRisks(assetIds: Set<string>): MockCyberRisk[] {
  if (assetIds.size === 0) return [];
  return cyberRisks.filter((cr) => cr.assetIds.some((aid) => assetIds.has(aid)));
}

export function assessmentScopedCyberRisks(
  assetIds: Set<string>,
  excludedCyberRiskIds: Set<string>,
): MockCyberRisk[] {
  return candidateScopedCyberRisks(assetIds).filter((cr) => !excludedCyberRiskIds.has(cr.id));
}

export function effectiveCyberRiskIdSet(
  assetIds: Set<string>,
  excludedCyberRiskIds: Set<string>,
): Set<string> {
  return new Set(assessmentScopedCyberRisks(assetIds, excludedCyberRiskIds).map((r) => r.id));
}

/** Threats linked to any included asset (asset ids only; cyber-risk exclusions do not remove threats here). */
export function candidateScopedThreats(assetIds: Set<string>): MockThreat[] {
  if (assetIds.size === 0) return [];
  return threats.filter((t) => t.assetIds.some((aid) => assetIds.has(aid)));
}

/**
 * Threats linked to included assets, minus explicit threat exclusions.
 * `excludedCyberRiskIds` is ignored for threat membership (still used for cyber risks and scenarios elsewhere).
 */
export function assessmentScopedThreats(
  assetIds: Set<string>,
  _excludedCyberRiskIds: Set<string>,
  excludedThreatIds: Set<string> = new Set(),
): MockThreat[] {
  if (assetIds.size === 0) return [];
  return candidateScopedThreats(assetIds).filter((t) => !excludedThreatIds.has(t.id));
}

/** Vulnerabilities on included assets (active for assessment), before user exclusions. */
export function candidateScopedVulnerabilities(assetIds: Set<string>): MockVulnerability[] {
  if (assetIds.size === 0) return [];
  return vulnerabilities.filter(
    (v) =>
      isVulnerabilityActiveForAssessment(v) && v.assetIds.some((aid) => assetIds.has(aid)),
  );
}

export function assessmentScopedVulnerabilities(
  assetIds: Set<string>,
  excludedVulnerabilityIds: Set<string> = new Set(),
): MockVulnerability[] {
  return candidateScopedVulnerabilities(assetIds).filter((v) => !excludedVulnerabilityIds.has(v.id));
}

/** Controls attached to any included asset (asset-centric scope). */
export function candidateScopedControls(assetIds: Set<string>): MockControl[] {
  if (assetIds.size === 0) return [];
  return controls.filter((c) => c.assetIds.some((aid) => assetIds.has(aid)));
}

export function assessmentScopedControls(
  assetIds: Set<string>,
  _excludedCyberRiskIds: Set<string>,
  excludedControlIds: Set<string> = new Set(),
): MockControl[] {
  if (assetIds.size === 0) return [];
  return candidateScopedControls(assetIds).filter((c) => !excludedControlIds.has(c.id));
}

export function assessmentScopedScenarios(
  assetIds: Set<string>,
  excludedCyberRiskIds: Set<string>,
  excludedScenarioIds: ReadonlySet<string> = new Set(),
): MockScenario[] {
  if (assetIds.size === 0) return [];
  const riskIds = effectiveCyberRiskIdSet(assetIds, excludedCyberRiskIds);
  return scenarios.filter(
    (s) =>
      assetIds.has(s.assetId) &&
      riskIds.has(s.cyberRiskId) &&
      !excludedScenarioIds.has(s.id),
  );
}

/** @deprecated Prefer assessmentScopedCyberRisks(assetIds, new Set()) */
export function scopedCyberRisks(assetIds: Set<string>): MockCyberRisk[] {
  return assessmentScopedCyberRisks(assetIds, new Set());
}

export function scopedThreats(assetIds: Set<string>): MockThreat[] {
  return assessmentScopedThreats(assetIds, new Set(), new Set());
}

export function scopedVulnerabilities(assetIds: Set<string>) {
  return assessmentScopedVulnerabilities(assetIds, new Set());
}

export function scopedControls(assetIds: Set<string>): MockControl[] {
  return assessmentScopedControls(assetIds, new Set(), new Set());
}

export function scopedScenarios(assetIds: Set<string>): MockScenario[] {
  return assessmentScopedScenarios(assetIds, new Set());
}

export const SCOPE_CATALOG_TOTALS = {
  cyberRisks: cyberRisks.length,
  threats: threats.length,
  vulnerabilities: vulnerabilities.filter(isVulnerabilityActiveForAssessment).length,
  controls: controls.length,
} as const;
