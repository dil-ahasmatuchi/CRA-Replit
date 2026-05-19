import {
  padId,
  getFivePointLabel,
  getLikelihoodLabel,
  getCyberRiskScoreLabel,
} from "./types.js";
import type { MockScenario, FivePointScaleValue } from "./types.js";
import { buildScoringRationale, buildVulnsByAssetIdMap, formatThreatPhrase } from "./buildScoringRationale.js";
import { cyberRisks } from "./cyberRisks.js";
import { assets } from "./assets.js";
import { markCatalogDirty } from "./persistence/catalogStore.js";
import { threats as allThreats } from "./threats.js";
import { vulnerabilities as allVulnerabilities } from "./vulnerabilities.js";

/**
 * One scenario per (cyber risk × threat × asset row) for threats in that risk.
 * Name: "{threat} on {asset}"; vulnerabilityIds = that threat’s vulns on the asset.
 */

function buildScenarioName(
  cyberRiskName: string,
  threatPhrase: string,
  assetName: string,
): string {
  if (threatPhrase) return `${threatPhrase} on ${assetName}`;
  return `${cyberRiskName} on ${assetName}`;
}

function scenarioSeverityValues(seq: number): {
  threatSeverity: FivePointScaleValue;
  vulnerabilitySeverity: FivePointScaleValue;
} {
  const threatSeverity = ((seq % 4) + 2) as FivePointScaleValue;
  const vulnerabilitySeverity = (((seq * 7) % 4) + 2) as FivePointScaleValue;
  return { threatSeverity, vulnerabilitySeverity };
}

function buildScenarios(): MockScenario[] {
  const threatById = new Map(allThreats.map((t) => [t.id, t]));
  const vulnById = new Map(allVulnerabilities.map((v) => [v.id, v]));
  const assetById = new Map(assets.map((a) => [a.id, a]));
  const vulnsByAssetId = buildVulnsByAssetIdMap(allVulnerabilities);
  const maps = { threatById, vulnById, vulnsByAssetId };

  const list: MockScenario[] = [];
  let seq = 0;

  for (const risk of cyberRisks) {
    // `risk.assetIds` is the union of assets from linked threats; keep in sync in cyberRisks.ts so we do not drop pairs here.
    for (const tid of risk.threatIds) {
      const threat = threatById.get(tid);
      if (!threat) continue;

      for (const assetId of threat.assetIds) {
        if (!risk.assetIds.includes(assetId)) continue;
        const asset = assetById.get(assetId);
        if (!asset) continue;

        const assetControlIds = [...(Array.isArray(asset.controlIds) ? asset.controlIds : [])];

        seq += 1;
        const scenarioThreatIds = [tid];
        const scenarioVulnIds = threat.vulnerabilityIds.filter((vid) => {
          const v = maps.vulnById.get(vid);
          return v != null && v.assetIds.includes(assetId);
        });

        const { threatSeverity, vulnerabilitySeverity } = scenarioSeverityValues(seq);
        const impact = asset.criticality;
        const likelihood = threatSeverity * vulnerabilitySeverity;
        const cyberRiskScore = impact * likelihood;
        const impactLabel = getFivePointLabel(impact);
        const threatSeverityLabel = getFivePointLabel(threatSeverity);
        const vulnerabilitySeverityLabel = getFivePointLabel(vulnerabilitySeverity);
        const likelihoodLabel = getLikelihoodLabel(likelihood);
        const cyberRiskScoreLabel = getCyberRiskScoreLabel(cyberRiskScore);

        const threatNamesForTitle = scenarioThreatIds
          .map((id) => maps.threatById.get(id)?.name)
          .filter(Boolean) as string[];
        const scenarioThreatPhrase = formatThreatPhrase(threatNamesForTitle);

        list.push({
          id: padId("SC", seq),
          name: buildScenarioName(risk.name, scenarioThreatPhrase, asset.name),
          ownerId: asset.ownerId,
          cyberRiskId: risk.id,
          assetId,
          impact,
          impactLabel,
          threatSeverity,
          threatSeverityLabel,
          vulnerabilitySeverity,
          vulnerabilitySeverityLabel,
          likelihood,
          likelihoodLabel,
          cyberRiskScore,
          cyberRiskScoreLabel,
          threatIds: scenarioThreatIds,
          vulnerabilityIds: scenarioVulnIds,
          scoringRationale: buildScoringRationale(
            risk.name,
            scenarioThreatPhrase,
            asset.name,
            asset.assetType,
            impactLabel,
            threatSeverityLabel,
            vulnerabilitySeverityLabel,
            likelihoodLabel,
            cyberRiskScoreLabel,
            scenarioThreatIds,
            scenarioVulnIds,
            assetId,
            maps,
          ),
          relationships: {
            cyberRiskId: risk.id,
            assetId,
            threatIds: scenarioThreatIds,
            vulnerabilityIds: scenarioVulnIds,
            controlIds: [...assetControlIds],
            mitigationPlanIds: risk.mitigationPlanIds,
          },
        });
      }
    }
  }

  return list;
}

function dedupePush(arr: string[], id: string): void {
  if (!arr.includes(id)) arr.push(id);
}

/** Wire scenario ids into cyber risks, threats, vulnerabilities, and assets (relationship mirrors). */
function applyScenarioEntityLinks(scenarioList: MockScenario[]): void {
  const riskById = new Map(cyberRisks.map((r) => [r.id, r]));
  const threatById = new Map(allThreats.map((t) => [t.id, t]));
  const vulnById = new Map(allVulnerabilities.map((v) => [v.id, v]));
  const assetById = new Map(assets.map((a) => [a.id, a]));

  for (const r of cyberRisks) {
    r.scenarioIds.length = 0;
  }
  for (const t of allThreats) {
    t.relationships.scenarioIds.length = 0;
  }
  for (const v of allVulnerabilities) {
    v.relationships.scenarioIds.length = 0;
  }
  for (const a of assets) {
    a.relationships.scenarioIds.length = 0;
  }

  for (const s of scenarioList) {
    const risk = riskById.get(s.cyberRiskId);
    if (risk) dedupePush(risk.scenarioIds, s.id);

    for (const tid of s.threatIds) {
      const t = threatById.get(tid);
      if (t) dedupePush(t.relationships.scenarioIds, s.id);
    }
    for (const vid of s.vulnerabilityIds) {
      const v = vulnById.get(vid);
      if (v) dedupePush(v.relationships.scenarioIds, s.id);
    }
    const a = assetById.get(s.assetId);
    if (a) dedupePush(a.relationships.scenarioIds, s.id);
  }
}

export const scenarios: MockScenario[] = buildScenarios();
applyScenarioEntityLinks(scenarios);

const scenarioById = new Map<string, MockScenario>();

function rebuildScenarioIndex(): void {
  scenarioById.clear();
  for (const s of scenarios) {
    scenarioById.set(s.id, s);
  }
}

rebuildScenarioIndex();

/** User edits / persisted partials layered on regenerated baseline rows. */
let scenarioOverrides: Record<string, Partial<MockScenario>> = {};

function mergeScenarioPatchInPlace(target: MockScenario, patch: Partial<MockScenario>): void {
  const { relationships, ...rest } = patch;
  Object.assign(target, rest);
  if (relationships) {
    Object.assign(target.relationships, relationships);
  }
}

function applyScenarioOverridesToRows(): void {
  for (const s of scenarios) {
    const o = scenarioOverrides[s.id];
    if (o) mergeScenarioPatchInPlace(s, o);
  }
}

export function getScenarioOverridesForPersistence(): Record<string, Partial<MockScenario>> {
  return { ...scenarioOverrides };
}

export function setScenarioOverridesFromPersistence(
  next: Record<string, Partial<MockScenario>> | undefined,
): void {
  scenarioOverrides = next && typeof next === "object" ? { ...next } : {};
}

/** Full scenario rows for catalog snapshots (schema v3). */
export function getScenariosForPersistence(): MockScenario[] {
  return JSON.parse(JSON.stringify(scenarios)) as MockScenario[];
}

/** Replace library scenarios (e.g. Pooja migration) and re-link cyber risks / threats / vulns / assets. */
export function replaceScenariosFromPersistence(next: MockScenario[]): void {
  scenarios.length = 0;
  scenarios.push(...next);
  applyScenarioEntityLinks(scenarios);
  rebuildScenarioIndex();
  applyScenarioOverridesToRows();
  markCatalogDirty();
}

/** Rebuild scenario rows from current cyber risks / threats / assets, then re-apply persisted overrides. */
export function rebuildScenariosFromGraph(): void {
  const next = buildScenarios();
  scenarios.length = 0;
  scenarios.push(...next);
  applyScenarioEntityLinks(scenarios);
  rebuildScenarioIndex();
  applyScenarioOverridesToRows();
}

/** Update stored likelihood / cyber risk labels from active scoring bands (rationale text unchanged). */
export function refreshScenarioScaleLabelsFromConfig(): void {
  for (const s of scenarios) {
    s.likelihoodLabel = getLikelihoodLabel(s.likelihood);
    s.cyberRiskScoreLabel = getCyberRiskScoreLabel(s.cyberRiskScore);
  }
}

export function patchScenario(id: string, patch: Partial<MockScenario>): void {
  scenarioOverrides[id] = { ...scenarioOverrides[id], ...patch };
  const row = scenarioById.get(id);
  if (row) mergeScenarioPatchInPlace(row, patch);
  markCatalogDirty();
}

export function getScenarioById(id: string): MockScenario | undefined {
  return scenarioById.get(id);
}
