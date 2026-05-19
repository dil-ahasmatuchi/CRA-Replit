import {
  padId,
  getFivePointLabel,
  getLikelihoodLabel,
  getCyberRiskScoreLabel,
} from "./types.js";
import type { MockCyberRisk, CyberRiskStatus, FivePointScaleValue } from "./types.js";
import { applyCyberRiskThreatInference } from "./cyberRiskThreatInference.js";
import { keywordSimilarity, mulberry32 } from "./relationshipHeuristics.js";
import { threats } from "./threats.js";
import { vulnerabilities } from "./vulnerabilities.js";
import { assets, getAssetById } from "./assets.js";
import { getControlById } from "./controls.js";
import { markCatalogDirty } from "./persistence/catalogStore.js";

const OWNER_ROTATION = [7, 9, 14, 15, 20, 33, 39, 49, 1, 5] as const;

/** Max share of inherent likelihood removed when mean active control effectiveness is 5/5. */
const RESIDUAL_LIKELIHOOD_ALPHA = 0.35;

/**
 * Library cyber risks from `RISK_SEEDS`. Threat links use keyword overlap (risk name vs threat title/domain) plus
 * seeded jitter for variable breadth; any threat not picked in the first pass is attached once to its
 * best-matching risk so the library stays fully covered.
 */
const RISK_SEEDS: { name: string; status: CyberRiskStatus }[] = [
  { name: "Ransomware and extortion disrupting critical operations and data availability", status: "Mitigation" },
  { name: "Phishing and impersonation compromising workforce and customer credentials", status: "Monitoring" },
  { name: "Denial-of-service events impairing service availability and revenue", status: "Assessment" },
  { name: "Insider actions or negligence leading to unauthorized data exfiltration", status: "Mitigation" },
  { name: "Business email compromise and payment fraud against the organization", status: "Monitoring" },
  { name: "Cyber incidents triggering regulatory non-compliance and enforcement action", status: "Assessment" },
  { name: "Supply chain compromise through vendors, software, or managed services", status: "Identification" },
  { name: "Application-layer attacks compromising confidentiality and integrity of data", status: "Mitigation" },
  { name: "Malware infection, illicit cryptomining, and lateral movement across systems", status: "Monitoring" },
  { name: "Account takeover enabling unauthorized access to systems and privileged functions", status: "Assessment" },
  { name: "Cloud or SaaS dependency failures causing extended operational outage", status: "Identification" },
  { name: "Sophisticated and AI-assisted cyber threats maintaining covert, long-term access", status: "Mitigation" },
  { name: "Exploitation of unpatched or zero-day vulnerabilities before remediations deploy", status: "Assessment" },
  { name: "Adversary-in-the-middle attacks intercepting or altering sensitive communications", status: "Monitoring" },
  { name: "Sophisticated cyber threats and AI-related security vulnerabilities", status: "Identification" },
  { name: "Credential stuffing and password reuse breaching customer or workforce accounts", status: "Mitigation" },
  { name: "Theft or leakage of trade secrets and competitively sensitive information", status: "Assessment" },
  { name: "Cyber incidents compromising confidential information and data subject privacy", status: "Monitoring" },
  { name: "Cyber resilience gap — IT infrastructure vulnerability exposure", status: "Assessment" },
  { name: "API abuse and excessive access undermining data protection and service integrity", status: "Identification" },
];

const threatById = new Map(threats.map((t) => [t.id, t]));

function dedupePush(arr: string[], id: string): void {
  if (!arr.includes(id)) arr.push(id);
}

/** Mean effectiveness (1–5) of Active controls among the given ids; 0 if none. */
function meanActiveControlEffectiveness(controlIds: readonly string[]): number {
  let sum = 0;
  let n = 0;
  for (const cid of controlIds) {
    const c = getControlById(cid);
    if (!c || c.status !== "Active") continue;
    const eff =
      typeof c.effectiveness === "number" && c.effectiveness >= 1 && c.effectiveness <= 5
        ? c.effectiveness
        : 3;
    sum += eff;
    n += 1;
  }
  return n === 0 ? 0 : sum / n;
}

/** Union of control ids on all assets linked to the risk (asset-centric controls). */
function controlIdsOnRiskAssets(assetIds: readonly string[] | undefined): string[] {
  const set = new Set<string>();
  const aids = Array.isArray(assetIds) ? assetIds : [];
  for (const aid of aids) {
    const a = getAssetById(aid);
    if (!a) continue;
    const cids = Array.isArray(a.controlIds) ? a.controlIds : [];
    for (const cid of cids) set.add(cid);
  }
  return [...set];
}

/** Residual likelihood from inherent and mean active control effectiveness on linked assets. */
export function applyResidualCyberRiskScores(risk: MockCyberRisk): void {
  const likelihood =
    typeof risk.likelihood === "number" && !Number.isNaN(risk.likelihood) ? risk.likelihood : 1;
  const impact =
    typeof risk.impact === "number" && risk.impact >= 1 && risk.impact <= 5 ? risk.impact : 1;
  const strength = meanActiveControlEffectiveness(controlIdsOnRiskAssets(risk.assetIds));
  const residualLikelihood = Math.max(
    1,
    Math.min(25, Math.round(likelihood * (1 - RESIDUAL_LIKELIHOOD_ALPHA * (strength / 5)))),
  );
  risk.residualLikelihood = residualLikelihood;
  risk.residualLikelihoodLabel = getLikelihoodLabel(residualLikelihood);
  const residualScore = impact * residualLikelihood;
  risk.residualCyberRiskScore = residualScore;
  risk.residualCyberRiskScoreLabel = getCyberRiskScoreLabel(residualScore);
}

/** Pick a variable number of threats by similarity to the risk name (reproducible per index). */
function selectThreatIdsForCyberRisk(riskName: string, riskIndex: number): string[] {
  const rng = mulberry32(201_100 + riskIndex * 997);
  const targetCount = 2 + Math.floor(rng() * 14);

  const scored = threats.map((t) => ({
    id: t.id,
    s: keywordSimilarity(riskName, `${t.name} ${t.domain}`) + rng() * 0.22,
  }));
  scored.sort((a, b) => b.s - a.s);

  return scored.slice(0, Math.min(targetCount, threats.length)).map((x) => x.id);
}

function refreshCyberRiskDerivedFields(risk: MockCyberRisk): void {
  risk.assetIds = unionAssetIdsForThreats(risk.threatIds);
  risk.vulnerabilityIds = vulnerabilityIdsForAssets(risk.assetIds);
  risk.relationships.assetIds = [...risk.assetIds];
  risk.relationships.vulnerabilityIds = [...risk.vulnerabilityIds];
}

/** Clears cyber-risk back-references so a new graph can be replayed (seed + persisted catalogs). */
function clearCyberRiskBackReferencesFromCatalog(): void {
  for (const v of vulnerabilities) {
    v.cyberRiskIds.length = 0;
    v.relationships.cyberRiskIds.length = 0;
  }
  for (const t of threats) {
    t.cyberRiskIds.length = 0;
    t.relationships.cyberRiskIds.length = 0;
  }
  for (const a of assets) {
    a.relationships.cyberRiskIds.length = 0;
  }
}

function linkCyberRiskToEntities(risk: MockCyberRisk): void {
  const vulnById = new Map(vulnerabilities.map((v) => [v.id, v]));
  const tById = new Map(threats.map((t) => [t.id, t]));
  const assetById = new Map(assets.map((a) => [a.id, a]));

  for (const tid of risk.threatIds) {
    const t = tById.get(tid);
    if (t) {
      dedupePush(t.cyberRiskIds, risk.id);
      dedupePush(t.relationships.cyberRiskIds, risk.id);
    }
  }

  for (const vid of risk.vulnerabilityIds) {
    const v = vulnById.get(vid);
    if (v) {
      dedupePush(v.cyberRiskIds, risk.id);
      dedupePush(v.relationships.cyberRiskIds, risk.id);
    }
  }

  for (const aid of risk.assetIds) {
    const a = assetById.get(aid);
    if (a) dedupePush(a.relationships.cyberRiskIds, risk.id);
  }
}

/** Replays `linkCyberRiskToEntities` for each loaded risk (mirrors seed `buildCyberRisks` wiring). */
function relinkCyberRisksToThreatsVulnsAssets(): void {
  clearCyberRiskBackReferencesFromCatalog();
  for (const r of cyberRisks) {
    linkCyberRiskToEntities(r);
  }
}

function unionAssetIdsForThreats(threatIds: string[]): string[] {
  const s = new Set<string>();
  for (const tid of threatIds) {
    const t = threatById.get(tid);
    if (t) {
      for (const a of t.assetIds) s.add(a);
    }
  }
  return [...s].sort();
}

function vulnerabilityIdsForAssets(assetIds: string[]): string[] {
  const set = new Set<string>();
  for (const v of vulnerabilities) {
    for (const va of v.assetIds) {
      if (assetIds.includes(va)) {
        set.add(v.id);
        break;
      }
    }
  }
  return [...set].sort();
}

function mitigationPlanIdsForRiskIndex(i: number): string[] {
  return [padId("MP", 1 + (i % 15)), padId("MP", 1 + ((i + 7) % 15))];
}

function buildCyberRisks(): MockCyberRisk[] {
  clearCyberRiskBackReferencesFromCatalog();

  const out: MockCyberRisk[] = [];

  for (let i = 0; i < RISK_SEEDS.length; i++) {
    const seed = RISK_SEEDS[i]!;
    const threatIds = selectThreatIdsForCyberRisk(seed.name, i);
    const assetIds = unionAssetIdsForThreats(threatIds);
    const vulnerabilityIds = vulnerabilityIdsForAssets(assetIds);
    const scenarioIds: string[] = [];

    const buIdx = Number(assets.find((a) => a.id === assetIds[0])?.orgUnitId.replace(/^BU-0*/, "") || "4");
    const ownerIdx = OWNER_ROTATION[i % OWNER_ROTATION.length]!;

    // Seeded RNG for random-looking distribution (Impact 1-5, Likelihood 1-25)
    const rng = mulberry32(888 + i * 13);
    const impact = (1 + Math.floor(rng() * 5)) as FivePointScaleValue;
    const likelihood = 1 + Math.floor(rng() * 25);
    const score = impact * likelihood;

    const mitigationPlanIds = mitigationPlanIdsForRiskIndex(i);

    const risk: MockCyberRisk = {
      id: padId("CR", i + 1),
      name: seed.name,
      ownerId: padId("USR", ownerIdx),
      status: seed.status,
      orgUnitId: padId("BU", buIdx),
      impact,
      impactLabel: getFivePointLabel(impact),
      likelihood,
      likelihoodLabel: getLikelihoodLabel(likelihood),
      cyberRiskScore: score,
      cyberRiskScoreLabel: getCyberRiskScoreLabel(score),
      residualLikelihood: likelihood,
      residualLikelihoodLabel: getLikelihoodLabel(likelihood),
      residualCyberRiskScore: score,
      residualCyberRiskScoreLabel: getCyberRiskScoreLabel(score),
      assetIds,
      threatIds,
      vulnerabilityIds,
      scenarioIds,
      mitigationPlanIds,
      relationships: {
        assetIds,
        threatIds,
        vulnerabilityIds,
        scenarioIds,
        mitigationPlanIds,
        assessmentIds: [],
      },
    };

    linkCyberRiskToEntities(risk);
    out.push(risk);
  }

  const usedThreatIds = new Set<string>();
  for (const r of out) {
    for (const tid of r.threatIds) usedThreatIds.add(tid);
  }

  for (const t of threats) {
    if (usedThreatIds.has(t.id)) continue;
    let bestIdx = 0;
    let bestScore = -1;
    for (let i = 0; i < out.length; i++) {
      const sc = keywordSimilarity(out[i]!.name, `${t.name} ${t.domain}`);
      if (sc > bestScore) {
        bestScore = sc;
        bestIdx = i;
      }
    }
    const risk = out[bestIdx]!;
    dedupePush(risk.threatIds, t.id);
    refreshCyberRiskDerivedFields(risk);
    linkCyberRiskToEntities(risk);
    usedThreatIds.add(t.id);
  }

  for (const r of out) {
    applyResidualCyberRiskScores(r);
  }

  return out;
}

export const cyberRisks: MockCyberRisk[] = buildCyberRisks();

const riskById = new Map(cyberRisks.map((r) => [r.id, r]));

function rebuildCyberRiskIndex(): void {
  riskById.clear();
  for (const r of cyberRisks) {
    riskById.set(r.id, r);
  }
}

export function replaceCyberRisksFromPersistence(next: MockCyberRisk[]): void {
  cyberRisks.length = 0;
  cyberRisks.push(...next);
  rebuildCyberRiskIndex();
  for (const r of cyberRisks) {
    applyCyberRiskThreatInference(r, threats);
  }
  relinkCyberRisksToThreatsVulnsAssets();
  for (const r of cyberRisks) {
    applyResidualCyberRiskScores(r);
  }
  syncIndirectLinksFromCyberRisks();
}

/** Relabel stored scale fields from active band configuration (no residual score math). */
export function refreshAllCyberRiskScaleLabelsFromConfig(): void {
  for (const r of cyberRisks) {
    r.cyberRiskScoreLabel = getCyberRiskScoreLabel(r.cyberRiskScore);
    r.residualCyberRiskScoreLabel = getCyberRiskScoreLabel(r.residualCyberRiskScore);
    r.likelihoodLabel = getLikelihoodLabel(r.likelihood);
    r.residualLikelihoodLabel = getLikelihoodLabel(r.residualLikelihood);
  }
}

/** Propagate control ids from linked assets; mitigation plan ids from linked cyber risks onto threats and vulnerabilities. */
function syncIndirectLinksFromCyberRisks(): void {
  for (const t of threats) {
    t.relationships.controlIds.length = 0;
    t.relationships.mitigationPlanIds.length = 0;
    for (const aid of t.assetIds) {
      const a = getAssetById(aid);
      if (!a) continue;
      const cids = Array.isArray(a.controlIds) ? a.controlIds : [];
      for (const cid of cids) {
        if (!t.relationships.controlIds.includes(cid)) t.relationships.controlIds.push(cid);
      }
    }
    for (const crid of t.cyberRiskIds) {
      const r = riskById.get(crid);
      if (!r) continue;
      for (const mid of r.mitigationPlanIds) {
        if (!t.relationships.mitigationPlanIds.includes(mid)) t.relationships.mitigationPlanIds.push(mid);
      }
    }
  }
  for (const v of vulnerabilities) {
    v.relationships.controlIds.length = 0;
    v.relationships.mitigationPlanIds.length = 0;
    for (const aid of v.assetIds) {
      const a = getAssetById(aid);
      if (!a) continue;
      const cids = Array.isArray(a.controlIds) ? a.controlIds : [];
      for (const cid of cids) {
        if (!v.relationships.controlIds.includes(cid)) v.relationships.controlIds.push(cid);
      }
    }
    for (const crid of v.cyberRiskIds) {
      const r = riskById.get(crid);
      if (!r) continue;
      for (const mid of r.mitigationPlanIds) {
        if (!v.relationships.mitigationPlanIds.includes(mid)) v.relationships.mitigationPlanIds.push(mid);
      }
    }
  }
}

syncIndirectLinksFromCyberRisks();

export function getCyberRiskById(id: string): MockCyberRisk | undefined {
  return riskById.get(id);
}

export function findCyberRiskByExactName(name: string): MockCyberRisk | undefined {
  const t = name.trim();
  if (!t) return undefined;
  return cyberRisks.find((r) => r.name === t);
}

export function linkMitigationPlanToCyberRisks(
  planId: string,
  cyberRiskIds: readonly string[],
): void {
  for (const id of cyberRiskIds) {
    const r = riskById.get(id);
    if (!r) continue;
    dedupePush(r.mitigationPlanIds, planId);
    dedupePush(r.relationships.mitigationPlanIds, planId);
  }
  syncIndirectLinksFromCyberRisks();
}

/** Removes `planId` from the given risks (both top-level and relationships) and re-syncs indirect links. */
export function unlinkMitigationPlanFromCyberRisks(
  planId: string,
  cyberRiskIds: readonly string[],
): void {
  for (const id of cyberRiskIds) {
    const r = riskById.get(id);
    if (!r) continue;
    r.mitigationPlanIds = r.mitigationPlanIds.filter((mid) => mid !== planId);
    r.relationships.mitigationPlanIds = r.relationships.mitigationPlanIds.filter((mid) => mid !== planId);
  }
  syncIndirectLinksFromCyberRisks();
}

export function updateCyberRisk(id: string, patch: Partial<MockCyberRisk>): void {
  const r = riskById.get(id);
  if (!r) return;
  const { relationships, ...rest } = patch;
  Object.assign(r, rest);
  if (relationships) {
    Object.assign(r.relationships, relationships);
  }
  syncIndirectLinksFromCyberRisks();
  markCatalogDirty();
}
