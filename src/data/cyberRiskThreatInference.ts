import { keywordSimilarity, mulberry32 } from "./relationshipHeuristics.js";
import type { MockCyberRisk, MockThreat } from "./types.js";

export function threatIntersectsRiskAssets(threat: MockThreat, riskAssetIds: ReadonlySet<string>): boolean {
  const aids = threat.assetIds;
  if (!Array.isArray(aids) || aids.length === 0) return false;
  return aids.some((aid) => riskAssetIds.has(aid));
}

function cyberRiskNumericSeed(id: string): number {
  const m = /^CR-(\d+)$/.exec(id.trim());
  if (m) return Number.parseInt(m[1]!, 10);
  let h = 0;
  for (let i = 0; i < id.length; i += 1) {
    h = (h * 31 + id.charCodeAt(i)) >>> 0;
  }
  return h === 0 ? 1 : h;
}

/**
 * Returns `THR-*` ids that intersect `risk.assetIds` (required for assessment-owned scenario tuple sync).
 * Keeps existing ids that still intersect; otherwise picks a deterministic subset of candidate threats.
 */
export function inferThreatIdsForCyberRisk(
  risk: Pick<MockCyberRisk, "id" | "name" | "assetIds" | "threatIds">,
  threats: readonly MockThreat[],
): string[] {
  const riskAssets = new Set(risk.assetIds ?? []);
  if (riskAssets.size === 0) return [];

  const threatById = new Map(threats.map((t) => [t.id, t]));

  const kept: string[] = [];
  for (const tid of risk.threatIds ?? []) {
    const t = threatById.get(tid);
    if (t && threatIntersectsRiskAssets(t, riskAssets)) kept.push(tid);
  }
  if (kept.length > 0) {
    return [...new Set(kept)].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  }

  const candidates = threats.filter((t) => threatIntersectsRiskAssets(t, riskAssets));
  if (candidates.length === 0) return [];

  const idx = cyberRiskNumericSeed(risk.id);
  const rng = mulberry32(201_100 + idx * 997);
  const targetCount = Math.min(candidates.length, 2 + Math.floor(rng() * 5));

  const scored = candidates.map((t) => ({
    id: t.id,
    s: keywordSimilarity(risk.name, `${t.name} ${t.domain}`) + rng() * 0.22,
  }));
  scored.sort((a, b) => (b.s !== a.s ? b.s - a.s : a.id.localeCompare(b.id, undefined, { numeric: true })));

  const picked = scored.slice(0, Math.max(1, Math.min(targetCount, scored.length))).map((x) => x.id);
  return [...new Set(picked)].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

/** Mutates `risk.threatIds` / `relationships.threatIds` only; does not change `assetIds`. */
export function applyCyberRiskThreatInference(risk: MockCyberRisk, threats: readonly MockThreat[]): void {
  const next = inferThreatIdsForCyberRisk(risk, threats);
  risk.threatIds = next;
  if (risk.relationships) {
    risk.relationships.threatIds = [...next];
  }
}
