import type { FivePointScaleLabel } from "./types.js";

/** Minimal threat shape for narrative generation. */
export type RationaleThreat = { name: string };

/** Minimal vulnerability shape for narrative generation. */
export type RationaleVulnerability = {
  name: string;
  domain: string;
  primaryCIAImpact: string[];
  assetIds: readonly string[];
};

const IMPACT_CONSEQUENCE: Record<FivePointScaleLabel, string> = {
  "Very high": "severe and far-reaching",
  High: "significant",
  Medium: "moderate but notable",
  Low: "limited",
  "Very low": "minimal",
};

export function formatThreatPhrase(names: string[]): string {
  const n = names.filter(Boolean);
  if (n.length === 0) return "";
  if (n.length === 1) return n[0]!;
  if (n.length === 2) return `${n[0]!} and ${n[1]!}`;
  return `${n.slice(0, -1).join(", ")}, and ${n[n.length - 1]!}`;
}

/** Index vulnerabilities by every asset they touch (same logic as legacy graph scenarios). */
export function buildVulnsByAssetIdMap<V extends RationaleVulnerability>(
  vulnerabilities: readonly V[],
): Map<string, V[]> {
  const vulnsByAssetId = new Map<string, V[]>();
  for (const v of vulnerabilities) {
    for (const aid of v.assetIds) {
      const list = vulnsByAssetId.get(aid);
      if (list) list.push(v);
      else vulnsByAssetId.set(aid, [v]);
    }
  }
  return vulnsByAssetId;
}

export type ScoringRationaleMaps = {
  threatById: Map<string, RationaleThreat | undefined>;
  vulnById: Map<string, RationaleVulnerability | undefined>;
  vulnsByAssetId: Map<string, RationaleVulnerability[]>;
};

export function buildScoringRationale(
  cyberRiskName: string,
  scenarioThreatPhrase: string,
  assetName: string,
  assetType: string,
  impactLabel: FivePointScaleLabel,
  threatSevLabel: FivePointScaleLabel,
  vulnSevLabel: FivePointScaleLabel,
  likelihoodLabel: FivePointScaleLabel,
  cyberRiskScoreLabel: FivePointScaleLabel,
  scenarioThreatIds: string[],
  scenarioVulnIds: string[],
  assetId: string,
  maps: ScoringRationaleMaps,
): string {
  const threatNamesList = scenarioThreatIds
    .map((id) => maps.threatById.get(id)?.name)
    .filter(Boolean) as string[];

  const vulnDetails = scenarioVulnIds
    .map((id) => maps.vulnById.get(id))
    .filter((v): v is RationaleVulnerability => v != null);

  const vulnNamesSentence = vulnDetails.map((v) => v.name).join("; ") || "N/A";

  const assetVulns = maps.vulnsByAssetId.get(assetId) ?? [];
  const vulnBullets = assetVulns
    .map(
      (v) =>
        `• ${v.name} (${v.domain}, ${v.primaryCIAImpact.length ? v.primaryCIAImpact.join(" · ") : "—"})`,
    )
    .join("\n");

  const threatFocus =
    scenarioThreatPhrase ||
    (threatNamesList.length ? formatThreatPhrase(threatNamesList) : "the modeled threat");

  const sections: string[] = [
    `Cyber risk (library) — ${cyberRiskName}: This scenario sits under the ${cyberRiskName} cyber risk in the library. Here we assess ${threatFocus} against ${assetName} (${assetType.toLowerCase()}).`,

    `Threat level (${threatSevLabel}): The threat severity is ${threatSevLabel.toLowerCase()} for this scenario’s threat vector${threatNamesList.length ? ` (${formatThreatPhrase(threatNamesList)})` : ""}.`,

    `Vulnerability level (${vulnSevLabel}): The vulnerability severity is ${vulnSevLabel.toLowerCase()}. All vulnerabilities scoped to this scenario were evaluated together; the rating reflects their combined exposure. Contributing items: ${vulnNamesSentence}.`,

    `Impact (${impactLabel}): ${assetName} is ${impactLabel.toLowerCase()}-criticality. Compromise or disruption would have ${IMPACT_CONSEQUENCE[impactLabel]} consequences for the organization.`,

    `Likelihood (${likelihoodLabel}): ${threatSevLabel} threat severity together with ${vulnSevLabel} vulnerability severity yields ${likelihoodLabel.toLowerCase()} likelihood of this scenario materializing.`,

    `Cyber risk score (${cyberRiskScoreLabel}): Given ${impactLabel.toLowerCase()} impact and ${likelihoodLabel.toLowerCase()} likelihood, the scenario cyber risk score is ${cyberRiskScoreLabel.toLowerCase()}.`,
  ];

  if (assetVulns.length > 0) {
    sections.push(`Other vulnerabilities recorded on ${assetName} (context):\n${vulnBullets}`);
  }

  return sections.join("\n\n");
}
