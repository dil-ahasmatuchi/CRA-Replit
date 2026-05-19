import { assets } from "../data/assets.js";
import type { CraRagKey } from "../data/craScoringScenarioLibrary.js";
import type { MockCyberRisk, MockScenario, FivePointScaleLabel } from "../data/types.js";
import {
  fivePointLabelToRag,
  getCyberRiskScoreLabel,
  getLikelihoodLabel,
} from "../data/types.js";
import {
  assessmentUiHasHiddenScenarioCatalogScores,
  scenarioCatalogScoresVisibleInAssessmentUi,
  type ScenarioCatalogMaskContext,
} from "../utils/scenarioCatalogScoreMask.js";
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
} from "./scopeAssessmentRollup.js";

export type AssessmentResultsScoreChip = {
  numeric: string;
  label: string;
  rag: CraRagKey;
};

export type AssessmentCyberResultsRow = {
  id: string;
  kind: "cyberRisk" | "scenario";
  groupId: string;
  name: string;
  impact: AssessmentResultsScoreChip | null;
  threat: AssessmentResultsScoreChip | null;
  vulnerability: AssessmentResultsScoreChip | null;
  likelihood: AssessmentResultsScoreChip | null;
  cyberRiskScore: AssessmentResultsScoreChip | null;
};

type Chip = AssessmentResultsScoreChip;

function chipFive(value: number, label: FivePointScaleLabel): Chip {
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

function chipLikelihood(value: number): Chip {
  const label = getLikelihoodLabel(value);
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

function chipCyberRiskScore(value: number): Chip {
  const label = getCyberRiskScoreLabel(value);
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

type ScenarioMetricChips = {
  impact: Chip;
  threat: Chip;
  vulnerability: Chip;
  likelihood: Chip;
  cyberRiskScore: Chip;
};

function scenarioRowChips(s: MockScenario): ScenarioMetricChips {
  return {
    impact: chipFive(s.impact, s.impactLabel),
    threat: chipFive(s.threatSeverity, s.threatSeverityLabel),
    vulnerability: chipFive(s.vulnerabilitySeverity, s.vulnerabilitySeverityLabel),
    likelihood: chipLikelihood(s.likelihood),
    cyberRiskScore: chipCyberRiskScore(s.cyberRiskScore),
  };
}

function maxChip(a: Chip, b: Chip): Chip {
  return Number.parseFloat(a.numeric) >= Number.parseFloat(b.numeric) ? a : b;
}

function riskRowChips(
  cr: MockCyberRisk,
  scens: MockScenario[],
): Omit<AssessmentCyberResultsRow, "id" | "kind" | "groupId" | "name"> {
  if (scens.length === 0) {
    const imp = chipFive(cr.impact, cr.impactLabel);
    const lik = chipLikelihood(cr.likelihood);
    const crs = chipCyberRiskScore(cr.cyberRiskScore);
    return {
      impact: imp,
      threat: imp,
      vulnerability: imp,
      likelihood: lik,
      cyberRiskScore: crs,
    };
  }
  const chips: ScenarioMetricChips[] = scens.map((s) => scenarioRowChips(s));
  const [head, ...rest] = chips;
  return {
    impact: rest.reduce((a, c) => maxChip(a, c.impact), head!.impact),
    threat: rest.reduce((a, c) => maxChip(a, c.threat), head!.threat),
    vulnerability: rest.reduce((a, c) => maxChip(a, c.vulnerability), head!.vulnerability),
    likelihood: rest.reduce((a, c) => maxChip(a, c.likelihood), head!.likelihood),
    cyberRiskScore: rest.reduce((a, c) => maxChip(a, c.cyberRiskScore), head!.cyberRiskScore),
  };
}

/** Cyber risk + scenario rows for Results, aligned with scoped Scoring data. */
export function buildCyberResultsRowsForScope(
  includedAssetIds: Set<string>,
  excludedScopeCyberRiskIds: Set<string>,
  excludedScopeScenarioIds: Set<string> = new Set(),
  scenarioScopeAssessmentId?: string,
): AssessmentCyberResultsRow[] {
  if (includedAssetIds.size === 0) return [];
  const risks = assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds);
  const scenarioList = assessmentScopedScenarios(
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
  );
  const byRisk = new Map<string, MockScenario[]>();
  for (const s of scenarioList) {
    const list = byRisk.get(s.cyberRiskId) ?? [];
    list.push(s);
    byRisk.set(s.cyberRiskId, list);
  }

  const rows: AssessmentCyberResultsRow[] = [];
  for (const cr of risks) {
    const scens = byRisk.get(cr.id) ?? [];
    const rc = riskRowChips(cr, scens);
    rows.push({
      id: cr.id,
      kind: "cyberRisk",
      groupId: cr.id,
      name: cr.name,
      ...rc,
    });
    for (const s of scens) {
      const sc = scenarioRowChips(s);
      rows.push({
        id: s.id,
        kind: "scenario",
        groupId: cr.id,
        name: s.name,
        ...sc,
      });
    }
  }
  return rows;
}

/** Inputs for {@link applyNewCraCatalogScoreMaskingToCyberResultsRows} / asset masking. */
export type AssessmentResultsCatalogMaskParams = ScenarioCatalogMaskContext;

/**
 * Every non–N/A scenario in the group has catalog scores released or manually revealed (aligns with
 * {@link AssessmentScoringTab} parent aggregation preconditions).
 */
function everyApplicableScenarioCatalogVisibleForResults(
  scenariosInGroup: readonly MockScenario[],
  p: AssessmentResultsCatalogMaskParams,
): boolean {
  const applicable = scenariosInGroup.filter((s) => !p.scenarioNotApplicableIds.has(s.id));
  if (applicable.length === 0) return false;
  return applicable.every((s) => scenarioCatalogScoresVisibleInAssessmentUi(s.id, p));
}

/**
 * Masks scenario scores on Results cyber rows (impact kept on scenarios) and clears parent cyber-risk
 * chips when any applicable scenario is still hidden, then recomputes parents when all are visible.
 */
export function applyNewCraCatalogScoreMaskingToCyberResultsRows(
  rows: AssessmentCyberResultsRow[],
  risksById: ReadonlyMap<string, MockCyberRisk>,
  scenariosByRiskId: ReadonlyMap<string, readonly MockScenario[]>,
  p: AssessmentResultsCatalogMaskParams,
): AssessmentCyberResultsRow[] {
  if (p.assessmentPhase === "assessmentApproved") {
    return rows;
  }
  const out = rows.map((row) => ({ ...row }));
  for (const row of out) {
    if (row.kind !== "scenario") continue;
    if (scenarioCatalogScoresVisibleInAssessmentUi(row.id, p)) continue;
    row.threat = null;
    row.vulnerability = null;
    row.likelihood = null;
    row.cyberRiskScore = null;
  }
  for (const row of out) {
    if (row.kind !== "cyberRisk") continue;
    const cr = risksById.get(row.id);
    const scens = scenariosByRiskId.get(row.id) ?? [];
    if (!cr) continue;
    if (!everyApplicableScenarioCatalogVisibleForResults(scens, p)) {
      row.impact = null;
      row.threat = null;
      row.vulnerability = null;
      row.likelihood = null;
      row.cyberRiskScore = null;
    } else {
      const rc = riskRowChips(cr, [...scens]);
      row.impact = rc.impact;
      row.threat = rc.threat;
      row.vulnerability = rc.vulnerability;
      row.likelihood = rc.likelihood;
      row.cyberRiskScore = rc.cyberRiskScore;
    }
  }
  return out;
}

/** Masks asset cyber risk score when any applicable scenario on that asset is still catalog-hidden. */
export function applyNewCraCatalogScoreMaskingToAssetResultsRows(
  rows: AssessmentAssetResultRow[],
  scenariosByAssetId: ReadonlyMap<string, readonly MockScenario[]>,
  p: AssessmentResultsCatalogMaskParams,
): AssessmentAssetResultRow[] {
  if (p.assessmentPhase === "assessmentApproved") {
    return rows;
  }
  return rows.map((row) => {
    const scens = scenariosByAssetId.get(row.assetId) ?? [];
    const hasHiddenApplicable = scens.some(
      (s) =>
        !p.scenarioNotApplicableIds.has(s.id) && !scenarioCatalogScoresVisibleInAssessmentUi(s.id, p),
    );
    if (!hasHiddenApplicable) return row;
    return { ...row, cyberRiskScore: null };
  });
}

/** True when some in-scope scenario still has catalog scores hidden on Results / hero. */
export function assessmentResultsHasHiddenScenarioScores(
  scenariosInScope: readonly MockScenario[],
  p: AssessmentResultsCatalogMaskParams,
): boolean {
  return assessmentUiHasHiddenScenarioCatalogScores(scenariosInScope, p);
}

export type AssessmentAssetResultRow = {
  id: string;
  name: string;
  assetId: string;
  cyberRiskScore: Chip | null;
  criticality: Chip;
  confidentiality: Chip;
  integrity: Chip;
  availability: Chip;
};

function maxScenarioCyberRiskChip(scens: MockScenario[]): Chip {
  let best = scens[0]!;
  for (const s of scens) {
    if (s.cyberRiskScore > best.cyberRiskScore) best = s;
  }
  return chipCyberRiskScore(best.cyberRiskScore);
}

/** Asset rows on Results for assets in scope (scores from scenarios on that asset). */
export function buildAssetResultRowsForScope(
  includedAssetIds: Set<string>,
  excludedScopeCyberRiskIds: Set<string>,
  excludedScopeScenarioIds: Set<string> = new Set(),
  scenarioScopeAssessmentId?: string,
): AssessmentAssetResultRow[] {
  if (includedAssetIds.size === 0) return [];
  const scenarioList = assessmentScopedScenarios(
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
  );
  const byAsset = new Map<string, MockScenario[]>();
  for (const s of scenarioList) {
    const list = byAsset.get(s.assetId) ?? [];
    list.push(s);
    byAsset.set(s.assetId, list);
  }

  const list = assets.filter((a) => includedAssetIds.has(a.id));
  return list.map((a, i) => {
    const scens = byAsset.get(a.id) ?? [];
    const crs =
      scens.length === 0
        ? chipCyberRiskScore(a.criticality * 10)
        : maxScenarioCyberRiskChip(scens);
    const crit = chipFive(a.criticality, a.criticalityLabel);
    return {
      id: String(i + 1),
      name: a.name,
      assetId: a.id,
      cyberRiskScore: crs,
      criticality: crit,
      confidentiality: crit,
      integrity: crit,
      availability: crit,
    };
  });
}
