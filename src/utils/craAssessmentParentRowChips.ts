import type { CraScenarioScoreAggregationMethod } from "../data/craAssessmentDraftTypes.js";
import type { CraRagKey } from "../data/craScoringScenarioLibrary.js";
import type {
  FivePointScaleLabel,
  FivePointScaleValue,
  MockScenario,
} from "../data/types.js";
import {
  fivePointLabelToRag,
  getCyberRiskScoreLabel,
  getFivePointLabel,
  getLikelihoodLabel,
} from "../data/types.js";
import { aggregateArithmeticMeanParentScores } from "./craParentScoreAggregation.js";

/** Same shape as {@link AssessmentResultsScoreChip} in `craAssessmentScopeRows` (kept here to avoid importing pages). */
export type CraParentResultMetricChip = {
  numeric: string;
  label: string;
  rag: CraRagKey;
};

function chipFive(value: number, label: FivePointScaleLabel): CraParentResultMetricChip {
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

function chipLikelihood(value: number): CraParentResultMetricChip {
  const label = getLikelihoodLabel(value);
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

function chipCyberRiskScore(value: number): CraParentResultMetricChip {
  const label = getCyberRiskScoreLabel(value);
  return {
    numeric: String(value),
    label,
    rag: fivePointLabelToRag(label) as CraRagKey,
  };
}

function pickScenarioWithMaxScore(
  scenarios: readonly MockScenario[],
  score: (s: MockScenario) => number,
): MockScenario {
  let best = scenarios[0]!;
  let bestN = score(best);
  for (let i = 1; i < scenarios.length; i++) {
    const s = scenarios[i]!;
    const n = score(s);
    if (n > bestN) {
      bestN = n;
      best = s;
    }
  }
  return best;
}

/** Parent row: Likelihood = T×V, Cyber risk score = I×L (matches {@link ScoringTable} parent aggregation). */
function deriveLikelihoodAndCyberRiskChips(
  impact: CraParentResultMetricChip,
  threat: CraParentResultMetricChip,
  vulnerability: CraParentResultMetricChip,
): { likelihood: CraParentResultMetricChip; cyberRiskScore: CraParentResultMetricChip } {
  const t = Number.parseFloat(threat.numeric);
  const v = Number.parseFloat(vulnerability.numeric);
  const i = Number.parseFloat(impact.numeric);
  if (!Number.isFinite(t) || !Number.isFinite(v) || !Number.isFinite(i)) {
    throw new Error("Invalid parent I/T/V chip numerics");
  }
  const likelihoodProduct = t * v;
  return {
    likelihood: chipLikelihood(likelihoodProduct),
    cyberRiskScore: chipCyberRiskScore(i * likelihoodProduct),
  };
}

export type ParentCyberRiskResultChips = {
  impact: CraParentResultMetricChip;
  threat: CraParentResultMetricChip;
  vulnerability: CraParentResultMetricChip;
  likelihood: CraParentResultMetricChip;
  cyberRiskScore: CraParentResultMetricChip;
};

/**
 * Parent cyber-risk row metrics from in-scope scenarios, aligned with Scoring tab aggregation
 * (Highest: max I/T/V then derive L & CRS; Average: mean I/T/V then derive).
 */
export function parentResultChipsFromScenarios(
  scenarios: readonly MockScenario[],
  method: CraScenarioScoreAggregationMethod,
): ParentCyberRiskResultChips {
  if (scenarios.length === 0) {
    throw new Error("parentResultChipsFromScenarios requires at least one scenario");
  }

  if (method === "average") {
    const numericInputs = scenarios.map((s) => ({
      impact: s.impact,
      threat: s.threatSeverity,
      vulnerability: s.vulnerabilitySeverity,
    }));
    const agg = aggregateArithmeticMeanParentScores(numericInputs);
    if (agg == null) {
      throw new Error("aggregateArithmeticMeanParentScores returned null");
    }
    const impact = chipFive(agg.impact, getFivePointLabel(agg.impact as FivePointScaleValue));
    const threat = chipFive(agg.threat, getFivePointLabel(agg.threat as FivePointScaleValue));
    const vulnerability = chipFive(
      agg.vulnerability,
      getFivePointLabel(agg.vulnerability as FivePointScaleValue),
    );
    const derived = deriveLikelihoodAndCyberRiskChips(impact, threat, vulnerability);
    return { impact, threat, vulnerability, ...derived };
  }

  const iS = pickScenarioWithMaxScore(scenarios, (s) => s.impact);
  const tS = pickScenarioWithMaxScore(scenarios, (s) => s.threatSeverity);
  const vS = pickScenarioWithMaxScore(scenarios, (s) => s.vulnerabilitySeverity);
  const impact = chipFive(iS.impact, iS.impactLabel);
  const threat = chipFive(tS.threatSeverity, tS.threatSeverityLabel);
  const vulnerability = chipFive(vS.vulnerabilitySeverity, vS.vulnerabilitySeverityLabel);
  const derived = deriveLikelihoodAndCyberRiskChips(impact, threat, vulnerability);
  return { impact, threat, vulnerability, ...derived };
}
