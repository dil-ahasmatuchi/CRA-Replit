import type { CraScenarioScoreAggregationMethod, CraScoringTypeChoice } from "./craAssessmentDraftTypes.js";
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
} from "./assessmentScopeRollup.js";
import {
  applyResidualCyberRiskScores,
  getCyberRiskById,
  updateCyberRisk,
} from "./cyberRisks.js";
import type {
  FivePointScaleLabel,
  FivePointScaleValue,
  MockCyberRisk,
  MockScenario,
} from "./types.js";
import { parentResultChipsFromScenarios } from "../utils/craAssessmentParentRowChips.js";

export type ApplyApprovedAssessmentCyberRiskWritebackArgs = {
  includedAssetIds: ReadonlySet<string>;
  excludedScopeCyberRiskIds: ReadonlySet<string>;
  excludedScopeScenarioIds: ReadonlySet<string>;
  scenarioNotApplicableIds: ReadonlySet<string>;
  scenarioScopeAssessmentId?: string;
  scoringType: CraScoringTypeChoice;
  scenarioScoreAggregationMethod: CraScenarioScoreAggregationMethod;
};

function scenarioItvComplete(s: MockScenario): boolean {
  const { impact, threatSeverity, vulnerabilitySeverity } = s;
  return (
    typeof impact === "number" &&
    impact >= 1 &&
    impact <= 5 &&
    typeof threatSeverity === "number" &&
    threatSeverity >= 1 &&
    threatSeverity <= 5 &&
    typeof vulnerabilitySeverity === "number" &&
    vulnerabilitySeverity >= 1 &&
    vulnerabilitySeverity <= 5
  );
}

/**
 * When an assessment is approved, copy aggregated parent scenario scores into scoped library
 * cyber risks (inherent vs residual per Details tab scoring type).
 */
export function applyApprovedAssessmentCyberRiskWriteback(
  args: ApplyApprovedAssessmentCyberRiskWritebackArgs,
): void {
  const {
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioNotApplicableIds,
    scenarioScopeAssessmentId,
    scoringType,
    scenarioScoreAggregationMethod,
  } = args;

  if (includedAssetIds.size === 0) return;

  const scopedRisks = assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds);
  const scenarioList = assessmentScopedScenarios(
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
  );

  const byRisk = new Map<string, MockScenario[]>();
  for (const s of scenarioList) {
    if (scenarioNotApplicableIds.has(s.id)) continue;
    const list = byRisk.get(s.cyberRiskId) ?? [];
    list.push(s);
    byRisk.set(s.cyberRiskId, list);
  }

  for (const risk of scopedRisks) {
    const applicable = byRisk.get(risk.id) ?? [];
    if (applicable.length === 0) continue;
    if (!applicable.every(scenarioItvComplete)) continue;

    const chips = parentResultChipsFromScenarios(applicable, scenarioScoreAggregationMethod);

    const impactN = Number.parseInt(chips.impact.numeric, 10);
    const likelihoodN = Number.parseFloat(chips.likelihood.numeric);
    const crsN = Number.parseFloat(chips.cyberRiskScore.numeric);
    if (
      !Number.isFinite(impactN) ||
      impactN < 1 ||
      impactN > 5 ||
      !Number.isFinite(likelihoodN) ||
      !Number.isFinite(crsN)
    ) {
      continue;
    }

    if (scoringType === "inherent") {
      updateCyberRisk(risk.id, {
        impact: impactN as FivePointScaleValue,
        impactLabel: chips.impact.label as FivePointScaleLabel,
        likelihood: likelihoodN,
        likelihoodLabel: chips.likelihood.label as FivePointScaleLabel,
        cyberRiskScore: crsN,
        cyberRiskScoreLabel: chips.cyberRiskScore.label as FivePointScaleLabel,
        residualScoresFromAssessment: false,
        residualImpact: undefined,
        residualImpactLabel: undefined,
      });
      const r = getCyberRiskById(risk.id);
      if (r) applyResidualCyberRiskScores(r);
      continue;
    }

    const inherentImpact = getCyberRiskById(risk.id)?.impact;
    const patch: Partial<MockCyberRisk> = {
      residualLikelihood: likelihoodN,
      residualLikelihoodLabel: chips.likelihood.label as FivePointScaleLabel,
      residualCyberRiskScore: crsN,
      residualCyberRiskScoreLabel: chips.cyberRiskScore.label as FivePointScaleLabel,
      residualScoresFromAssessment: true,
    };
    if (
      inherentImpact != null &&
      impactN !== inherentImpact &&
      impactN >= 1 &&
      impactN <= 5
    ) {
      patch.residualImpact = impactN as FivePointScaleValue;
      patch.residualImpactLabel = chips.impact.label as FivePointScaleLabel;
    } else {
      patch.residualImpact = undefined;
      patch.residualImpactLabel = undefined;
    }
    updateCyberRisk(risk.id, patch);
  }
}
