import type { MockCyberRisk } from "../data/types.js";
import type { AssessmentCyberResultsRow } from "../pages/craAssessmentScopeRows.js";

type CompleteParent = AssessmentCyberResultsRow & {
  impact: NonNullable<AssessmentCyberResultsRow["impact"]>;
  likelihood: NonNullable<AssessmentCyberResultsRow["likelihood"]>;
  cyberRiskScore: NonNullable<AssessmentCyberResultsRow["cyberRiskScore"]>;
};

function isCompleteParent(row: AssessmentCyberResultsRow): row is CompleteParent {
  return (
    row.kind === "cyberRisk" &&
    row.impact != null &&
    row.likelihood != null &&
    row.cyberRiskScore != null
  );
}

/**
 * Overlays **residual** likelihood, cyber risk score, and optional residual-only impact from scenario-derived
 * parent rows on the Results table. **Inherent** fields (`impact`, `likelihood`, `cyberRiskScore`, …) stay
 * on the library row so the matrix toggle can show inherent vs residual correctly.
 */
export function buildHeatmapCyberRisksForResultsTab(
  scopedLibraryRisks: readonly MockCyberRisk[],
  cyberResultRows: readonly AssessmentCyberResultsRow[],
): MockCyberRisk[] {
  const parents = new Map<string, AssessmentCyberResultsRow>();
  for (const row of cyberResultRows) {
    if (row.kind === "cyberRisk") parents.set(row.id, row);
  }

  return scopedLibraryRisks.map((risk) => {
    const parent = parents.get(risk.id);
    if (!parent || !isCompleteParent(parent)) return risk;

    const residualImpact = Number.parseInt(parent.impact.numeric, 10);
    if (!Number.isFinite(residualImpact) || residualImpact < 1 || residualImpact > 5) return risk;

    const score = Number.parseFloat(parent.cyberRiskScore.numeric);
    if (!Number.isFinite(score)) return risk;

    const likNum = Number.parseFloat(parent.likelihood.numeric);
    const residualLikelihood = Number.isFinite(likNum) ? likNum : risk.residualLikelihood;

    return {
      ...risk,
      residualLikelihood,
      residualLikelihoodLabel: parent.likelihood.label as MockCyberRisk["residualLikelihoodLabel"],
      residualCyberRiskScore: score,
      residualCyberRiskScoreLabel: parent.cyberRiskScore.label as MockCyberRisk["residualCyberRiskScoreLabel"],
      residualImpact: residualImpact as MockCyberRisk["impact"],
      residualImpactLabel: parent.impact.label as MockCyberRisk["residualImpactLabel"],
    };
  });
}
