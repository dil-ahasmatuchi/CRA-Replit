/** Shared CRA new-assessment draft model (used by page storage + catalog persistence). */

export type AssessmentPhase =
  | "draft"
  | "scoping"
  | "inProgress"
  | "review"
  | "overdue"
  | "assessmentApproved";

export type AiScoringPhase = "idle" | "processing" | "complete";

/**
 * Hydrate AI scoring phase from persisted JSON or catalog rows.
 * `"processing"` becomes `"idle"` so an interrupted session does not stick in a loading state.
 */
export function normalizeAiScoringPhaseForHydrate(raw: unknown): AiScoringPhase {
  if (raw === "complete" || raw === "idle" || raw === "processing") {
    return raw === "processing" ? "idle" : raw;
  }
  return "idle";
}

export type CraScoringTypeChoice = "inherent" | "residual";

/**
 * Maps persisted catalog `MockCyberRiskAssessment.assessmentType` (e.g. `"Inherent scoring"`,
 * `"Residual scoring"`) to the Scoring / Results tab basis. Unknown values default to residual.
 */
export function craScoringTypeChoiceFromCatalogAssessmentType(
  assessmentType: string,
): CraScoringTypeChoice {
  const t = assessmentType.trim().toLowerCase();
  if (t.startsWith("inherent")) return "inherent";
  if (t.startsWith("residual")) return "residual";
  return "residual";
}

/** How parent cyber-risk rows aggregate scenario scores in the Scoring tab. */
export type CraScenarioScoreAggregationMethod = "highest" | "average";

export type ScopeSubView =
  | "overview"
  | "assets"
  | "scopedCyberRisks"
  | "scopedThreats"
  | "scopedVulnerabilities"
  | "scopedControls";

export type CraNewAssessmentPersistedDraft = {
  activeTab: number;
  assessmentPhase: AssessmentPhase;
  name: string;
  assessmentId: string;
  assessmentType: string;
  startDate: string;
  dueDate: string;
  ownerIds: string[];
  scopeSubView: ScopeSubView;
  includedScopeAssetIds: string[];
  /** Cyber risk library ids explicitly removed from this assessment (still in candidate set from assets). */
  excludedScopeCyberRiskIds: string[];
  /** Threat library ids explicitly excluded while still linked to candidate scope. */
  excludedScopeThreatIds: string[];
  excludedScopeVulnerabilityIds: string[];
  excludedScopeControlIds: string[];
  aiScoringPhase: AiScoringPhase;
  scoringType: CraScoringTypeChoice;
  scenarioScoreAggregationMethod: CraScenarioScoreAggregationMethod;
  /** Scenario library ids marked n/a for this assessment (excluded from parent aggregation). */
  scenarioNotApplicableIds: string[];
  /** Scenario library ids explicitly removed from this assessment (hidden from scoring/results). */
  excludedScopeScenarioIds: string[];
  /**
   * When true (new CRA draft only), AI scoring has completed; show catalog scores for every in-scope scenario.
   * Not inferred from `aiScoringPhase`; set explicitly when the AI run finishes.
   */
  scenarioCatalogScoresReleased: boolean;
  /**
   * Scenario library ids for which the user saved scores on the rationale page before AI completed.
   * Those rows show catalog scores in the scoring table while others stay masked.
   */
  scenarioManuallyRevealedScoreIds: string[];
};
