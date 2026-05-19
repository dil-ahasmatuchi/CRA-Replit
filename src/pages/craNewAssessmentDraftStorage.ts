import type { AssessmentStatus } from "../data/types.js";
import {
  normalizeAiScoringPhaseForHydrate,
  type AiScoringPhase,
  type AssessmentPhase,
  type CraNewAssessmentPersistedDraft,
  type CraScenarioScoreAggregationMethod,
  type CraScoringTypeChoice,
  type ScopeSubView,
} from "../data/craAssessmentDraftTypes.js";
import {
  getPersistedCraDraft,
  hydratePersistedCraDraft,
  markCatalogDirty,
  setPersistedCraDraft,
} from "../data/persistence/catalogStore.js";
import { assessmentScopedScenarios } from "../data/assessmentScopeRollup.js";

export type {
  AiScoringPhase,
  AssessmentPhase,
  CraNewAssessmentPersistedDraft,
  CraScenarioScoreAggregationMethod,
  CraScoringTypeChoice,
  ScopeSubView,
} from "../data/craAssessmentDraftTypes.js";

/** `navigate` state when opening a scenario from the new CRA scoring or results table. */
export type CraScenarioDetailLocationState = {
  assessmentName?: string;
  scoringType?: CraScoringTypeChoice;
  aiScoringPhase?: AiScoringPhase;
  /** CRA assessment route to return to (e.g. `/cyber-risk/cyber-risk-assessments/new` or `.../:id`). */
  returnToAssessmentPath?: string;
  /**
   * Which main assessment tab the user was on (for back from scenario / rationale).
   * {@link NEW_CRA_SCORING_TAB_INDEX} = Scoring, {@link NEW_CRA_RESULTS_TAB_INDEX} = Results.
   */
  craReturnToTabIndex?: number;
  /** True when navigating from new CRA scoring tab (not catalog-backed assessment row). */
  fromNewCraDraft?: boolean;
  /** Snapshot: AI completed for assessment; all scenario catalog scores visible. */
  scenarioCatalogScoresReleased?: boolean;
  /** Snapshot: scenario ids with visible catalog scores after manual rationale save. */
  scenarioManuallyRevealedScoreIds?: string[];
  /** When present (e.g. after save + navigate), destination shows a one-time “Changes were saved.” toast. */
  showSavedChangesToast?: boolean;
};

const STORAGE_KEY = "cra_new_assessment_draft_v1";

const SCOPE_TAB_INDEX = 1;
const SCORING_TAB_INDEX = 2;
const RESULTS_TAB_INDEX = 3;

/** New CRA `AssessmentDetailsTab` tab indices (match persisted `activeTab`). */
export const NEW_CRA_SCORING_TAB_INDEX = SCORING_TAB_INDEX;
export const NEW_CRA_RESULTS_TAB_INDEX = RESULTS_TAB_INDEX;

function isAssessmentPhase(v: unknown): v is AssessmentPhase {
  return (
    v === "draft" ||
    v === "scoping" ||
    v === "inProgress" ||
    v === "review" ||
    v === "overdue" ||
    v === "assessmentApproved"
  );
}

function isCraScoringTypeChoice(v: unknown): v is CraScoringTypeChoice {
  return v === "inherent" || v === "residual";
}

function normalizeCraScoringTypeChoice(v: unknown): CraScoringTypeChoice {
  if (v === "inherent_residual") return "residual";
  if (isCraScoringTypeChoice(v)) return v;
  return "residual";
}

function isCraScenarioScoreAggregationMethod(v: unknown): v is CraScenarioScoreAggregationMethod {
  return v === "highest" || v === "average";
}

function normalizeScenarioScoreAggregationMethod(
  v: unknown,
): CraScenarioScoreAggregationMethod {
  return isCraScenarioScoreAggregationMethod(v) ? v : "highest";
}

function isScopeSubView(v: unknown): v is ScopeSubView {
  return (
    v === "overview" ||
    v === "assets" ||
    v === "scopedCyberRisks" ||
    v === "scopedThreats" ||
    v === "scopedVulnerabilities" ||
    v === "scopedControls"
  );
}

export function sanitizeCraNewAssessmentDraft(
  raw: Partial<CraNewAssessmentPersistedDraft>,
): CraNewAssessmentPersistedDraft {
  let activeTab =
    typeof raw.activeTab === "number" && raw.activeTab >= 0 && raw.activeTab <= 3
      ? raw.activeTab
      : 0;
  const assessmentPhase = isAssessmentPhase(raw.assessmentPhase) ? raw.assessmentPhase : "draft";
  const scopingStarted = assessmentPhase !== "draft";
  const assessmentStarted =
    assessmentPhase === "inProgress" ||
    assessmentPhase === "review" ||
    assessmentPhase === "overdue" ||
    assessmentPhase === "assessmentApproved";
  if (!scopingStarted && activeTab === SCOPE_TAB_INDEX) {
    activeTab = 0;
  }
  if (!assessmentStarted && (activeTab === SCORING_TAB_INDEX || activeTab === RESULTS_TAB_INDEX)) {
    activeTab = 0;
  }
  const scopeSubView = isScopeSubView(raw.scopeSubView) ? raw.scopeSubView : "overview";
  const ownerIds = Array.isArray(raw.ownerIds)
    ? (raw.ownerIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const includedScopeAssetIds = Array.isArray(raw.includedScopeAssetIds)
    ? (raw.includedScopeAssetIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const excludedScopeCyberRiskIds = Array.isArray(raw.excludedScopeCyberRiskIds)
    ? (raw.excludedScopeCyberRiskIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const excludedScopeThreatIds = Array.isArray(raw.excludedScopeThreatIds)
    ? (raw.excludedScopeThreatIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const excludedScopeVulnerabilityIds = Array.isArray(raw.excludedScopeVulnerabilityIds)
    ? (raw.excludedScopeVulnerabilityIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const excludedScopeControlIds = Array.isArray(raw.excludedScopeControlIds)
    ? (raw.excludedScopeControlIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const aiScoringPhase = normalizeAiScoringPhaseForHydrate(raw.aiScoringPhase);
  const scoringType = normalizeCraScoringTypeChoice(raw.scoringType);
  const scenarioScoreAggregationMethod = normalizeScenarioScoreAggregationMethod(
    raw.scenarioScoreAggregationMethod,
  );
  const scenarioNotApplicableIds = Array.isArray(raw.scenarioNotApplicableIds)
    ? (raw.scenarioNotApplicableIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const excludedScopeScenarioIds = Array.isArray(raw.excludedScopeScenarioIds)
    ? (raw.excludedScopeScenarioIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const scenarioCatalogScoresReleased = raw.scenarioCatalogScoresReleased === true;
  const scenarioManuallyRevealedScoreIdsRaw = Array.isArray(raw.scenarioManuallyRevealedScoreIds)
    ? (raw.scenarioManuallyRevealedScoreIds as unknown[]).filter((x): x is string => typeof x === "string")
    : [];
  const scenarioManuallyRevealedScoreIds = [...new Set(scenarioManuallyRevealedScoreIdsRaw)];
  return {
    activeTab,
    assessmentPhase,
    name: typeof raw.name === "string" ? raw.name : "",
    assessmentId: typeof raw.assessmentId === "string" ? raw.assessmentId : "",
    assessmentType: typeof raw.assessmentType === "string" ? raw.assessmentType : "",
    startDate: typeof raw.startDate === "string" ? raw.startDate : "",
    dueDate: typeof raw.dueDate === "string" ? raw.dueDate : "",
    ownerIds,
    scopeSubView,
    includedScopeAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
    aiScoringPhase,
    scoringType,
    scenarioScoreAggregationMethod,
    scenarioNotApplicableIds,
    excludedScopeScenarioIds,
    scenarioCatalogScoresReleased,
    scenarioManuallyRevealedScoreIds,
  };
}

export function loadCraNewAssessmentDraft(): CraNewAssessmentPersistedDraft | null {
  const fromCatalog = getPersistedCraDraft();
  if (fromCatalog) return sanitizeCraNewAssessmentDraft(fromCatalog);
  try {
    const item = sessionStorage.getItem(STORAGE_KEY);
    if (!item) return null;
    const parsed = JSON.parse(item) as unknown;
    if (parsed == null || typeof parsed !== "object") return null;
    const o = parsed as Record<string, unknown>;
    const migrated = sanitizeCraNewAssessmentDraft({
      activeTab: o.activeTab as number,
      assessmentPhase: o.assessmentPhase as AssessmentPhase,
      name: o.name as string,
      assessmentId: o.assessmentId as string,
      assessmentType: o.assessmentType as string,
      startDate: o.startDate as string,
      dueDate: o.dueDate as string,
      ownerIds: o.ownerIds as string[],
      scopeSubView: o.scopeSubView as ScopeSubView,
      includedScopeAssetIds: o.includedScopeAssetIds as string[],
      excludedScopeCyberRiskIds: o.excludedScopeCyberRiskIds as string[] | undefined,
      excludedScopeThreatIds: o.excludedScopeThreatIds as string[] | undefined,
      excludedScopeVulnerabilityIds: o.excludedScopeVulnerabilityIds as string[] | undefined,
      excludedScopeControlIds: o.excludedScopeControlIds as string[] | undefined,
      aiScoringPhase: o.aiScoringPhase as AiScoringPhase,
      scoringType: o.scoringType as CraScoringTypeChoice | undefined,
      scenarioScoreAggregationMethod: o.scenarioScoreAggregationMethod as
        | CraScenarioScoreAggregationMethod
        | undefined,
      scenarioNotApplicableIds: o.scenarioNotApplicableIds as string[] | undefined,
      excludedScopeScenarioIds: o.excludedScopeScenarioIds as string[] | undefined,
      scenarioCatalogScoresReleased: o.scenarioCatalogScoresReleased as boolean | undefined,
      scenarioManuallyRevealedScoreIds: o.scenarioManuallyRevealedScoreIds as string[] | undefined,
    });
    setPersistedCraDraft(migrated);
    try {
      sessionStorage.removeItem(STORAGE_KEY);
    } catch {
      // ignore
    }
    return migrated;
  } catch {
    return null;
  }
}

export function saveCraNewAssessmentDraft(draft: CraNewAssessmentPersistedDraft): void {
  setPersistedCraDraft(sanitizeCraNewAssessmentDraft(draft));
}

/**
 * When the session draft is in Scoping with scope assets and at least one scoped scenario,
 * advances phase to inProgress (Scoring) so returning from the scenario page restores the right phase.
 */
export function advanceCraPhaseToScoringIfEligible(): void {
  const draft = loadCraNewAssessmentDraft();
  if (!draft) return;
  if (draft.assessmentPhase !== "scoping") return;
  const assetIds = new Set(draft.includedScopeAssetIds);
  if (assetIds.size === 0) return;
  const excluded = new Set(draft.excludedScopeCyberRiskIds);
  const excludedScenarios = new Set(draft.excludedScopeScenarioIds);
  const craScope =
    typeof draft.assessmentId === "string" && /^CRA-\d+$/.test(draft.assessmentId)
      ? draft.assessmentId
      : undefined;
  if (assessmentScopedScenarios(assetIds, excluded, excludedScenarios, craScope).length === 0) return;
  saveCraNewAssessmentDraft({
    ...draft,
    assessmentPhase: "inProgress",
  });
}

/** Clears persisted draft (e.g. before a fresh "new assessment" visit). */
export function clearCraNewAssessmentDraft(): void {
  try {
    sessionStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
  hydratePersistedCraDraft(null);
  markCatalogDirty();
}

/** Maps list/grid `AssessmentStatus` to header workflow phase (e.g. when opening an existing mock assessment). */
export function assessmentStatusToPhase(status: AssessmentStatus): AssessmentPhase {
  switch (status) {
    case "Draft":
      return "draft";
    case "Scoping":
      return "scoping";
    case "Scoring":
      return "inProgress";
    case "Review":
      return "review";
    case "Approved":
      return "assessmentApproved";
    case "Overdue":
      return "overdue";
    default:
      return "draft";
  }
}

/** Inverse of {@link assessmentStatusToPhase} for the current CRA workflow. */
export function assessmentPhaseToAssessmentStatus(phase: AssessmentPhase): AssessmentStatus {
  switch (phase) {
    case "draft":
      return "Draft";
    case "scoping":
      return "Scoping";
    case "inProgress":
      return "Scoring";
    case "review":
      return "Review";
    case "overdue":
      return "Overdue";
    case "assessmentApproved":
      return "Approved";
  }
}
