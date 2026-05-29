import { useCallback, useMemo, useSyncExternalStore } from "react";
import { Box, Stack, Typography } from "@mui/material";
import { useNavigate } from "react-router";

import AssessmentScopeEmptyState from "../components/AssessmentScopeEmptyState.js";
import ScoringInfoCard from "../components/ScoringInfoCard.js";
import { ScoringTable, buildScoringTableRows } from "../components/ScoringTable.js";

import { getCatalogSnapshotVersion, subscribeCatalog } from "../data/persistence/catalogStore.js";
import {
  scenarioCatalogScoresVisibleInAssessmentUi,
  type ScenarioCatalogMaskContext,
} from "../utils/scenarioCatalogScoreMask.js";
import {
  scenarioRationaleReadOnlyPath,
  scenarioScoringRationalePath,
} from "./craScenarioRoutes.js";
import {
  NEW_CRA_SCORING_TAB_INDEX,
  type AiScoringPhase,
  type AssessmentPhase,
  type CraScenarioScoreAggregationMethod,
  type CraScoringTypeChoice,
} from "./craNewAssessmentDraftStorage.js";

const EMPTY_SCENARIO_NOT_APPLICABLE_IDS = new Set<string>();

const EMPTY_MANUAL_REVEAL_IDS: ReadonlySet<string> = new Set<string>();

type AssessmentScoringTabProps = {
  /** Passed to the scenario detail page for breadcrumbs. */
  assessmentName?: string;
  /** Current CRA assessment URL; used when returning from scenario scoring rationale. */
  returnToAssessmentPath: string;
  /** Parent-controlled aggregation for cyber-risk parent rows (persisted on the CRA draft). */
  aggregationMethod: CraScenarioScoreAggregationMethod;
  onAggregationMethodChange: (method: CraScenarioScoreAggregationMethod) => void;
  includedAssetIds: Set<string>;
  excludedScopeCyberRiskIds: Set<string>;
  assessmentPhase: AssessmentPhase;
  aiScoringPhase: AiScoringPhase;
  scoringType: CraScoringTypeChoice;
  /** Scoring or overdue phase: show AI scoring CTA above the table. */
  showAiScoringAction: boolean;
  onAiScoringClick: () => void;
  /** Empty state: navigate to Scope tab. */
  onGoToScope: () => void;
  /** Scenario library ids marked N/A for scoring (scores not masked for these rows). */
  scenarioNotApplicableIds?: ReadonlySet<string>;
  /** New CRA draft: per-scenario masking of catalog scores until AI completes or that scenario is saved on rationale. */
  isNewCraDraftFlow?: boolean;
  scenarioCatalogScoresReleased?: boolean;
  scenarioManuallyRevealedScoreIds?: ReadonlySet<string>;
  /** Pass-through to scenario rationale navigation state. */
  scenarioNavFromNewCraDraft?: boolean;
  scenarioNavCatalogScoresReleased?: boolean;
  scenarioNavManuallyRevealedScoreIds?: ReadonlySet<string>;
  /** Scenario library ids removed from this assessment (hidden from the scoring table). */
  excludedScopeScenarioIds?: ReadonlySet<string>;
  /** When set, only scenarios for this CRA (or untagged seed scenarios) appear in the grid. */
  scenarioScopeAssessmentId?: string;
  /** Remove a cyber risk from the assessment scope (same as Scope tab exclude). */
  onRemoveCyberRiskFromAssessment: (cyberRiskId: string) => void;
  /** Remove a scenario from the assessment scope. */
  onRemoveScenarioFromAssessment: (scenarioId: string) => void;
  /** When true, row action menus are disabled (e.g. approved assessment). */
  rowActionsDisabled?: boolean;
};

export default function AssessmentScoringTab({
  assessmentName = "",
  returnToAssessmentPath,
  aggregationMethod,
  onAggregationMethodChange,
  includedAssetIds,
  excludedScopeCyberRiskIds,
  assessmentPhase,
  aiScoringPhase,
  scoringType,
  showAiScoringAction,
  onAiScoringClick,
  onGoToScope,
  scenarioNotApplicableIds = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
  excludedScopeScenarioIds = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
  scenarioScopeAssessmentId,
  isNewCraDraftFlow = false,
  scenarioCatalogScoresReleased = true,
  scenarioManuallyRevealedScoreIds = EMPTY_MANUAL_REVEAL_IDS,
  scenarioNavFromNewCraDraft = false,
  scenarioNavCatalogScoresReleased = true,
  scenarioNavManuallyRevealedScoreIds = EMPTY_MANUAL_REVEAL_IDS,
  onRemoveCyberRiskFromAssessment,
  onRemoveScenarioFromAssessment,
  rowActionsDisabled = false,
}: AssessmentScoringTabProps) {
  const navigate = useNavigate();
  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    getCatalogSnapshotVersion,
  );
  const scoringRows = useMemo(
    () =>
      buildScoringTableRows(
        includedAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeScenarioIds,
        scenarioNotApplicableIds,
        scenarioScopeAssessmentId,
      ),
    [
      includedAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeScenarioIds,
      scenarioNotApplicableIds,
      scenarioScopeAssessmentId,
      catalogVersion,
    ],
  );

  const processingScenariosTotal = useMemo(
    () => scoringRows.filter((row) => row.kind === "scenario").length,
    [scoringRows],
  );

  const catalogMaskContext: ScenarioCatalogMaskContext = useMemo(
    () => ({
      assessmentPhase,
      aiScoringPhase,
      isNewCraDraftFlow: isNewCraDraftFlow ?? false,
      scenarioCatalogScoresReleased: scenarioCatalogScoresReleased ?? true,
      scenarioManuallyRevealedScoreIds,
      scenarioNotApplicableIds,
    }),
    [
      assessmentPhase,
      aiScoringPhase,
      isNewCraDraftFlow,
      scenarioCatalogScoresReleased,
      scenarioManuallyRevealedScoreIds,
      scenarioNotApplicableIds,
    ],
  );

  const rowsForDisplay = useMemo(() => {
    if (assessmentPhase === "assessmentApproved") {
      return scoringRows;
    }
    return scoringRows.map((r) => {
      if (r.kind !== "scenario") return r;
      if (scenarioCatalogScoresVisibleInAssessmentUi(r.id, catalogMaskContext)) return r;
      return {
        ...r,
        threat: null,
        vulnerability: null,
        likelihood: null,
        cyberRiskScore: null,
      };
    });
  }, [assessmentPhase, scoringRows, catalogMaskContext]);

  const goToScenario = useCallback(
    (scenarioId: string) => {
      const path =
        assessmentPhase === "assessmentApproved"
          ? scenarioRationaleReadOnlyPath(scenarioId)
          : scenarioScoringRationalePath(scenarioId);
      navigate(path, {
        state: {
          assessmentName: assessmentName.trim() || undefined,
          scoringType,
          aiScoringPhase,
          returnToAssessmentPath,
          craReturnToTabIndex: NEW_CRA_SCORING_TAB_INDEX,
          ...(assessmentPhase === "assessmentApproved"
            ? {}
            : {
                fromNewCraDraft: scenarioNavFromNewCraDraft,
                scenarioCatalogScoresReleased: scenarioNavCatalogScoresReleased,
                scenarioManuallyRevealedScoreIds: [...scenarioNavManuallyRevealedScoreIds],
              }),
        },
      });
    },
    [
      navigate,
      assessmentName,
      scoringType,
      aiScoringPhase,
      returnToAssessmentPath,
      assessmentPhase,
      scenarioNavFromNewCraDraft,
      scenarioNavCatalogScoresReleased,
      scenarioNavManuallyRevealedScoreIds,
    ],
  );

  if (includedAssetIds.size === 0) {
    return (
      <Stack
        sx={({ tokens: t }) => ({
          width: "100%",
          minWidth: 0,
          alignItems: "stretch",
          gap: t.core.spacing["3"].value,
          pt: t.core.spacing["3"].value,
          pb: t.core.spacing["4"].value,
        })}
      >
        <AssessmentScopeEmptyState variant="scoring" onPrimaryAction={onGoToScope} />
      </Stack>
    );
  }

  return (
    <Stack
      sx={({ tokens: t }) => ({
        width: "100%",
        minWidth: 0,
        alignItems: "stretch",
        gap: t.core.spacing["3"].value,
        pt: t.core.spacing["3"].value,
        pb: t.core.spacing["4"].value,
      })}
    >
      <ScoringInfoCard
        omitHeader={!showAiScoringAction}
        title={aiScoringPhase === "complete" ? "AI scoring completed" : "AI scoring"}
        description={
          aiScoringPhase === "complete"
            ? "Scoring and the rationales were generated. Review the results and adjust as needed."
            : undefined
        }
        actionLabel={aiScoringPhase === "complete" ? "Restart AI scoring" : undefined}
        onAction={showAiScoringAction ? onAiScoringClick : undefined}
        actionLoading={aiScoringPhase === "processing"}
        processingScenariosTotal={processingScenariosTotal}
        aggregationMethodRadio={{
          name: "cra-scoring-tab-aggregation",
          value: aggregationMethod,
          onValueChange: onAggregationMethodChange,
          disabled: aiScoringPhase === "processing",
        }}
      />
      {scoringRows.length === 0 ? (
        <Typography
          variant="body1"
          sx={({ tokens: t }) => ({ color: t.semantic.color.type.muted.value })}
        >
          No cyber risks or scenarios are linked to the selected assets. Adjust selections on the Scope tab if needed.
        </Typography>
      ) : (
        <Box
          sx={({ tokens: t }) => ({
            borderRadius: t.semantic.radius.md.value,
            background: "none",
            backgroundColor: "unset",
            overflow: "visible",
            width: "100%",
            p: 0,
          })}
        >
          <ScoringTable
            rows={rowsForDisplay}
            aggregationMethod={aggregationMethod}
            scenarioNotApplicableIds={scenarioNotApplicableIds}
            aiScoringPhase={aiScoringPhase}
            assessmentPhase={assessmentPhase}
            rowActionsDisabled={rowActionsDisabled}
            onScenarioRowClick={goToScenario}
            onRemoveCyberRiskFromAssessment={onRemoveCyberRiskFromAssessment}
            onRemoveScenarioFromAssessment={onRemoveScenarioFromAssessment}
          />
        </Box>
      )}
    </Stack>
  );
}
