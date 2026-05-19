import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from "react";
import type { MouseEvent } from "react";
import {
  Box,
  IconButton,
  Link,
  Menu,
  MenuItem,
  Skeleton,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";
import type { Theme } from "@mui/material/styles";
import { useNavigate } from "react-router";

import ExpandDownIcon from "@diligentcorp/atlas-react-bundle/icons/ExpandDown";
import MoreIcon from "@diligentcorp/atlas-react-bundle/icons/More";

import AssessmentScopeEmptyState from "../components/AssessmentScopeEmptyState.js";
import ScoringInfoCard from "../components/ScoringInfoCard.js";

import { ragDataVizColor, type RagDataVizKey } from "../data/ragDataVisualization.js";
import {
  fivePointLabelToRag,
  getCyberRiskScoreLabel,
  getFivePointLabel,
  getLikelihoodLabel,
} from "../data/types.js";
import type { FivePointScaleLabel, FivePointScaleValue } from "../data/types.js";
import { getCatalogSnapshotVersion, subscribeCatalog } from "../data/persistence/catalogStore.js";
import { aggregateArithmeticMeanParentScores } from "../utils/craParentScoreAggregation.js";
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
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
} from "../data/assessmentScopeRollup.js";

const EMPTY_SCENARIO_NOT_APPLICABLE_IDS = new Set<string>();

const EMPTY_MANUAL_REVEAL_IDS: ReadonlySet<string> = new Set<string>();

type ScoreValue = {
  numeric: string;
  label: string;
  rag: RagDataVizKey;
} | null;

type ScoringRow = {
  id: string;
  kind: "cyberRisk" | "scenario";
  /** Cyber risk group id scenarios belong to */
  groupId: string;
  tag: string;
  title: React.ReactNode;
  impact: ScoreValue;
  threat: ScoreValue;
  vulnerability: ScoreValue;
  likelihood: ScoreValue;
  cyberRiskScore: ScoreValue;
};

/** Name column is fixed width (sticky first column). */
const SCORING_NAME_COL_WIDTH_PX = 400;

/** Actions column is fixed width (sticky last column). */
const SCORING_ACTIONS_COL_WIDTH_PX = 48;

const SCORING_IMPACT_MIN_PX = 80;
const SCORING_THREAT_MIN_PX = 132;
const SCORING_VULNERABILITY_MIN_PX = 164;
const SCORING_LIKELIHOOD_MIN_PX = 110;
const SCORING_CYBER_RISK_SCORE_MIN_PX = 134;

/**
 * Metric columns use intrinsic width from cell content.
 * `width: 0.01%` is a common auto-table hint so extra horizontal space is not assigned here first.
 */
const scoringMetricThSx = {
  px: 2,
  width: "0.01%",
  maxWidth: "max-content",
  boxSizing: "border-box" as const,
  overflow: "visible",
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
};

const scoringMetricTdSx = {
  px: 2,
  py: 0,
  width: "0.01%",
  maxWidth: "max-content",
  verticalAlign: "middle" as const,
  boxSizing: "border-box" as const,
  overflow: "visible",
  whiteSpace: "nowrap" as const,
};

const scoringImpactMetricThSx = { ...scoringMetricThSx, minWidth: SCORING_IMPACT_MIN_PX };
const scoringImpactMetricTdSx = { ...scoringMetricTdSx, minWidth: SCORING_IMPACT_MIN_PX };
const scoringThreatMetricThSx = { ...scoringMetricThSx, minWidth: SCORING_THREAT_MIN_PX };
const scoringThreatMetricTdSx = { ...scoringMetricTdSx, minWidth: SCORING_THREAT_MIN_PX };
const scoringVulnerabilityMetricThSx = { ...scoringMetricThSx, minWidth: SCORING_VULNERABILITY_MIN_PX };
const scoringVulnerabilityMetricTdSx = { ...scoringMetricTdSx, minWidth: SCORING_VULNERABILITY_MIN_PX };
const scoringLikelihoodMetricThSx = { ...scoringMetricThSx, minWidth: SCORING_LIKELIHOOD_MIN_PX };
const scoringLikelihoodMetricTdSx = { ...scoringMetricTdSx, minWidth: SCORING_LIKELIHOOD_MIN_PX };
const scoringCyberRiskScoreMetricThSx = { ...scoringMetricThSx, minWidth: SCORING_CYBER_RISK_SCORE_MIN_PX };
const scoringCyberRiskScoreMetricTdSx = { ...scoringMetricTdSx, minWidth: SCORING_CYBER_RISK_SCORE_MIN_PX };

const scoringNameHeadCellSx = ({ tokens: t }: Theme) => ({
  position: "sticky" as const,
  left: 0,
  zIndex: 3,
  width: SCORING_NAME_COL_WIDTH_PX,
  minWidth: SCORING_NAME_COL_WIDTH_PX,
  maxWidth: SCORING_NAME_COL_WIDTH_PX,
  boxSizing: "border-box" as const,
  bgcolor: t.semantic.color.background.container.value,
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
  overflow: "visible" as const,
});

const scoringNameBodyCellSx = ({ tokens: t }: Theme) => ({
  position: "sticky" as const,
  left: 0,
  zIndex: 2,
  bgcolor: t.semantic.color.background.base.value,
  width: SCORING_NAME_COL_WIDTH_PX,
  minWidth: SCORING_NAME_COL_WIDTH_PX,
  maxWidth: SCORING_NAME_COL_WIDTH_PX,
  boxSizing: "border-box" as const,
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
  overflow: "visible" as const,
});

/** Cyber risk (parent) rows — subtle surface band */
const scoringCyberRiskRowBodyCellBgSx = ({ tokens: t }: Theme) => ({
  bgcolor: t.semantic.color.surface.variant.value,
});

/** Scenario rows — lighter band under parent */
const scoringScenarioRowBodyCellBgSx = ({ tokens: t }: Theme) => ({
  bgcolor: t.semantic.color.background.base.value,
});

function RiskLegendCell({ value }: { value: ScoreValue }) {
  return (
    <Box sx={{ minHeight: 56, display: "flex", alignItems: "center", py: 1 }}>
      {value == null ? (
        <Typography
          sx={({ tokens: t }) => ({
            fontSize: t.semantic.font.label.xs.fontSize.value,
            lineHeight: t.semantic.font.label.xs.lineHeight.value,
            letterSpacing: t.semantic.font.label.xs.letterSpacing.value,
            fontFamily: t.semantic.font.label.xs.fontFamily.value,
            fontWeight: t.semantic.font.label.xs.fontWeight.value,
            color: t.semantic.color.type.muted.value,
          })}
        >
          -
        </Typography>
      ) : (
        <Stack direction="row" alignItems="center" gap={1} sx={{ height: 16 }}>
          <Box
            sx={({ tokens: t }) => ({
              width: 16,
              height: 16,
              borderRadius: t.semantic.radius.sm.value,
              flexShrink: 0,
              bgcolor: ragDataVizColor(t, value.rag),
            })}
          />
          <Typography
            component="span"
            sx={({ tokens: t }) => ({
              fontSize: t.semantic.font.label.xs.fontSize.value,
              lineHeight: t.semantic.font.label.xs.lineHeight.value,
              letterSpacing: t.semantic.font.label.xs.letterSpacing.value,
              fontFamily: t.semantic.font.label.xs.fontFamily.value,
              fontWeight: t.semantic.font.label.xs.fontWeight.value,
              color: t.semantic.color.type.default.value,
              whiteSpace: "nowrap",
            })}
          >
            {value.numeric} - {value.label}
          </Typography>
        </Stack>
      )}
    </Box>
  );
}

const scoreTableCellContentSx = {
  display: "flex",
  alignItems: "center",
  width: "max-content",
  maxWidth: "100%",
  minWidth: 0,
  overflow: "visible",
  boxSizing: "border-box" as const,
};

function MetricLegendCell({ value }: { value: ScoreValue }) {
  return (
    <Box sx={scoreTableCellContentSx}>
      <RiskLegendCell value={value} />
    </Box>
  );
}

function toFivePointScore(value: number, label: FivePointScaleLabel): ScoreValue {
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

function toLikelihoodScore(value: number): ScoreValue {
  const label = getLikelihoodLabel(value);
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

function toCyberRiskScoreValue(value: number): ScoreValue {
  const label = getCyberRiskScoreLabel(value);
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

function buildScoringRowsForScope(
  includedAssetIds: Set<string>,
  excludedScopeCyberRiskIds: Set<string>,
  excludedScopeScenarioIds: ReadonlySet<string>,
  scenarioNotApplicableIds: ReadonlySet<string> = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
  scenarioScopeAssessmentId?: string,
): ScoringRow[] {
  if (includedAssetIds.size === 0) return [];
  const risks = assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds);
  const scenarioList = assessmentScopedScenarios(
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
  );
  const byRisk = new Map<string, (typeof scenarioList)[number][]>();
  for (const s of scenarioList) {
    const list = byRisk.get(s.cyberRiskId) ?? [];
    list.push(s);
    byRisk.set(s.cyberRiskId, list);
  }

  return risks.flatMap((cr) => {
    const riskRow: ScoringRow = {
      id: cr.id,
      kind: "cyberRisk",
      groupId: cr.id,
      tag: "Cyber risk",
      title: (
        <Link
          href="#"
          onClick={(e) => e.preventDefault()}
          underline="always"
          sx={({ tokens: t }) => ({
            fontSize: t.semantic.font.text.md.fontSize.value,
            lineHeight: t.semantic.font.text.md.lineHeight.value,
            letterSpacing: t.semantic.font.text.md.letterSpacing.value,
            fontWeight: 600,
            color: t.semantic.color.type.default.value,
          })}
        >
          {cr.name}
        </Link>
      ),
      impact: null,
      threat: null,
      vulnerability: null,
      likelihood: null,
      cyberRiskScore: null,
    };

    const relatedScenarios = byRisk.get(cr.id) ?? [];
    const scenarioRows: ScoringRow[] = relatedScenarios.map((s) => {
      const na = scenarioNotApplicableIds.has(s.id);
      return {
        id: s.id,
        kind: "scenario" as const,
        groupId: cr.id,
        tag: "Scenario",
        title: (
          <Typography
            sx={({ tokens: t }) => ({
              fontSize: t.semantic.font.text.md.fontSize.value,
              lineHeight: t.semantic.font.text.md.lineHeight.value,
              letterSpacing: t.semantic.font.text.md.letterSpacing.value,
              color: t.semantic.color.type.default.value,
            })}
          >
            {s.name}
          </Typography>
        ),
        impact: na ? null : toFivePointScore(s.impact, s.impactLabel),
        threat: na ? null : toFivePointScore(s.threatSeverity, s.threatSeverityLabel),
        vulnerability: na ? null : toFivePointScore(s.vulnerabilitySeverity, s.vulnerabilitySeverityLabel),
        likelihood: na ? null : toLikelihoodScore(s.likelihood),
        cyberRiskScore: na ? null : toCyberRiskScoreValue(s.cyberRiskScore),
      };
    });

    return [riskRow, ...scenarioRows];
  });
}

function parseScoreNumeric(value: ScoreValue): number | null {
  if (value == null) return null;
  const n = Number.parseFloat(value.numeric);
  return Number.isFinite(n) ? n : null;
}

/** Parent cyber-risk row: Likelihood = T×V, Cyber risk score = I×L (same as scenario rows). */
function derivedParentLikelihoodAndCyberRisk(
  impact: ScoreValue,
  threat: ScoreValue,
  vulnerability: ScoreValue,
): { likelihood: ScoreValue; cyberRiskScore: ScoreValue } {
  if (impact == null || threat == null || vulnerability == null) {
    return { likelihood: null, cyberRiskScore: null };
  }
  const t = parseScoreNumeric(threat);
  const v = parseScoreNumeric(vulnerability);
  const i = parseScoreNumeric(impact);
  if (t == null || v == null || i == null) {
    return { likelihood: null, cyberRiskScore: null };
  }
  const likelihoodProduct = t * v;
  return {
    likelihood: toLikelihoodScore(likelihoodProduct),
    cyberRiskScore: toCyberRiskScoreValue(i * likelihoodProduct),
  };
}

type MetricKey = "impact" | "threat" | "vulnerability" | "likelihood" | "cyberRiskScore";

function emptyParentAggregate(): Record<MetricKey, ScoreValue> {
  return {
    impact: null,
    threat: null,
    vulnerability: null,
    likelihood: null,
    cyberRiskScore: null,
  };
}

const SCENARIO_FULL_SCORE_METRICS: MetricKey[] = [
  "impact",
  "threat",
  "vulnerability",
  "likelihood",
  "cyberRiskScore",
];

function hasCompleteScenarioScores(row: ScoringRow): boolean {
  if (row.kind !== "scenario") return false;
  for (const k of SCENARIO_FULL_SCORE_METRICS) {
    const v = row[k];
    if (v == null || parseScoreNumeric(v) == null) return false;
  }
  return true;
}

/** Parent aggregates only when every non–N/A scenario in the group has full scores. */
function areAllApplicableScenariosFullyScored(
  scenariosInGroup: ScoringRow[],
  scenarioNotApplicableIds: ReadonlySet<string>,
): boolean {
  const applicable = scenariosInGroup.filter(
    (r) => r.kind === "scenario" && !scenarioNotApplicableIds.has(r.id),
  );
  if (applicable.length === 0) return false;
  return applicable.every(hasCompleteScenarioScores);
}

/** Highest value among scenarios for one metric (parent row when aggregation = Highest). */
function aggregateMetricForGroupHighest(scenariosInGroup: ScoringRow[], metric: MetricKey): ScoreValue {
  const withValue = scenariosInGroup.filter((s) => s[metric] != null);
  if (withValue.length === 0) return null;

  const values = withValue.map((s) => s[metric]!);
  let best = values[0];
  let bestN = parseScoreNumeric(best)!;
  for (const v of values) {
    const n = parseScoreNumeric(v)!;
    if (n > bestN) {
      bestN = n;
      best = v;
    }
  }
  return best;
}

/** Persisted `average` — arithmetic mean of I/T/V per scenario, then Likelihood = T×V, Cyber risk score = I×L. */
function aggregateAverageParent(scenariosInGroup: ScoringRow[]): Record<MetricKey, ScoreValue> {
  const participating = scenariosInGroup.filter(
    (s) =>
      s.kind === "scenario" &&
      s.impact != null &&
      s.threat != null &&
      s.vulnerability != null &&
      parseScoreNumeric(s.impact) != null &&
      parseScoreNumeric(s.threat) != null &&
      parseScoreNumeric(s.vulnerability) != null,
  );
  if (participating.length === 0) return emptyParentAggregate();

  const numericInputs = participating.map((s) => ({
    impact: parseScoreNumeric(s.impact)!,
    threat: parseScoreNumeric(s.threat)!,
    vulnerability: parseScoreNumeric(s.vulnerability)!,
  }));

  const agg = aggregateArithmeticMeanParentScores(numericInputs);
  if (agg == null) return emptyParentAggregate();

  const impact = toFivePointScore(
    agg.impact,
    getFivePointLabel(agg.impact as FivePointScaleValue),
  );
  const threat = toFivePointScore(
    agg.threat,
    getFivePointLabel(agg.threat as FivePointScaleValue),
  );
  const vulnerability = toFivePointScore(
    agg.vulnerability,
    getFivePointLabel(agg.vulnerability as FivePointScaleValue),
  );
  const derived = derivedParentLikelihoodAndCyberRisk(impact, threat, vulnerability);
  return {
    impact,
    threat,
    vulnerability,
    likelihood: derived.likelihood,
    cyberRiskScore: derived.cyberRiskScore,
  };
}

function NameCell({
  row,
  expanded,
  onToggle,
}: {
  row: ScoringRow;
  expanded: boolean;
  onToggle: () => void;
}) {
  const isGroup = row.kind === "cyberRisk";
  return (
    <Stack
      direction="row"
      alignItems={isGroup ? "center" : "flex-start"}
      gap={1}
      sx={(theme) => ({
        py: 1,
        minHeight: 56,
        pl: isGroup ? 0 : `calc(${theme.spacing(4)} + 10px)`,
      })}
    >
      {isGroup ? (
        <IconButton
          size="small"
          onClick={(e) => {
            e.stopPropagation();
            onToggle();
          }}
          aria-expanded={expanded}
          aria-label={expanded ? "Collapse cyber risk" : "Expand cyber risk"}
          sx={{ p: 0.5 }}
        >
          <Box
            component="span"
            aria-hidden
            sx={{
              display: "inline-flex",
              transform: expanded ? "rotate(0deg)" : "rotate(-90deg)",
              transition: "transform 0.2s",
            }}
          >
            <ExpandDownIcon />
          </Box>
        </IconButton>
      ) : null}
      <Stack gap={0.25} sx={{ minWidth: 0, flex: 1 }}>
        <Box
          sx={({ tokens: t }) => ({
            alignSelf: "flex-start",
            px: 0.5,
            py: 0.25,
            borderRadius: t.semantic.radius.sm.value,
            bgcolor: t.semantic.color.surface.variant.value,
          })}
        >
          <Typography
            sx={({ tokens: t }) => ({
              fontSize: t.semantic.font.label.sm.fontSize.value,
              lineHeight: t.semantic.font.label.sm.lineHeight.value,
              letterSpacing: t.semantic.font.label.sm.letterSpacing.value,
              fontWeight: 600,
              color: t.semantic.color.type.default.value,
            })}
          >
            {row.tag}
          </Typography>
        </Box>
        <Box
          sx={{
            minWidth: 0,
            whiteSpace: "normal",
            wordBreak: "break-word",
            overflowWrap: "break-word",
            "& .MuiTypography-root": { whiteSpace: "normal" },
            "& .MuiLink-root": { whiteSpace: "normal" },
          }}
        >
          {row.title}
        </Box>
      </Stack>
    </Stack>
  );
}

function MetricScoreSkeleton() {
  return (
    <Box sx={{ minHeight: 56, display: "flex", alignItems: "center", py: 1 }}>
      <Skeleton variant="rounded" width={120} height={22} sx={{ borderRadius: 1 }} />
    </Box>
  );
}

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
      buildScoringRowsForScope(
        includedAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeScenarioIds,
        scenarioNotApplicableIds,
        scenarioScopeAssessmentId,
      ),
    [includedAssetIds, excludedScopeCyberRiskIds, excludedScopeScenarioIds, scenarioNotApplicableIds, scenarioScopeAssessmentId, catalogVersion],
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
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [rowActionsMenu, setRowActionsMenu] = useState<
    null | { anchor: HTMLElement; rowKind: "cyberRisk" | "scenario"; rowId: string }
  >(null);

  useEffect(() => {
    const riskIds = scoringRows.filter((r) => r.kind === "cyberRisk").map((r) => r.id);
    setExpanded(Object.fromEntries(riskIds.map((id) => [id, true])));
  }, [scoringRows]);

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

  const toggleGroup = useCallback((groupId: string) => {
    setExpanded((prev) => ({ ...prev, [groupId]: !prev[groupId] }));
  }, []);

  const closeRowActionsMenu = useCallback(() => setRowActionsMenu(null), []);

  const handleRowActionsButtonClick = useCallback(
    (e: MouseEvent<HTMLElement>, rowKind: "cyberRisk" | "scenario", rowId: string) => {
      e.stopPropagation();
      if (rowActionsDisabled) return;
      setRowActionsMenu({ anchor: e.currentTarget, rowKind, rowId });
    },
    [rowActionsDisabled],
  );

  const handleConfirmRemoveFromMenu = useCallback(() => {
    setRowActionsMenu((prev) => {
      if (!prev) return prev;
      if (prev.rowKind === "cyberRisk") {
        onRemoveCyberRiskFromAssessment(prev.rowId);
      } else {
        onRemoveScenarioFromAssessment(prev.rowId);
      }
      return null;
    });
  }, [onRemoveCyberRiskFromAssessment, onRemoveScenarioFromAssessment]);

  useEffect(() => {
    setRowActionsMenu((prev) => {
      if (!prev) return prev;
      const still = rowsForDisplay.some((r) => r.id === prev.rowId && r.kind === prev.rowKind);
      return still ? prev : null;
    });
  }, [rowsForDisplay]);

  const scenariosByGroupId = useMemo(() => {
    const m = new Map<string, ScoringRow[]>();
    for (const row of rowsForDisplay) {
      if (row.kind !== "scenario") continue;
      const list = m.get(row.groupId) ?? [];
      list.push(row);
      m.set(row.groupId, list);
    }
    return m;
  }, [rowsForDisplay]);

  const aggregatedByGroupId = useMemo(() => {
    const result = new Map<string, Record<MetricKey, ScoreValue>>();
    for (const [groupId, scenarios] of scenariosByGroupId) {
      if (!areAllApplicableScenariosFullyScored(scenarios, scenarioNotApplicableIds)) {
        result.set(groupId, emptyParentAggregate());
        continue;
      }
      if (aggregationMethod === "average") {
        result.set(groupId, aggregateAverageParent(scenarios));
        continue;
      }
      const baseMetrics: Array<"impact" | "threat" | "vulnerability"> = [
        "impact",
        "threat",
        "vulnerability",
      ];
      const agg = {} as Record<MetricKey, ScoreValue>;
      for (const m of baseMetrics) {
        agg[m] = aggregateMetricForGroupHighest(scenarios, m);
      }
      const derived = derivedParentLikelihoodAndCyberRisk(agg.impact, agg.threat, agg.vulnerability);
      agg.likelihood = derived.likelihood;
      agg.cyberRiskScore = derived.cyberRiskScore;
      result.set(groupId, agg);
    }
    return result;
  }, [aggregationMethod, scenarioNotApplicableIds, scenariosByGroupId]);

  const visibleRows = useMemo(() => {
    const out: ScoringRow[] = [];
    let currentGroup = "";
    let groupOpen = true;
    for (const row of rowsForDisplay) {
      if (row.kind === "cyberRisk") {
        currentGroup = row.groupId;
        groupOpen = expanded[row.groupId] !== false;
        out.push(row);
        continue;
      }
      if (row.groupId === currentGroup && groupOpen) {
        out.push(row);
      }
    }
    return out;
  }, [expanded, rowsForDisplay]);

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
        description={aiScoringPhase === "complete" ? null : undefined}
        onAction={
          showAiScoringAction && aiScoringPhase !== "complete" ? onAiScoringClick : undefined
        }
        actionLoading={aiScoringPhase === "processing"}
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
      ) : null}

      {scoringRows.length === 0 ? null : (
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
        <TableContainer
          aria-busy={aiScoringPhase === "processing"}
          sx={{
            overflowX: "auto",
            overflowY: "visible",
            maxWidth: "100%",
            borderRadius: ({ tokens: t }) => t.semantic.radius.sm.value,
            bgcolor: ({ tokens: t }) => t.semantic.color.background.base.value,
          }}
        >
          <Table
            stickyHeader
            size="small"
            sx={{
              tableLayout: "auto",
              width: "100%",
              borderCollapse: "separate",
              borderSpacing: 0,
              "& .MuiTableCell-root": {
                borderBottom: ({ tokens: t }) => `1px solid ${t.semantic.color.ui.divider.default.value}`,
                overflow: "visible",
              },
              "& .MuiTableBody-root .MuiTableCell-root": {
                verticalAlign: "middle",
              },
            }}
          >
            <TableHead>
              <TableRow
                sx={({ tokens: t }) => ({
                  "& .MuiTableCell-head": {
                    bgcolor: t.semantic.color.background.container.value,
                    fontSize: t.semantic.font.label.sm.fontSize.value,
                    lineHeight: t.semantic.font.label.sm.lineHeight.value,
                    letterSpacing: t.semantic.font.label.sm.letterSpacing.value,
                    fontWeight: 600,
                    color: t.semantic.color.type.default.value,
                    py: 0.5,
                    px: 2,
                    verticalAlign: "middle",
                    overflow: "visible",
                  },
                })}
              >
                <TableCell sx={scoringNameHeadCellSx}>Name</TableCell>
                <TableCell sx={scoringImpactMetricThSx}>Impact</TableCell>
                <TableCell sx={scoringThreatMetricThSx}>Threat severity</TableCell>
                <TableCell sx={scoringVulnerabilityMetricThSx}>Vulnerability severity</TableCell>
                <TableCell sx={scoringLikelihoodMetricThSx}>Likelihood</TableCell>
                <TableCell sx={scoringCyberRiskScoreMetricThSx}>Cyber risk score</TableCell>
                <TableCell
                  align="right"
                  sx={({ tokens: t }) => ({
                    width: SCORING_ACTIONS_COL_WIDTH_PX,
                    minWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                    maxWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                    position: "sticky",
                    right: 0,
                    zIndex: 3,
                    bgcolor: t.semantic.color.background.container.value,
                  })}
                />
              </TableRow>
            </TableHead>
            <TableBody>
              {aiScoringPhase === "processing"
                ? visibleRows.map((row) => (
                    <TableRow key={row.id} hover={false}>
                      <TableCell
                        sx={[
                          scoringNameBodyCellSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <NameCell
                          row={row}
                          expanded={expanded[row.groupId] !== false}
                          onToggle={() => toggleGroup(row.groupId)}
                        />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringMetricTdSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringThreatMetricTdSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringVulnerabilityMetricTdSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringLikelihoodMetricTdSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringCyberRiskScoreMetricTdSx,
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        align="right"
                        sx={[
                          ({ tokens: t }) => ({
                            position: "sticky",
                            right: 0,
                            zIndex: 2,
                            width: SCORING_ACTIONS_COL_WIDTH_PX,
                            minWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                            maxWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                            bgcolor: t.semantic.color.background.base.value,
                            verticalAlign: "middle",
                          }),
                          row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                          row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                        ]}
                      >
                        <IconButton size="small" aria-label="Row actions" disabled>
                          <MoreIcon aria-hidden />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))
                : visibleRows.map((row) => {
                    const isScenario = row.kind === "scenario";
                    const parentAgg =
                      row.kind === "cyberRisk" ? aggregatedByGroupId.get(row.groupId) : undefined;
                    let impactValue: ScoreValue = isScenario ? row.impact : parentAgg?.impact ?? null;
                    let threatValue: ScoreValue = isScenario ? row.threat : parentAgg?.threat ?? null;
                    let vulnerabilityValue: ScoreValue = isScenario
                      ? row.vulnerability
                      : parentAgg?.vulnerability ?? null;
                    let likelihoodValue: ScoreValue = isScenario
                      ? row.likelihood
                      : parentAgg?.likelihood ?? null;
                    let cyberRiskScoreValue: ScoreValue = isScenario
                      ? row.cyberRiskScore
                      : parentAgg?.cyberRiskScore ?? null;
                    return (
                      <TableRow
                        key={row.id}
                        hover={isScenario}
                        tabIndex={isScenario ? 0 : undefined}
                        aria-label={
                          isScenario
                            ? assessmentPhase === "assessmentApproved"
                              ? `Open ${row.tag}: ${row.id}. Press Enter to view scenario rationale (read-only).`
                              : `Open ${row.tag}: ${row.id}. Press Enter to view scoring rationale.`
                            : undefined
                        }
                        onClick={() => {
                          if (isScenario) goToScenario(row.id);
                        }}
                        onKeyDown={(e) => {
                          if (!isScenario) return;
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            goToScenario(row.id);
                          }
                        }}
                        sx={
                          isScenario
                            ? ({ tokens: t }) => ({
                                cursor: "pointer",
                                "&.MuiTableRow-hover:hover": {
                                  backgroundColor: t.semantic.color.action.secondary.hoverFill.value,
                                },
                                "&.MuiTableRow-hover:hover .MuiTableCell-root": {
                                  backgroundColor: t.semantic.color.action.secondary.hoverFill.value,
                                },
                                "&:focus-visible": {
                                  outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                                  outlineOffset: -2,
                                },
                              })
                            : undefined
                        }
                      >
                        <TableCell
                          sx={[
                            scoringNameBodyCellSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <NameCell
                            row={row}
                            expanded={expanded[row.groupId] !== false}
                            onToggle={() => toggleGroup(row.groupId)}
                          />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringImpactMetricTdSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <Box sx={scoreTableCellContentSx}>
                            <RiskLegendCell value={impactValue} />
                          </Box>
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringThreatMetricTdSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={threatValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringVulnerabilityMetricTdSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={vulnerabilityValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringLikelihoodMetricTdSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={likelihoodValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringCyberRiskScoreMetricTdSx,
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={cyberRiskScoreValue} />
                        </TableCell>
                        <TableCell
                          align="right"
                          sx={[
                            ({ tokens: t }) => ({
                              position: "sticky",
                              right: 0,
                              zIndex: 2,
                              width: SCORING_ACTIONS_COL_WIDTH_PX,
                              minWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                              maxWidth: SCORING_ACTIONS_COL_WIDTH_PX,
                              bgcolor: t.semantic.color.background.base.value,
                              verticalAlign: "middle",
                            }),
                            row.kind === "cyberRisk" && scoringCyberRiskRowBodyCellBgSx,
                            row.kind === "scenario" && scoringScenarioRowBodyCellBgSx,
                          ]}
                          onClick={(e) => e.stopPropagation()}
                        >
                          <IconButton
                            size="small"
                            aria-label="Row actions"
                            aria-haspopup="true"
                            aria-expanded={
                              rowActionsMenu?.rowId === row.id && rowActionsMenu?.rowKind === row.kind
                                ? true
                                : undefined
                            }
                            aria-controls={
                              rowActionsMenu?.rowId === row.id && rowActionsMenu?.rowKind === row.kind
                                ? "assessment-scoring-row-actions-menu"
                                : undefined
                            }
                            disabled={rowActionsDisabled}
                            onClick={(e) => handleRowActionsButtonClick(e, row.kind, row.id)}
                          >
                            <MoreIcon aria-hidden />
                          </IconButton>
                        </TableCell>
                      </TableRow>
                    );
                  })}
            </TableBody>
          </Table>
        </TableContainer>
        <Menu
          id="assessment-scoring-row-actions-menu"
          anchorEl={rowActionsMenu?.anchor ?? null}
          open={Boolean(rowActionsMenu)}
          onClose={closeRowActionsMenu}
          anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
          transformOrigin={{ vertical: "top", horizontal: "right" }}
        >
          <MenuItem
            onClick={() => {
              handleConfirmRemoveFromMenu();
            }}
          >
            Remove
          </MenuItem>
        </Menu>
      </Box>
      )}
    </Stack>
  );
}
