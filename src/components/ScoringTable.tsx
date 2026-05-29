import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
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

import MoreIcon from "@diligentcorp/atlas-react-bundle/icons/More";

import {
  ASSESSMENT_CONFIDENCE_MIN_PX,
  ASSESSMENT_CYBER_RISK_SCORE_MIN_PX,
  ASSESSMENT_IMPACT_MIN_PX,
  ASSESSMENT_LIKELIHOOD_MIN_PX,
  ASSESSMENT_THREAT_MIN_PX,
  ASSESSMENT_VULNERABILITY_MIN_PX,
  AssessmentTreeNameCell,
  assessmentMetricTdSx,
  assessmentMetricThSx,
  assessmentTreeNameBodyCellSx,
  assessmentTreeNameHeadCellSx,
  assessmentTreeRowBodyCellBgSx,
  getConnectorType,
  scoreTableCellContentSx,
} from "./assessmentTreeTableUi.js";

import { ragDataVizColor, type RagDataVizKey } from "../data/ragDataVisualization.js";
import {
  fivePointLabelToRag,
  getCyberRiskScoreLabel,
  getFivePointLabel,
  getLikelihoodLabel,
} from "../data/types.js";
import type { FivePointScaleLabel, FivePointScaleValue } from "../data/types.js";
import { aggregateArithmeticMeanParentScores } from "../utils/craParentScoreAggregation.js";
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
} from "../data/assessmentScopeRollup.js";
import { formatScenarioConfidencePercent } from "../utils/scenarioConfidence.js";
import type {
  AiScoringPhase,
  AssessmentPhase,
  CraScenarioScoreAggregationMethod,
} from "../pages/craNewAssessmentDraftStorage.js";

const EMPTY_SCENARIO_NOT_APPLICABLE_IDS = new Set<string>();

export type ScoringTableScoreValue = {
  numeric: string;
  label: string;
  rag: RagDataVizKey;
} | null;

export type ScoringTableRow = {
  id: string;
  kind: "cyberRisk" | "scenario";
  /** Cyber risk group id scenarios belong to */
  groupId: string;
  tag: string;
  title: ReactNode;
  impact: ScoringTableScoreValue;
  threat: ScoringTableScoreValue;
  vulnerability: ScoringTableScoreValue;
  likelihood: ScoringTableScoreValue;
  cyberRiskScore: ScoringTableScoreValue;
  /** Scenario-only; parent rows use null. */
  confidencePercent: number | null;
};

/** Actions column is fixed width (sticky last column). */
const SCORING_ACTIONS_COL_WIDTH_PX = 48;

const scoringImpactMetricThSx = assessmentMetricThSx(ASSESSMENT_IMPACT_MIN_PX);
const scoringImpactMetricTdSx = assessmentMetricTdSx(ASSESSMENT_IMPACT_MIN_PX);
const scoringThreatMetricThSx = assessmentMetricThSx(ASSESSMENT_THREAT_MIN_PX);
const scoringThreatMetricTdSx = assessmentMetricTdSx(ASSESSMENT_THREAT_MIN_PX);
const scoringVulnerabilityMetricThSx = assessmentMetricThSx(ASSESSMENT_VULNERABILITY_MIN_PX);
const scoringVulnerabilityMetricTdSx = assessmentMetricTdSx(ASSESSMENT_VULNERABILITY_MIN_PX);
const scoringLikelihoodMetricThSx = assessmentMetricThSx(ASSESSMENT_LIKELIHOOD_MIN_PX);
const scoringLikelihoodMetricTdSx = assessmentMetricTdSx(ASSESSMENT_LIKELIHOOD_MIN_PX);
const scoringCyberRiskScoreMetricThSx = assessmentMetricThSx(ASSESSMENT_CYBER_RISK_SCORE_MIN_PX);
const scoringCyberRiskScoreMetricTdSx = assessmentMetricTdSx(ASSESSMENT_CYBER_RISK_SCORE_MIN_PX);
const scoringConfidenceMetricThSx = assessmentMetricThSx(ASSESSMENT_CONFIDENCE_MIN_PX);
const scoringConfidenceMetricTdSx = assessmentMetricTdSx(ASSESSMENT_CONFIDENCE_MIN_PX);

function RiskLegendCell({ value }: { value: ScoringTableScoreValue }) {
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

function MetricLegendCell({ value }: { value: ScoringTableScoreValue }) {
  return (
    <Box sx={scoreTableCellContentSx}>
      <RiskLegendCell value={value} />
    </Box>
  );
}

function ConfidenceCell({ value }: { value: number | null }) {
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
          {formatScenarioConfidencePercent(value)}
        </Typography>
      )}
    </Box>
  );
}

function toFivePointScore(value: number, label: FivePointScaleLabel): ScoringTableScoreValue {
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

function toLikelihoodScore(value: number): ScoringTableScoreValue {
  const label = getLikelihoodLabel(value);
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

function toCyberRiskScoreValue(value: number): ScoringTableScoreValue {
  const label = getCyberRiskScoreLabel(value);
  return { numeric: String(value), label, rag: fivePointLabelToRag(label) };
}

export function buildScoringTableRows(
  includedAssetIds: Set<string>,
  excludedScopeCyberRiskIds: Set<string>,
  excludedScopeScenarioIds: ReadonlySet<string>,
  scenarioNotApplicableIds: ReadonlySet<string> = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
  scenarioScopeAssessmentId?: string,
): ScoringTableRow[] {
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
    const riskRow: ScoringTableRow = {
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
      confidencePercent: null,
    };

    const relatedScenarios = byRisk.get(cr.id) ?? [];
    const scenarioRows: ScoringTableRow[] = relatedScenarios.map((s) => {
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
        confidencePercent: s.confidencePercent,
      };
    });

    return [riskRow, ...scenarioRows];
  });
}

function parseScoreNumeric(value: ScoringTableScoreValue): number | null {
  if (value == null) return null;
  const n = Number.parseFloat(value.numeric);
  return Number.isFinite(n) ? n : null;
}

/** Parent cyber-risk row: Likelihood = T×V, Cyber risk score = I×L (same as scenario rows). */
function derivedParentLikelihoodAndCyberRisk(
  impact: ScoringTableScoreValue,
  threat: ScoringTableScoreValue,
  vulnerability: ScoringTableScoreValue,
): { likelihood: ScoringTableScoreValue; cyberRiskScore: ScoringTableScoreValue } {
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

function emptyParentAggregate(): Record<MetricKey, ScoringTableScoreValue> {
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

function hasCompleteScenarioScores(row: ScoringTableRow): boolean {
  if (row.kind !== "scenario") return false;
  for (const k of SCENARIO_FULL_SCORE_METRICS) {
    const v = row[k];
    if (v == null || parseScoreNumeric(v) == null) return false;
  }
  return true;
}

/** Parent aggregates only when every non–N/A scenario in the group has full scores. */
function areAllApplicableScenariosFullyScored(
  scenariosInGroup: ScoringTableRow[],
  scenarioNotApplicableIds: ReadonlySet<string>,
): boolean {
  const applicable = scenariosInGroup.filter(
    (r) => r.kind === "scenario" && !scenarioNotApplicableIds.has(r.id),
  );
  if (applicable.length === 0) return false;
  return applicable.every(hasCompleteScenarioScores);
}

/** Highest value among scenarios for one metric (parent row when aggregation = Highest). */
function aggregateMetricForGroupHighest(scenariosInGroup: ScoringTableRow[], metric: MetricKey): ScoringTableScoreValue {
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
function aggregateAverageParent(scenariosInGroup: ScoringTableRow[]): Record<MetricKey, ScoringTableScoreValue> {
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

function MetricScoreSkeleton() {
  return (
    <Box sx={{ minHeight: 56, display: "flex", alignItems: "center", py: 1 }}>
      <Skeleton variant="rounded" width={120} height={22} sx={{ borderRadius: 1 }} />
    </Box>
  );
}
export type ScoringTableProps = {
  rows: ScoringTableRow[];
  aggregationMethod: CraScenarioScoreAggregationMethod;
  scenarioNotApplicableIds?: ReadonlySet<string>;
  aiScoringPhase: AiScoringPhase;
  assessmentPhase: AssessmentPhase;
  rowActionsDisabled?: boolean;
  onScenarioRowClick: (scenarioId: string) => void;
  onRemoveCyberRiskFromAssessment: (cyberRiskId: string) => void;
  onRemoveScenarioFromAssessment: (scenarioId: string) => void;
};

export function ScoringTable({
  rows,
  aggregationMethod,
  scenarioNotApplicableIds = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
  aiScoringPhase,
  assessmentPhase,
  rowActionsDisabled = false,
  onScenarioRowClick,
  onRemoveCyberRiskFromAssessment,
  onRemoveScenarioFromAssessment,
}: ScoringTableProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [rowActionsMenu, setRowActionsMenu] = useState<
    null | { anchor: HTMLElement; rowKind: "cyberRisk" | "scenario"; rowId: string }
  >(null);

  useEffect(() => {
    const riskIds = rows.filter((r) => r.kind === "cyberRisk").map((r) => r.id);
    setExpanded(Object.fromEntries(riskIds.map((id) => [id, true])));
  }, [rows]);

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
      const still = rows.some((r) => r.id === prev.rowId && r.kind === prev.rowKind);
      return still ? prev : null;
    });
  }, [rows]);

  const scenariosByGroupId = useMemo(() => {
    const m = new Map<string, ScoringTableRow[]>();
    for (const row of rows) {
      if (row.kind !== "scenario") continue;
      const list = m.get(row.groupId) ?? [];
      list.push(row);
      m.set(row.groupId, list);
    }
    return m;
  }, [rows]);

  const aggregatedByGroupId = useMemo(() => {
    const result = new Map<string, Record<MetricKey, ScoringTableScoreValue>>();
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
      const agg = {} as Record<MetricKey, ScoringTableScoreValue>;
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
    const out: ScoringTableRow[] = [];
    let currentGroup = "";
    let groupOpen = true;
    for (const row of rows) {
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
  }, [expanded, rows]);

  if (rows.length === 0) {
    return null;
  }

  return (
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
                <TableCell sx={assessmentTreeNameHeadCellSx}>Name</TableCell>
                <TableCell sx={scoringImpactMetricThSx}>Impact</TableCell>
                <TableCell sx={scoringThreatMetricThSx}>Threat severity</TableCell>
                <TableCell sx={scoringVulnerabilityMetricThSx}>Vulnerability severity</TableCell>
                <TableCell sx={scoringLikelihoodMetricThSx}>Likelihood</TableCell>
                <TableCell sx={scoringCyberRiskScoreMetricThSx}>Cyber risk score</TableCell>
                <TableCell sx={scoringConfidenceMetricThSx}>Confidence</TableCell>
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
                ? visibleRows.map((row, idx) => {
                    const connectorType = getConnectorType(row, visibleRows, idx);
                    return (
                      <TableRow key={row.id} hover={false}>
                        <TableCell
                          sx={[
                            assessmentTreeNameBodyCellSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <AssessmentTreeNameCell
                            kind={row.kind}
                            tag={row.tag}
                            title={row.title}
                            expanded={expanded[row.groupId] !== false}
                            onToggle={() => toggleGroup(row.groupId)}
                            connectorType={connectorType}
                          />
                        </TableCell>
                      <TableCell
                        sx={[
                          scoringImpactMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringThreatMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringVulnerabilityMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringLikelihoodMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringCyberRiskScoreMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <MetricScoreSkeleton />
                      </TableCell>
                      <TableCell
                        sx={[
                          scoringConfidenceMetricTdSx,
                          assessmentTreeRowBodyCellBgSx,
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
                          assessmentTreeRowBodyCellBgSx,
                        ]}
                      >
                        <IconButton size="small" aria-label="Row actions" disabled>
                          <MoreIcon aria-hidden />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                    );
                  })
                : visibleRows.map((row, idx) => {
                    const connectorType = getConnectorType(row, visibleRows, idx);
                    const isScenario = row.kind === "scenario";
                    const parentAgg =
                      row.kind === "cyberRisk" ? aggregatedByGroupId.get(row.groupId) : undefined;
                    let impactValue: ScoringTableScoreValue = isScenario ? row.impact : parentAgg?.impact ?? null;
                    let threatValue: ScoringTableScoreValue = isScenario ? row.threat : parentAgg?.threat ?? null;
                    let vulnerabilityValue: ScoringTableScoreValue = isScenario
                      ? row.vulnerability
                      : parentAgg?.vulnerability ?? null;
                    let likelihoodValue: ScoringTableScoreValue = isScenario
                      ? row.likelihood
                      : parentAgg?.likelihood ?? null;
                    let cyberRiskScoreValue: ScoringTableScoreValue = isScenario
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
                          if (isScenario) onScenarioRowClick(row.id);
                        }}
                        onKeyDown={(e) => {
                          if (!isScenario) return;
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            onScenarioRowClick(row.id);
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
                            assessmentTreeNameBodyCellSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <AssessmentTreeNameCell
                            kind={row.kind}
                            tag={row.tag}
                            title={row.title}
                            expanded={expanded[row.groupId] !== false}
                            onToggle={() => toggleGroup(row.groupId)}
                            connectorType={connectorType}
                          />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringImpactMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <Box sx={scoreTableCellContentSx}>
                            <RiskLegendCell value={impactValue} />
                          </Box>
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringThreatMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={threatValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringVulnerabilityMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={vulnerabilityValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringLikelihoodMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={likelihoodValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringCyberRiskScoreMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <MetricLegendCell value={cyberRiskScoreValue} />
                        </TableCell>
                        <TableCell
                          sx={[
                            scoringConfidenceMetricTdSx,
                            assessmentTreeRowBodyCellBgSx,
                          ]}
                        >
                          <ConfidenceCell
                            value={isScenario ? row.confidencePercent : null}
                          />
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
                            assessmentTreeRowBodyCellBgSx,
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
                                ? "scoring-table-row-actions-menu"
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
          id="scoring-table-row-actions-menu"
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
  );
}
