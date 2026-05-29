import { useCallback, useEffect, useMemo, useState, type KeyboardEvent } from "react";
import {
  Box,
  Button,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from "@mui/material";

import {
  ASSESSMENT_CYBER_RISK_SCORE_MIN_PX,
  ASSESSMENT_IMPACT_MIN_PX,
  ASSESSMENT_LIKELIHOOD_MIN_PX,
  ASSESSMENT_MITIGATION_MIN_PX,
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
import { NewToolbarStandalone } from "./NewToolbar.js";
import {
  type AssessmentCyberResultsRow,
  type AssessmentResultsScoreChip,
} from "../pages/craAssessmentScopeRows.js";
import { ragDataVizColor } from "../data/ragDataVisualization.js";

export type ResultsScoreChip = AssessmentResultsScoreChip;

const RESULTS_COLUMN_DEFS = [
  { field: "impact", headerName: "Impact" },
  { field: "threat", headerName: "Threat severity" },
  { field: "vulnerability", headerName: "Vulnerability severity" },
  { field: "likelihood", headerName: "Likelihood" },
  { field: "cyberRiskScore", headerName: "Cyber risk score" },
  { field: "mitigationPlan", headerName: "Mitigation plan" },
] as const;

type ResultsColumnField = (typeof RESULTS_COLUMN_DEFS)[number]["field"];

const resultsImpactMetricThSx = assessmentMetricThSx(ASSESSMENT_IMPACT_MIN_PX);
const resultsImpactMetricTdSx = assessmentMetricTdSx(ASSESSMENT_IMPACT_MIN_PX);
const resultsThreatMetricThSx = assessmentMetricThSx(ASSESSMENT_THREAT_MIN_PX);
const resultsThreatMetricTdSx = assessmentMetricTdSx(ASSESSMENT_THREAT_MIN_PX);
const resultsVulnerabilityMetricThSx = assessmentMetricThSx(ASSESSMENT_VULNERABILITY_MIN_PX);
const resultsVulnerabilityMetricTdSx = assessmentMetricTdSx(ASSESSMENT_VULNERABILITY_MIN_PX);
const resultsLikelihoodMetricThSx = assessmentMetricThSx(ASSESSMENT_LIKELIHOOD_MIN_PX);
const resultsLikelihoodMetricTdSx = assessmentMetricTdSx(ASSESSMENT_LIKELIHOOD_MIN_PX);
const resultsCyberRiskScoreMetricThSx = assessmentMetricThSx(ASSESSMENT_CYBER_RISK_SCORE_MIN_PX);
const resultsCyberRiskScoreMetricTdSx = assessmentMetricTdSx(ASSESSMENT_CYBER_RISK_SCORE_MIN_PX);
const resultsMitigationMetricThSx = assessmentMetricThSx(ASSESSMENT_MITIGATION_MIN_PX);
const resultsMitigationMetricTdSx = assessmentMetricTdSx(ASSESSMENT_MITIGATION_MIN_PX);

/** RAG-colored chip used on assessment results grids (cyber risks tree and assets). */
export function ResultsRiskChip({ value }: { value: ResultsScoreChip | null }) {
  if (value == null) {
    return (
      <Typography
        component="span"
        aria-label="Score not available until AI scoring completes or scores are revealed."
        sx={({ tokens: t }) => ({
          fontSize: t.semantic.font.label.xs.fontSize.value,
          lineHeight: t.semantic.font.label.xs.lineHeight.value,
          letterSpacing: t.semantic.font.label.xs.letterSpacing.value,
          fontWeight: t.semantic.font.label.xs.fontWeight.value,
          color: t.semantic.color.type.muted.value,
          whiteSpace: "nowrap",
        })}
      >
        —
      </Typography>
    );
  }
  return (
    <Stack direction="row" alignItems="center" gap={1} sx={{ height: 16, py: 1 }}>
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
          fontWeight: t.semantic.font.label.xs.fontWeight.value,
          color: t.semantic.color.type.default.value,
          whiteSpace: "nowrap",
        })}
      >
        {value.numeric} - {value.label}
      </Typography>
    </Stack>
  );
}

function ResultsMetricCell({ value }: { value: ResultsScoreChip | null }) {
  return (
    <Box sx={{ minHeight: 56, display: "flex", alignItems: "center", py: 1 }}>
      <Box sx={scoreTableCellContentSx}>
        <ResultsRiskChip value={value} />
      </Box>
    </Box>
  );
}

type CyberResultsRow = AssessmentCyberResultsRow;

function filterRowsByQuickSearch(
  rows: AssessmentCyberResultsRow[],
  query: string,
): AssessmentCyberResultsRow[] {
  const q = query.trim().toLowerCase();
  if (!q) return rows;

  const matchingGroupIds = new Set<string>();
  for (const row of rows) {
    if (row.name.toLowerCase().includes(q)) {
      matchingGroupIds.add(row.groupId);
    }
  }

  return rows.filter((row) => matchingGroupIds.has(row.groupId));
}

function buildVisibleRows(
  rows: AssessmentCyberResultsRow[],
  expanded: Record<string, boolean>,
): AssessmentCyberResultsRow[] {
  const out: AssessmentCyberResultsRow[] = [];
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
}

function resultsRowTitle(row: AssessmentCyberResultsRow) {
  return (
    <Typography
      sx={({ tokens: t }) => ({
        fontSize: t.semantic.font.text.md.fontSize.value,
        lineHeight: t.semantic.font.text.md.lineHeight.value,
        letterSpacing: t.semantic.font.text.md.letterSpacing.value,
        fontWeight: row.kind === "cyberRisk" ? 600 : undefined,
        color: t.semantic.color.type.default.value,
      })}
    >
      {row.name}
    </Typography>
  );
}

export type ResultsTableProps = {
  rows: AssessmentCyberResultsRow[];
  onOpenMitigationPlan: (row: CyberResultsRow) => void;
  /** When set, scenario rows are clickable (e.g. approved assessment → read-only rationale). */
  onScenarioRowClick?: (scenarioId: string) => void;
  /** Opens the page filter UI (e.g. [`FilterSideSheet`](./FilterSideSheet.tsx)). */
  onOpenFilters: () => void;
  /**
   * Number of filter criteria with a selection; drives **Filter (n)** and the filled filter icon on
   * [`NewToolbar`](./NewToolbar.tsx).
   */
  filterCriteriaCount?: number;
  /** Clears applied filters; enables **Clear filters** on the toolbar when `filterCriteriaCount` &gt; 0. */
  onClearFilters?: () => void;
};

/** Results table (tree) for cyber risk + scenario rows on the assessment Results tab. */
export function ResultsTable({
  rows,
  onOpenMitigationPlan,
  onScenarioRowClick,
  onOpenFilters,
  filterCriteriaCount = 0,
  onClearFilters,
}: ResultsTableProps) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [quickSearch, setQuickSearch] = useState("");
  const [hiddenColumns, setHiddenColumns] = useState<Set<ResultsColumnField>>(() => new Set());

  useEffect(() => {
    const riskIds = rows.filter((r) => r.kind === "cyberRisk").map((r) => r.id);
    setExpanded(Object.fromEntries(riskIds.map((id) => [id, true])));
  }, [rows]);

  const toggleGroup = useCallback((groupId: string) => {
    setExpanded((prev) => ({ ...prev, [groupId]: !prev[groupId] }));
  }, []);

  const searchFilteredRows = useMemo(
    () => filterRowsByQuickSearch(rows, quickSearch),
    [rows, quickSearch],
  );

  const visibleRows = useMemo(
    () => buildVisibleRows(searchFilteredRows, expanded),
    [searchFilteredRows, expanded],
  );

  const isColumnVisible = useCallback(
    (field: ResultsColumnField) => !hiddenColumns.has(field),
    [hiddenColumns],
  );

  const handleHiddenColumnsChange = useCallback((next: Set<string>) => {
    setHiddenColumns(next as Set<ResultsColumnField>);
  }, []);

  if (rows.length === 0) {
    return null;
  }

  return (
    <Stack gap={2} sx={{ width: "100%" }}>
      <NewToolbarStandalone
        searchValue={quickSearch}
        onSearchChange={setQuickSearch}
        onOpenFilters={onOpenFilters}
        filterCriteriaCount={filterCriteriaCount}
        onClearFilters={onClearFilters}
        columns={[...RESULTS_COLUMN_DEFS]}
        hiddenColumns={hiddenColumns}
        onHiddenColumnsChange={handleHiddenColumnsChange}
      />
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
          aria-label="Cyber risks in this assessment. Toolbar: quick search, filters, and column visibility. Expand a row to view scenarios. Scenario rows may open read-only rationale."
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
              minWidth: 1100,
              borderCollapse: "separate",
              borderSpacing: 0,
              "& .MuiTableCell-root": {
                borderBottom: ({ tokens: t }) =>
                  `1px solid ${t.semantic.color.ui.divider.default.value}`,
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
                {isColumnVisible("impact") ? (
                  <TableCell sx={resultsImpactMetricThSx}>Impact</TableCell>
                ) : null}
                {isColumnVisible("threat") ? (
                  <TableCell sx={resultsThreatMetricThSx}>Threat severity</TableCell>
                ) : null}
                {isColumnVisible("vulnerability") ? (
                  <TableCell sx={resultsVulnerabilityMetricThSx}>Vulnerability severity</TableCell>
                ) : null}
                {isColumnVisible("likelihood") ? (
                  <TableCell sx={resultsLikelihoodMetricThSx}>Likelihood</TableCell>
                ) : null}
                {isColumnVisible("cyberRiskScore") ? (
                  <TableCell sx={resultsCyberRiskScoreMetricThSx}>Cyber risk score</TableCell>
                ) : null}
                {isColumnVisible("mitigationPlan") ? (
                  <TableCell sx={resultsMitigationMetricThSx}>Mitigation plan</TableCell>
                ) : null}
              </TableRow>
            </TableHead>
            <TableBody>
              {visibleRows.map((row, idx) => {
                const connectorType = getConnectorType(row, visibleRows, idx);
                const isScenario = row.kind === "scenario";
                const scenarioClickable = isScenario && onScenarioRowClick != null;

                return (
                  <TableRow
                    key={row.id}
                    hover={scenarioClickable}
                    tabIndex={scenarioClickable ? 0 : undefined}
                    onClick={() => {
                      if (scenarioClickable) onScenarioRowClick(row.id);
                    }}
                    onKeyDown={(e: KeyboardEvent) => {
                      if (!scenarioClickable) return;
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        onScenarioRowClick(row.id);
                      }
                    }}
                    sx={
                      scenarioClickable
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
                    <TableCell sx={[assessmentTreeNameBodyCellSx, assessmentTreeRowBodyCellBgSx]}>
                      <AssessmentTreeNameCell
                        kind={row.kind}
                        tag={row.kind === "cyberRisk" ? "Cyber risk" : "Scenario"}
                        title={resultsRowTitle(row)}
                        expanded={expanded[row.groupId] !== false}
                        onToggle={() => toggleGroup(row.groupId)}
                        connectorType={connectorType}
                      />
                    </TableCell>
                    {isColumnVisible("impact") ? (
                      <TableCell sx={[resultsImpactMetricTdSx, assessmentTreeRowBodyCellBgSx]}>
                        <ResultsMetricCell value={row.impact} />
                      </TableCell>
                    ) : null}
                    {isColumnVisible("threat") ? (
                      <TableCell sx={[resultsThreatMetricTdSx, assessmentTreeRowBodyCellBgSx]}>
                        <ResultsMetricCell value={row.threat} />
                      </TableCell>
                    ) : null}
                    {isColumnVisible("vulnerability") ? (
                      <TableCell
                        sx={[resultsVulnerabilityMetricTdSx, assessmentTreeRowBodyCellBgSx]}
                      >
                        <ResultsMetricCell value={row.vulnerability} />
                      </TableCell>
                    ) : null}
                    {isColumnVisible("likelihood") ? (
                      <TableCell sx={[resultsLikelihoodMetricTdSx, assessmentTreeRowBodyCellBgSx]}>
                        <ResultsMetricCell value={row.likelihood} />
                      </TableCell>
                    ) : null}
                    {isColumnVisible("cyberRiskScore") ? (
                      <TableCell
                        sx={[resultsCyberRiskScoreMetricTdSx, assessmentTreeRowBodyCellBgSx]}
                      >
                        <ResultsMetricCell value={row.cyberRiskScore} />
                      </TableCell>
                    ) : null}
                    {isColumnVisible("mitigationPlan") ? (
                      <TableCell
                        sx={[resultsMitigationMetricTdSx, assessmentTreeRowBodyCellBgSx]}
                        onClick={(e) => e.stopPropagation()}
                      >
                        {row.kind === "cyberRisk" ? (
                          <Box sx={{ minHeight: 56, display: "flex", alignItems: "center", py: 1 }}>
                            <Button
                              size="small"
                              variant="text"
                              onClick={(e) => {
                                e.stopPropagation();
                                onOpenMitigationPlan(row);
                              }}
                              sx={({ tokens: t }) => ({
                                fontWeight: 600,
                                textTransform: "none",
                                color: t.semantic.color.action.link.default.value,
                              })}
                            >
                              + Mitigation plan
                            </Button>
                          </Box>
                        ) : null}
                      </TableCell>
                    ) : null}
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    </Stack>
  );
}
