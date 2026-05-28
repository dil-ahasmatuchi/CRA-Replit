import { useCallback, useMemo, useState, type MouseEvent } from "react";
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Link,
  Stack,
  ToggleButton,
  ToggleButtonGroup,
  Typography,
  type SxProps,
  type Theme,
} from "@mui/material";
import { useNavigate } from "react-router";

import { useCyberRiskScoringConfig } from "../context/CyberRiskScoringConfigContext.js";

import type { MockCyberRisk } from "../data/types.js";
import { buildMatrixQueryStringForRisksPage } from "../utils/cyberRiskMatrixTableQuery.js";
import {
  buildCyberRiskHeatmapAggregates,
  type CyberRiskHeatmapScoreBasis,
} from "../utils/cyberRiskMatrixAggregates.js";
import type { CyberRiskMatrixTableFilter } from "../utils/cyberRiskTableRows.js";
import {
  ragDataVizColor,
  type RiskHeatmapLevel,
  RISK_HEATMAP_LEVEL_TO_RAG,
} from "../data/ragDataVisualization.js";

export type { RiskHeatmapLegendItem } from "../utils/cyberRiskMatrixAggregates.js";

const CYBER_RISKS_PATH = "/cyber-risk/cyber-risks";

export type AssessmentMatrixMode = "default" | "inherentOnly" | "residualPreferred";

export type MatrixSelectionPayload = {
  kind: "cell" | "legend";
  basis: CyberRiskHeatmapScoreBasis;
  rowIdx?: number;
  colIdx?: number;
  level?: RiskHeatmapLevel;
  orgUnitId?: string | null;
};

export interface RisksMatrixProps {
  risks: readonly MockCyberRisk[];
  yAxisLabel?: string;
  xAxisLabel?: string;
  sx?: SxProps<Theme>;
  /** In-page list selection (e.g. Cyber risks list); otherwise `navigate` to the risks route with query. */
  onMatrixSelection?: (payload: MatrixSelectionPayload) => void;
  /** When an org. unit is selected in the parent (hero), pass through so the table can match the heatmap count. */
  orgUnitId?: string | null;
  /**
   * Assessment results: align matrix with CRA scoring type.
   * - Omitted or `"default"`: show Inherent/Residual toggle; Inherent is the default selection.
   * - `"inherentOnly"`: hide the toggle; matrix always uses Inherent.
   * - `"residualPreferred"`: show the toggle; Residual is the default selection.
   */
  assessmentMatrixMode?: AssessmentMatrixMode;
}

/**
 * Likelihood × impact cell severity for the 5×5 heatmap (same row/column semantics as
 * `buildCyberRiskHeatmapAggregates`: row 0 = very high likelihood … row 4 = very low;
 * col 0 = very low impact … col 4 = very high).
 *
 * Uses numeric weights VL=5 … VH=25 per axis; score = (L×I)/5 = 5×(5−rowIdx)×(colIdx+1), then CRA brackets.
 */
export function getCellLevel(rowIdx: number, colIdx: number): RiskHeatmapLevel {
  const score = 5 * (5 - rowIdx) * (colIdx + 1);
  if (score <= 25) return "veryLow";
  if (score <= 50) return "low";
  if (score <= 75) return "medium";
  if (score <= 100) return "high";
  return "veryHigh";
}

export default function RisksMatrix({
  risks,
  yAxisLabel = "Likelihood",
  xAxisLabel = "Impact",
  sx,
  onMatrixSelection,
  orgUnitId: orgUnitIdProp = null,
  assessmentMatrixMode = "default",
}: RisksMatrixProps) {
  const navigate = useNavigate();
  const { cyberScoreBands, likelihoodBands } = useCyberRiskScoringConfig();
  const isInherentOnly = assessmentMatrixMode === "inherentOnly";
  const showInherentResidualToggle = !isInherentOnly;
  const [basisState, setBasis] = useState<CyberRiskHeatmapScoreBasis>(() =>
    assessmentMatrixMode === "residualPreferred" ? "residual" : "inherent",
  );
  const basis: CyberRiskHeatmapScoreBasis = isInherentOnly ? "inherent" : basisState;

  const { grid, legend } = useMemo(
    () => buildCyberRiskHeatmapAggregates(risks, basis),
    [risks, basis, cyberScoreBands, likelihoodBands],
  );

  const gridRows = grid.length;
  const gridCols = grid[0]?.length ?? 0;
  const r = 6;

  const runMatrixAction = useCallback(
    (matrixFilter: CyberRiskMatrixTableFilter) => {
      const bu = orgUnitIdProp ?? null;
      const basePayload: MatrixSelectionPayload =
        matrixFilter.kind === "cell"
          ? { kind: "cell", basis: matrixFilter.basis, rowIdx: matrixFilter.rowIdx, colIdx: matrixFilter.colIdx, orgUnitId: bu }
          : {
              kind: "legend",
              basis: matrixFilter.basis,
              level: matrixFilter.level,
              orgUnitId: bu,
            };
      onMatrixSelection?.(basePayload);
      if (onMatrixSelection) return;
      const qs = buildMatrixQueryStringForRisksPage(matrixFilter, bu);
      void navigate({ pathname: CYBER_RISKS_PATH, search: qs.startsWith("?") ? qs.slice(1) : qs });
    },
    [orgUnitIdProp, navigate, onMatrixSelection],
  );

  const onCellCountClick = useCallback(
    (e: MouseEvent, rowIdx: number, colIdx: number) => {
      e.preventDefault();
      e.stopPropagation();
      runMatrixAction({ kind: "cell", basis, rowIdx, colIdx });
    },
    [basis, runMatrixAction],
  );

  const onLegendCountClick = useCallback(
    (e: MouseEvent, level: RiskHeatmapLevel) => {
      e.preventDefault();
      e.stopPropagation();
      runMatrixAction({ kind: "legend", basis, level });
    },
    [basis, runMatrixAction],
  );

  return (
    <Card
      sx={[
        { border: "none" },
        ...(sx === undefined || sx === null ? [] : Array.isArray(sx) ? sx : [sx]),
      ]}
    >
      <CardHeader
        sx={{ display: "flex" }}
        title={
          <Typography variant="h4" component="h2" fontWeight={600}>
            Cyber risks
          </Typography>
        }
        action={
          showInherentResidualToggle ? (
            <ToggleButtonGroup
              exclusive
              size="small"
              value={basis}
              onChange={(_e, value: CyberRiskHeatmapScoreBasis | null) => {
                if (value != null) setBasis(value);
              }}
              aria-label="Cyber risk score basis"
            >
              <ToggleButton value="inherent" aria-label="Inherent cyber risk score">
                Inherent
              </ToggleButton>
              <ToggleButton value="residual" aria-label="Residual cyber risk score">
                Residual
              </ToggleButton>
            </ToggleButtonGroup>
          ) : undefined
        }
      />
      <CardContent sx={{ pt: 0 }}>
        <Stack gap={2}>
          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: `auto repeat(${gridCols}, 1fr)`,
              gridTemplateRows: `repeat(${gridRows}, 1fr) auto`,
              gap: "4px",
              width: "100%",
            }}
          >
            <Box
              sx={{
                gridColumn: 1,
                gridRow: `1 / ${gridRows + 1}`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                pr: 1,
              }}
            >
              <Typography
                variant="textSm"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  writingMode: "vertical-rl",
                  transform: "rotate(180deg)",
                  whiteSpace: "nowrap",
                })}
              >
                {yAxisLabel}
              </Typography>
            </Box>

            {grid.map((row, rowIdx) =>
              row.map((count, colIdx) => {
                const level = getCellLevel(rowIdx, colIdx);
                const isVeryHigh = level === "veryHigh";
                const lastRow = gridRows - 1;
                const lastCol = row.length - 1;
                const tl = rowIdx === 0 && colIdx === 0 ? r : 0;
                const tr = rowIdx === 0 && colIdx === lastCol ? r : 0;
                const br = rowIdx === lastRow && colIdx === lastCol ? r : 0;
                const bl = rowIdx === lastRow && colIdx === 0 ? r : 0;
                const cellBorderRadius =
                  tl || tr || br || bl ? `${tl}px ${tr}px ${br}px ${bl}px` : 0;
                const hasRisks = count > 0;
                return (
                  <Box
                    key={`${rowIdx}-${colIdx}`}
                    aria-label={hasRisks ? `${count} risks` : "No risks"}
                    sx={({ tokens: t }) => ({
                      gridColumn: colIdx + 2,
                      gridRow: rowIdx + 1,
                      backgroundColor: ragDataVizColor(t, RISK_HEATMAP_LEVEL_TO_RAG[level]),
                      borderRadius: cellBorderRadius,
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "center",
                      minHeight: 48,
                      minWidth: 48,
                      opacity: hasRisks ? 1 : 0.3,
                    })}
                  >
                    {hasRisks ? (
                      <Link
                        component="button"
                        type="button"
                        underline="hover"
                        onClick={(e) => onCellCountClick(e, rowIdx, colIdx)}
                        aria-label={`${count} risks — filter list`}
                        sx={({ tokens: t }) => ({
                          fontFamily: t.semantic.font.text.sm.fontFamily.value,
                          fontSize: t.semantic.font.text.sm.fontSize.value,
                          lineHeight: t.semantic.font.text.sm.lineHeight.value,
                          letterSpacing: t.semantic.font.text.sm.letterSpacing.value,
                          fontWeight: 800,
                          color: isVeryHigh
                            ? t.semantic.color.type.inverse.value
                            : level === "low" || level === "medium" || level === "high"
                              ? t.core.color.gray["1000"].value
                              : "rgba(255, 255, 255, 1)",
                          background: "none",
                          border: 0,
                          padding: 0,
                          cursor: "pointer",
                          textAlign: "center",
                        })}
                      >
                        {count}
                      </Link>
                    ) : null}
                  </Box>
                );
              }),
            )}

            <Box
              sx={{
                gridColumn: `2 / ${gridCols + 2}`,
                gridRow: gridRows + 1,
                display: "flex",
                justifyContent: "flex-end",
                pt: 0.5,
              }}
            >
              <Typography
                variant="textSm"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                })}
              >
                {xAxisLabel}
              </Typography>
            </Box>
          </Box>

          <Box
            sx={{
              display: "grid",
              gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
              columnGap: 2,
              rowGap: 2,
              height: "88px",
            }}
          >
            {legend.map((item) => (
              <Stack key={item.label} gap={0}>
                <Stack direction="row" alignItems="center" gap={1}>
                  <Box
                    sx={({ tokens: t }) => ({
                      width: 16,
                      height: 16,
                      borderRadius: 0.5,
                      backgroundColor: ragDataVizColor(t, RISK_HEATMAP_LEVEL_TO_RAG[item.level]),
                      flexShrink: 0,
                    })}
                  />
                  <Typography
                    variant="textSm"
                    sx={({ tokens: t }) => ({
                      color: t.semantic.color.type.default.value,
                    })}
                  >
                    {item.label}
                  </Typography>
                </Stack>
                <Typography variant="textMd" sx={{ pl: 3, fontWeight: 600 }}>
                  <Link
                    component="button"
                    type="button"
                    underline="hover"
                    onClick={(e) => onLegendCountClick(e, item.level)}
                    aria-label={`${item.count} risks in ${item.label} — filter list`}
                    sx={{
                      background: "none",
                      border: 0,
                      padding: 0,
                      cursor: "pointer",
                      font: "inherit",
                      textAlign: "left",
                    }}
                  >
                    {item.count}
                  </Link>
                </Typography>
              </Stack>
            ))}
          </Box>
        </Stack>
      </CardContent>
    </Card>
  );
}
