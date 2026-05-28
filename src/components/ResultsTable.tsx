import { useCallback, useMemo, type KeyboardEvent } from "react";
import { Box, Button, Stack, Typography } from "@mui/material";
import {
  DataGridPro,
  GridTreeDataGroupingCell,
  type GridCellParams,
  type GridColDef,
  type GridRenderCellParams,
} from "@mui/x-data-grid-pro";
import ExpandDownIcon from "@diligentcorp/atlas-react-bundle/icons/ExpandDown";

import NewToolbar from "./NewToolbar.js";
import {
  type AssessmentCyberResultsRow,
  type AssessmentResultsScoreChip,
} from "../pages/craAssessmentScopeRows.js";
import { ragDataVizColor } from "../data/ragDataVisualization.js";

export type ResultsScoreChip = AssessmentResultsScoreChip;

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

type CyberResultsRow = AssessmentCyberResultsRow;

/** Tree path uses stable ids so parent/child rows group correctly in the DataGrid. */
type CyberResultsGridRow = AssessmentCyberResultsRow & { hierarchy: string[] };

const TREE_DATA_GROUPING_FIELD = "__tree_data_group__" as const;

function cyberResultsToTreeRows(rows: AssessmentCyberResultsRow[]): CyberResultsGridRow[] {
  return rows.map((row) => ({
    ...row,
    hierarchy: row.kind === "cyberRisk" ? [row.groupId] : [row.groupId, row.id],
  }));
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

/** Results table (tree DataGrid) for cyber risk + scenario rows on the assessment Results tab. */
export function ResultsTable({
  rows,
  onOpenMitigationPlan,
  onScenarioRowClick,
  onOpenFilters,
  filterCriteriaCount = 0,
  onClearFilters,
}: ResultsTableProps) {
  const treeRows = useMemo(() => cyberResultsToTreeRows(rows), [rows]);

  const groupingColDef = useMemo(
    () => ({
      field: "name",
      headerName: "Name",
      flex: 1,
      minWidth: 360,
      sortable: false,
      hideDescendantCount: true,
      /** Tree path uses ids; without this, the grouping cell shows path segments (ids) instead of labels. */
      valueGetter: (_value: unknown, row: CyberResultsGridRow) => row.name,
      renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => {
        const dataRow = params.api.getRow<CyberResultsGridRow>(params.id);
        const nameFontWeight = dataRow?.kind === "cyberRisk" ? 600 : 400;
        const displayName = dataRow?.name ?? "";
        return (
          <Box
            sx={({ tokens: t }) => ({
              width: "100%",
              height: "100%",
              display: "flex",
              alignItems: "center",
              minHeight: 56,
              "& .MuiDataGrid-treeDataGroupingCell > span": {
                fontSize: t.semantic.font.text.md.fontSize.value,
                lineHeight: t.semantic.font.text.md.lineHeight.value,
                letterSpacing: t.semantic.font.text.md.letterSpacing.value,
                color: t.semantic.color.type.default.value,
                fontWeight: nameFontWeight,
                whiteSpace: "normal",
                wordBreak: "break-word",
              },
            })}
          >
            <GridTreeDataGroupingCell
              {...(params as Parameters<typeof GridTreeDataGroupingCell>[0])}
              formattedValue={displayName}
              hideDescendantCount
              offsetMultiplier={12}
            />
          </Box>
        );
      },
    }),
    [],
  );

  const columns: GridColDef<CyberResultsGridRow>[] = useMemo(
    () => [
      {
        field: "impact",
        headerName: "Impact",
        width: 130,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => (
          <ResultsRiskChip value={params.row.impact} />
        ),
      },
      {
        field: "threat",
        headerName: "Threat severity",
        width: 150,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => (
          <ResultsRiskChip value={params.row.threat} />
        ),
      },
      {
        field: "vulnerability",
        headerName: "Vulnerability severity",
        width: 170,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => (
          <ResultsRiskChip value={params.row.vulnerability} />
        ),
      },
      {
        field: "likelihood",
        headerName: "Likelihood",
        width: 120,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => (
          <ResultsRiskChip value={params.row.likelihood} />
        ),
      },
      {
        field: "cyberRiskScore",
        headerName: "Cyber risk score",
        width: 150,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) => (
          <ResultsRiskChip value={params.row.cyberRiskScore} />
        ),
      },
      {
        field: "mitigationPlan",
        headerName: "Mitigation plan",
        width: 176,
        sortable: false,
        renderCell: (params: GridRenderCellParams<CyberResultsGridRow>) =>
          params.row.kind === "cyberRisk" ? (
            <Button
              size="small"
              variant="text"
              onClick={(e) => {
                e.stopPropagation();
                onOpenMitigationPlan(params.row);
              }}
              sx={({ tokens: t }) => ({
                fontWeight: 600,
                textTransform: "none",
                color: t.semantic.color.action.link.default.value,
              })}
            >
              + Mitigation plan
            </Button>
          ) : null,
      },
    ],
    [onOpenMitigationPlan],
  );

  const getRowClassName = useCallback(
    (params: { row: CyberResultsGridRow }) =>
      onScenarioRowClick != null && params.row.kind === "scenario"
        ? "cra-results-scenario-row--clickable"
        : "",
    [onScenarioRowClick],
  );

  const handleRowClick = useCallback(
    (params: { row: CyberResultsGridRow }) => {
      if (params.row.kind === "scenario" && onScenarioRowClick != null) {
        onScenarioRowClick(params.row.id);
      }
    },
    [onScenarioRowClick],
  );

  const handleCellKeyDown = useCallback(
    (params: GridCellParams<CyberResultsGridRow>, event: KeyboardEvent) => {
      if (onScenarioRowClick == null) return;
      if (params.row.kind !== "scenario") return;
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        onScenarioRowClick(params.row.id);
      }
    },
    [onScenarioRowClick],
  );

  const renderToolbar = useCallback(
    () => (
      <NewToolbar
        onOpenFilters={onOpenFilters}
        filterCriteriaCount={filterCriteriaCount}
        onClearFilters={onClearFilters}
      />
    ),
    [onOpenFilters, filterCriteriaCount, onClearFilters],
  );

  return (
    <Box sx={{ width: "100%" }}>
      <DataGridPro<CyberResultsGridRow>
        treeData
        getTreeDataPath={(row) => row.hierarchy}
        defaultGroupingExpansionDepth={-1}
        groupingColDef={groupingColDef}
        rows={treeRows}
        columns={columns}
        getRowId={(r) => r.id}
        getRowClassName={getRowClassName}
        onRowClick={handleRowClick}
        onCellKeyDown={handleCellKeyDown}
        autoHeight
        disableRowSelectionOnClick
        showToolbar
        pinnedColumns={{ left: [TREE_DATA_GROUPING_FIELD] }}
        pinnedColumnsSectionSeparator="border"
        hideFooter
        slots={{
          toolbar: renderToolbar,
          treeDataExpandIcon: (iconProps) => (
            <Box
              component="span"
              sx={{ display: "inline-flex", transform: "rotate(-90deg)" }}
              aria-hidden
            >
              <ExpandDownIcon {...iconProps} />
            </Box>
          ),
          treeDataCollapseIcon: (iconProps) => (
            <Box component="span" sx={{ display: "inline-flex" }} aria-hidden>
              <ExpandDownIcon {...iconProps} />
            </Box>
          ),
        }}
        slotProps={{
          main: {
            "aria-label":
              "Cyber risks in this assessment. Toolbar: quick search, filters, and column visibility. Column headers contain action menus. Expand a row to view scenarios. Scenario rows may open read-only rationale.",
          },
        }}
        sx={({ tokens: t }) => ({
          border: "none",
          borderRadius: t.semantic.radius.md.value,
          bgcolor: t.semantic.color.background.base.value,
          minWidth: 1100,
          "& .MuiDataGrid-scrollShadow": { display: "none" },
          "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
          "& .MuiDataGrid-columnHeaders": {
            backgroundColor: t.semantic.color.background.container.value,
          },
          "& .MuiDataGrid-columnHeaderTitle": {
            fontWeight: 600,
            fontSize: t.semantic.font.label.sm.fontSize.value,
            lineHeight: t.semantic.font.label.sm.lineHeight.value,
            letterSpacing: t.semantic.font.label.sm.letterSpacing.value,
          },
          "& .MuiDataGrid-withBorderColor": {
            borderColor: t.semantic.color.outline.default.value,
          },
          "& .MuiDataGrid-row.cra-results-scenario-row--clickable": {
            cursor: "pointer",
          },
          "& .MuiDataGrid-row.cra-results-scenario-row--clickable:hover": {
            backgroundColor: t.semantic.color.action.secondary.hoverFill.value,
          },
          "& .MuiDataGrid-row.cra-results-scenario-row--clickable:focus-within": {
            outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
            outlineOffset: -2,
          },
        })}
        showColumnVerticalBorder
        showCellVerticalBorder
      />
    </Box>
  );
}
