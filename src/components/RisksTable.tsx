import { Avatar, Box, Link, Stack, Typography, useTheme } from "@mui/material";
import {
  DataGridPro,
  type GridColDef,
  type GridRenderCellParams,
} from "@mui/x-data-grid-pro";
import { NavLink } from "react-router";
import AvatarIcon from "@diligentcorp/atlas-react-bundle/icons/Avatar";

import {
  type RiskHeatmapLevel,
  ragDataVizColor,
  RISK_HEATMAP_LEVEL_TO_RAG,
} from "../data/ragDataVisualization.js";
import type { CyberRiskStatus } from "../data/types.js";
import type { CyberRiskRow } from "../utils/cyberRiskTableRows.js";
import NewToolbar from "./NewToolbar.js";

type WorkflowStatus = CyberRiskStatus;

const AVATAR_COLORS = ["red", "blue", "green", "purple", "yellow"] as const;

const WORKFLOW_STATUS_COLOR: Record<
  WorkflowStatus,
  "warning" | "information" | "generic" | "success"
> = {
  Assessment: "warning",
  Mitigation: "information",
  Identification: "generic",
  Monitoring: "success",
  Draft: "generic",
};

function CyberRiskScoreCell({
  score,
  level,
}: {
  score: string;
  level: RiskHeatmapLevel | null;
}) {
  if (!level) {
    return <Typography variant="textMd">{score}</Typography>;
  }

  return (
    <Stack direction="row" alignItems="center" gap={1}>
      <Box
        sx={({ tokens: t }) => ({
          width: 16,
          height: 16,
          borderRadius: 0.5,
          backgroundColor: ragDataVizColor(t, RISK_HEATMAP_LEVEL_TO_RAG[level]),
          flexShrink: 0,
        })}
      />
      <Typography variant="textMd">{score}</Typography>
    </Stack>
  );
}

function OwnerCell({ name, initials }: { name: string; initials: string }) {
  const { presets } = useTheme();
  const { getAvatarProps } = presets.AvatarPresets;
  const isUnassigned = name === "Unassigned";
  const colorIndex = initials
    ? initials.charCodeAt(0) % AVATAR_COLORS.length
    : 0;

  return (
    <Stack direction="row" alignItems="center" gap={1}>
      <Avatar
        {...getAvatarProps({
          size: "small",
          color: AVATAR_COLORS[colorIndex],
        })}
        aria-label={name}
        role="img"
      >
        {isUnassigned ? <AvatarIcon aria-hidden /> : initials}
      </Avatar>
      <Typography variant="textMd">{name}</Typography>
    </Stack>
  );
}

function WorkflowStatusBadge({ status }: { status: WorkflowStatus }) {
  const { presets } = useTheme();
  const StatusIndicator =
    presets.StatusIndicatorPresets?.components.StatusIndicator;

  return <StatusIndicator color={WORKFLOW_STATUS_COLOR[status]} label={status} />;
}

export type RisksTableProps = {
  rows: CyberRiskRow[];
  /** Opens the page filter UI (e.g. [`FilterSideSheet`](./FilterSideSheet.tsx)). */
  onOpenFilters: () => void;
  /** When &gt; 0, toolbar shows `Filter (n)`, filled filter icon, and **Clear filters** if `onClearFilters` is set. */
  filterCriteriaCount?: number;
  /** Clears applied side-sheet filters; paired with `filterCriteriaCount` from [`countCyberRiskFilterCriteria`](../utils/cyberRiskTableRows.js). */
  onClearFilters?: () => void;
};

export default function RisksTable({
  rows,
  onOpenFilters,
  filterCriteriaCount = 0,
  onClearFilters,
}: RisksTableProps) {
  const columns: GridColDef<CyberRiskRow>[] = [
    {
      field: "name",
      headerName: "Name",
      flex: 1,
      minWidth: 300,
      renderCell: (params: GridRenderCellParams<CyberRiskRow>) => (
        <Link
          component={NavLink}
          to={`/cyber-risk/cyber-risks/${encodeURIComponent(params.row.id)}`}
          underline="hover"
          variant="textMd"
          color="inherit"
        >
          {params.value}
        </Link>
      ),
    },
    {
      field: "riskId",
      headerName: "ID",
      width: 120,
    },
    {
      field: "cyberRiskScore",
      headerName: "Residual cyber risk score",
      width: 170,
      renderCell: (params: GridRenderCellParams<CyberRiskRow>) => (
        <CyberRiskScoreCell
          score={params.row.cyberRiskScore}
          level={params.row.riskLevel}
        />
      ),
    },
    {
      field: "ownerName",
      headerName: "Owner",
      width: 200,
      renderCell: (params: GridRenderCellParams<CyberRiskRow>) => (
        <OwnerCell
          name={params.row.ownerName}
          initials={params.row.ownerInitials}
        />
      ),
    },
    {
      field: "assets",
      headerName: "Assets",
      width: 100,
      type: "number",
    },
    {
      field: "assessmentCount",
      headerName: "Assessments",
      width: 120,
      type: "number",
      align: "right",
      headerAlign: "right",
    },
    {
      field: "workflowStatus",
      headerName: "Workflow status",
      width: 160,
      renderCell: (params: GridRenderCellParams<CyberRiskRow>) => (
        <WorkflowStatusBadge status={params.row.workflowStatus} />
      ),
    },
  ];

  return (
    <Box sx={{ width: "100%" }}>
      <DataGridPro
        rows={rows}
        columns={columns}
        getRowId={(row) => row.id}
        pagination
        pageSizeOptions={[10, 25, 50]}
        initialState={{
          pagination: { paginationModel: { pageSize: 10 } },
        }}
        disableRowSelectionOnClick
        showToolbar
        slots={{
          toolbar: () => (
            <NewToolbar
              onOpenFilters={onOpenFilters}
              filterCriteriaCount={filterCriteriaCount}
              onClearFilters={onClearFilters}
            />
          ),
        }}
        slotProps={{
          main: {
            "aria-label":
              "Cyber risks table. Column headers contain action menus. Press CTRL + ENTER to open the action menu.",
          },
          basePagination: {
            material: {
              labelRowsPerPage: "Rows",
            },
          },
        }}
        sx={{ border: 0 }}
      />
    </Box>
  );
}
