import {
  PageHeader,
  OverflowBreadcrumbs,
} from "@diligentcorp/atlas-react-bundle";
import {
  Avatar,
  Box,
  Button,
  Container,
  InputAdornment,
  Stack,
  TextField,
  Typography,
  useTheme,
} from "@mui/material";
import {
  ragDataVizColor,
  type RagDataVizKey,
} from "../data/ragDataVisualization.js";
import type { FivePointScaleValue, FivePointScaleLabel, MitigationPlanStatus } from "../data/types.js";
import {
  DataGridPro,
  type GridColDef,
  type GridRenderCellParams,
  ColumnsPanelTrigger,
  FilterPanelTrigger,
  QuickFilter,
  QuickFilterControl,
  Toolbar,
} from "@mui/x-data-grid-pro";
import { useCallback, useMemo, useState, useSyncExternalStore } from "react";
import { NavLink } from "react-router";

import AddIcon from "@diligentcorp/atlas-react-bundle/icons/Add";
import SearchIcon from "@diligentcorp/atlas-react-bundle/icons/Search";
import FilterIcon from "@diligentcorp/atlas-react-bundle/icons/Filter";
import ColumnsIcon from "@diligentcorp/atlas-react-bundle/icons/Columns";
import AvatarIcon from "@diligentcorp/atlas-react-bundle/icons/Avatar";

import MitigationPlanPageSideSheet from "../components/MitigationPlanPageSideSheet.js";
import MitigationPlanStatusChip from "../components/MitigationPlanStatusChip.js";
import { useSavedChangesToast } from "../context/SavedChangesToastContext.js";
import { assets } from "../data/assets.js";
import { getCyberRiskById } from "../data/cyberRisks.js";
import { mitigationPlans, mitigationPlanSortTimeMs } from "../data/mitigationPlans.js";
import {
  getCatalogSnapshotVersion,
  subscribeCatalog,
} from "../data/persistence/catalogStore.js";
import { getUserById } from "../data/users.js";

interface MitigationPlanRow {
  id: string;
  planId: string;
  name: string;
  status: MitigationPlanStatus;
  severityScore: FivePointScaleValue;
  ownerName: string;
  ownerInitials: string;
  relatedRiskName: string;
  relatedControlsCount: number;
  dueDate: string;
  assets: number;
}

const AVATAR_COLORS = ["red", "blue", "green", "purple", "yellow"] as const;

const SEVERITY_LABELS: Record<FivePointScaleValue, FivePointScaleLabel> = {
  1: "Very low",
  2: "Low",
  3: "Medium",
  4: "High",
  5: "Very high",
};

const SEVERITY_RAG: Record<FivePointScaleValue, RagDataVizKey> = {
  1: "pos05",
  2: "pos04",
  3: "neu03",
  4: "neg03",
  5: "neg05",
};

function formatPlanDueDate(iso: string): string {
  if (!iso.trim()) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}

function relatedRiskLabel(cyberRiskIds: readonly string[]): string {
  const names = cyberRiskIds
    .map((id) => getCyberRiskById(id)?.name)
    .filter((n): n is string => Boolean(n && n.trim()));
  if (names.length === 0) return "—";
  if (names.length === 1) return names[0]!;
  return `${names[0]!} (+${names.length - 1})`;
}

function distinctAssetCountForCyberRisks(cyberRiskIds: readonly string[]): number {
  const ids = new Set<string>();
  for (const rid of cyberRiskIds) {
    const risk = getCyberRiskById(rid);
    if (!risk) continue;
    const list = risk.assetIds ?? [];
    for (const aid of list) ids.add(aid);
  }
  return ids.size;
}

function buildMitigationPlanGridRows(): MitigationPlanRow[] {
  const sorted = [...mitigationPlans].sort(
    (a, b) => mitigationPlanSortTimeMs(b) - mitigationPlanSortTimeMs(a),
  );
  return sorted.map((plan) => {
    const owner = getUserById(plan.ownerId);
    const assetCount =
      plan.assetIds != null && plan.assetIds.length > 0
        ? plan.assetIds.length
        : distinctAssetCountForCyberRisks(plan.cyberRiskIds);
    const controlsCount =
      plan.controlIds.length > 0
        ? plan.controlIds.length
        : (plan.relatedControlNames?.length ?? 0);
    return {
      id: plan.id,
      planId: plan.id,
      name: plan.name,
      status: plan.status,
      severityScore: plan.severity,
      ownerName: owner?.fullName ?? "Unknown",
      ownerInitials: owner?.initials ?? "",
      relatedRiskName: relatedRiskLabel(plan.cyberRiskIds),
      relatedControlsCount: controlsCount,
      dueDate: formatPlanDueDate(plan.dueDate),
      assets: assetCount,
    };
  });
}

function SeverityLevelCell({ value }: { value: FivePointScaleValue }) {
  const { tokens } = useTheme();
  const ragKey = SEVERITY_RAG[value];
  const label = SEVERITY_LABELS[value];

  return (
    <Stack direction="row" alignItems="center" gap={1}>
      <Box
        sx={{
          width: 16,
          height: 16,
          borderRadius: 0.5,
          backgroundColor: ragDataVizColor(tokens, ragKey),
          flexShrink: 0,
        }}
      />
      <Typography variant="labelXs">
        {value} - {label}
      </Typography>
    </Stack>
  );
}

function OwnerCell({ name, initials }: { name: string; initials: string }) {
  const { presets } = useTheme();
  const { getAvatarProps } = presets.AvatarPresets;
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
        {initials || <AvatarIcon aria-hidden />}
      </Avatar>
      <Typography variant="textMd">{name}</Typography>
    </Stack>
  );
}

function CustomToolbar() {
  return (
    <Toolbar>
      <QuickFilter expanded>
        <QuickFilterControl
          render={({ ref, value, ...other }) => (
            <TextField
              {...other}
              inputRef={ref}
              value={value ?? ""}
              placeholder="Search by"
              size="small"
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                  ...other.slotProps?.input,
                },
                ...other.slotProps,
              }}
            />
          )}
        />
      </QuickFilter>
      <FilterPanelTrigger
        render={(props) => (
          <Button
            {...props}
            startIcon={<FilterIcon />}
            aria-label="Show filters"
          >
            Filter
          </Button>
        )}
      />
      <ColumnsPanelTrigger
        render={(props) => (
          <Button
            {...props}
            startIcon={<ColumnsIcon />}
            aria-label="Select columns"
          >
            Columns
          </Button>
        )}
      />
    </Toolbar>
  );
}

function MitigationPlansDataGrid({
  onMitigationPlanNameClick,
}: {
  onMitigationPlanNameClick: (planId: string) => void;
}) {
  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    () => 0,
  );
  const rows = useMemo(() => buildMitigationPlanGridRows(), [catalogVersion]);

  const columns: GridColDef<MitigationPlanRow>[] = [
    {
      field: "planId",
      headerName: "ID",
      width: 100,
    },
    {
      field: "name",
      headerName: "Name",
      flex: 1,
      minWidth: 250,
      renderCell: (params: GridRenderCellParams<MitigationPlanRow>) => (
        <Typography
          component="span"
          variant="textMd"
          sx={({ tokens }) => ({
            cursor: "pointer",
            color: tokens.semantic.color.action.primary.default.value,
            textDecoration: "underline",
          })}
        >
          {params.value as string}
        </Typography>
      ),
    },
    {
      field: "status",
      headerName: "Status",
      width: 130,
      renderCell: (params: GridRenderCellParams<MitigationPlanRow>) => (
        <MitigationPlanStatusChip status={params.value as MitigationPlanStatus} />
      ),
    },
    {
      field: "severityScore",
      headerName: "Severity level",
      width: 150,
      renderCell: (params: GridRenderCellParams<MitigationPlanRow>) => (
        <SeverityLevelCell value={params.value as FivePointScaleValue} />
      ),
    },
    {
      field: "ownerName",
      headerName: "Owner",
      width: 200,
      renderCell: (params: GridRenderCellParams<MitigationPlanRow>) => (
        <OwnerCell
          name={params.row.ownerName}
          initials={params.row.ownerInitials}
        />
      ),
    },
    {
      field: "relatedRiskName",
      headerName: "Related risk",
      width: 260,
    },
    {
      field: "relatedControlsCount",
      headerName: "Controls",
      width: 150,
      type: "number",
      align: "right",
      headerAlign: "right",
    },
    {
      field: "assets",
      headerName: "Assets",
      width: 100,
      type: "number",
    },
    {
      field: "dueDate",
      headerName: "Due date",
      width: 140,
    },
  ];

  return (
    <Box sx={{ width: "100%" }}>
      <DataGridPro
        rows={rows}
        columns={columns}
        getRowId={(row) => row.id}
        pagination
        pageSizeOptions={[5, 10, 25]}
        initialState={{
          pagination: { paginationModel: { pageSize: 10 } },
        }}
        disableRowSelectionOnClick
        showToolbar
        onCellClick={(params, event) => {
          if (params.field !== "name") return;
          event.defaultMuiPrevented = true;
          onMitigationPlanNameClick(params.row.planId);
        }}
        slots={{
          toolbar: CustomToolbar,
        }}
        slotProps={{
          main: {
            "aria-label":
              "Mitigation plans table. Column headers contain action menus. Press CTRL + ENTER to open the action menu.",
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

export default function MitigationPlansPage() {
  const [mitigationPlanSideSheetOpen, setMitigationPlanSideSheetOpen] = useState(false);
  const [editingMitigationPlanId, setEditingMitigationPlanId] = useState<string | null>(null);
  const { showSuccessToast } = useSavedChangesToast();

  const closeSideSheet = useCallback(() => {
    setMitigationPlanSideSheetOpen(false);
    setEditingMitigationPlanId(null);
  }, []);

  const openCreateSideSheet = useCallback(() => {
    setEditingMitigationPlanId(null);
    setMitigationPlanSideSheetOpen(true);
  }, []);

  const openEditSideSheet = useCallback((planId: string) => {
    setEditingMitigationPlanId(planId);
    setMitigationPlanSideSheetOpen(true);
  }, []);

  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    () => 0,
  );

  const mitigationPlanAssetOptions = useMemo(
    () =>
      [...assets]
        .map((a) => ({ id: a.id, label: a.name }))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [catalogVersion],
  );

  return (
    <Container sx={{ py: 2 }}>
      <Stack gap={3}>
        <PageHeader
          pageTitle="Mitigation plans"
          breadcrumbs={
            <OverflowBreadcrumbs
              leadingElement={<span>Asset Manager</span>}
              items={[
                {
                  id: "cyber-risk",
                  label: "Cyber risk management",
                  url: "/cyber-risk/overview",
                },
                {
                  id: "mitigation-plans",
                  label: "Mitigation plans",
                  url: "/cyber-risk/mitigation-plans",
                },
              ]}
              hideLastItem={true}
              aria-label="Breadcrumbs"
            >
              {({ label, url }) => <NavLink to={url}>{label}</NavLink>}
            </OverflowBreadcrumbs>
          }
          moreButton={
            <Button
              variant="contained"
              startIcon={<AddIcon />}
              onClick={openCreateSideSheet}
            >
              New mitigation plan
            </Button>
          }
        />
        <MitigationPlansDataGrid onMitigationPlanNameClick={openEditSideSheet} />
        <MitigationPlanPageSideSheet
          key={mitigationPlanSideSheetOpen ? (editingMitigationPlanId ?? "create") : "closed"}
          open={mitigationPlanSideSheetOpen}
          onClose={closeSideSheet}
          cyberRiskName=""
          editingPlanId={editingMitigationPlanId}
          assetOptions={mitigationPlanAssetOptions}
          onMitigationPlanCreated={() =>
            showSuccessToast("Mitigation plan created successfully.")
          }
          onMitigationPlanUpdated={() =>
            showSuccessToast("Mitigation plan saved successfully.")
          }
          onMitigationPlanDeleted={() =>
            showSuccessToast("Mitigation plan deleted.")
          }
        />
      </Stack>
    </Container>
  );
}
