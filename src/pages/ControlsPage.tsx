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
  DataGridPro,
  type GridColDef,
  type GridRenderCellParams,
  ColumnsPanelTrigger,
  FilterPanelTrigger,
  QuickFilter,
  QuickFilterControl,
  Toolbar,
} from "@mui/x-data-grid-pro";
import { useMemo, useSyncExternalStore } from "react";
import { NavLink } from "react-router";

import SearchIcon from "@diligentcorp/atlas-react-bundle/icons/Search";
import FilterIcon from "@diligentcorp/atlas-react-bundle/icons/Filter";
import ColumnsIcon from "@diligentcorp/atlas-react-bundle/icons/Columns";
import AvatarIcon from "@diligentcorp/atlas-react-bundle/icons/Avatar";

import { getAssetById } from "../data/assets.js";
import { controls } from "../data/controls.js";
import { cyberRisks } from "../data/cyberRisks.js";
import { getOrgUnitById } from "../data/orgUnits.js";
import {
  getCatalogSnapshotVersion,
  subscribeCatalog,
} from "../data/persistence/catalogStore.js";
import type { ControlStatus } from "../data/types.js";
import { getUserById } from "../data/users.js";

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

interface ControlRow {
  id: string;
  controlId: string;
  name: string;
  status: ControlStatus;
  preventDetect: string;
  linkedOrgUnits: string;
  ownerName: string;
  ownerInitials: string;
  assets: number;
  cyberRisks: number;
  keyControl: "Yes" | "No";
  controlFrequency: string;
}

const AVATAR_COLORS = ["red", "blue", "green", "purple", "yellow"] as const;

/** Union of control ids attached to an asset (top-level and relationships). */
function controlIdsOnAsset(assetId: string): Set<string> {
  const out = new Set<string>();
  const a = getAssetById(assetId);
  if (!a) return out;
  for (const cid of a.controlIds ?? []) out.add(cid);
  for (const cid of a.relationships.controlIds ?? []) out.add(cid);
  return out;
}

/** For each cyber risk, count distinct controls on its linked assets; aggregate per control id. */
function buildCyberRiskCountByControlId(): Map<string, number> {
  const counts = new Map<string, number>();
  for (const risk of cyberRisks) {
    const onRisk = new Set<string>();
    for (const aid of risk.assetIds ?? []) {
      for (const cid of controlIdsOnAsset(aid)) onRisk.add(cid);
    }
    for (const cid of onRisk) {
      counts.set(cid, (counts.get(cid) ?? 0) + 1);
    }
  }
  return counts;
}

function linkedOrgUnitsLabel(assetIds: readonly string[]): string {
  const names: string[] = [];
  const seen = new Set<string>();
  for (const aid of assetIds) {
    const a = getAssetById(aid);
    if (!a) continue;
    const ou = getOrgUnitById(a.orgUnitId);
    const label = (ou?.name ?? a.orgUnitId).trim();
    if (label && !seen.has(label)) {
      seen.add(label);
      names.push(label);
    }
  }
  if (names.length === 0) return "—";
  if (names.length === 1) return names[0]!;
  return `${names[0]!} (+${names.length - 1})`;
}

function buildControlGridRows(): ControlRow[] {
  const riskCounts = buildCyberRiskCountByControlId();
  return [...controls]
    .sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }))
    .map((c) => {
      const owner = getUserById(c.ownerId);
      return {
        id: c.id,
        controlId: c.id,
        name: c.name,
        status: c.status,
        preventDetect: c.controlType,
        linkedOrgUnits: linkedOrgUnitsLabel(c.assetIds ?? []),
        ownerName: owner?.fullName ?? "Unknown",
        ownerInitials: owner?.initials ?? "",
        assets: c.assetIds?.length ?? 0,
        cyberRisks: riskCounts.get(c.id) ?? 0,
        keyControl: c.keyControl ? "Yes" : "No",
        controlFrequency: c.controlFrequency,
      };
    });
}

// ---------------------------------------------------------------------------
// Custom cell renderers
// ---------------------------------------------------------------------------

const STATUS_COLOR_MAP: Record<ControlStatus, "success" | "generic" | "subtle"> = {
  Active: "success",
  Archived: "generic",
  Draft: "subtle",
};

function StatusCell({ value }: { value: ControlStatus }) {
  const { presets } = useTheme();
  const StatusIndicator =
    presets.StatusIndicatorPresets?.components.StatusIndicator;

  return <StatusIndicator color={STATUS_COLOR_MAP[value]} label={value} />;
}

function OwnerCell({ name, initials }: { name: string; initials: string }) {
  const { presets } = useTheme();
  const { getAvatarProps } = presets.AvatarPresets;
  const showPlaceholderAvatar = name === "Unassigned" || name === "Unknown";
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
        {showPlaceholderAvatar ? <AvatarIcon aria-hidden /> : initials}
      </Avatar>
      <Typography variant="textMd">{name}</Typography>
    </Stack>
  );
}

function LinkedOrgUnitsCell({ value }: { value: string }) {
  return (
    <Typography variant="textMd" sx={{ whiteSpace: "normal" }}>
      {value}
    </Typography>
  );
}

// ---------------------------------------------------------------------------
// Toolbar
// ---------------------------------------------------------------------------

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
              label="Search by"
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
          <Button {...props} startIcon={<FilterIcon />} aria-label="Show filters">
            Filter
          </Button>
        )}
      />
      <ColumnsPanelTrigger
        render={(props) => (
          <Button {...props} startIcon={<ColumnsIcon />} aria-label="Select columns">
            Columns
          </Button>
        )}
      />
    </Toolbar>
  );
}

// ---------------------------------------------------------------------------
// Data grid
// ---------------------------------------------------------------------------

function ControlsDataGrid() {
  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    () => 0,
  );

  const rows = useMemo(
    () => buildControlGridRows(),
    [catalogVersion, controls.length],
  );

  const columns: GridColDef<ControlRow>[] = [
    {
      field: "controlId",
      headerName: "ID",
      width: 110,
    },
    {
      field: "name",
      headerName: "Name",
      flex: 1,
      minWidth: 200,
      renderCell: (params: GridRenderCellParams<ControlRow>) => (
        <Typography component="span" variant="textMd" sx={{ whiteSpace: "normal" }}>
          {params.value as string}
        </Typography>
      ),
    },
    {
      field: "status",
      headerName: "Status",
      width: 120,
      renderCell: (params: GridRenderCellParams<ControlRow>) => (
        <StatusCell value={params.value as ControlStatus} />
      ),
    },
    {
      field: "preventDetect",
      headerName: "Prevent / Detect",
      width: 140,
    },
    {
      field: "linkedOrgUnits",
      headerName: "Linked org units",
      width: 240,
      renderCell: (params: GridRenderCellParams<ControlRow>) => (
        <LinkedOrgUnitsCell value={params.value as string} />
      ),
    },
    {
      field: "ownerName",
      headerName: "Owner",
      width: 200,
      renderCell: (params: GridRenderCellParams<ControlRow>) => (
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
      field: "cyberRisks",
      headerName: "Cyber risks",
      width: 120,
      type: "number",
    },
    {
      field: "keyControl",
      headerName: "Key control",
      width: 120,
    },
    {
      field: "controlFrequency",
      headerName: "Control frequency",
      width: 160,
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
          pagination: { paginationModel: { pageSize: 25 } },
        }}
        disableRowSelectionOnClick
        showToolbar
        slots={{
          toolbar: CustomToolbar,
        }}
        slotProps={{
          main: {
            "aria-label":
              "Controls table. Column headers contain action menus. Press CTRL + ENTER to open the action menu.",
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

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ControlsPage() {
  return (
    <Container sx={{ py: 2 }}>
      <Stack gap={3}>
        <PageHeader
          pageTitle="Controls"
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
                  id: "controls",
                  label: "Controls",
                  url: "/cyber-risk/controls",
                },
              ]}
              hideLastItem={true}
              aria-label="Breadcrumbs"
            >
              {({ label, url }) => <NavLink to={url}>{label}</NavLink>}
            </OverflowBreadcrumbs>
          }
        />
        <ControlsDataGrid />
      </Stack>
    </Container>
  );
}
