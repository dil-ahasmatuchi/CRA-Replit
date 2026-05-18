import { useCallback, useMemo, useState } from "react";
import {
  Box,
  Button,
  InputAdornment,
  Link,
  Stack,
  Switch,
  TextField,
  ToggleButton,
  ToggleButtonGroup,
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
  gridPaginatedVisibleSortedGridRowIdsSelector,
  useGridApiContext,
  useGridSelector,
} from "@mui/x-data-grid-pro";

import CertCyberRiskStrategyIcon from "@diligentcorp/atlas-react-bundle/icons/CertCyberRiskStrategy";
import ColumnsIcon from "@diligentcorp/atlas-react-bundle/icons/Columns";
import DocumentIcon from "@diligentcorp/atlas-react-bundle/icons/Document";
import FilterIcon from "@diligentcorp/atlas-react-bundle/icons/Filter";
import FolderIcon from "@diligentcorp/atlas-react-bundle/icons/Folder";
import HistoryIcon from "@diligentcorp/atlas-react-bundle/icons/History";
import RiskControlsIcon from "@diligentcorp/atlas-react-bundle/icons/RiskControls";
import SearchIcon from "@diligentcorp/atlas-react-bundle/icons/Search";

import { ragDataVizColor, type RagDataVizKey } from "../data/ragDataVisualization.js";
import { assets } from "../data/assets.js";
import { controls } from "../data/controls.js";
import { cyberRisks } from "../data/cyberRisks.js";
import { objectives } from "../data/objectives.js";
import { processes } from "../data/processes.js";
import { threats } from "../data/threats.js";
import {
  isVulnerabilityActiveForAssessment,
  vulnerabilities,
} from "../data/vulnerabilities.js";
import { getUserById, joinUserFullNames } from "../data/users.js";
import type {
  CyberRiskStatus,
  FivePointScaleValue,
  MockControl,
  MockCyberRisk,
  MockThreat,
  MockVulnerability,
} from "../data/types.js";
import {
  assessmentScopedControls,
  assessmentScopedCyberRisks,
  assessmentScopedThreats,
  assessmentScopedVulnerabilities,
  candidateScopedControls,
  candidateScopedCyberRisks,
  candidateScopedThreats,
  candidateScopedVulnerabilities,
  SCOPE_CATALOG_TOTALS,
} from "./scopeAssessmentRollup.js";
import AssessmentScopeEmptyState from "../components/AssessmentScopeEmptyState.js";
import FilterAssets from "../components/FilterAssets.js";
import FilterRisks from "../components/FilterRisks.js";
import FilterSideSheet from "../components/FilterSideSheet.js";
import FilterThreats from "../components/FilterThreats.js";
import { DEFAULT_SEARCH_FIELD_SX } from "../components/NewToolbar.js";
import { ScopeCard } from "../components/ScopeCard.js";
import ScopedRiskSS from "../components/ScopedRiskSS.js";
import ScopeToolbar, {
  type ScopeViewFilter,
} from "../components/ScopeToolbar.js";
import {
  applyCyberRiskTableFiltersToCatalogRows,
  countCyberRiskFilterCriteria,
  CYBER_RISK_WORKFLOW_FILTER_OPTIONS,
  EMPTY_CYBER_RISK_TABLE_FILTERS,
  type CyberRiskTableFilters,
} from "../utils/cyberRiskTableRows.js";
import {
  applyScopeAssetFilters,
  countScopeAssetFilterCriteria,
  EMPTY_SCOPE_ASSET_TABLE_FILTERS,
  hasAnyScopeAssetFilterSelected,
} from "../utils/scopeAssetTableFilters.js";
import {
  countThreatFilterCriteria,
  EMPTY_THREAT_TABLE_FILTERS,
  type ThreatTableFilters,
} from "../utils/threatTableFilters.js";
import {
  filterScopeThreatRowsByThreatTableFilters,
  scopeThreatRowsToThreatFilterRows,
  unionScopeThreatLinkedAssetIds,
  unionScopeThreatLinkedVulnerabilityIds,
} from "../utils/scopeThreatTableFilters.js";

export type ScopeSubView =
  | "overview"
  | "assets"
  | "scopedCyberRisks"
  | "scopedThreats"
  | "scopedVulnerabilities"
  | "scopedControls";

export type ScopeAssetRow = {
  id: number;
  assetId: string;
  included: boolean;
  assetName: string;
  assetType: string;
  cyberRisks: number;
  threats: number;
  vulnerabilities: number;
  /** Distinct library controls linked via cyber risks that touch this asset. */
  controls: number;
  criticality: FivePointScaleValue;
  objectives: number;
  processes: number;
  /** Primary catalog org. unit (asset); used for filters. */
  orgUnitId: string;
  /** Distinct org. units: the asset’s org. unit plus org. units on linked cyber risks. */
  relatedOrgUnitsCount: number;
};

export type ScopeCyberRiskRow = MockCyberRisk & { included: boolean };

export type ScopeThreatRow = MockThreat & { included: boolean; toggleDisabled: boolean };

export type ScopeVulnerabilityRow = MockVulnerability & { included: boolean };

export type ScopeControlRow = MockControl & { included: boolean; toggleDisabled: boolean };

const CRITICALITY_META: Record<
  FivePointScaleValue,
  { label: string; rag: RagDataVizKey }
> = {
  5: { label: "5 - Very high", rag: "neg05" },
  4: { label: "4 - High", rag: "neg03" },
  3: { label: "3 - Medium", rag: "neu03" },
  2: { label: "2 - Low", rag: "pos04" },
  1: { label: "1 - Very low", rag: "pos05" },
};

function buildScopeRows(): ScopeAssetRow[] {
  const crCountByAsset = new Map<string, number>();
  for (const cr of cyberRisks) {
    for (const aid of cr.assetIds) {
      crCountByAsset.set(aid, (crCountByAsset.get(aid) ?? 0) + 1);
    }
  }

  const threatCountByAsset = new Map<string, number>();
  for (const t of threats) {
    for (const aid of t.assetIds) {
      threatCountByAsset.set(aid, (threatCountByAsset.get(aid) ?? 0) + 1);
    }
  }

  const vulnCountByAsset = new Map<string, number>();
  for (const v of vulnerabilities) {
    if (!isVulnerabilityActiveForAssessment(v)) continue;
    for (const aid of v.assetIds) {
      vulnCountByAsset.set(aid, (vulnCountByAsset.get(aid) ?? 0) + 1);
    }
  }

  const controlIdsByAsset = new Map<string, Set<string>>();
  for (const c of controls) {
    for (const aid of c.assetIds) {
      let set = controlIdsByAsset.get(aid);
      if (!set) {
        set = new Set();
        controlIdsByAsset.set(aid, set);
      }
      set.add(c.id);
    }
  }

  const objectiveCountByAsset = new Map<string, number>();
  for (const o of objectives) {
    for (const aid of new Set(o.relationships.assetIds)) {
      objectiveCountByAsset.set(aid, (objectiveCountByAsset.get(aid) ?? 0) + 1);
    }
  }

  const processCountByAsset = new Map<string, number>();
  for (const p of processes) {
    for (const aid of new Set(p.relationships.assetIds)) {
      processCountByAsset.set(aid, (processCountByAsset.get(aid) ?? 0) + 1);
    }
  }

  return assets.map((a, i) => {
    const relatedOuIds = new Set<string>();
    relatedOuIds.add(a.orgUnitId);
    for (const cr of cyberRisks) {
      if (cr.assetIds.includes(a.id)) relatedOuIds.add(cr.orgUnitId);
    }
    return {
      id: i + 1,
      assetId: a.id,
      included: false,
      assetName: a.name,
      assetType: a.assetType,
      cyberRisks: crCountByAsset.get(a.id) ?? 0,
      threats: threatCountByAsset.get(a.id) ?? 0,
      vulnerabilities: vulnCountByAsset.get(a.id) ?? 0,
      controls: controlIdsByAsset.get(a.id)?.size ?? 0,
      criticality: a.criticality,
      objectives: objectiveCountByAsset.get(a.id) ?? 0,
      processes: processCountByAsset.get(a.id) ?? 0,
      orgUnitId: a.orgUnitId,
      relatedOrgUnitsCount: relatedOuIds.size,
    };
  });
}

function ScopeDataGridInclusionToolbar({
  view,
  onViewChange,
  totalCount,
  includedCount,
  toolbarAriaLabel = "Scope assets toolbar",
  inclusionFilterAriaLabel = "Filter assets by inclusion",
}: {
  view: ScopeViewFilter;
  onViewChange: (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => void;
  totalCount: number;
  includedCount: number;
  toolbarAriaLabel?: string;
  inclusionFilterAriaLabel?: string;
}) {
  return (
    <Toolbar
      aria-label={toolbarAriaLabel}
    >
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
              sx={DEFAULT_SEARCH_FIELD_SX}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon aria-hidden />
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
      <Box sx={{ flex: "1 1 120px" }} />
      <ToggleButtonGroup
        value={view}
        exclusive
        onChange={onViewChange}
        aria-label={inclusionFilterAriaLabel}
        size="small"
        sx={({ tokens: t }) => ({
          "& .MuiToggleButton-root": {
            px: 2,
            py: 1,
            textTransform: "none",
            fontWeight: 600,
            borderColor: t.semantic.color.outline.default.value,
          },
          "& .Mui-selected": {
            backgroundColor: `${t.semantic.color.action.primary.default.value} !important`,
            color: `${t.semantic.color.action.primary.onPrimary.value} !important`,
          },
        })}
      >
        <ToggleButton value="all">All ({totalCount})</ToggleButton>
        <ToggleButton value="included">
          {includedCount > 0 ? `Included (${includedCount})` : "Included"}
        </ToggleButton>
        <ToggleButton value="excluded">Not included</ToggleButton>
      </ToggleButtonGroup>
    </Toolbar>
  );
}

function CriticalityCell({ level }: { level: FivePointScaleValue }) {
  const meta = CRITICALITY_META[level];
  return (
    <Stack direction="row" alignItems="center" gap={1}>
      <Box
        sx={({ tokens: t }) => ({
          width: 14,
          height: 14,
          flexShrink: 0,
          bgcolor: ragDataVizColor(t, meta.rag),
          borderRadius: 0.5,
        })}
        aria-hidden
      />
      <Typography variant="body1" component="span" sx={{ fontSize: 14, lineHeight: "20px" }}>
        {meta.label}
      </Typography>
    </Stack>
  );
}

function NumericLink({
  value,
  ariaLabel,
  onPress,
}: {
  value: number;
  ariaLabel: string;
  /** When set, called after preventing default (e.g. open side sheet). */
  onPress?: () => void;
}) {
  return (
    <Link
      component="button"
      type="button"
      underline="always"
      onClick={(e: React.MouseEvent) => {
        e.preventDefault();
        e.stopPropagation();
        onPress?.();
      }}
      sx={({ tokens: t }) => ({
        cursor: "pointer",
        fontWeight: 400,
        fontSize: 16,
        lineHeight: "24px",
        color: t.semantic.color.action.link.default.value,
        verticalAlign: "inherit",
      })}
      aria-label={ariaLabel}
    >
      {value}
    </Link>
  );
}

/** Uses grid state so “this page” = same rows as on screen (sort, filter, pagination). */
function ScopeIncludedColumnHeader({
  rows,
  onBulkRowIdsIncluded,
  togglesReadOnly = false,
}: {
  rows: ScopeAssetRow[];
  onBulkRowIdsIncluded: (dataGridRowIds: number[], included: boolean) => void;
  /** When true, column header does not run bulk include/exclude. */
  togglesReadOnly?: boolean;
}) {
  const apiRef = useGridApiContext();
  const rowIdsOnPage = useGridSelector(apiRef, gridPaginatedVisibleSortedGridRowIdsSelector);

  const idsOnPage = useMemo(
    () => rowIdsOnPage.map((id) => (typeof id === "number" ? id : Number(id))),
    [rowIdsOnPage],
  );

  const allPageRowsIncluded =
    idsOnPage.length > 0 &&
    idsOnPage.every((id) => rows.find((r) => r.id === id)?.included === true);

  const pageIncludedCount = useMemo(
    () => idsOnPage.filter((id) => rows.find((r) => r.id === id)?.included).length,
    [idsOnPage, rows],
  );

  const headerIncludeIntermediate =
    idsOnPage.length > 0 &&
    pageIncludedCount > 0 &&
    pageIncludedCount < idsOnPage.length;

  const handleHeaderToggle = useCallback(() => {
    if (togglesReadOnly) return;
    const ids = gridPaginatedVisibleSortedGridRowIdsSelector(apiRef).map((id) =>
      typeof id === "number" ? id : Number(id),
    );
    if (ids.length === 0) return;
    const everyOnPageIncluded = ids.every(
      (id) => rows.find((r) => r.id === id)?.included === true,
    );
    const nextIncluded = !everyOnPageIncluded;
    onBulkRowIdsIncluded(ids, nextIncluded);
  }, [apiRef, rows, onBulkRowIdsIncluded, togglesReadOnly]);

  const headerAriaLabel = togglesReadOnly
    ? "Include in scope. Bulk actions are disabled for approved assessments."
    : headerIncludeIntermediate
      ? "Some assets on this page are in scope. Click to include all on this page."
      : allPageRowsIncluded
        ? "All assets on this page are in scope. Click to exclude all on this page."
        : "Click to include or exclude all assets shown on this page.";

  return (
    <Box
      role={togglesReadOnly ? "presentation" : "button"}
      tabIndex={togglesReadOnly ? -1 : 0}
      aria-label={headerAriaLabel}
      onKeyDown={
        togglesReadOnly
          ? undefined
          : (e: React.KeyboardEvent) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                e.stopPropagation();
                handleHeaderToggle();
              }
            }
      }
      sx={({ tokens: t }) => ({
        position: "relative",
        display: "flex",
        alignItems: "center",
        justifyContent: "flex-start",
        width: "calc(100% + 20px)",
        minHeight: "var(--DataGrid-headerHeight, 48px)",
        m: 0,
        mx: "-10px",
        px: "10px",
        py: 0,
        boxSizing: "border-box",
        color: "inherit",
        cursor: togglesReadOnly ? "default" : "pointer",
        border: "none",
        background: "none",
        outline: "none",
        ...(!togglesReadOnly
          ? {
              "&:focus-visible": {
                outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                outlineOffset: -2,
              },
            }
          : {}),
      })}
    >
      <Box sx={{ display: "flex", alignItems: "center", pointerEvents: "none" }}>
        <Switch
          size="small"
          // @ts-expect-error Lens Switch color union is "default" only; primary required for indeterminate theme rules
          color="primary"
          checked={allPageRowsIncluded}
          disabled={togglesReadOnly}
          tabIndex={-1}
          slotProps={{
            input: {
              tabIndex: -1,
              "aria-hidden": true,
              ...(headerIncludeIntermediate ? { "aria-checked": "mixed" as const } : {}),
            },
          }}
        />
      </Box>
      {!togglesReadOnly ? (
        <Box
          aria-hidden
          onClick={(e: React.MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
            handleHeaderToggle();
          }}
          sx={{
            position: "absolute",
            inset: 0,
            zIndex: 1,
            cursor: "pointer",
          }}
        />
      ) : null}
    </Box>
  );
}

/** Uses grid state so “this page” = same rows as on screen (sort, filter, pagination). */
function ScopePagedIncludedColumnHeader({
  rows,
  onBulkRowIdsIncluded,
  entityPlural,
  togglesReadOnly = false,
}: {
  rows: { id: string; included: boolean }[];
  onBulkRowIdsIncluded: (rowIds: string[], included: boolean) => void;
  entityPlural: string;
  togglesReadOnly?: boolean;
}) {
  const apiRef = useGridApiContext();
  const rowIdsOnPage = useGridSelector(apiRef, gridPaginatedVisibleSortedGridRowIdsSelector);

  const idsOnPage = useMemo(
    () => rowIdsOnPage.map((id) => String(id)),
    [rowIdsOnPage],
  );

  const allPageRowsIncluded =
    idsOnPage.length > 0 &&
    idsOnPage.every((id) => rows.find((r) => r.id === id)?.included === true);

  const pageIncludedCount = useMemo(
    () => idsOnPage.filter((id) => rows.find((r) => r.id === id)?.included).length,
    [idsOnPage, rows],
  );

  const headerIncludeIntermediate =
    idsOnPage.length > 0 &&
    pageIncludedCount > 0 &&
    pageIncludedCount < idsOnPage.length;

  const handleHeaderToggle = useCallback(() => {
    if (togglesReadOnly) return;
    const ids = gridPaginatedVisibleSortedGridRowIdsSelector(apiRef).map((id) => String(id));
    if (ids.length === 0) return;
    const everyOnPageIncluded = ids.every(
      (id) => rows.find((r) => r.id === id)?.included === true,
    );
    const nextIncluded = !everyOnPageIncluded;
    onBulkRowIdsIncluded(ids, nextIncluded);
  }, [apiRef, rows, onBulkRowIdsIncluded, togglesReadOnly]);

  const headerAriaLabel = togglesReadOnly
    ? `Include in scope. Bulk actions are disabled for approved assessments.`
    : headerIncludeIntermediate
      ? `Some ${entityPlural} on this page are in scope. Click to include all on this page.`
      : allPageRowsIncluded
        ? `All ${entityPlural} on this page are in scope. Click to exclude all on this page.`
        : `Click to include or exclude all ${entityPlural} shown on this page.`;

  return (
    <Box
      role={togglesReadOnly ? "presentation" : "button"}
      tabIndex={togglesReadOnly ? -1 : 0}
      aria-label={headerAriaLabel}
      onKeyDown={
        togglesReadOnly
          ? undefined
          : (e: React.KeyboardEvent) => {
              if (e.key === "Enter" || e.key === " ") {
                e.preventDefault();
                e.stopPropagation();
                handleHeaderToggle();
              }
            }
      }
      sx={({ tokens: t }) => ({
        position: "relative",
        display: "flex",
        alignItems: "center",
        justifyContent: "flex-start",
        width: "calc(100% + 20px)",
        minHeight: "var(--DataGrid-headerHeight, 48px)",
        m: 0,
        mx: "-10px",
        px: "10px",
        py: 0,
        boxSizing: "border-box",
        color: "inherit",
        cursor: togglesReadOnly ? "default" : "pointer",
        border: "none",
        background: "none",
        outline: "none",
        ...(!togglesReadOnly
          ? {
              "&:focus-visible": {
                outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                outlineOffset: -2,
              },
            }
          : {}),
      })}
    >
      <Box sx={{ display: "flex", alignItems: "center", pointerEvents: "none" }}>
        <Switch
          size="small"
          // @ts-expect-error Lens Switch color union is "default" only; primary required for indeterminate theme rules
          color="primary"
          checked={allPageRowsIncluded}
          disabled={togglesReadOnly}
          tabIndex={-1}
          slotProps={{
            input: {
              tabIndex: -1,
              "aria-hidden": true,
              ...(headerIncludeIntermediate ? { "aria-checked": "mixed" as const } : {}),
            },
          }}
        />
      </Box>
      {!togglesReadOnly ? (
        <Box
          aria-hidden
          onClick={(e: React.MouseEvent) => {
            e.preventDefault();
            e.stopPropagation();
            handleHeaderToggle();
          }}
          sx={{
            position: "absolute",
            inset: 0,
            zIndex: 1,
            cursor: "pointer",
          }}
        />
      ) : null}
    </Box>
  );
}

function ScopeCyberRiskIncludedColumnHeader({
  rows,
  onBulkCyberRiskRowIdsIncluded,
  togglesReadOnly = false,
}: {
  rows: ScopeCyberRiskRow[];
  onBulkCyberRiskRowIdsIncluded: (cyberRiskIds: string[], included: boolean) => void;
  togglesReadOnly?: boolean;
}) {
  return (
    <ScopePagedIncludedColumnHeader
      rows={rows}
      onBulkRowIdsIncluded={onBulkCyberRiskRowIdsIncluded}
      entityPlural="cyber risks"
      togglesReadOnly={togglesReadOnly}
    />
  );
}

function ScopeOverviewCards({
  totalAssets,
  includedAssets,
  includedCyberRisks,
  includedThreats,
  includedVulnerabilities,
  includedControls,
  onEditAssetsScope,
  onOpenCyberRisks,
  onOpenThreats,
  onOpenVulnerabilities,
  onOpenControls,
}: {
  totalAssets: number;
  includedAssets: number;
  includedCyberRisks: number;
  includedThreats: number;
  includedVulnerabilities: number;
  includedControls: number;
  onEditAssetsScope: () => void;
  onOpenCyberRisks: () => void;
  onOpenThreats: () => void;
  onOpenVulnerabilities: () => void;
  onOpenControls: () => void;
}) {
  const { presets } = useTheme();
  const CardHeaderIcon = presets.CardComponentsPresets?.components?.CardHeaderIcon;

  const wrapHeaderIcon = (icon: React.ReactElement) =>
    CardHeaderIcon ? <CardHeaderIcon icon={icon} /> : icon;

  return (
    <Stack gap={3} sx={{ pt: 3, pb: 4, width: "100%" }}>
      <Box
        sx={{
          display: "grid",
          width: "100%",
          gridTemplateColumns: "1fr",
          gap: 2,
          alignItems: "stretch",
        }}
      >
        <ScopeCard
          title="Assets"
          icon={wrapHeaderIcon(<FolderIcon size="lg" aria-hidden />)}
          includedCount={includedAssets}
          totalCount={totalAssets}
          countNoun="Assets"
          onCardClick={onEditAssetsScope}
          cardActionAriaLabel="Include assets: open the scoped assets view for this assessment"
        />
        <ScopeCard
          title="Cyber risks"
          icon={wrapHeaderIcon(<CertCyberRiskStrategyIcon size="lg" aria-hidden />)}
          includedCount={includedCyberRisks}
          totalCount={SCOPE_CATALOG_TOTALS.cyberRisks}
          countNoun="Cyber risks"
          onCardClick={onOpenCyberRisks}
          cardActionAriaLabel="View cyber risks included in this assessment"
        />
        <ScopeCard
          title="Threats"
          icon={wrapHeaderIcon(<HistoryIcon size="lg" aria-hidden />)}
          includedCount={includedThreats}
          totalCount={SCOPE_CATALOG_TOTALS.threats}
          countNoun="Threats"
          onCardClick={onOpenThreats}
          cardActionAriaLabel="View threats included in this assessment"
        />
        <ScopeCard
          title="Vulnerabilities"
          icon={wrapHeaderIcon(<DocumentIcon size="lg" aria-hidden />)}
          includedCount={includedVulnerabilities}
          totalCount={SCOPE_CATALOG_TOTALS.vulnerabilities}
          countNoun="Vulnerabilities"
          onCardClick={onOpenVulnerabilities}
          cardActionAriaLabel="View vulnerabilities included in this assessment"
        />
        <ScopeCard
          title="Controls"
          icon={wrapHeaderIcon(<RiskControlsIcon size="lg" aria-hidden />)}
          includedCount={includedControls}
          totalCount={SCOPE_CATALOG_TOTALS.controls}
          countNoun="Controls"
          onCardClick={onOpenControls}
          cardActionAriaLabel="View controls included in this assessment"
        />
      </Box>
    </Stack>
  );
}

function ScopeAssetsDataGrid({
  rows,
  onToggleAssetIncluded,
  onBulkRowIdsIncluded,
  togglesReadOnly = false,
}: {
  rows: ScopeAssetRow[];
  onToggleAssetIncluded: (assetId: string, included: boolean) => void;
  onBulkRowIdsIncluded: (dataGridRowIds: number[], included: boolean) => void;
  togglesReadOnly?: boolean;
}) {
  const [view, setView] = useState<ScopeViewFilter>("all");
  const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });
  const [cyberRiskSheetOpen, setCyberRiskSheetOpen] = useState(false);
  const [cyberRisksForSheet, setCyberRisksForSheet] = useState<MockCyberRisk[]>([]);
  const [isScopeAssetsFilterOpen, setIsScopeAssetsFilterOpen] = useState(false);
  const [appliedScopeAssetFilters, setAppliedScopeAssetFilters] = useState(
    EMPTY_SCOPE_ASSET_TABLE_FILTERS,
  );
  const [draftScopeAssetFilters, setDraftScopeAssetFilters] = useState(
    EMPTY_SCOPE_ASSET_TABLE_FILTERS,
  );

  const hasCommittedScopeAssetFilters = useMemo(
    () => hasAnyScopeAssetFilterSelected(appliedScopeAssetFilters),
    [appliedScopeAssetFilters],
  );
  const hasDraftScopeAssetFilterSelection = useMemo(
    () => hasAnyScopeAssetFilterSelected(draftScopeAssetFilters),
    [draftScopeAssetFilters],
  );
  const hasClearableScopeAssetFilterState =
    hasCommittedScopeAssetFilters || hasDraftScopeAssetFilterSelection;

  const appliedFilterCriteriaCount = useMemo(
    () => countScopeAssetFilterCriteria(appliedScopeAssetFilters),
    [appliedScopeAssetFilters],
  );

  const handleOpenScopeAssetFilters = useCallback(() => {
    setDraftScopeAssetFilters(appliedScopeAssetFilters);
    setIsScopeAssetsFilterOpen(true);
  }, [appliedScopeAssetFilters]);

  const handleCloseScopeAssetFilterSheet = useCallback(() => {
    setDraftScopeAssetFilters(appliedScopeAssetFilters);
    setIsScopeAssetsFilterOpen(false);
  }, [appliedScopeAssetFilters]);

  const handleDiscardScopeAssetFilters = useCallback(() => {
    setDraftScopeAssetFilters(appliedScopeAssetFilters);
  }, [appliedScopeAssetFilters]);

  const handleClearScopeAssetFilters = useCallback(() => {
    setDraftScopeAssetFilters(EMPTY_SCOPE_ASSET_TABLE_FILTERS);
    setAppliedScopeAssetFilters(EMPTY_SCOPE_ASSET_TABLE_FILTERS);
  }, []);

  const handleApplyScopeAssetFilters = useCallback(() => {
    setAppliedScopeAssetFilters(draftScopeAssetFilters);
    setIsScopeAssetsFilterOpen(false);
  }, [draftScopeAssetFilters]);

  const handleOpenCyberRisksForAsset = useCallback((assetId: string) => {
    setCyberRisksForSheet(cyberRisks.filter((cr) => cr.assetIds.includes(assetId)));
    setCyberRiskSheetOpen(true);
  }, []);

  const includedCount = useMemo(() => rows.filter((r) => r.included).length, [rows]);

  const filteredRows = useMemo(() => {
    let next = rows;
    if (view === "included") next = next.filter((r) => r.included);
    else if (view === "excluded") next = next.filter((r) => !r.included);
    return applyScopeAssetFilters(next, appliedScopeAssetFilters);
  }, [rows, view, appliedScopeAssetFilters]);

  const setIncluded = useCallback(
    (id: number, included: boolean) => {
      const row = rows.find((r) => r.id === id);
      if (row) onToggleAssetIncluded(row.assetId, included);
    },
    [rows, onToggleAssetIncluded],
  );

  const handleViewChange = useCallback(
    (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => {
      if (v) {
        setView(v);
        setPaginationModel((m) => ({ ...m, page: 0 }));
      }
    },
    [],
  );

  const columns: GridColDef<ScopeAssetRow>[] = useMemo(
    () => [
      {
        field: "included",
        headerName: "",
        width: 200,
        sortable: false,
        filterable: false,
        disableColumnMenu: true,
        editable: false,
        renderHeader: () => (
          <ScopeIncludedColumnHeader
            rows={rows}
            onBulkRowIdsIncluded={onBulkRowIdsIncluded}
            togglesReadOnly={togglesReadOnly}
          />
        ),
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => {
          const included = params.row.included;
          const label = included ? "Included" : "Not included";
          return (
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              role={togglesReadOnly ? "group" : "button"}
              tabIndex={togglesReadOnly ? -1 : 0}
              aria-label={
                togglesReadOnly
                  ? `${label} for ${params.row.assetName}.`
                  : `${label}. Click to ${included ? "exclude" : "include"} ${params.row.assetName} from scope.`
              }
              aria-pressed={togglesReadOnly ? undefined : included}
              onClick={togglesReadOnly ? undefined : () => setIncluded(params.row.id, !included)}
              onKeyDown={
                togglesReadOnly
                  ? undefined
                  : (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setIncluded(params.row.id, !included);
                      }
                    }
              }
              sx={({ tokens: t }) => ({
                height: "100%",
                width: "100%",
                minWidth: 0,
                py: 0.5,
                cursor: togglesReadOnly ? "default" : "pointer",
                boxSizing: "border-box",
                ...(!togglesReadOnly
                  ? {
                      "&:focus-visible": {
                        outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                        outlineOffset: -2,
                      },
                    }
                  : {}),
              })}
            >
              <Switch
                size="small"
                checked={included}
                disabled={togglesReadOnly}
                tabIndex={-1}
                sx={{ pointerEvents: "none" }}
                slotProps={{
                  input: {
                    tabIndex: -1,
                    "aria-hidden": true,
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  whiteSpace: "nowrap",
                })}
              >
                {label}
              </Typography>
            </Stack>
          );
        },
      },
      {
        field: "assetName",
        headerName: "Asset name",
        flex: 1,
        minWidth: 220,
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <Link
            href="#"
            underline="hover"
            onClick={(e: React.MouseEvent) => e.preventDefault()}
            sx={{ fontSize: 16, lineHeight: "24px" }}
          >
            {params.value as string}
          </Link>
        ),
      },
      {
        field: "assetType",
        headerName: "Asset type",
        width: 140,
      },
      {
        field: "relatedOrgUnitsCount",
        headerName: "Org. units",
        width: 140,
        type: "number",
        align: "left",
        headerAlign: "left",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <Typography
            component="span"
            variant="body1"
            sx={{ fontSize: 16, lineHeight: "24px" }}
            aria-label={`Org. units related to ${params.row.assetName}: ${params.value as number}`}
          >
            {params.value as number}
          </Typography>
        ),
      },
      {
        field: "cyberRisks",
        headerName: "Cyber risks",
        width: 120,
        type: "number",
        align: "left",
        headerAlign: "left",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Cyber risks for ${params.row.assetName}: ${params.value}. Click to view details.`}
            onPress={() => handleOpenCyberRisksForAsset(params.row.assetId)}
          />
        ),
      },
      {
        field: "threats",
        headerName: "Threats",
        width: 120,
        type: "number",
        align: "left",
        headerAlign: "left",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Threats for ${params.row.assetName}: ${params.value}`}
          />
        ),
      },
      {
        field: "vulnerabilities",
        headerName: "Vulnerabilities",
        width: 140,
        type: "number",
        align: "left",
        headerAlign: "left",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Vulnerabilities for ${params.row.assetName}: ${params.value}`}
          />
        ),
      },
      {
        field: "controls",
        headerName: "Controls",
        width: 120,
        type: "number",
        align: "left",
        headerAlign: "left",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Controls linked to cyber risks for ${params.row.assetName}: ${params.value}`}
          />
        ),
      },
      {
        field: "criticality",
        headerName: "Criticality",
        width: 180,
        sortable: true,
        valueGetter: (_v, row) => row.criticality,
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <CriticalityCell level={params.row.criticality} />
        ),
      },
      {
        field: "objectives",
        headerName: "Objectives",
        width: 110,
        type: "number",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Objectives for ${params.row.assetName}`}
          />
        ),
      },
      {
        field: "processes",
        headerName: "Processes",
        width: 110,
        type: "number",
        renderCell: (params: GridRenderCellParams<ScopeAssetRow>) => (
          <NumericLink
            value={params.value as number}
            ariaLabel={`Processes for ${params.row.assetName}`}
          />
        ),
      },
    ],
    [rows, onBulkRowIdsIncluded, setIncluded, handleOpenCyberRisksForAsset, togglesReadOnly],
  );

  return (
    <>
      <Box sx={{ width: "100%", pt: 2, pb: 3, minHeight: 520 }}>
        <DataGridPro
        rows={filteredRows}
        columns={columns}
        pagination
        autoHeight
        pinnedColumnsSectionSeparator="border"
        pinnedRowsSectionSeparator="border"
        paginationModel={paginationModel}
        onPaginationModelChange={setPaginationModel}
        pageSizeOptions={[10, 25, 50]}
        showToolbar
        slots={{
          toolbar: () => (
            <ScopeToolbar
              view={view}
              onViewChange={handleViewChange}
              totalCount={rows.length}
              includedCount={includedCount}
              onOpenFilters={handleOpenScopeAssetFilters}
              filterCriteriaCount={appliedFilterCriteriaCount}
              onClearFilters={handleClearScopeAssetFilters}
            />
          ),
        }}
        disableRowSelectionOnClick
        getRowId={(r) => r.id}
        slotProps={{
          main: {
            "aria-label":
              "Assessment scope assets. Use the first column to include or exclude assets.",
          },
          basePagination: {
            material: { labelRowsPerPage: "Rows" },
          },
        }}
        initialState={{
          sorting: {
            sortModel: [{ field: "assetName", sort: "asc" }],
          },
        }}
        sx={({ tokens: t }) => ({
          border: "none",
          borderRadius: t.semantic.radius.md.value,
          "& .MuiDataGrid-scrollShadow": {
            display: "none",
          },
          "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": {
            boxShadow: "none",
          },
          "& .MuiDataGrid-columnHeaders": {
            backgroundColor: t.semantic.color.surface.variant.value,
          },
          "& .MuiDataGrid-columnHeaderTitle": {
            fontWeight: 600,
            fontSize: 12,
            letterSpacing: "0.3px",
          },
          "& .MuiDataGrid-withBorderColor": {
            borderColor: t.semantic.color.outline.default.value,
          },
        })}
        showColumnVerticalBorder
        showCellVerticalBorder
        />
      </Box>
      <ScopedRiskSS
        open={cyberRiskSheetOpen}
        onClose={() => setCyberRiskSheetOpen(false)}
        title="Cyber risks"
        cyberRisks={cyberRisksForSheet}
      />
      <FilterSideSheet
        open={isScopeAssetsFilterOpen}
        onClose={handleCloseScopeAssetFilterSheet}
        onApply={handleApplyScopeAssetFilters}
        onClear={handleClearScopeAssetFilters}
        onDiscard={handleDiscardScopeAssetFilters}
        hasClearableFilterState={hasClearableScopeAssetFilterState}
        hasDraftFilterSelection={hasDraftScopeAssetFilterSelection}
        titleId="scope-assets-filters-title"
        contentAriaLabel="Scope assets filters"
      >
        <FilterAssets
          value={draftScopeAssetFilters}
          onChange={setDraftScopeAssetFilters}
        />
      </FilterSideSheet>
    </>
  );
}

function scopeCyberRiskWorkflowOptions(rows: ScopeCyberRiskRow[]): CyberRiskStatus[] {
  const seen = new Set(rows.map((r) => r.status));
  const ordered = CYBER_RISK_WORKFLOW_FILTER_OPTIONS.filter((s) => seen.has(s));
  const catalogOrder = new Set(CYBER_RISK_WORKFLOW_FILTER_OPTIONS as readonly string[]);
  const extras = [...seen].filter((s) => !catalogOrder.has(s));
  extras.sort((a, b) => a.localeCompare(b));
  return [...ordered, ...extras];
}

function ScopeScopedCyberRisksGrid({
  rows,
  hasIncludedAssets,
  onSetCyberRiskScopeIncluded,
  onBulkCyberRiskRowIdsIncluded,
  onNavigateToScopedAssets,
  togglesReadOnly = false,
}: {
  rows: ScopeCyberRiskRow[];
  hasIncludedAssets: boolean;
  onSetCyberRiskScopeIncluded: (cyberRiskId: string, included: boolean) => void;
  onBulkCyberRiskRowIdsIncluded: (cyberRiskIds: string[], included: boolean) => void;
  onNavigateToScopedAssets: () => void;
  togglesReadOnly?: boolean;
}) {
  const [view, setView] = useState<ScopeViewFilter>("all");
  const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });
  const [isScopeCyberRisksFilterOpen, setIsScopeCyberRisksFilterOpen] = useState(false);
  const [appliedScopeCyberRiskFilters, setAppliedScopeCyberRiskFilters] =
    useState<CyberRiskTableFilters>(EMPTY_CYBER_RISK_TABLE_FILTERS);
  const [draftScopeCyberRiskFilters, setDraftScopeCyberRiskFilters] = useState<CyberRiskTableFilters>(
    EMPTY_CYBER_RISK_TABLE_FILTERS,
  );

  const hasCommittedScopeCyberRiskFilters = useMemo(
    () => countCyberRiskFilterCriteria(appliedScopeCyberRiskFilters) > 0,
    [appliedScopeCyberRiskFilters],
  );
  const hasDraftScopeCyberRiskFilterSelection = useMemo(
    () => countCyberRiskFilterCriteria(draftScopeCyberRiskFilters) > 0,
    [draftScopeCyberRiskFilters],
  );
  const hasClearableScopeCyberRiskFilterState =
    hasCommittedScopeCyberRiskFilters || hasDraftScopeCyberRiskFilterSelection;

  const appliedFilterCriteriaCount = useMemo(
    () => countCyberRiskFilterCriteria(appliedScopeCyberRiskFilters),
    [appliedScopeCyberRiskFilters],
  );

  const handleOpenScopeCyberRiskFilters = useCallback(() => {
    setDraftScopeCyberRiskFilters(appliedScopeCyberRiskFilters);
    setIsScopeCyberRisksFilterOpen(true);
  }, [appliedScopeCyberRiskFilters]);

  const handleCloseScopeCyberRiskFilterSheet = useCallback(() => {
    setDraftScopeCyberRiskFilters(appliedScopeCyberRiskFilters);
    setIsScopeCyberRisksFilterOpen(false);
  }, [appliedScopeCyberRiskFilters]);

  const handleDiscardScopeCyberRiskFilters = useCallback(() => {
    setDraftScopeCyberRiskFilters(appliedScopeCyberRiskFilters);
  }, [appliedScopeCyberRiskFilters]);

  const handleClearScopeCyberRiskFilters = useCallback(() => {
    setDraftScopeCyberRiskFilters(EMPTY_CYBER_RISK_TABLE_FILTERS);
    setAppliedScopeCyberRiskFilters(EMPTY_CYBER_RISK_TABLE_FILTERS);
  }, []);

  const handleApplyScopeCyberRiskFilters = useCallback(() => {
    setAppliedScopeCyberRiskFilters(draftScopeCyberRiskFilters);
    setIsScopeCyberRisksFilterOpen(false);
  }, [draftScopeCyberRiskFilters]);

  const workflowOptionsForFilter = useMemo(() => scopeCyberRiskWorkflowOptions(rows), [rows]);
  const boundedOwnerIds = useMemo(() => [...new Set(rows.map((r) => r.ownerId))], [rows]);
  const boundedScoreLabels = useMemo(() => [...new Set(rows.map((r) => r.cyberRiskScoreLabel))], [rows]);
  const boundedAssetIds = useMemo(() => {
    const ids = new Set<string>();
    for (const r of rows) for (const aid of r.assetIds) ids.add(aid);
    return [...ids];
  }, [rows]);

  const includedCount = useMemo(() => rows.filter((r) => r.included).length, [rows]);

  const filteredRows = useMemo(() => {
    let next = rows;
    if (view === "included") next = next.filter((r) => r.included);
    else if (view === "excluded") next = next.filter((r) => !r.included);
    return applyCyberRiskTableFiltersToCatalogRows(next, appliedScopeCyberRiskFilters);
  }, [rows, view, appliedScopeCyberRiskFilters]);

  const setIncluded = useCallback(
    (cyberRiskId: string, included: boolean) => {
      onSetCyberRiskScopeIncluded(cyberRiskId, included);
    },
    [onSetCyberRiskScopeIncluded],
  );

  const handleViewChange = useCallback(
    (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => {
      if (v) {
        setView(v);
        setPaginationModel((m) => ({ ...m, page: 0 }));
      }
    },
    [],
  );

  const columns: GridColDef<ScopeCyberRiskRow>[] = useMemo(
    () => [
      {
        field: "included",
        headerName: "",
        width: 200,
        sortable: false,
        filterable: false,
        disableColumnMenu: true,
        editable: false,
        renderHeader: () => (
          <ScopeCyberRiskIncludedColumnHeader
            rows={rows}
            onBulkCyberRiskRowIdsIncluded={onBulkCyberRiskRowIdsIncluded}
            togglesReadOnly={togglesReadOnly}
          />
        ),
        renderCell: (params: GridRenderCellParams<ScopeCyberRiskRow>) => {
          const included = params.row.included;
          const label = included ? "Included" : "Not included";
          return (
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              role={togglesReadOnly ? "group" : "button"}
              tabIndex={togglesReadOnly ? -1 : 0}
              aria-label={
                togglesReadOnly
                  ? `${label} for ${params.row.name}.`
                  : `${label}. Click to ${included ? "exclude" : "include"} ${params.row.name} from scope.`
              }
              aria-pressed={togglesReadOnly ? undefined : included}
              onClick={togglesReadOnly ? undefined : () => setIncluded(params.row.id, !included)}
              onKeyDown={
                togglesReadOnly
                  ? undefined
                  : (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setIncluded(params.row.id, !included);
                      }
                    }
              }
              sx={({ tokens: t }) => ({
                height: "100%",
                width: "100%",
                minWidth: 0,
                py: 0.5,
                cursor: togglesReadOnly ? "default" : "pointer",
                boxSizing: "border-box",
                ...(!togglesReadOnly
                  ? {
                      "&:focus-visible": {
                        outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                        outlineOffset: -2,
                      },
                    }
                  : {}),
              })}
            >
              <Switch
                size="small"
                checked={included}
                disabled={togglesReadOnly}
                tabIndex={-1}
                sx={{ pointerEvents: "none" }}
                slotProps={{
                  input: {
                    tabIndex: -1,
                    "aria-hidden": true,
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  whiteSpace: "nowrap",
                })}
              >
                {label}
              </Typography>
            </Stack>
          );
        },
      },
      {
        field: "name",
        headerName: "Name",
        flex: 1,
        minWidth: 240,
        renderCell: (params: GridRenderCellParams<ScopeCyberRiskRow>) => (
          <Link href="#" underline="hover" onClick={(e: React.MouseEvent) => e.preventDefault()}>
            {params.value as string}
          </Link>
        ),
      },
      { field: "id", headerName: "ID", width: 110 },
      { field: "status", headerName: "Workflow status", width: 140 },
      {
        field: "cyberRiskScoreCombined",
        headerName: "Cyber risk score",
        width: 180,
        valueGetter: (_v, row) => `${row.cyberRiskScore} - ${row.cyberRiskScoreLabel}`,
      },
      {
        field: "ownerId",
        headerName: "Owner",
        width: 200,
        valueGetter: (_v, row) => getUserById(row.ownerId)?.fullName ?? "Unassigned",
      },
    ],
    [rows, onBulkCyberRiskRowIdsIncluded, setIncluded, togglesReadOnly],
  );

  if (rows.length === 0) {
    return hasIncludedAssets ? (
      <AssessmentScopeEmptyState variant="scopeEntity" entityTitle="Cyber risks" reason="noLinks" />
    ) : (
      <AssessmentScopeEmptyState
        variant="scopeEntity"
        entityTitle="Cyber risks"
        reason="needAssets"
        onNavigateToScopedAssets={onNavigateToScopedAssets}
      />
    );
  }

  return (
    <>
      <Stack gap={2} sx={{ width: "100%", pt: 2, pb: 3 }}>
        <Box sx={{ width: "100%", minHeight: 400 }}>
          <DataGridPro
            rows={filteredRows}
            columns={columns}
            getRowId={(r) => r.id}
            pagination
            autoHeight
            paginationModel={paginationModel}
            onPaginationModelChange={setPaginationModel}
            pageSizeOptions={[10, 25, 50]}
            showToolbar
            slots={{
              toolbar: () => (
                <ScopeToolbar
                  view={view}
                  onViewChange={handleViewChange}
                  totalCount={rows.length}
                  includedCount={includedCount}
                  onOpenFilters={handleOpenScopeCyberRiskFilters}
                  filterCriteriaCount={appliedFilterCriteriaCount}
                  onClearFilters={handleClearScopeCyberRiskFilters}
                  toolbarAriaLabel="Scoped cyber risks toolbar"
                  inclusionFilterAriaLabel="Filter cyber risks by inclusion"
                />
              ),
            }}
            disableRowSelectionOnClick
            slotProps={{
              main: {
                "aria-label":
                  "Cyber risks linked to assets in assessment scope. Use the first column to include or exclude each risk.",
              },
              basePagination: { material: { labelRowsPerPage: "Rows" } },
            }}
            initialState={{
              sorting: { sortModel: [{ field: "name", sort: "asc" }] },
            }}
            sx={({ tokens: t }) => ({
              border: "none",
              borderRadius: t.semantic.radius.md.value,
              "& .MuiDataGrid-scrollShadow": { display: "none" },
              "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
              "& .MuiDataGrid-columnHeaders": {
                backgroundColor: t.semantic.color.surface.variant.value,
              },
              "& .MuiDataGrid-columnHeaderTitle": {
                fontWeight: 600,
                fontSize: 12,
                letterSpacing: "0.3px",
              },
              "& .MuiDataGrid-withBorderColor": {
                borderColor: t.semantic.color.outline.default.value,
              },
            })}
            showColumnVerticalBorder
            showCellVerticalBorder
          />
        </Box>
      </Stack>
      <FilterSideSheet
        open={isScopeCyberRisksFilterOpen}
        onClose={handleCloseScopeCyberRiskFilterSheet}
        onApply={handleApplyScopeCyberRiskFilters}
        onClear={handleClearScopeCyberRiskFilters}
        onDiscard={handleDiscardScopeCyberRiskFilters}
        hasClearableFilterState={hasClearableScopeCyberRiskFilterState}
        hasDraftFilterSelection={hasDraftScopeCyberRiskFilterSelection}
        titleId="scope-cyber-risks-filters-title"
        contentAriaLabel="Scoped cyber risks filters"
      >
        <FilterRisks
          value={draftScopeCyberRiskFilters}
          onChange={setDraftScopeCyberRiskFilters}
          workflowOptions={workflowOptionsForFilter}
          boundedOwnerIds={boundedOwnerIds}
          boundedAssetIds={boundedAssetIds}
          boundedScoreLabels={boundedScoreLabels}
        />
      </FilterSideSheet>
    </>
  );
}

function ScopeScopedThreatsGrid({
  rows,
  hasIncludedAssets,
  onSetThreatScopeIncluded,
  onBulkThreatRowIdsIncluded,
  onNavigateToScopedAssets,
  togglesReadOnly = false,
}: {
  rows: ScopeThreatRow[];
  hasIncludedAssets: boolean;
  onSetThreatScopeIncluded: (threatId: string, included: boolean) => void;
  onBulkThreatRowIdsIncluded: (threatIds: string[], included: boolean) => void;
  onNavigateToScopedAssets: () => void;
  togglesReadOnly?: boolean;
}) {
  const [view, setView] = useState<ScopeViewFilter>("all");
  const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });
  const [isScopeThreatsFilterOpen, setIsScopeThreatsFilterOpen] = useState(false);
  const [appliedScopeThreatFilters, setAppliedScopeThreatFilters] =
    useState<ThreatTableFilters>(EMPTY_THREAT_TABLE_FILTERS);
  const [draftScopeThreatFilters, setDraftScopeThreatFilters] = useState<ThreatTableFilters>(
    EMPTY_THREAT_TABLE_FILTERS,
  );

  const hasCommittedScopeThreatFilters = useMemo(
    () => countThreatFilterCriteria(appliedScopeThreatFilters) > 0,
    [appliedScopeThreatFilters],
  );
  const hasDraftScopeThreatFilterSelection = useMemo(
    () => countThreatFilterCriteria(draftScopeThreatFilters) > 0,
    [draftScopeThreatFilters],
  );
  const hasClearableScopeThreatFilterState =
    hasCommittedScopeThreatFilters || hasDraftScopeThreatFilterSelection;

  const appliedThreatFilterCriteriaCount = useMemo(
    () => countThreatFilterCriteria(appliedScopeThreatFilters),
    [appliedScopeThreatFilters],
  );

  const handleOpenScopeThreatFilters = useCallback(() => {
    setDraftScopeThreatFilters(appliedScopeThreatFilters);
    setIsScopeThreatsFilterOpen(true);
  }, [appliedScopeThreatFilters]);

  const handleCloseScopeThreatFilterSheet = useCallback(() => {
    setDraftScopeThreatFilters(appliedScopeThreatFilters);
    setIsScopeThreatsFilterOpen(false);
  }, [appliedScopeThreatFilters]);

  const handleDiscardScopeThreatFilters = useCallback(() => {
    setDraftScopeThreatFilters(appliedScopeThreatFilters);
  }, [appliedScopeThreatFilters]);

  const handleClearScopeThreatFilters = useCallback(() => {
    setDraftScopeThreatFilters(EMPTY_THREAT_TABLE_FILTERS);
    setAppliedScopeThreatFilters(EMPTY_THREAT_TABLE_FILTERS);
  }, []);

  const handleApplyScopeThreatFilters = useCallback(() => {
    setAppliedScopeThreatFilters(draftScopeThreatFilters);
    setIsScopeThreatsFilterOpen(false);
  }, [draftScopeThreatFilters]);

  const threatFilterRows = useMemo(() => scopeThreatRowsToThreatFilterRows(rows), [rows]);
  const boundedThreatAssetIds = useMemo(() => unionScopeThreatLinkedAssetIds(rows), [rows]);
  const boundedThreatVulnerabilityIds = useMemo(
    () => unionScopeThreatLinkedVulnerabilityIds(rows),
    [rows],
  );

  const includedCount = useMemo(() => rows.filter((r) => r.included).length, [rows]);

  const filteredRows = useMemo(() => {
    let next = rows;
    if (view === "included") next = next.filter((r) => r.included);
    else if (view === "excluded") next = next.filter((r) => !r.included);
    return filterScopeThreatRowsByThreatTableFilters(next, appliedScopeThreatFilters);
  }, [rows, view, appliedScopeThreatFilters]);

  const setIncluded = useCallback(
    (threatId: string, included: boolean) => {
      onSetThreatScopeIncluded(threatId, included);
    },
    [onSetThreatScopeIncluded],
  );

  const handleViewChange = useCallback(
    (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => {
      if (v) {
        setView(v);
        setPaginationModel((m) => ({ ...m, page: 0 }));
      }
    },
    [],
  );

  const columns: GridColDef<ScopeThreatRow>[] = useMemo(
    () => [
      {
        field: "included",
        headerName: "",
        width: 200,
        sortable: false,
        filterable: false,
        disableColumnMenu: true,
        editable: false,
        renderHeader: () => (
          <ScopePagedIncludedColumnHeader
            rows={rows}
            onBulkRowIdsIncluded={onBulkThreatRowIdsIncluded}
            entityPlural="threats"
            togglesReadOnly={togglesReadOnly}
          />
        ),
        renderCell: (params: GridRenderCellParams<ScopeThreatRow>) => {
          const { included, toggleDisabled, name, id } = params.row;
          const label = included ? "Included" : "Not included";
          if (toggleDisabled) {
            return (
              <Stack
                direction="row"
                alignItems="center"
                gap={1}
                aria-label={`${name} is not available to include in scope.`}
                sx={{
                  height: "100%",
                  width: "100%",
                  minWidth: 0,
                  py: 0.5,
                  opacity: 0.72,
                  boxSizing: "border-box",
                }}
              >
                <Switch size="small" checked={false} disabled tabIndex={-1} />
                <Typography
                  variant="caption"
                  sx={({ tokens: t }) => ({
                    color: t.semantic.color.type.muted.value,
                    whiteSpace: "nowrap",
                  })}
                >
                  Not included
                </Typography>
              </Stack>
            );
          }
          return (
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              role={togglesReadOnly ? "group" : "button"}
              tabIndex={togglesReadOnly ? -1 : 0}
              aria-label={
                togglesReadOnly
                  ? `${label} for ${name}.`
                  : `${label}. Click to ${included ? "exclude" : "include"} ${name} from scope.`
              }
              aria-pressed={togglesReadOnly ? undefined : included}
              onClick={togglesReadOnly ? undefined : () => setIncluded(id, !included)}
              onKeyDown={
                togglesReadOnly
                  ? undefined
                  : (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setIncluded(id, !included);
                      }
                    }
              }
              sx={({ tokens: t }) => ({
                height: "100%",
                width: "100%",
                minWidth: 0,
                py: 0.5,
                cursor: togglesReadOnly ? "default" : "pointer",
                boxSizing: "border-box",
                ...(!togglesReadOnly
                  ? {
                      "&:focus-visible": {
                        outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                        outlineOffset: -2,
                      },
                    }
                  : {}),
              })}
            >
              <Switch
                size="small"
                checked={included}
                disabled={togglesReadOnly}
                tabIndex={-1}
                sx={{ pointerEvents: "none" }}
                slotProps={{
                  input: {
                    tabIndex: -1,
                    "aria-hidden": true,
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  whiteSpace: "nowrap",
                })}
              >
                {label}
              </Typography>
            </Stack>
          );
        },
      },
      {
        field: "name",
        headerName: "Name",
        flex: 1,
        minWidth: 240,
        renderCell: (params: GridRenderCellParams<ScopeThreatRow>) => (
          <Link href="#" underline="hover" onClick={(e: React.MouseEvent) => e.preventDefault()}>
            {params.value as string}
          </Link>
        ),
      },
      { field: "id", headerName: "ID", width: 110 },
      {
        field: "domain",
        headerName: "Threat domain",
        flex: 1,
        minWidth: 200,
      },
      {
        field: "sources",
        headerName: "Threat source types",
        flex: 1,
        minWidth: 200,
        valueGetter: (_v, row) => row.sources.join(", "),
      },
      { field: "status", headerName: "Status", width: 120 },
      {
        field: "ownerIds",
        headerName: "Owner",
        width: 200,
        valueGetter: (_v, row) => joinUserFullNames(row.ownerIds),
      },
    ],
    [rows, onBulkThreatRowIdsIncluded, setIncluded, togglesReadOnly],
  );

  if (rows.length === 0) {
    return hasIncludedAssets ? (
      <AssessmentScopeEmptyState variant="scopeEntity" entityTitle="Threats" reason="noLinks" />
    ) : (
      <AssessmentScopeEmptyState
        variant="scopeEntity"
        entityTitle="Threats"
        reason="needAssets"
        onNavigateToScopedAssets={onNavigateToScopedAssets}
      />
    );
  }

  return (
    <>
      <Stack gap={2} sx={{ width: "100%", pt: 2, pb: 3 }}>
        <Box sx={{ width: "100%", minHeight: 400 }}>
          <DataGridPro
            rows={filteredRows}
            columns={columns}
            getRowId={(r) => r.id}
            pagination
            autoHeight
            paginationModel={paginationModel}
            onPaginationModelChange={setPaginationModel}
            pageSizeOptions={[10, 25, 50]}
            showToolbar
            slots={{
              toolbar: () => (
                <ScopeToolbar
                  view={view}
                  onViewChange={handleViewChange}
                  totalCount={rows.length}
                  includedCount={includedCount}
                  onOpenFilters={handleOpenScopeThreatFilters}
                  filterCriteriaCount={appliedThreatFilterCriteriaCount}
                  onClearFilters={handleClearScopeThreatFilters}
                  toolbarAriaLabel="Scoped threats toolbar"
                  inclusionFilterAriaLabel="Filter threats by inclusion"
                />
              ),
            }}
            disableRowSelectionOnClick
            slotProps={{
              main: {
                "aria-label":
                  "Threats linked to assets in assessment scope. Use the first column to include or exclude each threat.",
              },
              basePagination: { material: { labelRowsPerPage: "Rows" } },
            }}
            initialState={{
              sorting: { sortModel: [{ field: "name", sort: "asc" }] },
            }}
            sx={({ tokens: t }) => ({
              border: "none",
              borderRadius: t.semantic.radius.md.value,
              "& .MuiDataGrid-scrollShadow": { display: "none" },
              "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
              "& .MuiDataGrid-columnHeaders": {
                backgroundColor: t.semantic.color.surface.variant.value,
              },
              "& .MuiDataGrid-columnHeaderTitle": {
                fontWeight: 600,
                fontSize: 12,
                letterSpacing: "0.3px",
              },
              "& .MuiDataGrid-withBorderColor": {
                borderColor: t.semantic.color.outline.default.value,
              },
            })}
            showColumnVerticalBorder
            showCellVerticalBorder
          />
        </Box>
      </Stack>
      <FilterSideSheet
        open={isScopeThreatsFilterOpen}
        onClose={handleCloseScopeThreatFilterSheet}
        onApply={handleApplyScopeThreatFilters}
        onClear={handleClearScopeThreatFilters}
        onDiscard={handleDiscardScopeThreatFilters}
        hasClearableFilterState={hasClearableScopeThreatFilterState}
        hasDraftFilterSelection={hasDraftScopeThreatFilterSelection}
        titleId="scope-threats-filters-title"
        contentAriaLabel="Threat filters for assessment scope"
      >
        <FilterThreats
          value={draftScopeThreatFilters}
          onChange={setDraftScopeThreatFilters}
          rows={threatFilterRows}
          boundedAssetIds={boundedThreatAssetIds}
          boundedVulnerabilityIds={boundedThreatVulnerabilityIds}
        />
      </FilterSideSheet>
    </>
  );
}

function ScopeScopedVulnerabilitiesGrid({
  rows,
  hasIncludedAssets,
  onSetVulnerabilityScopeIncluded,
  onBulkVulnerabilityRowIdsIncluded,
  onNavigateToScopedAssets,
  togglesReadOnly = false,
}: {
  rows: ScopeVulnerabilityRow[];
  hasIncludedAssets: boolean;
  onSetVulnerabilityScopeIncluded: (vulnerabilityId: string, included: boolean) => void;
  onBulkVulnerabilityRowIdsIncluded: (vulnerabilityIds: string[], included: boolean) => void;
  onNavigateToScopedAssets: () => void;
  togglesReadOnly?: boolean;
}) {
  const [view, setView] = useState<ScopeViewFilter>("all");
  const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });

  const includedCount = useMemo(() => rows.filter((r) => r.included).length, [rows]);

  const filteredRows = useMemo(() => {
    if (view === "included") return rows.filter((r) => r.included);
    if (view === "excluded") return rows.filter((r) => !r.included);
    return rows;
  }, [rows, view]);

  const setIncluded = useCallback(
    (vulnerabilityId: string, included: boolean) => {
      onSetVulnerabilityScopeIncluded(vulnerabilityId, included);
    },
    [onSetVulnerabilityScopeIncluded],
  );

  const handleViewChange = useCallback(
    (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => {
      if (v) {
        setView(v);
        setPaginationModel((m) => ({ ...m, page: 0 }));
      }
    },
    [],
  );

  const columns: GridColDef<ScopeVulnerabilityRow>[] = useMemo(
    () => [
      {
        field: "included",
        headerName: "",
        width: 200,
        sortable: false,
        filterable: false,
        disableColumnMenu: true,
        editable: false,
        renderHeader: () => (
          <ScopePagedIncludedColumnHeader
            rows={rows}
            onBulkRowIdsIncluded={onBulkVulnerabilityRowIdsIncluded}
            entityPlural="vulnerabilities"
            togglesReadOnly={togglesReadOnly}
          />
        ),
        renderCell: (params: GridRenderCellParams<ScopeVulnerabilityRow>) => {
          const included = params.row.included;
          const label = included ? "Included" : "Not included";
          return (
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              role={togglesReadOnly ? "group" : "button"}
              tabIndex={togglesReadOnly ? -1 : 0}
              aria-label={
                togglesReadOnly
                  ? `${label} for ${params.row.name}.`
                  : `${label}. Click to ${included ? "exclude" : "include"} ${params.row.name} from scope.`
              }
              aria-pressed={togglesReadOnly ? undefined : included}
              onClick={togglesReadOnly ? undefined : () => setIncluded(params.row.id, !included)}
              onKeyDown={
                togglesReadOnly
                  ? undefined
                  : (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setIncluded(params.row.id, !included);
                      }
                    }
              }
              sx={({ tokens: t }) => ({
                height: "100%",
                width: "100%",
                minWidth: 0,
                py: 0.5,
                cursor: togglesReadOnly ? "default" : "pointer",
                boxSizing: "border-box",
                ...(!togglesReadOnly
                  ? {
                      "&:focus-visible": {
                        outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                        outlineOffset: -2,
                      },
                    }
                  : {}),
              })}
            >
              <Switch
                size="small"
                checked={included}
                disabled={togglesReadOnly}
                tabIndex={-1}
                sx={{ pointerEvents: "none" }}
                slotProps={{
                  input: {
                    tabIndex: -1,
                    "aria-hidden": true,
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  whiteSpace: "nowrap",
                })}
              >
                {label}
              </Typography>
            </Stack>
          );
        },
      },
      {
        field: "name",
        headerName: "Name",
        flex: 1,
        minWidth: 240,
        renderCell: (params: GridRenderCellParams<ScopeVulnerabilityRow>) => (
          <Link href="#" underline="hover" onClick={(e: React.MouseEvent) => e.preventDefault()}>
            {params.value as string}
          </Link>
        ),
      },
      { field: "id", headerName: "Meta ID", width: 100 },
      { field: "displayId", headerName: "Display ID", width: 120 },
      { field: "domain", headerName: "Domain", width: 130 },
      {
        field: "vulnerabilityType",
        headerName: "Type",
        flex: 1,
        minWidth: 200,
        valueGetter: (_v, row) => row.vulnerabilityType ?? "—",
      },
      { field: "status", headerName: "Status", width: 120 },
      {
        field: "primaryCIAImpact",
        headerName: "Primary CIA impact",
        width: 200,
        valueGetter: (_v, row) =>
          row.primaryCIAImpact.length ? row.primaryCIAImpact.join(" · ") : "—",
      },
      {
        field: "ownerIds",
        headerName: "Owner",
        width: 200,
        valueGetter: (_v, row) => joinUserFullNames(row.ownerIds),
      },
    ],
    [rows, onBulkVulnerabilityRowIdsIncluded, setIncluded, togglesReadOnly],
  );

  if (rows.length === 0) {
    return hasIncludedAssets ? (
      <AssessmentScopeEmptyState
        variant="scopeEntity"
        entityTitle="Vulnerabilities"
        reason="noLinks"
      />
    ) : (
      <AssessmentScopeEmptyState
        variant="scopeEntity"
        entityTitle="Vulnerabilities"
        reason="needAssets"
        onNavigateToScopedAssets={onNavigateToScopedAssets}
      />
    );
  }

  return (
    <Stack gap={2} sx={{ width: "100%", pt: 2, pb: 3 }}>
      <Box sx={{ width: "100%", minHeight: 400 }}>
        <DataGridPro
          rows={filteredRows}
          columns={columns}
          getRowId={(r) => r.id}
          pagination
          autoHeight
          paginationModel={paginationModel}
          onPaginationModelChange={setPaginationModel}
          pageSizeOptions={[10, 25, 50]}
          showToolbar
          slots={{
            toolbar: () => (
              <ScopeDataGridInclusionToolbar
                view={view}
                onViewChange={handleViewChange}
                totalCount={rows.length}
                includedCount={includedCount}
                toolbarAriaLabel="Scoped vulnerabilities toolbar"
                inclusionFilterAriaLabel="Filter vulnerabilities by inclusion"
              />
            ),
          }}
          disableRowSelectionOnClick
          slotProps={{
            main: {
              "aria-label":
                "Vulnerabilities linked to assets in assessment scope. Use the first column to include or exclude each vulnerability.",
            },
            basePagination: { material: { labelRowsPerPage: "Rows" } },
          }}
          initialState={{
            sorting: { sortModel: [{ field: "name", sort: "asc" }] },
          }}
          sx={({ tokens: t }) => ({
            border: "none",
            borderRadius: t.semantic.radius.md.value,
            "& .MuiDataGrid-scrollShadow": { display: "none" },
            "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
            "& .MuiDataGrid-columnHeaders": {
              backgroundColor: t.semantic.color.surface.variant.value,
            },
            "& .MuiDataGrid-columnHeaderTitle": {
              fontWeight: 600,
              fontSize: 12,
              letterSpacing: "0.3px",
            },
            "& .MuiDataGrid-withBorderColor": {
              borderColor: t.semantic.color.outline.default.value,
            },
          })}
          showColumnVerticalBorder
          showCellVerticalBorder
        />
      </Box>
    </Stack>
  );
}

function ScopeScopedControlsGrid({
  rows,
  hasIncludedAssets,
  onSetControlScopeIncluded,
  onBulkControlRowIdsIncluded,
  onNavigateToScopedAssets,
  togglesReadOnly = false,
}: {
  rows: ScopeControlRow[];
  hasIncludedAssets: boolean;
  onSetControlScopeIncluded: (controlId: string, included: boolean) => void;
  onBulkControlRowIdsIncluded: (controlIds: string[], included: boolean) => void;
  onNavigateToScopedAssets: () => void;
  togglesReadOnly?: boolean;
}) {
  const [view, setView] = useState<ScopeViewFilter>("all");
  const [paginationModel, setPaginationModel] = useState({ page: 0, pageSize: 10 });

  const includedCount = useMemo(() => rows.filter((r) => r.included).length, [rows]);

  const filteredRows = useMemo(() => {
    if (view === "included") return rows.filter((r) => r.included);
    if (view === "excluded") return rows.filter((r) => !r.included);
    return rows;
  }, [rows, view]);

  const setIncluded = useCallback(
    (controlId: string, included: boolean) => {
      onSetControlScopeIncluded(controlId, included);
    },
    [onSetControlScopeIncluded],
  );

  const handleViewChange = useCallback(
    (_e: React.MouseEvent<HTMLElement>, v: ScopeViewFilter | null) => {
      if (v) {
        setView(v);
        setPaginationModel((m) => ({ ...m, page: 0 }));
      }
    },
    [],
  );

  const columns: GridColDef<ScopeControlRow>[] = useMemo(
    () => [
      {
        field: "included",
        headerName: "",
        width: 200,
        sortable: false,
        filterable: false,
        disableColumnMenu: true,
        editable: false,
        renderHeader: () => (
          <ScopePagedIncludedColumnHeader
            rows={rows}
            onBulkRowIdsIncluded={onBulkControlRowIdsIncluded}
            entityPlural="controls"
            togglesReadOnly={togglesReadOnly}
          />
        ),
        renderCell: (params: GridRenderCellParams<ScopeControlRow>) => {
          const { included, toggleDisabled, name, id } = params.row;
          const label = included ? "Included" : "Not included";
          if (toggleDisabled) {
            return (
              <Stack
                direction="row"
                alignItems="center"
                gap={1}
                aria-label={`${name} cannot be included until at least one linked cyber risk is in scope.`}
                sx={{
                  height: "100%",
                  width: "100%",
                  minWidth: 0,
                  py: 0.5,
                  opacity: 0.72,
                  boxSizing: "border-box",
                }}
              >
                <Switch size="small" checked={false} disabled tabIndex={-1} />
                <Typography
                  variant="caption"
                  sx={({ tokens: t }) => ({
                    color: t.semantic.color.type.muted.value,
                    whiteSpace: "nowrap",
                  })}
                >
                  Not included
                </Typography>
              </Stack>
            );
          }
          return (
            <Stack
              direction="row"
              alignItems="center"
              gap={1}
              role={togglesReadOnly ? "group" : "button"}
              tabIndex={togglesReadOnly ? -1 : 0}
              aria-label={
                togglesReadOnly
                  ? `${label} for ${name}.`
                  : `${label}. Click to ${included ? "exclude" : "include"} ${name} from scope.`
              }
              aria-pressed={togglesReadOnly ? undefined : included}
              onClick={togglesReadOnly ? undefined : () => setIncluded(id, !included)}
              onKeyDown={
                togglesReadOnly
                  ? undefined
                  : (e: React.KeyboardEvent) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setIncluded(id, !included);
                      }
                    }
              }
              sx={({ tokens: t }) => ({
                height: "100%",
                width: "100%",
                minWidth: 0,
                py: 0.5,
                cursor: togglesReadOnly ? "default" : "pointer",
                boxSizing: "border-box",
                ...(!togglesReadOnly
                  ? {
                      "&:focus-visible": {
                        outline: `2px solid ${t.semantic.color.action.primary.default.value}`,
                        outlineOffset: -2,
                      },
                    }
                  : {}),
              })}
            >
              <Switch
                size="small"
                checked={included}
                disabled={togglesReadOnly}
                tabIndex={-1}
                sx={{ pointerEvents: "none" }}
                slotProps={{
                  input: {
                    tabIndex: -1,
                    "aria-hidden": true,
                  },
                }}
              />
              <Typography
                variant="caption"
                sx={({ tokens: t }) => ({
                  color: t.semantic.color.type.muted.value,
                  whiteSpace: "nowrap",
                })}
              >
                {label}
              </Typography>
            </Stack>
          );
        },
      },
      {
        field: "name",
        headerName: "Name",
        flex: 1,
        minWidth: 240,
        renderCell: (params: GridRenderCellParams<ScopeControlRow>) => (
          <Link href="#" underline="hover" onClick={(e: React.MouseEvent) => e.preventDefault()}>
            {params.value as string}
          </Link>
        ),
      },
      { field: "id", headerName: "ID", width: 110 },
      { field: "status", headerName: "Status", width: 120 },
      { field: "controlType", headerName: "Type", width: 140 },
      { field: "controlFrequency", headerName: "Frequency", width: 140 },
      {
        field: "keyControl",
        headerName: "Key control",
        width: 120,
        valueGetter: (_v, row) => (row.keyControl ? "Yes" : "No"),
      },
      {
        field: "ownerId",
        headerName: "Owner",
        width: 200,
        valueGetter: (_v, row) => getUserById(row.ownerId)?.fullName ?? "Unassigned",
      },
    ],
    [rows, onBulkControlRowIdsIncluded, setIncluded, togglesReadOnly],
  );

  if (rows.length === 0) {
    return hasIncludedAssets ? (
      <AssessmentScopeEmptyState variant="scopeEntity" entityTitle="Controls" reason="noLinks" />
    ) : (
      <AssessmentScopeEmptyState
        variant="scopeEntity"
        entityTitle="Controls"
        reason="needAssets"
        onNavigateToScopedAssets={onNavigateToScopedAssets}
      />
    );
  }

  return (
    <Stack gap={2} sx={{ width: "100%", pt: 2, pb: 3 }}>
      <Box sx={{ width: "100%", minHeight: 400 }}>
        <DataGridPro
          rows={filteredRows}
          columns={columns}
          getRowId={(r) => r.id}
          pagination
          autoHeight
          paginationModel={paginationModel}
          onPaginationModelChange={setPaginationModel}
          pageSizeOptions={[10, 25, 50]}
          showToolbar
          slots={{
            toolbar: () => (
              <ScopeDataGridInclusionToolbar
                view={view}
                onViewChange={handleViewChange}
                totalCount={rows.length}
                includedCount={includedCount}
                toolbarAriaLabel="Scoped controls toolbar"
                inclusionFilterAriaLabel="Filter controls by inclusion"
              />
            ),
          }}
          disableRowSelectionOnClick
          slotProps={{
            main: {
              "aria-label":
                "Controls linked to assets in assessment scope. Use the first column to include or exclude each control when linked cyber risks are in scope.",
            },
            basePagination: { material: { labelRowsPerPage: "Rows" } },
          }}
          initialState={{
            sorting: { sortModel: [{ field: "name", sort: "asc" }] },
          }}
          sx={({ tokens: t }) => ({
            border: "none",
            borderRadius: t.semantic.radius.md.value,
            "& .MuiDataGrid-scrollShadow": { display: "none" },
            "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
            "& .MuiDataGrid-columnHeaders": {
              backgroundColor: t.semantic.color.surface.variant.value,
            },
            "& .MuiDataGrid-columnHeaderTitle": {
              fontWeight: 600,
              fontSize: 12,
              letterSpacing: "0.3px",
            },
            "& .MuiDataGrid-withBorderColor": {
              borderColor: t.semantic.color.outline.default.value,
            },
          })}
          showColumnVerticalBorder
          showCellVerticalBorder
        />
      </Box>
    </Stack>
  );
}

type AssessmentScopeTabProps = {
  scopeSubView: ScopeSubView;
  onScopeSubViewChange: (view: ScopeSubView) => void;
  includedAssetIds: Set<string>;
  excludedScopeCyberRiskIds: Set<string>;
  onSetCyberRiskScopeIncluded: (cyberRiskId: string, included: boolean) => void;
  onBulkCyberRisksScopeIncluded: (cyberRiskIds: string[], included: boolean) => void;
  excludedScopeThreatIds: Set<string>;
  onSetThreatScopeIncluded: (threatId: string, included: boolean) => void;
  onBulkThreatsScopeIncluded: (threatIds: string[], included: boolean) => void;
  excludedScopeVulnerabilityIds: Set<string>;
  onSetVulnerabilityScopeIncluded: (vulnerabilityId: string, included: boolean) => void;
  onBulkVulnerabilitiesScopeIncluded: (vulnerabilityIds: string[], included: boolean) => void;
  excludedScopeControlIds: Set<string>;
  onSetControlScopeIncluded: (controlId: string, included: boolean) => void;
  onBulkControlsScopeIncluded: (controlIds: string[], included: boolean) => void;
  onToggleAssetIncluded: (assetId: string, included: boolean) => void;
  onBulkAssetIdsIncluded: (assetIds: string[], included: boolean) => void;
  /** When true (e.g. approved assessment), scope include/exclude toggles are not editable. */
  scopeTogglesReadOnly?: boolean;
};

export default function AssessmentScopeTab({
  scopeSubView,
  onScopeSubViewChange,
  includedAssetIds,
  excludedScopeCyberRiskIds,
  onSetCyberRiskScopeIncluded,
  onBulkCyberRisksScopeIncluded,
  excludedScopeThreatIds,
  onSetThreatScopeIncluded,
  onBulkThreatsScopeIncluded,
  excludedScopeVulnerabilityIds,
  onSetVulnerabilityScopeIncluded,
  onBulkVulnerabilitiesScopeIncluded,
  excludedScopeControlIds,
  onSetControlScopeIncluded,
  onBulkControlsScopeIncluded,
  onToggleAssetIncluded,
  onBulkAssetIdsIncluded,
  scopeTogglesReadOnly = false,
}: AssessmentScopeTabProps) {
  const rows = useMemo(
    () =>
      buildScopeRows().map((r) => ({
        ...r,
        included: includedAssetIds.has(r.assetId),
      })),
    [includedAssetIds],
  );

  const includedCount = includedAssetIds.size;

  const handleBulkRowIdsIncluded = useCallback(
    (rowIds: number[], included: boolean) => {
      const assetIds = rowIds
        .map((id) => rows.find((r) => r.id === id)?.assetId)
        .filter((x): x is string => Boolean(x));
      onBulkAssetIdsIncluded(assetIds, included);
    },
    [rows, onBulkAssetIdsIncluded],
  );

  const scopedCrRows = useMemo(
    () => assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds),
    [includedAssetIds, excludedScopeCyberRiskIds],
  );

  const scopeCyberRiskGridRows = useMemo((): ScopeCyberRiskRow[] => {
    return candidateScopedCyberRisks(includedAssetIds).map((cr) => ({
      ...cr,
      included: !excludedScopeCyberRiskIds.has(cr.id),
    }));
  }, [includedAssetIds, excludedScopeCyberRiskIds]);

  const scopeThreatGridRows = useMemo((): ScopeThreatRow[] => {
    return candidateScopedThreats(includedAssetIds).map((t) => ({
      ...t,
      included: !excludedScopeThreatIds.has(t.id),
      toggleDisabled: false,
    }));
  }, [includedAssetIds, excludedScopeThreatIds]);

  const scopeVulnerabilityGridRows = useMemo((): ScopeVulnerabilityRow[] => {
    return candidateScopedVulnerabilities(includedAssetIds).map((v) => ({
      ...v,
      included: !excludedScopeVulnerabilityIds.has(v.id),
    }));
  }, [includedAssetIds, excludedScopeVulnerabilityIds]);

  const scopeControlGridRows = useMemo((): ScopeControlRow[] => {
    return candidateScopedControls(includedAssetIds).map((c) => {
      const touchesIncludedAsset = c.assetIds.some((aid) => includedAssetIds.has(aid));
      const included = touchesIncludedAsset && !excludedScopeControlIds.has(c.id);
      return { ...c, included, toggleDisabled: !touchesIncludedAsset };
    });
  }, [includedAssetIds, excludedScopeControlIds]);

  const scopedThreatRows = useMemo(
    () =>
      assessmentScopedThreats(
        includedAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeThreatIds,
      ),
    [includedAssetIds, excludedScopeThreatIds],
  );
  const scopedVulnRows = useMemo(
    () => assessmentScopedVulnerabilities(includedAssetIds, excludedScopeVulnerabilityIds),
    [includedAssetIds, excludedScopeVulnerabilityIds],
  );
  const scopedControlRows = useMemo(
    () =>
      assessmentScopedControls(
        includedAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeControlIds,
      ),
    [includedAssetIds, excludedScopeCyberRiskIds, excludedScopeControlIds],
  );

  if (scopeSubView === "assets") {
    return (
      <ScopeAssetsDataGrid
        rows={rows}
        onToggleAssetIncluded={onToggleAssetIncluded}
        onBulkRowIdsIncluded={handleBulkRowIdsIncluded}
        togglesReadOnly={scopeTogglesReadOnly}
      />
    );
  }

  if (scopeSubView === "scopedCyberRisks") {
    return (
      <ScopeScopedCyberRisksGrid
        rows={scopeCyberRiskGridRows}
        hasIncludedAssets={includedCount > 0}
        onSetCyberRiskScopeIncluded={onSetCyberRiskScopeIncluded}
        onBulkCyberRiskRowIdsIncluded={onBulkCyberRisksScopeIncluded}
        onNavigateToScopedAssets={() => onScopeSubViewChange("assets")}
        togglesReadOnly={scopeTogglesReadOnly}
      />
    );
  }

  if (scopeSubView === "scopedThreats") {
    return (
      <ScopeScopedThreatsGrid
        rows={scopeThreatGridRows}
        hasIncludedAssets={includedCount > 0}
        onSetThreatScopeIncluded={onSetThreatScopeIncluded}
        onBulkThreatRowIdsIncluded={onBulkThreatsScopeIncluded}
        onNavigateToScopedAssets={() => onScopeSubViewChange("assets")}
        togglesReadOnly={scopeTogglesReadOnly}
      />
    );
  }

  if (scopeSubView === "scopedVulnerabilities") {
    return (
      <ScopeScopedVulnerabilitiesGrid
        rows={scopeVulnerabilityGridRows}
        hasIncludedAssets={includedCount > 0}
        onSetVulnerabilityScopeIncluded={onSetVulnerabilityScopeIncluded}
        onBulkVulnerabilityRowIdsIncluded={onBulkVulnerabilitiesScopeIncluded}
        onNavigateToScopedAssets={() => onScopeSubViewChange("assets")}
        togglesReadOnly={scopeTogglesReadOnly}
      />
    );
  }

  if (scopeSubView === "scopedControls") {
    return (
      <ScopeScopedControlsGrid
        rows={scopeControlGridRows}
        hasIncludedAssets={includedCount > 0}
        onSetControlScopeIncluded={onSetControlScopeIncluded}
        onBulkControlRowIdsIncluded={onBulkControlsScopeIncluded}
        onNavigateToScopedAssets={() => onScopeSubViewChange("assets")}
        togglesReadOnly={scopeTogglesReadOnly}
      />
    );
  }

  return (
    <ScopeOverviewCards
      totalAssets={rows.length}
      includedAssets={includedCount}
      includedCyberRisks={scopedCrRows.length}
      includedThreats={scopedThreatRows.length}
      includedVulnerabilities={scopedVulnRows.length}
      includedControls={scopedControlRows.length}
      onEditAssetsScope={() => onScopeSubViewChange("assets")}
      onOpenCyberRisks={() => onScopeSubViewChange("scopedCyberRisks")}
      onOpenThreats={() => onScopeSubViewChange("scopedThreats")}
      onOpenVulnerabilities={() => onScopeSubViewChange("scopedVulnerabilities")}
      onOpenControls={() => onScopeSubViewChange("scopedControls")}
    />
  );
}
