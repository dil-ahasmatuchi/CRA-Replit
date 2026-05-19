import { useCallback, useMemo, useState } from "react";
import { SectionHeader } from "@diligentcorp/atlas-react-bundle";
import { useNavigate } from "react-router";

import AssessmentScopeEmptyState from "../components/AssessmentScopeEmptyState.js";
import FilterResults, {
  copyFilterResultsValue,
  countFilterResultsCriteria,
  EMPTY_FILTER_RESULTS,
  filterAssessmentCyberResultsRows,
  filterResultsValueEquals,
  type FilterResultsValue,
} from "../components/FilterResults.js";
import FilterSideSheet from "../components/FilterSideSheet.js";
import MitigationPlanPageSideSheet from "../components/MitigationPlanPageSideSheet.js";
import ResultsHero from "../components/ResultsHero.js";
import ScoringInfoCardRead from "../components/ScoringInfoCardRead.js";
import { ResultsRiskChip, ResultsTreeData } from "../components/ResultsTreeData.js";
import type { MatrixSelectionPayload } from "../components/RisksMatrix.js";
import { Box, Link, Stack } from "@mui/material";
import { DataGridPro, type GridColDef, type GridRenderCellParams } from "@mui/x-data-grid-pro";
import { assets } from "../data/assets.js";
import {
  applyNewCraCatalogScoreMaskingToAssetResultsRows,
  applyNewCraCatalogScoreMaskingToCyberResultsRows,
  assessmentResultsHasHiddenScenarioScores,
  buildAssetResultRowsForScope,
  buildCyberResultsRowsForScope,
  type AssessmentAssetResultRow,
  type AssessmentCyberResultsRow,
  type AssessmentResultsCatalogMaskParams,
} from "./craAssessmentScopeRows.js";
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
} from "../data/assessmentScopeRollup.js";
import { scenarioRationaleReadOnlyPath } from "./craScenarioRoutes.js";
import {
  NEW_CRA_RESULTS_TAB_INDEX,
  type AiScoringPhase,
  type AssessmentPhase,
  type CraScoringTypeChoice,
} from "./craNewAssessmentDraftStorage.js";
import type { CraScenarioScoreAggregationMethod } from "../data/craAssessmentDraftTypes.js";
import { filterAssessmentCyberResultsByMatrixFilter } from "../utils/assessmentResultsMatrixFilter.js";
import type { CyberRiskMatrixTableFilter } from "../utils/cyberRiskTableRows.js";

type CyberResultsRow = AssessmentCyberResultsRow;
type AssetResultRow = AssessmentAssetResultRow;

const EMPTY_SCENARIO_NOT_APPLICABLE_IDS = new Set<string>();
const EMPTY_MANUAL_REVEAL_IDS = new Set<string>();

function AssetsResultsGrid({ rows }: { rows: AssetResultRow[] }) {
  const columns: GridColDef<AssetResultRow>[] = useMemo(
    () => [
      {
        field: "name",
        headerName: "Name",
        flex: 1,
        minWidth: 220,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <Link
            href="#"
            onClick={(e) => e.preventDefault()}
            underline="hover"
            sx={({ tokens: t }) => ({
              fontWeight: 600,
              fontSize: t.semantic.font.text.md.fontSize.value,
              color: t.semantic.color.action.link.default.value,
            })}
          >
            {params.value as string}
          </Link>
        ),
      },
      {
        field: "assetId",
        headerName: "ID",
        width: 120,
      },
      {
        field: "cyberRiskScore",
        headerName: "Cyber risk score",
        width: 150,
        sortable: false,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <ResultsRiskChip value={params.row.cyberRiskScore} />
        ),
      },
      {
        field: "criticality",
        headerName: "Criticality level",
        width: 140,
        sortable: false,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <ResultsRiskChip value={params.row.criticality} />
        ),
      },
      {
        field: "confidentiality",
        headerName: "Confidentiality",
        width: 130,
        sortable: false,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <ResultsRiskChip value={params.row.confidentiality} />
        ),
      },
      {
        field: "integrity",
        headerName: "Integrity",
        width: 120,
        sortable: false,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <ResultsRiskChip value={params.row.integrity} />
        ),
      },
      {
        field: "availability",
        headerName: "Availability",
        width: 130,
        sortable: false,
        renderCell: (params: GridRenderCellParams<AssetResultRow>) => (
          <ResultsRiskChip value={params.row.availability} />
        ),
      },
    ],
    [],
  );

  return (
    <Box sx={{ width: "100%" }}>
      <DataGridPro
        rows={rows}
        columns={columns}
        autoHeight
        disableRowSelectionOnClick
        pinnedColumns={{ left: ["name"] }}
        pinnedColumnsSectionSeparator="border"
        getRowId={(r) => r.id}
        hideFooter
        slotProps={{
          main: { "aria-label": "Assets in this assessment" },
        }}
        sx={({ tokens: t }) => ({
          border: "none",
          borderRadius: t.semantic.radius.md.value,
          "& .MuiDataGrid-scrollShadow": { display: "none" },
          "& .MuiDataGrid-columnHeader, & .MuiDataGrid-cell": { boxShadow: "none" },
          "& .MuiDataGrid-columnHeaders": {
            backgroundColor: t.semantic.color.background.container.value,
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
  );
}

export default function AssessmentResultsTab({
  includedAssetIds,
  excludedScopeCyberRiskIds,
  excludedScopeScenarioIds = new Set(),
  scenarioScopeAssessmentId,
  onGoToScoring,
  assessmentName = "",
  returnToAssessmentPath = "",
  assessmentPhase,
  scoringType,
  aiScoringPhase,
  aggregationMethod,
  isNewCraDraftFlow = false,
  scenarioCatalogScoresReleased = true,
  scenarioManuallyRevealedScoreIds = EMPTY_MANUAL_REVEAL_IDS,
  scenarioNotApplicableIds = EMPTY_SCENARIO_NOT_APPLICABLE_IDS,
}: {
  includedAssetIds: Set<string>;
  excludedScopeCyberRiskIds: Set<string>;
  excludedScopeScenarioIds?: Set<string>;
  /** When set, only scenarios for this CRA (or untagged seed scenarios) appear in Results. */
  scenarioScopeAssessmentId?: string;
  onGoToScoring: () => void;
  /** Matches {@link AssessmentScoringTab} — used when navigating to scenario read-only rationale. */
  assessmentName?: string;
  returnToAssessmentPath?: string;
  assessmentPhase: AssessmentPhase;
  scoringType: CraScoringTypeChoice;
  aiScoringPhase: AiScoringPhase;
  /** Same source as {@link AssessmentScoringTab} aggregation radios (read-only display on Results). */
  aggregationMethod: CraScenarioScoreAggregationMethod;
  /** When true, apply the same scenario catalog score masking as {@link AssessmentScoringTab}. */
  isNewCraDraftFlow?: boolean;
  scenarioCatalogScoresReleased?: boolean;
  scenarioManuallyRevealedScoreIds?: ReadonlySet<string>;
  scenarioNotApplicableIds?: ReadonlySet<string>;
}) {
  const navigate = useNavigate();

  const goToScenarioReadOnly = useCallback(
    (scenarioId: string) => {
      navigate(scenarioRationaleReadOnlyPath(scenarioId), {
        state: {
          assessmentName: assessmentName.trim() || undefined,
          scoringType,
          aiScoringPhase,
          returnToAssessmentPath: returnToAssessmentPath.trim() || undefined,
          craReturnToTabIndex: NEW_CRA_RESULTS_TAB_INDEX,
          fromNewCraDraft: false,
          scenarioCatalogScoresReleased: true,
          scenarioManuallyRevealedScoreIds: [],
        },
      });
    },
    [navigate, assessmentName, scoringType, aiScoringPhase, returnToAssessmentPath],
  );

  const onScenarioRowClick =
    assessmentPhase === "assessmentApproved" ? goToScenarioReadOnly : undefined;

  const catalogMaskParams: AssessmentResultsCatalogMaskParams = useMemo(
    () => ({
      assessmentPhase,
      aiScoringPhase,
      isNewCraDraftFlow,
      scenarioCatalogScoresReleased,
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

  const scenarioListInScope = useMemo(
    () =>
      assessmentScopedScenarios(
        includedAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeScenarioIds,
        scenarioScopeAssessmentId,
      ),
    [includedAssetIds, excludedScopeCyberRiskIds, excludedScopeScenarioIds, scenarioScopeAssessmentId],
  );

  const scenariosByRiskId = useMemo(() => {
    const m = new Map<string, (typeof scenarioListInScope)[number][]>();
    for (const s of scenarioListInScope) {
      const list = m.get(s.cyberRiskId) ?? [];
      list.push(s);
      m.set(s.cyberRiskId, list);
    }
    return m;
  }, [scenarioListInScope]);

  const scenariosByAssetId = useMemo(() => {
    const m = new Map<string, (typeof scenarioListInScope)[number][]>();
    for (const s of scenarioListInScope) {
      const list = m.get(s.assetId) ?? [];
      list.push(s);
      m.set(s.assetId, list);
    }
    return m;
  }, [scenarioListInScope]);

  const cyberResultRows = useMemo(() => {
    const raw = buildCyberResultsRowsForScope(
      includedAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeScenarioIds,
      scenarioScopeAssessmentId,
    );
    const risks = assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds);
    const risksById = new Map(risks.map((r) => [r.id, r] as const));
    return applyNewCraCatalogScoreMaskingToCyberResultsRows(raw, risksById, scenariosByRiskId, catalogMaskParams);
  }, [
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
    scenariosByRiskId,
    catalogMaskParams,
  ]);

  const assetResultRows = useMemo(() => {
    const raw = buildAssetResultRowsForScope(
      includedAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeScenarioIds,
      scenarioScopeAssessmentId,
    );
    return applyNewCraCatalogScoreMaskingToAssetResultsRows(raw, scenariosByAssetId, catalogMaskParams);
  }, [
    includedAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeScenarioIds,
    scenarioScopeAssessmentId,
    scenariosByAssetId,
    catalogMaskParams,
  ]);

  const suppressScenarioDerivedOverview = assessmentResultsHasHiddenScenarioScores(
    scenarioListInScope,
    catalogMaskParams,
  );
  const relatedAssetNames = useMemo(
    () => assets.filter((a) => includedAssetIds.has(a.id)).map((a) => a.name),
    [includedAssetIds],
  );

  const [cyberSectionExpanded, setCyberSectionExpanded] = useState(true);
  const [assetsSectionExpanded, setAssetsSectionExpanded] = useState(true);

  const [sideSheetOpen, setSideSheetOpen] = useState(false);
  const [sideSheetCyberRiskName, setSideSheetCyberRiskName] = useState("");
  const [cyberResultsFilterOpen, setCyberResultsFilterOpen] = useState(false);
  const [appliedFilterResults, setAppliedFilterResults] = useState<FilterResultsValue>(() =>
    copyFilterResultsValue(EMPTY_FILTER_RESULTS),
  );
  const [draftFilterResults, setDraftFilterResults] = useState<FilterResultsValue>(() =>
    copyFilterResultsValue(EMPTY_FILTER_RESULTS),
  );
  const [heatmapMatrixFilter, setHeatmapMatrixFilter] = useState<CyberRiskMatrixTableFilter | null>(
    null,
  );

  const handleOpenMitigationPlan = useCallback((row: CyberResultsRow) => {
    setSideSheetCyberRiskName(row.name);
    setSideSheetOpen(true);
  }, []);

  const openCyberResultsFilters = useCallback(() => {
    setDraftFilterResults(copyFilterResultsValue(appliedFilterResults));
    setCyberResultsFilterOpen(true);
  }, [appliedFilterResults]);

  const handleCloseCyberResultsFilters = useCallback(() => {
    setDraftFilterResults(copyFilterResultsValue(appliedFilterResults));
    setCyberResultsFilterOpen(false);
  }, [appliedFilterResults]);

  const handleApplyCyberResultsFilters = useCallback(() => {
    setAppliedFilterResults(copyFilterResultsValue(draftFilterResults));
    setCyberResultsFilterOpen(false);
  }, [draftFilterResults]);

  const handleDiscardCyberResultsFilters = useCallback(() => {
    setDraftFilterResults(copyFilterResultsValue(appliedFilterResults));
  }, [appliedFilterResults]);

  const handleClearCyberResultsFilters = useCallback(() => {
    const cleared = copyFilterResultsValue(EMPTY_FILTER_RESULTS);
    setDraftFilterResults(cleared);
    setAppliedFilterResults(cleared);
    setHeatmapMatrixFilter(null);
  }, []);

  const handleToolbarClearCyberResultsFilters = useCallback(() => {
    setAppliedFilterResults(copyFilterResultsValue(EMPTY_FILTER_RESULTS));
    setDraftFilterResults(copyFilterResultsValue(EMPTY_FILTER_RESULTS));
    setHeatmapMatrixFilter(null);
  }, []);

  const filterCriteriaCount =
    countFilterResultsCriteria(appliedFilterResults) + (heatmapMatrixFilter != null ? 1 : 0);

  const scopedCyberRisks = useMemo(
    () => assessmentScopedCyberRisks(includedAssetIds, excludedScopeCyberRiskIds),
    [includedAssetIds, excludedScopeCyberRiskIds],
  );

  const cyberRiskById = useMemo(
    () => new Map(scopedCyberRisks.map((r) => [r.id, r] as const)),
    [scopedCyberRisks],
  );

  const handleMatrixSelectionForResultsTable = useCallback((p: MatrixSelectionPayload) => {
    if (p.kind === "cell" && p.rowIdx != null && p.colIdx != null) {
      setHeatmapMatrixFilter({
        kind: "cell",
        basis: p.basis,
        rowIdx: p.rowIdx,
        colIdx: p.colIdx,
      });
      return;
    }
    if (p.kind === "legend" && p.level != null) {
      setHeatmapMatrixFilter({ kind: "legend", basis: p.basis, level: p.level });
    }
  }, []);

  const filteredCyberResultRows = useMemo(() => {
    const afterSheet = filterAssessmentCyberResultsRows(cyberResultRows, appliedFilterResults);
    return filterAssessmentCyberResultsByMatrixFilter(
      afterSheet,
      heatmapMatrixFilter,
      cyberRiskById,
    );
  }, [cyberResultRows, appliedFilterResults, heatmapMatrixFilter, cyberRiskById]);

  if (includedAssetIds.size === 0) {
    return (
      <Stack sx={{ pt: 3, pb: 4, width: "100%" }}>
        <AssessmentScopeEmptyState variant="results" onPrimaryAction={onGoToScoring} />
      </Stack>
    );
  }

  return (
    <Stack gap={6} sx={{ pt: 3, pb: 4, width: "100%" }}>
      <ScoringInfoCardRead
        aggregationMethod={aggregationMethod}
        aggregationMethodRadio={{ name: "cra-results-tab-aggregation" }}
      />
      <ResultsHero
        scopedRisks={scopedCyberRisks}
        assetResultRows={assetResultRows}
        scoringType={scoringType}
        onMatrixSelection={handleMatrixSelectionForResultsTable}
        suppressScenarioDerivedOverview={suppressScenarioDerivedOverview}
      />

      <SectionHeader
        title="Cyber risks"
        headingLevel="h2"
        isExpandable
        isExpanded={cyberSectionExpanded}
        expandButtonAriaLabel={cyberSectionExpanded ? "Collapse cyber risks section" : "Expand cyber risks section"}
        onExpand={() => setCyberSectionExpanded(true)}
        onCollapse={() => setCyberSectionExpanded(false)}
      >
        {cyberSectionExpanded ? (
          <ResultsTreeData
            rows={filteredCyberResultRows}
            onOpenMitigationPlan={handleOpenMitigationPlan}
            onScenarioRowClick={onScenarioRowClick}
            onOpenFilters={openCyberResultsFilters}
            filterCriteriaCount={filterCriteriaCount}
            onClearFilters={handleToolbarClearCyberResultsFilters}
          />
        ) : null}
      </SectionHeader>

      <SectionHeader
        title="Assets"
        headingLevel="h2"
        isExpandable
        isExpanded={assetsSectionExpanded}
        expandButtonAriaLabel={assetsSectionExpanded ? "Collapse assets section" : "Expand assets section"}
        onExpand={() => setAssetsSectionExpanded(true)}
        onCollapse={() => setAssetsSectionExpanded(false)}
      >
        {assetsSectionExpanded ? <AssetsResultsGrid rows={assetResultRows} /> : null}
      </SectionHeader>

      <MitigationPlanPageSideSheet
        open={sideSheetOpen}
        onClose={() => setSideSheetOpen(false)}
        cyberRiskName={sideSheetCyberRiskName}
        relatedAssetNames={relatedAssetNames}
      />

      <FilterSideSheet
        open={cyberResultsFilterOpen}
        onClose={handleCloseCyberResultsFilters}
        onApply={handleApplyCyberResultsFilters}
        onDiscard={handleDiscardCyberResultsFilters}
        onClear={handleClearCyberResultsFilters}
        hasDraftFilterSelection={!filterResultsValueEquals(draftFilterResults, appliedFilterResults)}
        hasClearableFilterState={filterCriteriaCount > 0}
        title="Filters"
        titleId="cra-results-filter-side-sheet-title"
        contentAriaLabel="Cyber risks results filters"
      >
        <FilterResults
          value={draftFilterResults}
          onChange={setDraftFilterResults}
          boundedRows={cyberResultRows}
        />
      </FilterSideSheet>
    </Stack>
  );
}
