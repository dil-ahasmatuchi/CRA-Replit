// @ts-nocheck — dev showcase; keep route working while catalog types drift from Atlas bundle.
import { useMemo, useState, type ReactNode } from "react";
import { Box, MenuItem, Stack, Typography } from "@mui/material";

import AIBanner from "../../components/AIBanner.js";
import AICard from "../../components/AICard.js";
import AggregationMethodRadio from "../../components/AggregationMethodRadio.js";
import AssessmentDetailHeader from "../../components/AssessmentDetailHeader.js";
import AssessmentScopeEmptyState from "../../components/AssessmentScopeEmptyState.js";
import AssessmentStatus from "../../components/AssessmentStatus.js";
import AssessmentWysiwygEditor from "../../components/AssessmentWysiwygEditor.js";
import AssetsByCyberRiskScoreDonut from "../../components/AssetsByCyberRiskScoreDonut.js";
import CraScenarioEmphasisTitle from "../../components/CraScenarioEmphasisTitle.js";
import CyberRiskScoringScalesContent from "../../components/CyberRiskScoringScalesContent.js";
import DropdownButton from "../../components/DropdownButton.js";
import FilterAssets from "../../components/FilterAssets.js";
import FilterResults, { EMPTY_FILTER_RESULTS } from "../../components/FilterResults.js";
import FilterRisks from "../../components/FilterRisks.js";
import FilterSideSheet from "../../components/FilterSideSheet.js";
import FilterThreats from "../../components/FilterThreats.js";
import HistoryAccordion from "../../components/HistoryAccordion.js";
import LabelScoreLegend from "../../components/LabelScoreLegend.js";
import LabelValue from "../../components/LabelValue.js";
import LabelValueMd from "../../components/LabelValueMd.js";
import MetaTag from "../../components/MetaTag.js";
import MitigationPlanPageSideSheet from "../../components/MitigationPlanPageSideSheet.js";
import MitigationPlanStatusChip from "../../components/MitigationPlanStatusChip.js";
import NewToolbar from "../../components/NewToolbar.js";
import OrgUnitDropdown, { type OrgUnitOption } from "../../components/OrgUnitDropdown.js";
import OverviewHero from "../../components/OverviewHero.js";
import PageLayout from "../../components/PageLayout.js";
import Placeholder from "../../components/Placeholder.js";
import RadioButtonArray from "../../components/RadioButtonArray.js";
import ReadOnlyScoringLegendsRow from "../../components/ReadOnlyScoringLegendsRow.js";
import { RelationCard } from "../../components/RelationCard.js";
import { RelationLinkedObjectRow } from "../../components/RelationLinkedObjectRow.js";
import ResultsHero from "../../components/ResultsHero.js";
import { ResultsTreeData } from "../../components/ResultsTreeData.js";
import RiskDetailHeader from "../../components/RiskDetailHeader.js";
import RiskSettingsHeader from "../../components/RiskSettingsHeader.js";
import RiskStatus from "../../components/RiskStatus.js";
import RiskStatusDonut from "../../components/RiskStatusDonut.js";
import RisksHeroSection from "../../components/RisksHeroSection.js";
import RisksMatrix from "../../components/RisksMatrix.js";
import RisksTable from "../../components/RisksTable.js";
import ScopedRiskSS from "../../components/ScopedRiskSS.js";
import ScenarioHistoryReadOnlyPanel, {
  buildScenarioHistorySnapshot,
} from "../../components/ScenarioHistoryReadOnlyPanel.js";
import { ScenarioHistorySection } from "../../components/ScenarioHistorySection.js";
import ScenarioScoringDropdownsBlock, {
  type ScenarioScoringInitialScores,
} from "../../components/ScenarioScoringDropdownsBlock.js";
import { ScopeCard } from "../../components/ScopeCard.js";
import ScopeToolbar from "../../components/ScopeToolbar.js";
import ScrollToTop from "../../components/ScrollToTop.js";
import ScoringFormulas from "../../components/ScoringFormulas.js";
import ScoringFormulasWide from "../../components/ScoringFormulasWide.js";
import ScoringInfo from "../../components/ScoringInfo.js";
import ScoringInfoCard from "../../components/ScoringInfoCard.js";
import ScoringInfoCardRead from "../../components/ScoringInfoCardRead.js";
import ScoringMetricField from "../../components/ScoringMetricField.js";
import ScoringRationaleDropdowns from "../../components/ScoringRationaleDropdowns.js";
import ScoringRationaleFormattedBody from "../../components/ScoringRationaleFormattedBody.js";
import ScoringRationaleHeader from "../../components/ScoringRationaleHeader.js";
import ScoringScaleBar, { type ScoringRangeSegment } from "../../components/scoringScales/ScoringScaleBar.js";
import ScoringScaleCard from "../../components/scoringScales/ScoringScaleCard.js";
import ScoringScaleSection from "../../components/scoringScales/ScoringScaleSection.js";
import ScoringScaleWide from "../../components/ScoringScaleWide.js";
import ScoringWide from "../../components/ScoringWide.js";
import ScoringScaleInfo from "../../components/ScoringScaleInfo.js";
import StatusDropdown from "../../components/StatusDropdown.js";
import ThreatDetailAssessmentsTab from "../../components/ThreatDetailAssessmentsTab.js";
import ThreatDetailHeader from "../../components/ThreatDetailHeader.js";
import UnsavedChangesDialog from "../../components/UnsavedChangesDialog.js";
import VulnerabilityDetailHeader from "../../components/VulnerabilityDetailHeader.js";

import { cyberRisks } from "../../data/cyberRisks.js";
import { getScenarioById } from "../../data/scenarios.js";
import { threats } from "../../data/threats.js";
import { vulnerabilities } from "../../data/vulnerabilities.js";
import { assets } from "../../data/assets.js";
import type { ScoringBandRow } from "../../data/cyberRiskScoringScales.js";
import {
  buildAssetResultRowsForScope,
  buildCyberResultsRowsForScope,
} from "../craAssessmentScopeRows.js";
import { assessmentScopedCyberRisks } from "../../data/assessmentScopeRollup.js";
import { buildCyberRiskRows } from "../../utils/cyberRiskTableRows.js";
import { SCORE_OPTIONS } from "../../components/ScoringMetricField.js";

import RiskIcon from "@diligentcorp/atlas-react-bundle/icons/Risk";

const DEMO_SCORES: ScenarioScoringInitialScores = {
  impact: SCORE_OPTIONS[2] ?? null,
  threat: SCORE_OPTIONS[2] ?? null,
  vulnerability: SCORE_OPTIONS[2] ?? null,
  likelihood: SCORE_OPTIONS[3] ?? null,
  cyberRiskScore: SCORE_OPTIONS[3] ?? null,
};

const DEMO_BAR_SEGMENTS: ScoringRangeSegment[] = [
  { bandLabel: "Very low", from: 1, to: 25, rag: "pos05" },
  { bandLabel: "Low", from: 26, to: 50, rag: "pos04" },
  { bandLabel: "Medium", from: 51, to: 75, rag: "neu03" },
  { bandLabel: "High", from: 76, to: 100, rag: "neg03" },
  { bandLabel: "Very high", from: 101, to: 125, rag: "neg05" },
];

const DEMO_BAND_ROW: ScoringBandRow = {
  level: "veryLow",
  name: "Very low",
  from: 1,
  to: 25,
  description: "Prototype band",
  rag: "pos05",
};

function FilterAssetsDemo() {
  const [v, setV] = useState(() => ({
    criticalityLabels: [] as string[],
    assetTypeLabels: [] as string[],
    orgUnitLabels: [] as string[],
  }));
  return <FilterAssets value={v} onChange={setV} />;
}

function FilterRisksDemo() {
  const [v, setV] = useState(() => ({
    statusLabels: [] as string[],
    ownerIds: [] as string[],
    orgUnitLabels: [] as string[],
  }));
  return <FilterRisks value={v} onChange={setV} />;
}

function FilterThreatsDemo() {
  const [v, setV] = useState(() => ({
    statusLabels: [] as string[],
    domainLabels: [] as string[],
    sourceLabels: [] as string[],
    ownerIds: [] as string[],
  }));
  return <FilterThreats value={v} onChange={setV} />;
}

function FilterResultsDemo() {
  const [v, setV] = useState(EMPTY_FILTER_RESULTS);
  return <FilterResults value={v} onChange={setV} />;
}

function OrgUnitDropdownDemo() {
  const opts: OrgUnitOption[] = useMemo(
    () => [
      { id: "ou-1", label: "Chicago — Operations" },
      { id: "ou-2", label: "New York — IT" },
    ],
    [],
  );
  const [val, setVal] = useState<OrgUnitOption | null>(null);
  return <OrgUnitDropdown options={opts} value={val} onChange={setVal} />;
}

function RadioButtonArrayDemo() {
  const [v, setV] = useState("a");
  return (
    <RadioButtonArray
      label="Sample choice"
      name="dev-radio-demo"
      options={[
        { value: "a", label: "Option A" },
        { value: "b", label: "Option B" },
      ]}
      value={v}
      onChange={setV}
    />
  );
}

function RiskSettingsHeaderDemo() {
  const [tab, setTab] = useState(0);
  return <RiskSettingsHeader tab={tab} onTabChange={setTab} />;
}

function RiskDetailHeaderDemo() {
  const risk = cyberRisks[0];
  const [tab, setTab] = useState(0);
  if (!risk) return <Typography>No cyber risks.</Typography>;
  const owner = "Demo user";
  return (
    <RiskDetailHeader
      pageTitle={risk.name}
      riskId={risk.id}
      displayId="—"
      metaNow="5 May 2026"
      createdBy={owner}
      lastUpdatedBy={owner}
      status={risk.status}
      tab={tab}
      onTabChange={setTab}
    />
  );
}

function ThreatDetailHeaderDemo() {
  const threat = threats[0];
  const [tab, setTab] = useState(0);
  const [status, setStatus] = useState(threat?.status ?? "Draft");
  if (!threat) return <Typography>No threats.</Typography>;
  return (
    <ThreatDetailHeader
      pageTitle={threat.name}
      threatId={threat.id}
      displayId={threat.displayId}
      metaNow="5 May 2026"
      createdBy="Demo user"
      status={status}
      onStatusChange={setStatus}
      tab={tab}
      onTabChange={setTab}
    />
  );
}

function VulnerabilityDetailHeaderDemo() {
  const v = vulnerabilities[0];
  const [tab, setTab] = useState(0);
  if (!v) return <Typography>No vulnerabilities.</Typography>;
  const primaryCiaSummary =
    v.primaryCIAImpact.length > 0 ? v.primaryCIAImpact.join(", ") : "—";
  const vulnerabilityTypeLabel = v.vulnerabilityType ?? "—";
  return (
    <VulnerabilityDetailHeader
      pageTitle={v.name}
      metaId={v.id}
      displayId={v.displayId}
      domain={v.domain}
      vulnerabilityTypeLabel={vulnerabilityTypeLabel}
      primaryCiaSummary={primaryCiaSummary}
      ownersLabel="Demo owner"
      metaNow="5 May 2026"
      createdBy="Demo user"
      status={v.status}
      tab={tab}
      onTabChange={setTab}
    />
  );
}

function ScenarioHistorySectionDemo() {
  const scenario = getScenarioById("SCE-001") ?? getScenarioById("SCE-002");
  const snapshot = scenario
    ? buildScenarioHistorySnapshot(scenario, DEMO_SCORES)
    : { scores: DEMO_SCORES, rationaleBody: "Sample rationale." };
  const [expanded, setExpanded] = useState<string | false>("e1");
  return (
    <ScenarioHistorySection
      scenarioId="dev-demo"
      entries={[
        {
          id: "e1",
          owner: "Demo user",
          at: new Date(),
          snapshot,
        },
      ]}
      expandedEntryId={expanded}
      onExpandedEntryChange={setExpanded}
    />
  );
}

function ScoringScaleSectionDemo() {
  const [expanded, setExpanded] = useState(true);
  const [editing, setEditing] = useState(false);
  const [row, setRow] = useState<ScoringBandRow>(DEMO_BAND_ROW);
  return (
    <ScoringScaleSection
      title="Sample scale section"
      sectionId="dev-scale-sec-h"
      detailRegionId="dev-scale-sec-body"
      expanded={expanded}
      onToggleExpanded={() => setExpanded((x) => !x)}
      editing={editing}
      onToggleEdit={() => setEditing((x) => !x)}
      rangeBar={<ScoringScaleBar segments={DEMO_BAR_SEGMENTS} scaleMin={1} scaleMax={125} />}
    >
      <ScoringScaleCard row={row} readOnly={!editing} onChange={(u) => setRow((r) => ({ ...r, ...u }))} />
    </ScoringScaleSection>
  );
}

function StatusDropdownDemo() {
  const opts = ["Draft", "Active", "Archived"] as const;
  return (
    <StatusDropdown
      value="Draft"
      options={[...opts]}
      aria-label="Demo status"
      resolveDotFill={() => "#ccc"}
      renderChip={({ value: v }) => <Typography variant="textSm">{v}</Typography>}
    />
  );
}

function AssessmentDetailHeaderDemo() {
  const [phase, setPhase] = useState<import("../../pages/craNewAssessmentDraftStorage.js").AssessmentPhase>(
    "draft",
  );
  const [tab, setTab] = useState(0);
  return (
    <AssessmentDetailHeader
      assessmentName="Demo assessment"
      assessmentId="DEMO-001"
      dueDate="2026-12-31"
      createdAtDisplay="2026-01-01"
      createdBy="Demo user"
      lastUpdatedAtDisplay="2026-01-02"
      lastUpdatedByDisplay="Demo user"
      assessmentPhase={phase}
      onPhaseChange={setPhase}
      activeTab={tab}
      onActiveTabChange={setTab}
      onScopeSubViewBack={() => {}}
      onScopeDetailDone={() => {}}
      onSave={() => {}}
      onReassess={() => {}}
    />
  );
}

function ResultsHeroDemo() {
  const aid = assets[0]?.id;
  const included = useMemo(() => (aid ? new Set([aid]) : new Set<string>()), [aid]);
  const rows = useMemo(() => buildAssetResultRowsForScope(included, new Set()), [included]);
  const risks = useMemo(() => assessmentScopedCyberRisks(included, new Set()), [included]);
  if (!aid) return <Typography>No assets in mock data.</Typography>;
  return <ResultsHero scopedRisks={risks} assetResultRows={rows} scoringType="residual" />;
}

function ResultsTreeDataDemo() {
  const aid = assets[0]?.id;
  const included = useMemo(() => (aid ? new Set([aid]) : new Set<string>()), [aid]);
  const cyberRows = useMemo(
    () => buildCyberResultsRowsForScope(included, new Set(), new Set()),
    [included],
  );
  if (!aid) return <Typography>No assets in mock data.</Typography>;
  return (
    <Box sx={{ height: 420, width: "100%" }}>
      <ResultsTreeData
        rows={cyberRows}
        onOpenMitigationPlan={() => {}}
        onScenarioRowClick={() => {}}
        onOpenFilters={() => {}}
      />
    </Box>
  );
}

/** Renders the live component preview for a dev showcase slug. */
export function renderShowcaseComponent(slug: string): ReactNode {
  const risk0 = cyberRisks[0];
  const threat0 = threats[0];
  const vuln0 = vulnerabilities[0];
  const scenario0 = getScenarioById("SCE-001");

  switch (slug) {
    case "ai-banner":
      return <AIBanner />;
    case "ai-card":
      return (
        <AICard>
          <Typography variant="body2">Card body</Typography>
        </AICard>
      );
    case "aggregation-method-radio":
      return <AggregationMethodRadio />;
    case "assessment-detail-header":
      return <AssessmentDetailHeaderDemo />;
    case "assessment-scope-empty-state":
      return <AssessmentScopeEmptyState variant="scoring" onPrimaryAction={() => {}} />;
    case "assessment-status":
      return <AssessmentStatus status="Scoring" />;
    case "assessment-wysiwyg-editor":
      return (
        <AssessmentWysiwygEditor
          fieldId="dev-wysiwyg"
          label="Rationale"
          placeholder="Type here…"
          value="Sample text."
          onChange={() => {}}
          aria-label="Rationale editor"
        />
      );
    case "assets-by-cyber-risk-score-donut":
      return <AssetsByCyberRiskScoreDonut segments={[]} />;
    case "cra-scenario-emphasis-title":
      return (
        <CraScenarioEmphasisTitle
          segments={[
            { text: "Scenario ", emphasis: false },
            { text: "SCE-001", emphasis: true },
          ]}
        />
      );
    case "cyber-risk-scoring-scales-content":
      return <CyberRiskScoringScalesContent />;
    case "dropdown-button":
      return (
        <DropdownButton label="Actions">
          <MenuItem>One</MenuItem>
          <MenuItem>Two</MenuItem>
        </DropdownButton>
      );
    case "filter-assets":
      return <FilterAssetsDemo />;
    case "filter-results":
      return <FilterResultsDemo />;
    case "filter-risks":
      return <FilterRisksDemo />;
    case "filter-side-sheet":
      return (
        <FilterSideSheet open onClose={() => {}} title="Filters">
          <Typography variant="body2">Filter content area</Typography>
        </FilterSideSheet>
      );
    case "filter-threats":
      return <FilterThreatsDemo />;
    case "history-accordion":
      return (
        <HistoryAccordion
          panelId="dev-hist"
          title="Owner"
          subtitle="1 Jan 2026 / 12:00:00 pm"
          expanded
          onExpandedChange={() => {}}
        >
          <Typography variant="body2">Details</Typography>
        </HistoryAccordion>
      );
    case "label-score-legend":
      return (
        <LabelScoreLegend
          label="Impact"
          value={{ numeric: "4", label: "High", rag: "neg03" }}
        />
      );
    case "label-value":
      return <LabelValue label="Field" value="Value" />;
    case "label-value-md":
      return <LabelValueMd label="Field" value="Markdown **value**" />;
    case "meta-tag":
      return <MetaTag label="ID" value="CRA-001" />;
    case "mitigation-plan-page-side-sheet":
      return (
        <MitigationPlanPageSideSheet
          open
          onClose={() => {}}
          cyberRiskName={risk0?.name ?? "Sample risk"}
          assetOptions={[]}
        />
      );
    case "mitigation-plan-status-chip":
      return <MitigationPlanStatusChip status="In progress" />;
    case "new-toolbar":
      return (
        <Box sx={{ border: 1, borderColor: "divider", p: 1 }}>
          <NewToolbar showFilterButton={false} />
        </Box>
      );
    case "org-unit-dropdown":
      return <OrgUnitDropdownDemo />;
    case "overview-hero":
      return <OverviewHero />;
    case "page-layout":
      return (
        <PageLayout>
          <Typography>Inside PageLayout</Typography>
        </PageLayout>
      );
    case "placeholder":
      return <Placeholder>Dev placeholder</Placeholder>;
    case "radio-button-array":
      return <RadioButtonArrayDemo />;
    case "read-only-scoring-legends-row":
      return <ReadOnlyScoringLegendsRow scores={DEMO_SCORES} />;
    case "relation-card":
      return (
        <RelationCard
          objectTypeTitle="Cyber risks"
          linkedObjectsNounPhrase="cyber risks"
          icon={<RiskIcon aria-hidden />}
          items={[]}
        />
      );
    case "relation-linked-object-row":
      return (
        <RelationLinkedObjectRow
          title="Linked item"
          subtitle="Subtitle"
          metaLine="Meta"
          href="#"
        />
      );
    case "results-hero":
      return <ResultsHeroDemo />;
    case "results-tree-data":
      return <ResultsTreeDataDemo />;
    case "risk-detail-header":
      return <RiskDetailHeaderDemo />;
    case "risk-settings-header":
      return <RiskSettingsHeaderDemo />;
    case "risk-status":
      return <RiskStatus status="Assessment" />;
    case "risk-status-donut":
      return <RiskStatusDonut draft={2} identification={1} assessment={3} mitigation={1} monitoring={0} />;
    case "risks-hero-section":
      return <RisksHeroSection />;
    case "risks-matrix":
      return (
        <Box sx={{ maxWidth: 720 }}>
          <RisksMatrix risks={cyberRisks} />
        </Box>
      );
    case "risks-table":
      return (
        <Box sx={{ height: 400, width: "100%" }}>
          <RisksTable rows={buildCyberRiskRows()} onOpenFilters={() => {}} />
        </Box>
      );
    case "scoped-risk-ss":
      return <ScopedRiskSS open onClose={() => {}} cyberRisks={cyberRisks.slice(0, 3)} />;
    case "scenario-history-read-only-panel":
      return scenario0 ? (
        <ScenarioHistoryReadOnlyPanel snapshot={buildScenarioHistorySnapshot(scenario0, DEMO_SCORES)} />
      ) : (
        <Typography>No scenario.</Typography>
      );
    case "scenario-history-section":
      return <ScenarioHistorySectionDemo />;
    case "scenario-scoring-dropdowns-block":
      return scenario0 ? (
        <ScenarioScoringDropdownsBlock
          title="Scenario scores"
          initialScores={DEMO_SCORES}
          onAppendScoringRationale={() => {}}
          onScoresChange={() => {}}
        />
      ) : (
        <Typography>No scenario.</Typography>
      );
    case "scope-card":
      return (
        <ScopeCard
          title="Assets"
          icon={<Typography>A</Typography>}
          includedCount={3}
          totalCount={10}
          countNoun="Assets"
        />
      );
    case "scope-toolbar":
      return (
        <Box sx={{ border: 1, borderColor: "divider", p: 1 }}>
          <ScopeToolbar
            view="all"
            onViewChange={() => {}}
            totalCount={10}
            includedCount={3}
            onOpenFilters={() => {}}
          />
        </Box>
      );
    case "scroll-to-top":
      return (
        <Typography variant="body2">
          ScrollToTop has no visible UI; it resets scroll on navigation. It is mounted in the app shell.
        </Typography>
      );
    case "scoring-formulas":
      return <ScoringFormulas />;
    case "scoring-formulas-wide":
      return <ScoringFormulasWide shrinkToContent />;
    case "scoring-info":
      return (
        <Box sx={{ px: 3, width: "100%" }}>
          <ScoringInfo />
        </Box>
      );
    case "scoring-info-card":
      return (
        <ScoringInfoCard
          onAction={() => {}}
          aggregationMethodRadio={{ name: "showcase-scoring-info-card-aggregation" }}
        />
      );
    case "scoring-info-card-read":
      return (
        <ScoringInfoCardRead
          aggregationMethodRadio={{ name: "showcase-scoring-info-card-read-aggregation" }}
        />
      );
    case "scoring-metric-field":
      return (
        <ScoringMetricField
          label="Impact"
          value={DEMO_SCORES.impact}
          onChange={() => {}}
          options={SCORE_OPTIONS}
        />
      );
    case "scoring-rationale-dropdowns":
      return (
        <ScoringRationaleDropdowns
          impact={DEMO_SCORES.impact}
          threat={DEMO_SCORES.threat}
          vulnerability={DEMO_SCORES.vulnerability}
          onImpactChange={() => {}}
          onThreatChange={() => {}}
          onVulnerabilityChange={() => {}}
        />
      );
    case "scoring-rationale-formatted-body":
      return <ScoringRationaleFormattedBody text="**Bold** and _italic_ rationale." />;
    case "scoring-rationale-header":
      return (
        <ScoringRationaleHeader
          scenarioName="Demo scenario"
          scenarioId="SCE-001"
          breadcrumbs={<Typography variant="body2">Breadcrumbs slot</Typography>}
          onBack={() => {}}
          backButtonAriaLabel="Back"
        />
      );
    case "scoring-scale-bar":
      return <ScoringScaleBar segments={DEMO_BAR_SEGMENTS} scaleMin={1} scaleMax={125} />;
    case "scoring-scale-card":
      return <ScoringScaleCard row={DEMO_BAND_ROW} readOnly onChange={() => {}} />;
    case "scoring-scale-info":
      return <ScoringScaleInfo />;
    case "scoring-scale-section":
      return <ScoringScaleSectionDemo />;
    case "scoring-scale-wide":
      return <ScoringScaleWide />;
    case "scoring-wide":
      return <ScoringWide />;
    case "status-dropdown":
      return <StatusDropdownDemo />;
    case "threat-detail-assessments-tab":
      return threat0 ? (
        <Box sx={{ height: 360, width: "100%" }}>
          <ThreatDetailAssessmentsTab threatId={threat0.id} threatAssetIds={threat0.assetIds} />
        </Box>
      ) : (
        <Typography>No threats.</Typography>
      );
    case "threat-detail-header":
      return <ThreatDetailHeaderDemo />;
    case "unsaved-changes-dialog":
      return <UnsavedChangesDialog open onClose={() => {}} onDiscard={() => {}} onSave={() => {}} />;
    case "vulnerability-detail-header":
      return <VulnerabilityDetailHeaderDemo />;
    default:
      return null;
  }
}
