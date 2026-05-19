import { useMemo, useState, useSyncExternalStore } from "react";
import { PageHeader, OverflowBreadcrumbs } from "@diligentcorp/atlas-react-bundle";
import FolderIcon from "@diligentcorp/atlas-react-bundle/icons/Folder";
import { Accordion, AccordionDetails, AccordionSummary, Box, Button, Stack, Tab, Tabs, useTheme } from "@mui/material";
import { DataGridPro, type GridColDef } from "@mui/x-data-grid-pro";
import { NavLink, useLocation } from "react-router";

import FilterSideSheet from "../components/FilterSideSheet.js";
import NewToolbar from "../components/NewToolbar.js";
import MitigationPlanPageSideSheet from "../components/MitigationPlanPageSideSheet.js";
import ScopedRiskSS from "../components/ScopedRiskSS.js";
import { useSavedChangesToast } from "../context/SavedChangesToastContext.js";
import LabelScoreLegend from "../components/LabelScoreLegend.js";
import LabelValue from "../components/LabelValue.js";
import PageLayout from "../components/PageLayout.js";
import ScoringInfoCard from "../components/ScoringInfoCard.js";
import ScoringWide from "../components/ScoringWide.js";
import AIBanner from "../components/AIBanner.js";
import RadioButtonArray from "../components/RadioButtonArray.js";
import { ScopeCard } from "../components/ScopeCard.js";
import ScoringScaleInfo from "../components/ScoringScaleInfo.js";
import ScoringFormulas from "../components/ScoringFormulas.js";
import { assets } from "../data/assets.js";
import { cyberRisks } from "../data/cyberRisks.js";
import {
  getCatalogSnapshotVersion,
  subscribeCatalog,
} from "../data/persistence/catalogStore.js";
import {
  atlasPageHeaderNavigationTabsSx,
  atlasPageHeaderTabsSlotProps,
} from "../utils/atlasNavigationTabsSx.js";

function TabPanel({
  children,
  value,
  index,
}: {
  children: React.ReactNode;
  value: number;
  index: number;
}) {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`activity-tabpanel-${index}`}
      aria-labelledby={`activity-tab-${index}`}
    >
      {value === index && children}
    </div>
  );
}

const TAB_LABELS = ["Tab 1", "Tab 2", "Tab 3"] as const;

type ActivityTab3Row = { id: string; label: string };

const ACTIVITY_TAB3_GRID_ROWS: ActivityTab3Row[] = [
  { id: "row-1", label: "Sample activity item A" },
  { id: "row-2", label: "Sample activity item B" },
];

const activityTab3Columns: GridColDef<ActivityTab3Row>[] = [
  { field: "label", headerName: "Label", flex: 1, minWidth: 200 },
];

const AGGREGATION_METHOD_OPTIONS = [
  { value: "highest", label: "Highest" },
  { value: "average", label: "Average" },
  { value: "lowest", label: "Lowest" },
] as const;

export default function ActivityPage() {
  const location = useLocation();
  const { showSuccessToast } = useSavedChangesToast();
  const [activeTab, setActiveTab] = useState(0);
  const [isSideSheetOpen, setIsSideSheetOpen] = useState(false);
  const [isFilterSideSheetOpen, setIsFilterSideSheetOpen] = useState(false);
  const [isScopedRiskSSOpen, setIsScopedRiskSSOpen] = useState(false);
  const [activityTab3Aggregation, setActivityTab3Aggregation] = useState("highest");
  const [activityTab3ViewMode, setActivityTab3ViewMode] = useState("list");
  const [activityTab3Pairing, setActivityTab3Pairing] = useState("independent");
  const { presets } = useTheme();
  const { TabsPresets, AccordionPresets } = presets;
  const CardHeaderIcon = presets.CardComponentsPresets?.components?.CardHeaderIcon;
  const scopeCardIcon = CardHeaderIcon ? (
    <CardHeaderIcon icon={<FolderIcon size="lg" aria-hidden />} />
  ) : (
    <FolderIcon size="lg" aria-hidden />
  );

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    () => 0,
  );

  const mitigationPlanDemoAssetOptions = useMemo(
    () =>
      [...assets]
        .slice(0, 5)
        .map((a) => ({ id: a.id, label: a.name }))
        .sort((a, b) => a.label.localeCompare(b.label)),
    [catalogVersion],
  );

  const breadcrumbItems = [
    {
      id: "current",
      label: "Activity",
      url: location.pathname,
    },
  ];

  return (
    <PageLayout>
      <Stack gap={0} sx={{ width: "100%", alignSelf: "stretch", minWidth: 0 }}>
        <PageHeader
          pageTitle="Activity"
          breadcrumbs={
            <OverflowBreadcrumbs
              leadingElement={<span>Asset Manager</span>}
              items={breadcrumbItems}
              hideLastItem={true}
              aria-label="Breadcrumbs"
            >
              {({ label, url }) => <NavLink to={url}>{label}</NavLink>}
            </OverflowBreadcrumbs>
          }
        />

        <Tabs
          value={activeTab}
          onChange={handleTabChange}
          className="atlas-size-large"
          aria-label="Activity tabs"
          {...TabsPresets.Tabs.alignToPageHeader}
          slotProps={atlasPageHeaderTabsSlotProps}
          sx={{
            ...(TabsPresets.Tabs.alignToPageHeader?.sx as Record<string, unknown> | undefined),
            ...atlasPageHeaderNavigationTabsSx,
          }}
        >
          {TAB_LABELS.map((label, index) => (
            <Tab
              key={label}
              label={label}
              id={`activity-tab-${index}`}
              aria-controls={`activity-tabpanel-${index}`}
            />
          ))}
        </Tabs>

        <TabPanel value={activeTab} index={0}>
          <Box sx={{ py: 2, width: "100%" }}>
            <Stack
              sx={({ tokens: t }) => ({
                width: "100%",
                alignItems: "stretch",
                gap: t.core.spacing["3"].value,
              })}
            >
              <Stack
                direction="row"
                sx={({ tokens: t }) => ({
                  width: "100%",
                  alignItems: "center",
                  gap: t.core.spacing["3"].value,
                })}
              >
                <Button variant="contained" onClick={() => setIsSideSheetOpen(true)}>
                  + Mitigation plan
                </Button>
                <Button variant="outlined" onClick={() => setIsScopedRiskSSOpen(true)}>
                  Scoped risk details
                </Button>
              </Stack>
              <ScoringInfoCard
                aggregationMethodRadio={{ name: "activity-tab1-aggregation" }}
                onAction={() => {}}
              />
              <ScoringWide />
            </Stack>
          </Box>
        </TabPanel>

        <MitigationPlanPageSideSheet
          open={isSideSheetOpen}
          onClose={() => setIsSideSheetOpen(false)}
          cyberRiskName={cyberRisks[0]?.name ?? ""}
          assetOptions={mitigationPlanDemoAssetOptions}
          onMitigationPlanCreated={() =>
            showSuccessToast("Mitigation plan created successfully.")
          }
        />

        <FilterSideSheet
          open={isFilterSideSheetOpen}
          onClose={() => setIsFilterSideSheetOpen(false)}
          onApply={() => setIsFilterSideSheetOpen(false)}
        />

        <ScopedRiskSS
          open={isScopedRiskSSOpen}
          onClose={() => setIsScopedRiskSSOpen(false)}
          cyberRisks={cyberRisks[0] != null ? [cyberRisks[0]] : []}
        />
        <TabPanel value={activeTab} index={1}>
          <Box sx={{ py: 2, width: "100%" }}>
            <Stack
              sx={({ tokens: t }) => ({
                width: "100%",
                alignItems: "stretch",
                gap: t.core.spacing["3"].value,
              })}
            >
              <ScopeCard
                title="Assets"
                icon={scopeCardIcon}
                includedCount={0}
                totalCount={assets.length}
                countNoun="Assets"
                cardActionAriaLabel="Empty variant: no assets included (activity preview)"
              />
              <ScopeCard
                title="Assets"
                icon={scopeCardIcon}
                includedCount={12}
                totalCount={assets.length}
                countNoun="Assets"
                cardActionAriaLabel="Filled variant: assets included (activity preview)"
              />
              <AIBanner onAction={() => {}} />
              <ScoringScaleInfo />
              <ScoringFormulas />
              <Accordion defaultExpanded={false}>
                <AccordionSummary
                  aria-controls="activity-tab2-accordion-content"
                  id="activity-tab2-accordion-header"
                >
                  <AccordionPresets.components.Header
                    titleTextProps={{
                      text: "Accordion Title",
                      variant: "h4",
                      component: "h3",
                    }}
                    subtitleText="Expandable section for activity details"
                  />
                </AccordionSummary>
                <AccordionDetails>
                  <Box sx={{ p: 2 }}>
                    This is a placeholder text for the accordion content.
                  </Box>
                </AccordionDetails>
              </Accordion>
            </Stack>
          </Box>
        </TabPanel>
        <TabPanel value={activeTab} index={2}>
          <Box sx={{ py: 2, width: "100%" }}>
            <Box sx={{ width: "100%", mb: 2 }}>
              <DataGridPro
                rows={ACTIVITY_TAB3_GRID_ROWS}
                columns={activityTab3Columns}
                disableRowSelectionOnClick
                hideFooter
                showToolbar
                slots={{
                  toolbar: () => (
                    <NewToolbar onOpenFilters={() => setIsFilterSideSheetOpen(true)} />
                  ),
                }}
                slotProps={{
                  main: {
                    "aria-label":
                      "Activity tab 3 preview table. Column headers contain action menus.",
                  },
                }}
                sx={{ border: 0 }}
              />
            </Box>
            <Stack
              gap={2}
              sx={({ tokens: t }) => ({
                alignItems: "flex-start",
                width: "100%",
                maxWidth: "100%",
                "& > *": { minWidth: 0 },
                mt: t.core.spacing["1"].value,
              })}
            >
              <RadioButtonArray
                label="Aggregation method"
                options={[...AGGREGATION_METHOD_OPTIONS]}
                value={activityTab3Aggregation}
                onChange={setActivityTab3Aggregation}
                showAction
                showIcon
                showActionText
                actionHref="/settings/cyber-risk-settings"
                actionText="View scoring logic and aggregation details"
              />
              <RadioButtonArray
                label="Layout preview (text only, no icon)"
                options={[
                  { value: "list", label: "List" },
                  { value: "grid", label: "Grid" },
                ]}
                value={activityTab3ViewMode}
                onChange={setActivityTab3ViewMode}
                showAction
                showIcon={false}
                showActionText
                actionHref="#"
                actionText="About layout options"
              />
              <RadioButtonArray
                label="Pairing (radios only, no link)"
                options={[
                  { value: "independent", label: "Independent" },
                  { value: "paired", label: "Paired" },
                ]}
                value={activityTab3Pairing}
                onChange={setActivityTab3Pairing}
                showAction={false}
              />
              <LabelScoreLegend
                label="Risk level"
                value={{ numeric: "4", label: "High", rag: "neg03" }}
              />
              <LabelValue label="Asset ID" value="ASSET-101" />
            </Stack>
          </Box>
        </TabPanel>
      </Stack>
    </PageLayout>
  );
}
