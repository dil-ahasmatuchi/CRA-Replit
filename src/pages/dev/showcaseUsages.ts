export type ShowcaseUsage = {
  usedInPages: { label: string; path: string }[];
  usedInComponents: string[];
};

/** Curated “where used” metadata (prototype; extend as needed). */
export const SHOWCASE_USAGES: Record<string, ShowcaseUsage> = {
  "ai-banner": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "ai-card": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "aggregation-method-radio": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["RadioButtonArray"],
  },
  "assessment-detail-header": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [
      "AssessmentStatus",
      "MetaTag",
      "StatusDropdown",
    ],
  },
  "assessment-scope-empty-state": {
    usedInPages: [{ label: "Assessment scope tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "assessment-status": {
    usedInPages: [
      { label: "Cyber risk assessments", path: "/cyber-risk/cyber-risk-assessments" },
      { label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" },
    ],
    usedInComponents: ["AssessmentDetailHeader"],
  },
  "assessment-wysiwyg-editor": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "assets-by-cyber-risk-score-donut": {
    usedInPages: [{ label: "Overview", path: "/cyber-risk/overview" }],
    usedInComponents: [],
  },
  "cra-scenario-emphasis-title": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: [],
  },
  "cyber-risk-scoring-scales-content": {
    usedInPages: [{ label: "Cyber risk settings", path: "/settings/cyber-risk-settings" }],
    usedInComponents: [],
  },
  "dropdown-button": {
    usedInPages: [{ label: "Cyber risks", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: [],
  },
  "filter-assets": {
    usedInPages: [{ label: "Assessment scope tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["FilterSideSheet"],
  },
  "filter-results": {
    usedInPages: [{ label: "Assessment results tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "filter-risks": {
    usedInPages: [{ label: "Cyber risks", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: ["FilterSideSheet"],
  },
  "filter-side-sheet": {
    usedInPages: [
      { label: "Cyber risks", path: "/cyber-risk/cyber-risks" },
      { label: "Threats", path: "/cyber-risk/threats" },
      { label: "Vulnerabilities", path: "/cyber-risk/vulnerabilities" },
    ],
    usedInComponents: [],
  },
  "filter-threats": {
    usedInPages: [{ label: "Threats", path: "/cyber-risk/threats" }],
    usedInComponents: ["FilterSideSheet"],
  },
  "history-accordion": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: [],
  },
  "label-score-legend": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "label-value": {
    usedInPages: [{ label: "Cyber risk detail", path: "/cyber-risk/cyber-risks/CR-001" }],
    usedInComponents: [],
  },
  "label-value-md": {
    usedInPages: [{ label: "Cyber risk detail", path: "/cyber-risk/cyber-risks/CR-001" }],
    usedInComponents: [],
  },
  "meta-tag": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["AssessmentDetailHeader"],
  },
  "mitigation-plan-page-side-sheet": {
    usedInPages: [{ label: "Mitigation plans", path: "/cyber-risk/mitigation-plans" }],
    usedInComponents: [],
  },
  "mitigation-plan-status-chip": {
    usedInPages: [{ label: "Mitigation plans", path: "/cyber-risk/mitigation-plans" }],
    usedInComponents: [],
  },
  "new-toolbar": {
    usedInPages: [
      { label: "Cyber risks", path: "/cyber-risk/cyber-risks" },
      { label: "Threats", path: "/cyber-risk/threats" },
    ],
    usedInComponents: [],
  },
  "org-unit-dropdown": {
    usedInPages: [{ label: "Overview", path: "/cyber-risk/overview" }],
    usedInComponents: [],
  },
  "overview-hero": {
    usedInPages: [{ label: "Overview", path: "/cyber-risk/overview" }],
    usedInComponents: ["AssetsByCyberRiskScoreDonut", "RisksMatrix"],
  },
  "page-layout": {
    usedInPages: [{ label: "Risks page layout", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: [],
  },
  "placeholder": {
    usedInPages: [{ label: "Dashboard", path: "/dashboard" }],
    usedInComponents: [],
  },
  "radio-button-array": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["AggregationMethodRadio"],
  },
  "read-only-scoring-legends-row": {
    usedInPages: [{ label: "Rationale read-only", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001/rationale-read-only" }],
    usedInComponents: [],
  },
  "relation-card": {
    usedInPages: [{ label: "Cyber risk detail", path: "/cyber-risk/cyber-risks/CR-001" }],
    usedInComponents: [],
  },
  "relation-linked-object-row": {
    usedInPages: [{ label: "Cyber risk detail", path: "/cyber-risk/cyber-risks/CR-001" }],
    usedInComponents: ["RelationCard"],
  },
  "results-hero": {
    usedInPages: [{ label: "Assessment results tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "results-table": {
    usedInPages: [{ label: "Assessment results tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "risk-detail-header": {
    usedInPages: [{ label: "Cyber risk detail", path: "/cyber-risk/cyber-risks/CR-001" }],
    usedInComponents: [],
  },
  "risk-settings-header": {
    usedInPages: [{ label: "Cyber risk settings", path: "/settings/cyber-risk-settings" }],
    usedInComponents: [],
  },
  "risk-status": {
    usedInPages: [{ label: "Cyber risks table", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: [],
  },
  "risk-status-donut": {
    usedInPages: [{ label: "Risks hero", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: ["RisksHeroSection"],
  },
  "risks-hero-section": {
    usedInPages: [{ label: "Cyber risks", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: ["RiskStatusDonut", "RisksMatrix"],
  },
  "risks-matrix": {
    usedInPages: [
      { label: "Cyber risks", path: "/cyber-risk/cyber-risks" },
      { label: "Overview", path: "/cyber-risk/overview" },
    ],
    usedInComponents: ["RisksHeroSection", "OverviewHero"],
  },
  "risks-table": {
    usedInPages: [{ label: "Cyber risks", path: "/cyber-risk/cyber-risks" }],
    usedInComponents: ["RiskStatus"],
  },
  "scoped-risk-ss": {
    usedInPages: [{ label: "Assessment scope tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "scenario-history-read-only-panel": {
    usedInPages: [{ label: "Rationale read-only", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001/rationale-read-only" }],
    usedInComponents: [],
  },
  "scenario-history-section": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: [],
  },
  "scenario-scoring-dropdowns-block": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScoringMetricField", "ScoringRationaleDropdowns"],
  },
  "scope-card": {
    usedInPages: [{ label: "Assessment scope tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "scope-toolbar": {
    usedInPages: [{ label: "Assessment scope tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "scroll-to-top": {
    usedInPages: [{ label: "App shell", path: "/cyber-risk/overview" }],
    usedInComponents: [],
  },
  "scoring-formulas": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "scoring-formulas-wide": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScoringWide"],
  },
  "scoring-info": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["ScoringScaleInfo"],
  },
  "scoring-info-card": {
    usedInPages: [
      { label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" },
      { label: "Activity (preview)", path: "/activity" },
    ],
    usedInComponents: ["ScoringInfo"],
  },
  "scoring-info-card-read": {
    usedInPages: [],
    usedInComponents: ["ScoringInfoCardRead"],
  },
  "scoring-loading": {
    usedInPages: [
      { label: "Assessment Results Tab", path: "/assessments/:id/results" },
    ],
    usedInComponents: ["ScoringStatusBar"],
  },
  "scoring-metric-field": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScenarioScoringDropdownsBlock"],
  },
  "scoring-rationale-dropdowns": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScenarioScoringDropdownsBlock"],
  },
  "scoring-rationale-formatted-body": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: [],
  },
  "scoring-rationale-header": {
    usedInPages: [
      { label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" },
      { label: "Rationale read-only", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001/rationale-read-only" },
    ],
    usedInComponents: [],
  },
  "scoring-scale-bar": {
    usedInPages: [{ label: "Cyber risk settings", path: "/settings/cyber-risk-settings" }],
    usedInComponents: ["ScoringScaleSection"],
  },
  "scoring-scale-card": {
    usedInPages: [{ label: "Cyber risk settings", path: "/settings/cyber-risk-settings" }],
    usedInComponents: ["ScoringScaleSection"],
  },
  "scoring-scale-info": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["ScoringScaleWide"],
  },
  "scoring-scale-section": {
    usedInPages: [{ label: "Cyber risk settings", path: "/settings/cyber-risk-settings" }],
    usedInComponents: ["ScoringScaleCard", "ScoringScaleBar"],
  },
  "scoring-scale-wide": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScoringWide", "ScoringScaleInfo"],
  },
  "scoring-table": {
    usedInPages: [{ label: "Assessment scoring tab", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "scoring-wide": {
    usedInPages: [{ label: "Scoring rationale", path: "/cyber-risk/cyber-risk-assessments/new/scenario/SCE-001" }],
    usedInComponents: ["ScoringFormulasWide", "ScoringScaleWide"],
  },
  "status-dropdown": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: ["AssessmentDetailHeader"],
  },
  "threat-detail-assessments-tab": {
    usedInPages: [{ label: "Threat detail", path: "/cyber-risk/threats/THR-001" }],
    usedInComponents: ["AssessmentStatus"],
  },
  "threat-detail-header": {
    usedInPages: [{ label: "Threat detail", path: "/cyber-risk/threats/THR-001" }],
    usedInComponents: [],
  },
  "unsaved-changes-dialog": {
    usedInPages: [{ label: "Assessment details", path: "/cyber-risk/cyber-risk-assessments/new" }],
    usedInComponents: [],
  },
  "vulnerability-detail-header": {
    usedInPages: [{ label: "Vulnerability detail", path: "/cyber-risk/vulnerabilities/VUL-001" }],
    usedInComponents: [],
  },
};

export function usageForSlug(slug: string): ShowcaseUsage {
  return SHOWCASE_USAGES[slug] ?? { usedInPages: [], usedInComponents: [] };
}
