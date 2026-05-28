// Types & utilities
export type {
  FivePointScaleValue,
  FivePointScaleLabel,
  CyberRiskStatus,
  AssessmentStatus,
  ControlStatus,
  ThreatStatus,
  VulnerabilityStatus,
  MitigationPlanStatus,
  AssetStatus,
  ControlType,
  ControlFrequency,
  ThreatSource,
  ThreatActor,
  ThreatAttackVector,
  ThreatDomain,
  MockThreatAttachment,
  VulnerabilityDomain,
  VulnerabilityType,
  CIAImpact,
  AssetType,
  MockUser,
  MockOrgUnit,
  MockAsset,
  MockAssetRelationships,
  MockThreat,
  MockThreatRelationships,
  MockVulnerability,
  MockVulnerabilityRelationships,
  MockControl,
  MockCyberRisk,
  MockCyberRiskRelationships,
  MockScenario,
  MockScenarioRelationships,
  MockCyberRiskAssessment,
  MockMitigationPlan,
  MockObjective,
  MockObjectiveRelationships,
  MockProcess,
  MockProcessRelationships,
} from "./types.js";

export {
  getFivePointLabel,
  getLikelihoodLabel,
  getLikelihoodRange,
  getCyberRiskScoreLabel,
  getCyberRiskScoreRange,
  fivePointLabelToRag,
  padId,
  THREAT_SOURCE_OPTION_DETAILS,
  THREAT_ACTOR_OPTIONS,
  THREAT_ATTACK_VECTOR_OPTIONS,
  VULNERABILITY_TYPE_OPTIONS,
} from "./types.js";

export {
  ASSESSMENT_STATUS_LABELS,
  assessmentStatusLabel,
  assessmentStatusFromDisplayLabel,
} from "./assessmentStatusLabels.js";

// Data collections & lookup helpers
export { users, getUserById } from "./users.js";
export { orgUnits, getOrgUnitById } from "./orgUnits.js";
export { assets, getAssetById } from "./assets.js";
export {
  threats,
  getThreatById,
  remapThreatIdFromLegacySequential,
  addThreat,
  updateThreat,
  replaceThreatsFromPersistence,
  subscribeThreats,
  getThreatsSnapshotVersion,
} from "./threats.js";
export {
  vulnerabilities,
  getVulnerabilityById,
  isVulnerabilityActiveForAssessment,
} from "./vulnerabilities.js";
export { controls, getControlById } from "./controls.js";
export {
  cyberRisks,
  getCyberRiskById,
  findCyberRiskByExactName,
  linkMitigationPlanToCyberRisks,
  unlinkMitigationPlanFromCyberRisks,
} from "./cyberRisks.js";
export {
  scenarios,
  getScenarioById,
  patchScenario,
  rebuildScenariosFromGraph,
  getScenarioOverridesForPersistence,
  buildScenarioFromGraph,
  stableSeveritySeqFromTuple,
  applyScenariosGraphRelinks,
  deleteScenarioOverridesForIds,
} from "./scenarios.js";
export { syncAssessmentOwnedScenarios } from "./assessmentScenarioSync.js";
export { applyApprovedAssessmentCyberRiskWriteback } from "./applyApprovedAssessmentCyberRiskWriteback.js";
export type { ApplyApprovedAssessmentCyberRiskWritebackArgs } from "./applyApprovedAssessmentCyberRiskWriteback.js";
export {
  riskAssessments,
  getRiskAssessmentById,
  getRiskAssessmentsForThreatId,
  addRiskAssessment,
  allocateNextCraId,
  updateRiskAssessment,
  computeAssessmentRollupForAssetIds,
  replaceRiskAssessmentsFromPersistence,
  subscribeRiskAssessments,
  getRiskAssessmentsSnapshotVersion,
} from "./riskAssessments.js";
export {
  mitigationPlans,
  getMitigationPlanById,
  createMitigationPlan,
  updateMitigationPlan,
  deleteMitigationPlan,
  mitigationPlanSortTimeMs,
  type CreateMitigationPlanInput,
  type UpdateMitigationPlanInput,
} from "./mitigationPlans.js";
export { objectives, getObjectiveById } from "./objectives.js";
export { processes, getProcessById } from "./processes.js";

export type {
  CraNewAssessmentPersistedDraft,
  CraScenarioScoreAggregationMethod,
} from "./craAssessmentDraftTypes.js";

export {
  markCatalogDirty,
  subscribeCatalog,
  getCatalogSnapshotVersion,
  touchCatalogForImmediateUiRefresh,
  resetPrototypeCatalog,
  resetPrototypeCatalogAsync,
} from "./persistence/catalogStore.js";
export { applyPersistedCatalog, applyCatalogFromStorage, applyCatalogFromStorageWithFallback } from "./persistence/applyCatalogSnapshot.js";
export { buildPersistedCatalogSnapshot } from "./persistence/catalogSnapshotBuilder.js";
