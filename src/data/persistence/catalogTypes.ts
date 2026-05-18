import type { CraNewAssessmentPersistedDraft } from "../craAssessmentDraftTypes.js";
import type { ScoringBandRow } from "../cyberRiskScoringScales.js";
import type {
  MockAsset,
  MockOrgUnit,
  MockControl,
  MockCyberRisk,
  MockCyberRiskAssessment,
  MockMitigationPlan,
  MockScenario,
  MockThreat,
  MockUser,
  MockVulnerability,
} from "../types.js";

/** Persisted catalog blob (localStorage / IndexedDB). */
export type PersistedCatalogV1 = {
  schemaVersion: 2;
  users: MockUser[];
  orgUnits: MockOrgUnit[];
  assets: MockAsset[];
  vulnerabilities: MockVulnerability[];
  threats: MockThreat[];
  controls: MockControl[];
  mitigationPlans: MockMitigationPlan[];
  cyberRisks: MockCyberRisk[];
  riskAssessments: MockCyberRiskAssessment[];
  /** Partial scenario patches keyed by scenario id (baseline comes from regenerated graph). */
  scenarioOverrides: Record<string, Partial<MockScenario>>;
  /** New-assessment draft (replaces sessionStorage-only persistence). */
  craDraft: CraNewAssessmentPersistedDraft | null;
  /** Cyber risk score bands (1–125 → five labels); omitted in older snapshots → defaults. */
  cyberScoreBands?: ScoringBandRow[];
  /** Likelihood product bands (1–25); omitted in older snapshots → defaults. */
  likelihoodBands?: ScoringBandRow[];
};

/**
 * Pooja WAL migration catalog: full scenario rows are supplied and `applyPersistedCatalog` skips graph regeneration.
 */
export type PersistedCatalogV3 = Omit<PersistedCatalogV1, "schemaVersion"> & {
  schemaVersion: 3;
  scenarios: MockScenario[];
};

export type PersistedCatalog = PersistedCatalogV1 | PersistedCatalogV3;

export const CATALOG_STORAGE_KEY = "cra_proto_catalog_v3";

/** Pre–schema-v3 snapshots; cleared with {@link resetCatalogStorage} so older blobs never shadow the bundled catalog. */
export const LEGACY_CATALOG_STORAGE_KEY = "cra_proto_catalog_v2";
