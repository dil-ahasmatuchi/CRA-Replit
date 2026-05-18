import { replaceAssetsFromPersistence } from "../assets.js";
import { replaceOrgUnitsFromPersistence } from "../orgUnits.js";
import { replaceControlsFromPersistence } from "../controls.js";
import { replaceCyberRisksFromPersistence } from "../cyberRisks.js";
import { replaceMitigationPlansFromPersistence } from "../mitigationPlans.js";
import { sanitizeCraNewAssessmentDraft } from "../../pages/craNewAssessmentDraftStorage.js";
import {
  hydratePersistedCraDraft,
  loadRawCatalogJson,
  loadRawCatalogJsonAsync,
  parsePersistedCatalog,
} from "./catalogStore.js";
import { replaceRiskAssessmentsFromPersistence } from "../riskAssessments.js";
import {
  rebuildScenariosFromGraph,
  refreshScenarioScaleLabelsFromConfig,
  replaceScenariosFromPersistence,
  setScenarioOverridesFromPersistence,
} from "../scenarios.js";
import { replaceThreatsFromPersistence } from "../threats.js";
import {
  bandsFullyValid,
  setActiveCyberRiskScoreBands,
  setActiveLikelihoodBands,
  type ScoringBandRow,
} from "../cyberRiskScoringScales.js";
import { refreshAllCyberRiskScaleLabelsFromConfig } from "../cyberRisks.js";
import { replaceUsersFromPersistence } from "../users.js";
import { replaceVulnerabilitiesFromPersistence } from "../vulnerabilities.js";
import { rebuildObjectivesFromCurrentCatalog } from "../objectives.js";
import { rebuildProcessesFromCurrentCatalog } from "../processes.js";

import type { PersistedCatalog, PersistedCatalogV3 } from "./catalogTypes.js";

function applyPersistedScoringBands(catalog: PersistedCatalog): void {
  const { cyberScoreBands, likelihoodBands } = catalog;
  if (
    Array.isArray(cyberScoreBands) &&
    cyberScoreBands.length === 5 &&
    bandsFullyValid(cyberScoreBands as ScoringBandRow[])
  ) {
    setActiveCyberRiskScoreBands(cyberScoreBands as ScoringBandRow[]);
  }
  if (
    Array.isArray(likelihoodBands) &&
    likelihoodBands.length === 5 &&
    bandsFullyValid(likelihoodBands as ScoringBandRow[])
  ) {
    setActiveLikelihoodBands(likelihoodBands as ScoringBandRow[]);
  }
}

export function applyPersistedCatalog(catalog: PersistedCatalog): void {
  if (!catalog) return;
  if (catalog.schemaVersion !== 2 && catalog.schemaVersion !== 3) return;
  if (!Array.isArray(catalog.users) || !Array.isArray(catalog.threats)) return;

  applyPersistedScoringBands(catalog);

  replaceUsersFromPersistence(catalog.users);
  replaceOrgUnitsFromPersistence(catalog.orgUnits);
  replaceAssetsFromPersistence(catalog.assets);
  replaceVulnerabilitiesFromPersistence(catalog.vulnerabilities);
  replaceThreatsFromPersistence(catalog.threats);
  replaceControlsFromPersistence(catalog.controls);
  replaceMitigationPlansFromPersistence(catalog.mitigationPlans);
  replaceCyberRisksFromPersistence(catalog.cyberRisks);
  setScenarioOverridesFromPersistence(catalog.scenarioOverrides);
  if (
    catalog.schemaVersion === 3 &&
    Array.isArray((catalog as PersistedCatalogV3).scenarios) &&
    (catalog as PersistedCatalogV3).scenarios.length > 0
  ) {
    replaceScenariosFromPersistence((catalog as PersistedCatalogV3).scenarios);
  } else {
    rebuildScenariosFromGraph();
  }
  replaceRiskAssessmentsFromPersistence(catalog.riskAssessments);
  hydratePersistedCraDraft(
    catalog.craDraft != null ? sanitizeCraNewAssessmentDraft(catalog.craDraft) : null,
  );

  refreshAllCyberRiskScaleLabelsFromConfig();
  refreshScenarioScaleLabelsFromConfig();
  rebuildObjectivesFromCurrentCatalog();
  rebuildProcessesFromCurrentCatalog();
}


/** Like {@link applyCatalogFromStorage} but applies `fallback` when no valid persisted blob exists. */
export async function applyCatalogFromStorageWithFallback(fallback: PersistedCatalog): Promise<void> {
  let json = loadRawCatalogJson();
  if (!json) {
    json = await loadRawCatalogJsonAsync();
  }
  const catalog = json ? parsePersistedCatalog(json) : null;
  if (catalog) applyPersistedCatalog(catalog);
  else applyPersistedCatalog(fallback);
}


export async function applyCatalogFromStorage(): Promise<void> {
  let json = loadRawCatalogJson();
  if (!json) {
    json = await loadRawCatalogJsonAsync();
  }
  if (!json) return;
  const catalog = parsePersistedCatalog(json);
  if (!catalog) return;
  applyPersistedCatalog(catalog);
}
