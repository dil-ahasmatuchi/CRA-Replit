import { assets } from "../assets.js";
import { orgUnits } from "../orgUnits.js";
import { controls } from "../controls.js";
import { cyberRisks } from "../cyberRisks.js";
import { mitigationPlans } from "../mitigationPlans.js";
import { riskAssessments } from "../riskAssessments.js";
import {
  getScenarioOverridesForPersistence,
  getScenariosForPersistence,
} from "../scenarios.js";
import { threats } from "../threats.js";
import { users } from "../users.js";
import { vulnerabilities } from "../vulnerabilities.js";
import {
  getActiveCyberRiskScoreBands,
  getActiveLikelihoodBands,
} from "../cyberRiskScoringScales.js";
import { getPersistedCraDraft } from "./catalogStore.js";
import type { PersistedCatalogV3 } from "./catalogTypes.js";

function cloneJson<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

/** Builds a full catalog snapshot for localStorage / IndexedDB. */
export function buildPersistedCatalogSnapshot(): PersistedCatalogV3 {
  return {
    schemaVersion: 3,
    users: cloneJson(users),
    orgUnits: cloneJson(orgUnits),
    assets: cloneJson(assets),
    vulnerabilities: cloneJson(vulnerabilities),
    threats: cloneJson(threats),
    controls: cloneJson(controls),
    mitigationPlans: cloneJson(mitigationPlans),
    cyberRisks: cloneJson(cyberRisks),
    riskAssessments: cloneJson(riskAssessments),
    scenarios: cloneJson(getScenariosForPersistence()),
    scenarioOverrides: cloneJson(getScenarioOverridesForPersistence()),
    craDraft: (() => {
      const d = getPersistedCraDraft();
      return d ? cloneJson(d) : null;
    })(),
    cyberScoreBands: cloneJson([...getActiveCyberRiskScoreBands()]),
    likelihoodBands: cloneJson([...getActiveLikelihoodBands()]),
  };
}
