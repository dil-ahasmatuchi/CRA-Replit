/**
 * Tightens Q2 ransomware CRA scope: only specified cyber risks, threats, vulns, scenarios;
 * excludes controls on scoped assets (optional: keep specific control ids in scope for residual).
 * Run: node scripts/narrow-cra029-scope.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.join(__dirname, "../src/data/generated/pooja-migrated-catalog.v3.json");

const CRA_ID = "CRA-029";
const SCOPE_ASSETS = new Set(["AST-001", "AST-002", "AST-017"]);
/** User order: CR-002, CR-010, CR-001 */
const CYBER_RISK_IDS_ORDERED = ["CR-002", "CR-010", "CR-001"];
const ALLOWED_CYBER_RISK_IDS = new Set(CYBER_RISK_IDS_ORDERED);
/** User order */
const THREAT_IDS_ORDERED = ["THR-001", "THR-002", "THR-039", "THR-004", "THR-003"];
const ALLOWED_THREAT_IDS = new Set(THREAT_IDS_ORDERED);
/** User narrative order */
const VULN_IDS_ORDERED = [
  "VUL-004",
  "VUL-013",
  "VUL-011",
  "VUL-002",
  "VUL-008",
  "VUL-028",
  "VUL-030",
];
const ALLOWED_VULN_IDS = new Set(VULN_IDS_ORDERED);

function isVulnActiveForAssessment(v) {
  const st = v.status;
  return st !== "Draft" && st !== "Archived";
}

function sortIds(ids) {
  return [...new Set(ids)].sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
}

/**
 * @param {unknown} catalog
 * @param {{ craId?: string; controlsAlwaysInScopeIds?: ReadonlySet<string> }} [options]
 */
export function computeNarrowScope(catalog, options = {}) {
  const craId = options.craId ?? "CRA-029";
  const controlsAlwaysInScopeIds = options.controlsAlwaysInScopeIds ?? new Set();

  const excludedScopeCyberRiskIds = sortIds(
    catalog.cyberRisks
      .filter((cr) => cr.assetIds?.some((a) => SCOPE_ASSETS.has(a)) && !ALLOWED_CYBER_RISK_IDS.has(cr.id))
      .map((cr) => cr.id),
  );

  const excludedScopeThreatIds = sortIds(
    catalog.threats
      .filter((t) => t.assetIds?.some((a) => SCOPE_ASSETS.has(a)) && !ALLOWED_THREAT_IDS.has(t.id))
      .map((t) => t.id),
  );

  const excludedScopeVulnerabilityIds = sortIds(
    catalog.vulnerabilities
      .filter(
        (v) =>
          isVulnActiveForAssessment(v) &&
          v.assetIds?.some((a) => SCOPE_ASSETS.has(a)) &&
          !ALLOWED_VULN_IDS.has(v.id),
      )
      .map((v) => v.id),
  );

  const controlIdsTouchingScope = catalog.controls
    .filter((c) => c.assetIds?.some((a) => SCOPE_ASSETS.has(a)))
    .map((c) => c.id);
  const excludedScopeControlIds = sortIds(
    controlIdsTouchingScope.filter((id) => !controlsAlwaysInScopeIds.has(id)),
  );

  const riskIds = new Set(
    catalog.cyberRisks
      .filter(
        (cr) =>
          cr.assetIds?.some((a) => SCOPE_ASSETS.has(a)) &&
          !excludedScopeCyberRiskIds.includes(cr.id),
      )
      .map((cr) => cr.id),
  );

  const ownedTupleKeys = new Set(
    catalog.scenarios
      .filter((x) => x.assessmentId === craId)
      .map((x) => `${x.cyberRiskId}|${x.assetId}|${(x.threatIds ?? [])[0] ?? ""}`),
  );

  const allowedScenarioIds = new Set(
    catalog.scenarios.filter((s) => s.assessmentId === craId).map((s) => s.id),
  );

  const candidateScenarioIds = [];
  for (const s of catalog.scenarios) {
    if (!SCOPE_ASSETS.has(s.assetId) || !riskIds.has(s.cyberRiskId)) continue;
    if (s.assessmentId != null && s.assessmentId !== craId) continue;
    if (craId && ownedTupleKeys.size > 0) {
      const tupleKey = `${s.cyberRiskId}|${s.assetId}|${(s.threatIds ?? [])[0] ?? ""}`;
      if (s.assessmentId == null && ownedTupleKeys.has(tupleKey)) continue;
    }
    candidateScenarioIds.push(s.id);
  }

  const excludedScopeScenarioIds = sortIds(
    candidateScenarioIds.filter((id) => !allowedScenarioIds.has(id)),
  );

  const cyberRiskIds = CYBER_RISK_IDS_ORDERED.filter((id) =>
    catalog.cyberRisks.some(
      (cr) => cr.id === id && cr.assetIds?.some((a) => SCOPE_ASSETS.has(a)),
    ),
  );

  const threatIds = [...THREAT_IDS_ORDERED];

  const vulnerabilityIds = [...VULN_IDS_ORDERED];

  const scenarioIds = sortIds(
    catalog.scenarios
      .filter((s) => {
        if (!SCOPE_ASSETS.has(s.assetId) || !riskIds.has(s.cyberRiskId)) return false;
        if (excludedScopeScenarioIds.includes(s.id)) return false;
        if (s.assessmentId != null && s.assessmentId !== craId) return false;
        if (craId && ownedTupleKeys.size > 0) {
          const tupleKey = `${s.cyberRiskId}|${s.assetId}|${(s.threatIds ?? [])[0] ?? ""}`;
          if (s.assessmentId == null && ownedTupleKeys.has(tupleKey)) return false;
        }
        return true;
      })
      .map((s) => s.id),
  );

  return {
    assetIds: [...SCOPE_ASSETS].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })),
    cyberRiskIds,
    threatIds,
    vulnerabilityIds,
    scenarioIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
    excludedScopeScenarioIds,
  };
}

function main() {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const catalog = JSON.parse(raw);
  const cra = catalog.riskAssessments?.find((a) => a.id === CRA_ID);
  if (!cra) {
    console.error("No", CRA_ID, "in catalog.");
    process.exit(1);
  }

  const next = computeNarrowScope(catalog, { craId: CRA_ID });
  Object.assign(cra, next, {
    instructions: cra.instructions,
    name: cra.name,
    ownerId: cra.ownerId,
    status: cra.status,
    assessmentType: cra.assessmentType,
    startDate: cra.startDate,
    dueDate: cra.dueDate,
    aiScoringPhase: cra.aiScoringPhase,
  });

  fs.writeFileSync(catalogPath, `${JSON.stringify(catalog, null, 2)}\n`);
  console.log("Updated", CRA_ID, "scope exclusions:");
  console.log("  excluded cyber risks:", next.excludedScopeCyberRiskIds.length);
  console.log("  excluded threats:", next.excludedScopeThreatIds.length);
  console.log("  excluded vulnerabilities:", next.excludedScopeVulnerabilityIds.length);
  console.log("  excluded controls (scoped assets, minus always-in-scope):", next.excludedScopeControlIds.length);
  console.log("  excluded scenarios:", next.excludedScopeScenarioIds.length);
}

const isMainModule =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMainModule) main();
