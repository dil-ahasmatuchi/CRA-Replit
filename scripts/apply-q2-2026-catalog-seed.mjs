/**
 * One-shot patcher: Q2 2026 ransomware readiness seed data for pooja-migrated-catalog.v3.json
 * Run: node scripts/apply-q2-2026-catalog-seed.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { computeNarrowScope } from "./narrow-cra029-scope.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.join(__dirname, "../src/data/generated/pooja-migrated-catalog.v3.json");

const CRA_ID = "CRA-029";
const VUL_BY_NAME = {
  "Broken access control and authorization gaps": "VUL-002",
  "Missing or weak multi-factor authentication": "VUL-004",
  "Excessive database privilege grants": "VUL-008",
  "Default or weak system credentials": "VUL-011",
  "Absent or misconfigured endpoint detection": "VUL-013",
  "Insufficient security awareness and training": "VUL-028",
  "Incomplete or untested incident response plan": "VUL-030",
};

const INSTRUCTIONS =
  "Evaluate the organization's exposure to ransomware and destructive malware across the three highest-leverage targets: identity infrastructure, source code, and customer data. Assess inherent risk before controls, then evaluate residual risk after the recommended mitigation plan is in place.";

function dedupePush(arr, id) {
  if (!arr.includes(id)) arr.push(id);
}

function ensureAssetOnVulnerability(v, assetId) {
  dedupePush(v.assetIds, assetId);
  if (v.relationships && Array.isArray(v.relationships.assetIds)) {
    dedupePush(v.relationships.assetIds, assetId);
  }
}

const scenarioDefs = [
  {
    id: "SCA-CRA-029-CR-001-AST-001-THR-001",
    name: "Account takeover and session abuse on Customer Database Server (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-001"],
    vulnerabilityIds: ["VUL-004", "VUL-011", "VUL-002", "VUL-008"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 20,
    likelihoodLabel: "High",
    cyberRiskScore: 80,
    cyberRiskScoreLabel: "High",
    rationale: `Q2 2026 ransomware readiness — Unauthorized privileged access and credential compromise.

We assess account takeover and session abuse against Customer Database Server. Contributing vulnerabilities include missing or weak multi-factor authentication (VUL-004), default or weak system credentials (VUL-011), broken access control and authorization gaps (VUL-002), and excessive database privilege grants (VUL-008). Together they allow credential replay, session hijacking, and lateral movement into data stores.

Threat level is very high because organized ransomware operators routinely harvest credentials from phishing and infostealer ecosystems. For this catalog slice combined vulnerability severity is high (not very high), keeping the parent likelihood in the high band alongside high asset impact.

Likelihood is high and the scenario cyber risk score is high: privileged access paths are exposed and actively targeted.`,
  },
  {
    id: "SCA-CRA-029-CR-001-AST-001-THR-002",
    name: "Automated credential stuffing on Customer Database Server (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-002"],
    vulnerabilityIds: ["VUL-011", "VUL-002", "VUL-004"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 20,
    likelihoodLabel: "High",
    cyberRiskScore: 80,
    cyberRiskScoreLabel: "High",
    rationale: `Credential stuffing against Customer Database Server succeeds when default or weak system credentials (VUL-011) and missing phishing-resistant MFA (VUL-004) let attackers validate large password lists. Broken access control and authorization gaps (VUL-002) amplify impact by allowing elevated sessions to persist.

Threat actors automate login attempts at scale; likelihood is high and overall cyber risk score is high for this scenario under Q2 scope.`,
  },
  {
    id: "SCA-CRA-029-CR-001-AST-001-THR-039",
    name: "Broken authentication on internet-facing paths to Customer Database Server (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-039"],
    vulnerabilityIds: ["VUL-002", "VUL-004", "VUL-008"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 20,
    likelihoodLabel: "High",
    cyberRiskScore: 80,
    cyberRiskScoreLabel: "High",
    rationale: `Broken authentication on internet-facing microservices (THR-039) maps to authorization gaps (VUL-002), absent strong MFA on admin paths (VUL-004), and excessive database privilege grants (VUL-008). Attackers chain API abuse to reach the customer database tier.

Impact is high; combined severities are capped at high residual vulnerability exposure for this slice, yielding high likelihood and a high scenario cyber risk score.`,
  },
  {
    id: "SCA-CRA-029-CR-001-AST-002-THR-001",
    name: "Account takeover and session abuse on Active Directory Service (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-001"],
    vulnerabilityIds: ["VUL-004", "VUL-011", "VUL-002"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 20,
    likelihoodLabel: "High",
    cyberRiskScore: 60,
    cyberRiskScoreLabel: "Medium",
    rationale: `Active Directory is the control plane for identity. Account takeover (THR-001) against AD is fueled by weak MFA (VUL-004), default credentials on service accounts (VUL-011), and authorization gaps (VUL-002). Medium asset impact pairs with high combined severity on this tuple after capping residual vulnerability at high.

Scenario score is medium; sibling scenarios on higher-impact assets carry the peak scores for CR-001.`,
  },
  {
    id: "SCA-CRA-029-CR-001-AST-002-THR-002",
    name: "Automated credential stuffing on Active Directory Service (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-002"],
    vulnerabilityIds: ["VUL-011", "VUL-004"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 20,
    likelihoodLabel: "High",
    cyberRiskScore: 60,
    cyberRiskScoreLabel: "Medium",
    rationale: `Credential stuffing against Active Directory (THR-002) exploits weak passwords and absent phishing-resistant MFA (VUL-004, VUL-011). This scenario supports the overall CR-001 exposure narrative while peak scores come from customer data paths.`,
  },
  {
    id: "SCA-CRA-029-CR-001-AST-002-THR-039",
    name: "Broken authentication against Active Directory Service (Q2 CRA)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-039"],
    vulnerabilityIds: ["VUL-002", "VUL-004"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 4,
    vulnerabilitySeverityLabel: "High",
    likelihood: 19,
    likelihoodLabel: "High",
    cyberRiskScore: 57,
    cyberRiskScoreLabel: "Medium",
    rationale: `Broken authentication patterns (THR-039) against identity infrastructure leverage authorization gaps (VUL-002) and weak MFA coverage (VUL-004), keeping AD in the blast radius for ransomware preparation.`,
  },
  {
    id: "SCA-CRA-029-CR-002-AST-001-THR-003",
    name: "Ransomware and destructive malware against Customer Database Server (Q2 CRA)",
    cyberRiskId: "CR-002",
    assetId: "AST-001",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-011", "VUL-030"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 22,
    likelihoodLabel: "Very high",
    cyberRiskScore: 88,
    cyberRiskScoreLabel: "High",
    rationale: `Ransomware (THR-003) against Customer Database Server is worsened by absent or misconfigured endpoint detection (VUL-013), default or weak credentials on recovery interfaces (VUL-011), and an incomplete or untested incident response plan (VUL-030) that delays isolation.

High asset impact and very high combined severities produce a high cyber risk score for this scenario.`,
  },
  {
    id: "SCA-CRA-029-CR-002-AST-002-THR-003",
    name: "Ransomware and destructive malware against Active Directory Service (Q2 CRA)",
    cyberRiskId: "CR-002",
    assetId: "AST-002",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-030", "VUL-028"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 22,
    likelihoodLabel: "Very high",
    cyberRiskScore: 66,
    cyberRiskScoreLabel: "Medium",
    rationale: `Encrypting or wiping domain controllers is a common ransomware pivot. Endpoint detection gaps (VUL-013), weak tabletop coverage (VUL-030), and insufficient security awareness (VUL-028) slow detection. Medium impact on this asset still yields very high likelihood; peak CR-002 scores come from Code Repository and Customer Database scenarios.`,
  },
  {
    id: "SCA-CRA-029-CR-002-AST-017-THR-003",
    name: "Ransomware and destructive malware against Code Repository (Q2 CRA)",
    cyberRiskId: "CR-002",
    assetId: "AST-017",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-011", "VUL-030"],
    impact: 5,
    impactLabel: "Very high",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 23,
    likelihoodLabel: "Very high",
    cyberRiskScore: 115,
    cyberRiskScoreLabel: "Very high",
    rationale: `Source code is a crown jewel: ransomware and destructive malware (THR-003) against the Code Repository combines very high impact with absent or misconfigured endpoint detection (VUL-013), weak credentials on build agents (VUL-011), and immature IR runbooks (VUL-030). Attackers can destroy builds, poison artifacts, and move to production.

Likelihood and cyber risk score are very high for this scenario.`,
  },
  {
    id: "SCA-CRA-029-CR-010-AST-001-THR-004",
    name: "Phishing and business email compromise against Customer Database Server (Q2 CRA)",
    cyberRiskId: "CR-010",
    assetId: "AST-001",
    threatIds: ["THR-004"],
    vulnerabilityIds: ["VUL-004", "VUL-028", "VUL-030"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 22,
    likelihoodLabel: "Very high",
    cyberRiskScore: 88,
    cyberRiskScoreLabel: "High",
    rationale: `Phishing and BEC (THR-004) against operators of Customer Database Server exploit missing phishing-resistant MFA (VUL-004), insufficient security awareness and training (VUL-028), and incomplete IR rehearsal (VUL-030). One successful session can lead to mass data impact.

Cyber risk score is high for this scenario.`,
  },
  {
    id: "SCA-CRA-029-CR-010-AST-002-THR-004",
    name: "Phishing and business email compromise against Active Directory Service (Q2 CRA)",
    cyberRiskId: "CR-010",
    assetId: "AST-002",
    threatIds: ["THR-004"],
    vulnerabilityIds: ["VUL-004", "VUL-028"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 22,
    likelihoodLabel: "Very high",
    cyberRiskScore: 66,
    cyberRiskScoreLabel: "Medium",
    rationale: `Phishing against administrators of Active Directory (THR-004) pairs very high threat severity with weak MFA adoption (VUL-004) and training gaps (VUL-028). This scenario keeps identity administrators inside the social-engineering blast radius.`,
  },
  {
    id: "SCA-CRA-029-CR-010-AST-017-THR-004",
    name: "Phishing and business email compromise against Code Repository (Q2 CRA)",
    cyberRiskId: "CR-010",
    assetId: "AST-017",
    threatIds: ["THR-004"],
    vulnerabilityIds: ["VUL-028", "VUL-004", "VUL-030"],
    impact: 5,
    impactLabel: "Very high",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 5,
    vulnerabilitySeverityLabel: "Very high",
    likelihood: 23,
    likelihoodLabel: "Very high",
    cyberRiskScore: 115,
    cyberRiskScoreLabel: "Very high",
    rationale: `Developers with access to Code Repository are high-value phishing targets. Very high impact on the repository, very high threat from BEC, and weaknesses in MFA (VUL-004), awareness (VUL-028), and IR readiness (VUL-030) create a very high cyber risk score.`,
  },
];

const newScenarioRows = scenarioDefs.map((d) => ({
  id: d.id,
  name: d.name,
  ownerId: "USR-001",
  cyberRiskId: d.cyberRiskId,
  assetId: d.assetId,
  assessmentId: CRA_ID,
  impact: d.impact,
  impactLabel: d.impactLabel,
  threatSeverity: d.threatSeverity,
  threatSeverityLabel: d.threatSeverityLabel,
  vulnerabilitySeverity: d.vulnerabilitySeverity,
  vulnerabilitySeverityLabel: d.vulnerabilitySeverityLabel,
  likelihood: d.likelihood,
  likelihoodLabel: d.likelihoodLabel,
  cyberRiskScore: d.cyberRiskScore,
  cyberRiskScoreLabel: d.cyberRiskScoreLabel,
  threatIds: d.threatIds,
  vulnerabilityIds: d.vulnerabilityIds,
  scoringRationale: d.rationale,
  relationships: {
    cyberRiskId: d.cyberRiskId,
    assetId: d.assetId,
    threatIds: [...d.threatIds],
    vulnerabilityIds: [...d.vulnerabilityIds],
    controlIds: [],
    mitigationPlanIds: [],
  },
}));

const scenarioIds = newScenarioRows.map((s) => s.id);

const actionPlan1 = [
  "Inventory all privileged accounts across AD, Code Repository, and Customer DB (including service accounts and break-glass accounts).",
  "Procure and distribute FIDO2 security keys (primary) and enroll passkeys (secondary) for all privileged users.",
  "Configure conditional access policies in the identity provider to require phishing-resistant MFA for admin, developer, and database access roles.",
  "Pilot with the IT admin group for 2 weeks; capture friction points and support load.",
  "Roll out to all privileged users in waves by business unit; deprecate SMS and TOTP for these accounts.",
  "Implement break-glass account procedures with hardware-key-only access stored in dual-control vault.",
  "Verify enforcement with monthly conditional access reports.",
].join("\n");

const actionPlan2 = [
  "Define EDR requirements: behavioral ransomware detection, automated isolation, kernel-level visibility, 24/7 managed response option.",
  "Run a 2-week bake-off between two leading vendors on representative endpoint sample.",
  "Procure licensing for full endpoint fleet plus servers hosting scoped assets.",
  "Deploy in monitor-only mode for 2 weeks to baseline normal behavior and tune false positives.",
  "Switch to prevention mode for endpoint fleet; phase server enforcement to avoid operational impact.",
  "Integrate alerts with SOC / SIEM and define ransomware-specific runbooks (auto-isolate on encryption behavior).",
].join("\n");

const mp1 = {
  id: "MP-029",
  name: "Phishing-Resistant MFA Rollout",
  ownerId: "USR-001",
  status: "Completed",
  dueDate: "2026-03-15",
  orgUnitId: "BU-050",
  severity: 4,
  severityLabel: "High",
  controlIds: ["CTL-001"],
  cyberRiskIds: ["CR-001"],
  assessmentIds: [CRA_ID],
  assetIds: ["AST-001", "AST-002"],
  actionPlan: actionPlan1,
};

const mp2 = {
  id: "MP-030",
  name: "Endpoint Detection & Response Deployment",
  ownerId: "USR-001",
  status: "Completed",
  dueDate: "2026-03-20",
  orgUnitId: "BU-049",
  severity: 5,
  severityLabel: "Very high",
  controlIds: ["CTL-EDR"],
  cyberRiskIds: ["CR-002"],
  assessmentIds: [CRA_ID],
  assetIds: ["AST-017"],
  actionPlan: actionPlan2,
  relatedControlNames: ["Endpoint Detection & Response"],
};

const newAssessment = {
  id: CRA_ID,
  name: "Q2 2026 Ransomware Readiness Assessment",
  ownerId: "USR-001",
  status: "Approved",
  assessmentType: "Inherent scoring",
  startDate: "2026-04-01",
  dueDate: "2026-06-30",
  assetIds: ["AST-001", "AST-002", "AST-017"],
  cyberRiskIds: [],
  threatIds: [],
  vulnerabilityIds: [],
  scenarioIds: [],
  excludedScopeCyberRiskIds: [],
  excludedScopeThreatIds: [],
  excludedScopeVulnerabilityIds: [],
  excludedScopeControlIds: [],
  excludedScopeScenarioIds: [],
  aiScoringPhase: "complete",
  instructions: INSTRUCTIONS,
};

const ctlEdr = {
  id: "CTL-EDR",
  name: "Endpoint Detection & Response",
  ownerId: "USR-001",
  status: "Active",
  controlType: "Detective",
  keyControl: true,
  controlFrequency: "Daily",
  assetIds: ["AST-017"],
  effectiveness: 5,
  effectivenessLabel: "Very high",
};

const ctlSat = {
  id: "CTL-SAT",
  name: "Security Awareness & Anti-Phishing Training",
  ownerId: "USR-001",
  status: "Active",
  controlType: "Preventive",
  keyControl: true,
  controlFrequency: "Monthly",
  assetIds: ["AST-001", "AST-002"],
  effectiveness: 5,
  effectivenessLabel: "Very high",
};

function main() {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const c = JSON.parse(raw);

  if (c.riskAssessments?.some((a) => a.id === CRA_ID)) {
    console.error("Catalog already contains", CRA_ID, "— abort to avoid duplicates.");
    process.exit(1);
  }

  // Assets criticality
  for (const a of c.assets) {
    if (a.id === "AST-001") {
      a.criticality = 4;
      a.criticalityLabel = "High";
    }
    if (a.id === "AST-017") {
      a.criticality = 5;
      a.criticalityLabel = "Very high";
    }
  }

  // CTL-001 includes AST-002
  const ctl1 = c.controls.find((x) => x.id === "CTL-001");
  if (ctl1) dedupePush(ctl1.assetIds, "AST-002");

  c.controls.push(ctlEdr, ctlSat);

  // Vulnerabilities on scoped assets
  const scopeAssets = ["AST-001", "AST-002", "AST-017"];
  const vulnNamesForAssets = {
    "AST-001": [
      "Missing or weak multi-factor authentication",
      "Default or weak system credentials",
      "Broken access control and authorization gaps",
      "Excessive database privilege grants",
      "Absent or misconfigured endpoint detection",
      "Insufficient security awareness and training",
      "Incomplete or untested incident response plan",
    ],
    "AST-002": [
      "Missing or weak multi-factor authentication",
      "Default or weak system credentials",
      "Broken access control and authorization gaps",
      "Insufficient security awareness and training",
      "Incomplete or untested incident response plan",
    ],
    "AST-017": [
      "Absent or misconfigured endpoint detection",
      "Default or weak system credentials",
      "Insufficient security awareness and training",
      "Incomplete or untested incident response plan",
    ],
  };
  for (const aid of scopeAssets) {
    const names = vulnNamesForAssets[aid];
    for (const nm of names) {
      const vid = VUL_BY_NAME[nm];
      const v = c.vulnerabilities.find((x) => x.id === vid);
      if (v) ensureAssetOnVulnerability(v, aid);
    }
  }

  // Mitigation plans
  c.mitigationPlans.push(mp1, mp2);

  // Scenarios: insert after last element or append
  c.scenarios.push(...newScenarioRows);

  // Cyber risks CR-001, CR-002, CR-010 — append scenario + mitigation ids; bump inherent for CR-001/CR-002
  const cr1 = c.cyberRisks.find((r) => r.id === "CR-001");
  const cr2 = c.cyberRisks.find((r) => r.id === "CR-002");
  const cr10 = c.cyberRisks.find((r) => r.id === "CR-010");
  for (const sid of scenarioIds) {
    if (cr1 && sid.includes("CR-001")) {
      dedupePush(cr1.scenarioIds, sid);
      dedupePush(cr1.relationships.scenarioIds, sid);
    }
    if (cr2 && sid.includes("CR-002")) {
      dedupePush(cr2.scenarioIds, sid);
      dedupePush(cr2.relationships.scenarioIds, sid);
    }
    if (cr10 && sid.includes("CR-010")) {
      dedupePush(cr10.scenarioIds, sid);
      dedupePush(cr10.relationships.scenarioIds, sid);
    }
  }
  if (cr1) {
    dedupePush(cr1.mitigationPlanIds, "MP-029");
    dedupePush(cr1.relationships.mitigationPlanIds, "MP-029");
    cr1.likelihood = 20;
    cr1.likelihoodLabel = "High";
    cr1.impact = 4;
    cr1.impactLabel = "High";
    cr1.cyberRiskScore = 80;
    cr1.cyberRiskScoreLabel = "High";
  }
  if (cr2) {
    dedupePush(cr2.mitigationPlanIds, "MP-030");
    dedupePush(cr2.relationships.mitigationPlanIds, "MP-030");
    cr2.likelihood = 22;
    cr2.likelihoodLabel = "Very high";
    cr2.impact = 5;
    cr2.impactLabel = "Very high";
    cr2.cyberRiskScore = 110;
    cr2.cyberRiskScoreLabel = "Very high";
  }
  if (cr10) {
    dedupePush(cr10.relationships.assessmentIds, CRA_ID);
    cr10.likelihood = 22;
    cr10.likelihoodLabel = "Very high";
    cr10.impact = 5;
    cr10.impactLabel = "Very high";
    cr10.cyberRiskScore = 110;
    cr10.cyberRiskScoreLabel = "Very high";
  }

  c.riskAssessments.unshift(newAssessment);
  const craRow = c.riskAssessments.find((a) => a.id === CRA_ID);
  if (craRow) Object.assign(craRow, computeNarrowScope(c, { craId: CRA_ID }));

  fs.writeFileSync(catalogPath, `${JSON.stringify(c, null, 2)}\n`);
  console.log("Wrote", catalogPath);
}

main();
