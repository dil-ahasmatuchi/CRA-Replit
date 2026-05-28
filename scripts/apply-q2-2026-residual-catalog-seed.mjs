/**
 * One-shot patcher: Q2 2026 ransomware residual re-assessment (CRA-030) for pooja-migrated-catalog.v3.json
 * Run: node scripts/apply-q2-2026-residual-catalog-seed.mjs
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { computeNarrowScope } from "./narrow-cra029-scope.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const catalogPath = path.join(__dirname, "../src/data/generated/pooja-migrated-catalog.v3.json");

const CRA_ID = "CRA-030";

const INSTRUCTIONS = [
  "Following completion of the Q2 2026 Ransomware Readiness Assessment and closure of two priority mitigation plans (Phishing-Resistant MFA Rollout and Endpoint Detection & Response Deployment), this assessment re-evaluates the residual cyber risk exposure across the same scope.",
  "The objective is to validate whether the implemented controls have materially reduced the inherent risk identified in Q2, capture the new risk posture for Risk Committee approval, and identify any remaining gaps that require further mitigation.",
  "Scoring methodology and asset impact ratings are unchanged from the inherent assessment to ensure trend comparability.",
  "Controls now in scope for residual scoring: CTL-001 Multi-factor authentication (FIDO2 and passkeys for privileged accounts) and CTL-EDR Endpoint Detection & Response (deployed across the endpoint fleet and scoped servers).",
].join("\n\n");

function dedupePush(arr, id) {
  if (!arr.includes(id)) arr.push(id);
}

/** Same 12 tuples as CRA-029; CR-001/CR-002 scores lowered vs inherent; CR-010 unchanged. */
const scenarioDefs = [
  {
    id: "SCA-CRA-030-CR-001-AST-001-THR-001",
    name: "Account takeover and session abuse on Customer Database Server (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-001"],
    vulnerabilityIds: ["VUL-004", "VUL-011", "VUL-002", "VUL-008"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 14,
    likelihoodLabel: "Medium",
    cyberRiskScore: 56,
    cyberRiskScoreLabel: "Medium",
    rationale: `Q2 2026 residual re-assessment — Unauthorized privileged access and credential compromise.

Account takeover and session abuse against Customer Database Server is reassessed after CTL-001 (FIDO2 and passkeys for privileged accounts) materially reduced missing or weak MFA exposure (VUL-004). Residual exposure still includes default or weak system credentials on legacy interfaces (VUL-011), broken access control and authorization gaps (VUL-002), and excessive database privilege grants (VUL-008).

Threat severity remains very high because attackers still monetize harvested credentials. Combined residual vulnerability severity is medium after MFA hardening. Likelihood and scenario cyber risk score are medium—lower than the Q2 inherent pass—while privileged paths still warrant monitoring.`,
  },
  {
    id: "SCA-CRA-030-CR-001-AST-001-THR-002",
    name: "Automated credential stuffing on Customer Database Server (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-002"],
    vulnerabilityIds: ["VUL-011", "VUL-002", "VUL-004"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 13,
    likelihoodLabel: "Medium",
    cyberRiskScore: 52,
    cyberRiskScoreLabel: "Medium",
    rationale: `Credential stuffing (THR-002) is dampened by phishing-resistant MFA on privileged paths (CTL-001), lowering the practical value of password spraying against the highest-risk accounts. Residual gaps remain where legacy accounts or service principals still rely on weaker factors (VUL-004, VUL-011) and authorization drift persists (VUL-002).

Residual likelihood is medium and the scenario score is medium—below the inherent Q2 assessment but not eliminated.`,
  },
  {
    id: "SCA-CRA-030-CR-001-AST-001-THR-039",
    name: "Broken authentication on internet-facing paths to Customer Database Server (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-001",
    threatIds: ["THR-039"],
    vulnerabilityIds: ["VUL-002", "VUL-004", "VUL-008"],
    impact: 4,
    impactLabel: "High",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 14,
    likelihoodLabel: "Medium",
    cyberRiskScore: 56,
    cyberRiskScoreLabel: "Medium",
    rationale: `Broken authentication on internet-facing microservices (THR-039) still maps to authorization gaps (VUL-002) and excessive database privilege grants (VUL-008), but admin-facing paths now enforce stronger MFA (CTL-001), reducing blast radius to the customer database tier.

Residual combined vulnerability severity is medium; likelihood is medium and the scenario cyber risk score is medium versus the higher inherent Q2 position.`,
  },
  {
    id: "SCA-CRA-030-CR-001-AST-002-THR-001",
    name: "Account takeover and session abuse on Active Directory Service (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-001"],
    vulnerabilityIds: ["VUL-004", "VUL-011", "VUL-002"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 14,
    likelihoodLabel: "Medium",
    cyberRiskScore: 42,
    cyberRiskScoreLabel: "Medium",
    rationale: `Active Directory remains the identity control plane. After CTL-001, account takeover (THR-001) is harder for privileged operators, but residual credential hygiene issues (VUL-011) and authorization gaps (VUL-002) still matter for break-glass and legacy automation accounts.

Medium asset impact with medium residual likelihood yields a medium scenario score, down from the inherent Q2 AD scenarios.`,
  },
  {
    id: "SCA-CRA-030-CR-001-AST-002-THR-002",
    name: "Automated credential stuffing on Active Directory Service (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-002"],
    vulnerabilityIds: ["VUL-011", "VUL-004"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 12,
    likelihoodLabel: "Medium",
    cyberRiskScore: 36,
    cyberRiskScoreLabel: "Very low",
    rationale: `Automated stuffing (THR-002) against AD is less effective where phishing-resistant MFA blocks interactive abuse of stolen passwords (CTL-001). Residual risk concentrates on accounts not yet migrated or dependent on legacy protocols (VUL-004, VUL-011).

Likelihood is medium; scenario cyber risk score is very low on this medium-impact asset after control uplift.`,
  },
  {
    id: "SCA-CRA-030-CR-001-AST-002-THR-039",
    name: "Broken authentication against Active Directory Service (Q2 residual)",
    cyberRiskId: "CR-001",
    assetId: "AST-002",
    threatIds: ["THR-039"],
    vulnerabilityIds: ["VUL-002", "VUL-004"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 5,
    threatSeverityLabel: "Very high",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 12,
    likelihoodLabel: "Medium",
    cyberRiskScore: 36,
    cyberRiskScoreLabel: "Very low",
    rationale: `Broken authentication patterns (THR-039) still touch authorization gaps (VUL-002), but privileged authentication now follows stronger MFA policy (CTL-001), shrinking realistic abuse paths.

Residual likelihood is medium and the scenario score is very low for this medium-impact AD row compared with inherent Q2.`,
  },
  {
    id: "SCA-CRA-030-CR-002-AST-001-THR-003",
    name: "Ransomware and destructive malware against Customer Database Server (Q2 residual)",
    cyberRiskId: "CR-002",
    assetId: "AST-001",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-011", "VUL-030"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 3,
    threatSeverityLabel: "Medium",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 9,
    likelihoodLabel: "Low",
    cyberRiskScore: 27,
    cyberRiskScoreLabel: "Very low",
    rationale: `Ransomware (THR-003) against Customer Database Server is reassessed after CTL-EDR improved detection and response on scoped servers and endpoints hosting recovery paths. Residual scoring reflects materially reduced exploitable threat and vulnerability severity (medium threat, medium vulnerability) on this tuple after EDR uplift.

Parent aggregation still peaks on the Code Repository tuple for CR-002; this row is a lower residual slice with low combined likelihood product.`,
  },
  {
    id: "SCA-CRA-030-CR-002-AST-002-THR-003",
    name: "Ransomware and destructive malware against Active Directory Service (Q2 residual)",
    cyberRiskId: "CR-002",
    assetId: "AST-002",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-030", "VUL-028"],
    impact: 3,
    impactLabel: "Medium",
    threatSeverity: 3,
    threatSeverityLabel: "Medium",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 9,
    likelihoodLabel: "Low",
    cyberRiskScore: 27,
    cyberRiskScoreLabel: "Very low",
    rationale: `Domain controller ransomware pivots are still plausible at reduced residual severity after CTL-EDR: threat and vulnerability severities are capped at medium on this AD slice, yielding a low likelihood product versus the inherent Q2 pass.

Scenario score is very low on medium impact; parent row peaks on the repository tuple.`,
  },
  {
    id: "SCA-CRA-030-CR-002-AST-017-THR-003",
    name: "Ransomware and destructive malware against Code Repository (Q2 residual)",
    cyberRiskId: "CR-002",
    assetId: "AST-017",
    threatIds: ["THR-003"],
    vulnerabilityIds: ["VUL-013", "VUL-011", "VUL-030"],
    impact: 5,
    impactLabel: "Very high",
    threatSeverity: 3,
    threatSeverityLabel: "Medium",
    vulnerabilitySeverity: 3,
    vulnerabilitySeverityLabel: "Medium",
    likelihood: 9,
    likelihoodLabel: "Low",
    cyberRiskScore: 45,
    cyberRiskScoreLabel: "Low",
    rationale: `The Code Repository remains a crown-jewel asset (very high impact). After EDR deployment, residual assessment caps combined threat and vulnerability severity at medium on this tuple, so the parent likelihood product is low and the scenario cyber risk score is low (45) versus inherent very high.

This row drives the CR-002 parent residual position in the low-likelihood band while CR-010 remains the top-right peak.`,
  },
  {
    id: "SCA-CRA-030-CR-010-AST-001-THR-004",
    name: "Phishing and business email compromise against Customer Database Server (Q2 residual)",
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
    rationale: `Phishing and BEC (THR-004) against operators of Customer Database Server still exploit human factors: gaps in phishing-resistant coverage where non-privileged workflows remain (VUL-004), insufficient security awareness and training (VUL-028), and incomplete IR rehearsal (VUL-030). MFA rollout targeted privileged paths; social engineering remains a primary path to session misuse.

No dedicated mitigation plan closed for CR-010 in this storyline, so residual posture matches the inherent Q2 assessment for this scenario tuple.`,
  },
  {
    id: "SCA-CRA-030-CR-010-AST-002-THR-004",
    name: "Phishing and business email compromise against Active Directory Service (Q2 residual)",
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
    rationale: `Phishing against administrators of Active Directory (THR-004) still pairs very high threat severity with MFA gaps outside the privileged rollout perimeter (VUL-004) and training weaknesses (VUL-028). CTL-001 reduces some paths, but administrator social engineering remains a dominant residual vector for CR-010.

Scores are unchanged from inherent Q2 for comparability where no CR-010 mitigation plan completed.`,
  },
  {
    id: "SCA-CRA-030-CR-010-AST-017-THR-004",
    name: "Phishing and business email compromise against Code Repository (Q2 residual)",
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
    rationale: `Developers with access to the Code Repository remain high-value phishing targets. Very high impact, very high threat from BEC, and persistent weaknesses in awareness (VUL-028), inconsistent MFA on developer workflows (VUL-004), and IR readiness under pressure (VUL-030) keep this scenario at the top of the CR-010 range.

Unchanged from inherent Q2: no CR-010 mitigation plan closure in this catalog narrative.`,
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

function main() {
  const raw = fs.readFileSync(catalogPath, "utf8");
  const c = JSON.parse(raw);

  if (c.riskAssessments?.some((a) => a.id === CRA_ID)) {
    console.error("Catalog already contains", CRA_ID, "— abort to avoid duplicates.");
    process.exit(1);
  }

  c.scenarios.push(...newScenarioRows);

  const scope = computeNarrowScope(c, {
    craId: CRA_ID,
    controlsAlwaysInScopeIds: new Set(["CTL-001", "CTL-EDR"]),
  });

  const newAssessment = {
    id: CRA_ID,
    name: "Q2 2026 Ransomware Residual Risk Re-Assessment",
    ownerId: "USR-001",
    status: "Approved",
    assessmentType: "Residual scoring",
    startDate: "2026-06-01",
    dueDate: "2026-06-30",
    ...scope,
    instructions: INSTRUCTIONS,
    aiScoringPhase: "complete",
  };

  const idx = c.riskAssessments.findIndex((a) => a.id === "CRA-029");
  if (idx === -1) {
    console.error("CRA-029 not found; insert CRA-030 at start of riskAssessments.");
    c.riskAssessments.unshift(newAssessment);
  } else {
    c.riskAssessments.splice(idx + 1, 0, newAssessment);
  }

  for (const mp of c.mitigationPlans ?? []) {
    if (mp.id === "MP-029" || mp.id === "MP-030") {
      dedupePush(mp.assessmentIds, CRA_ID);
    }
  }

  fs.writeFileSync(catalogPath, `${JSON.stringify(c, null, 2)}\n`);
  console.log("Wrote", catalogPath, "— added", CRA_ID, "and", newScenarioRows.length, "scenarios.");
}

main();
