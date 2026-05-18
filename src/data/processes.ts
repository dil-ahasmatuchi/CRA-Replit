import { padId } from "./types.js";
import type { MockProcess, MockProcessRelationships } from "./types.js";
import { assets, getAssetById } from "./assets.js";
import { orgUnits } from "./orgUnits.js";
import { threats } from "./threats.js";
import { vulnerabilities } from "./vulnerabilities.js";
import { controls } from "./controls.js";
import { cyberRisks } from "./cyberRisks.js";
import { scenarios } from "./scenarios.js";
import { riskAssessments } from "./riskAssessments.js";
import { mitigationPlans } from "./mitigationPlans.js";
import { objectives } from "./objectives.js";
import { users } from "./users.js";
import { mulberry32 } from "./relationshipHeuristics.js";

function activeUserCount(): number {
  return Math.max(1, users.length);
}

function dedupeIds(ids: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const id of ids) {
    if (!seen.has(id)) {
      seen.add(id);
      out.push(id);
    }
  }
  return out;
}

function pickDistinctInts(
  rng: () => number,
  maxExclusive: number,
  count: number,
): number[] {
  const cap = Math.min(count, maxExclusive);
  const used = new Set<number>();
  const out: number[] = [];
  let guard = 0;
  while (out.length < cap && guard < maxExclusive * 8) {
    guard += 1;
    const v = Math.floor(rng() * maxExclusive);
    if (used.has(v)) continue;
    used.add(v);
    out.push(v);
  }
  return out;
}

function pickRandomAssetIds(rng: () => number, count: number): string[] {
  const idxs = pickDistinctInts(rng, assets.length, count);
  return idxs.map((k) => assets[k]!.id);
}

function cyberRiskAt(i: number) {
  return cyberRisks[i % cyberRisks.length]!;
}

function buildProcessRelationships(index: number): MockProcessRelationships {
  const rng = mulberry32(0x50726300 + index * 7937 + 29);

  const nCr = 4 + Math.floor(rng() * 4);
  const startCr = Math.floor(rng() * cyberRisks.length);
  const crIndices: number[] = [];
  for (let k = 0; k < nCr; k++) {
    const step = 1 + Math.floor(rng() * 9);
    crIndices.push((startCr + k * step + Math.floor(rng() * 3)) % cyberRisks.length);
  }

  const primaryCr = cyberRiskAt(crIndices[0]!);

  const fromCyberRisks: string[] = [];
  for (const ci of crIndices) {
    fromCyberRisks.push(...cyberRiskAt(ci).assetIds);
  }

  const extraAssetCount = 14 + Math.floor(rng() * 22);
  const extraRandomAssets = pickRandomAssetIds(rng, extraAssetCount);

  const assetIds = dedupeIds([...fromCyberRisks, ...extraRandomAssets]);

  const buFromAssets = assetIds
    .map((id) => getAssetById(id)?.orgUnitId)
    .filter((x): x is string => Boolean(x));
  const extraBu = pickDistinctInts(rng, orgUnits.length, 3 + Math.floor(rng() * 5)).map(
    (k) => orgUnits[k]!.id,
  );
  const orgUnitIds = dedupeIds([
    ...buFromAssets,
    primaryCr.orgUnitId,
    ...extraBu,
  ]);

  const fromThreats: string[] = [];
  for (const ci of crIndices) {
    fromThreats.push(...cyberRiskAt(ci).threatIds);
  }
  const extraThreats = pickDistinctInts(rng, threats.length, 5 + Math.floor(rng() * 10)).map(
    (k) => threats[k]!.id,
  );
  const threatIds = dedupeIds([...fromThreats, ...extraThreats]);

  const fromVulns: string[] = [];
  for (const ci of crIndices) {
    fromVulns.push(...cyberRiskAt(ci).vulnerabilityIds);
  }
  const extraVulns = pickDistinctInts(
    rng,
    vulnerabilities.length,
    5 + Math.floor(rng() * 12),
  ).map((k) => vulnerabilities[k]!.id);
  const vulnerabilityIds = dedupeIds([...fromVulns, ...extraVulns]);

  const controlIdsFromAssets = assetIds
    .slice(0, 28)
    .flatMap((aid) => getAssetById(aid)?.controlIds.slice(0, 3) ?? []);
  const extraControls = pickDistinctInts(rng, controls.length, 6 + Math.floor(rng() * 12)).map(
    (k) => controls[k]!.id,
  );
  const controlIds = dedupeIds([...controlIdsFromAssets, ...extraControls]);

  const cyberRiskIds = dedupeIds(crIndices.map((ci) => cyberRiskAt(ci).id));

  const scenarioIds = dedupeIds([
    ...scenarios
      .filter(
        (s) =>
          cyberRiskIds.includes(s.cyberRiskId) ||
          cyberRiskIds.includes(s.relationships.cyberRiskId),
      )
      .slice(0, 8 + Math.floor(rng() * 8))
      .map((s) => s.id),
    ...pickDistinctInts(rng, scenarios.length, 3).map((k) => scenarios[k]!.id),
  ]);

  const assessmentIds = dedupeIds([
    ...riskAssessments
      .filter((a) => a.cyberRiskIds.some((id) => cyberRiskIds.includes(id)))
      .slice(0, 4 + Math.floor(rng() * 6))
      .map((a) => a.id),
    ...pickDistinctInts(rng, riskAssessments.length, 2).map((k) => riskAssessments[k]!.id),
  ]);

  const mitigationPlanIds = dedupeIds([
    ...mitigationPlans
      .filter((mp) => mp.cyberRiskIds.some((id) => cyberRiskIds.includes(id)))
      .map((mp) => mp.id)
      .slice(0, 4 + Math.floor(rng() * 5)),
    ...pickDistinctInts(rng, mitigationPlans.length, 2).map((k) => mitigationPlans[k]!.id),
  ]);

  const nObj = 2 + Math.floor(rng() * 5);
  const objectiveIds = pickDistinctInts(rng, objectives.length, nObj).map(
    (k) => objectives[k]!.id,
  );

  return {
    orgUnitIds,
    assetIds,
    threatIds,
    vulnerabilityIds,
    controlIds,
    cyberRiskIds,
    scenarioIds,
    assessmentIds,
    mitigationPlanIds,
    objectiveIds,
  };
}

type ProcessSeed = { title: string; description: string };

const PROCESS_SEEDS: readonly ProcessSeed[] = [
  { title: "Quarterly access certification for critical applications", description: "Owners attest privileged and shared accounts against HR authoritative sources and revoke dormant rights within SLA." },
  { title: "Vulnerability scanning and patch prioritization cycle", description: "Run credentialed scans, merge results with threat intel, and route findings to asset owners with risk-based due dates." },
  { title: "Security architecture review gate for major projects", description: "Assess data flows, trust boundaries, and control inheritance before funding or production promotion milestones." },
  { title: "Incident severity classification and executive notification", description: "Apply consistent severity matrices, legal hold triggers, and leadership briefing templates within the first operational hour." },
  { title: "Third-party security questionnaire and evidence validation", description: "Standardize vendor assessments, sample test controls, and record compensating measures for residual gaps." },
  { title: "Backup immutability and restoration rehearsal", description: "Verify isolated backup copies, test selective restores, and document recovery time evidence for auditors." },
  { title: "Secrets rotation and vault hygiene program", description: "Automate rotation for high-risk credentials, eliminate long-lived API keys in code repositories, and monitor vault access patterns." },
  { title: "Secure baseline configuration for server and container images", description: "Publish hardened images, enforce drift detection in CI, and track exceptions with time-bound approvals." },
  { title: "Data retention and lawful disposal workflow", description: "Align retention schedules with policy, legal holds, and secure destruction methods for physical and logical media." },
  { title: "Security awareness phishing simulation and coaching", description: "Deliver localized simulations, micro-learning nudges, and manager coaching for repeat clickers without shaming." },
  { title: "Privileged session monitoring and break-glass auditing", description: "Record administrator sessions on crown-jewel systems, enforce dual control for break-glass accounts, and review samples weekly." },
  { title: "Change advisory security checkpoint", description: "Security reviewers validate risky changes, emergency change post-mortems, and segregation of duties for production deploys." },
  { title: "Logging pipeline health and alert tuning review", description: "Monitor ingestion lag, parser errors, and false-positive rates; tune use cases with SOC and application owners." },
  { title: "Endpoint detection policy lifecycle", description: "Stage prevention policies, measure performance impact, and roll out progressively with rollback criteria." },
  { title: "Cloud identity federation and guest account governance", description: "Review external identities quarterly, enforce conditional access baselines, and disable unused federation trusts." },
  { title: "Application penetration test intake and remediation tracking", description: "Prioritize findings by exploitability and data sensitivity, track fixes in the defect system, and verify closure." },
  { title: "Business impact analysis refresh for tier-one services", description: "Update recovery priorities, dependencies, and manual workarounds after major architecture or vendor changes." },
  { title: "Secure coding training for product teams", description: "Role-based modules on OWASP categories, threat modeling hooks, and hands-on labs tied to the organization’s stack." },
  { title: "DDoS and edge traffic resilience testing", description: "Exercise scrubbing centers, origin shielding, and customer communication scripts under coordinated test traffic." },
  { title: "Encryption key ceremony and dual control procedures", description: "Document HSM ceremonies, witness requirements, and split knowledge for master keys with annual walkthroughs." },
  { title: "Physical access recertification for data halls", description: "Revalidate badge access lists, escort rules, and visitor logs against approved personnel for regulated zones." },
  { title: "Secure disposal of end-of-life assets", description: "Chain-of-custody forms, verified wiping or destruction vendors, and certificate of destruction retention." },
  { title: "Security metrics reporting to risk committee", description: "Produce trend lines on exposure, control testing, incidents, and remediation aging with plain-language commentary." },
  { title: "Red team findings remediation program", description: "Translate offensive findings into tracked epics, retest criteria, and acceptance by system owners." },
  { title: "API gateway policy review and rate limit calibration", description: "Validate authentication schemes, schema validation, and abuse detection thresholds against observed traffic." },
  { title: "Customer data subject request handling with security checks", description: "Authenticate requesters, scope searches safely, and log disclosures for privacy regulators and internal QA." },
  { title: "Software bill of materials generation for releases", description: "Attach SBOM artifacts to releases, flag critical CVEs, and block promotion when policy thresholds are exceeded." },
  { title: "Wireless guest network segmentation audit", description: "Confirm guest isolation from corporate VLANs, captive portal integrity, and logging of authentication events." },
  { title: "Executive crisis tabletop facilitation", description: "Run cross-functional tabletops with legal, comms, IT, and security using realistic injects and after-action reports." },
  { title: "Contract security clause library maintenance", description: "Update standard clauses for confidentiality, breach notification, audit rights, and subprocessors with legal review." },
  { title: "Security champion community of practice", description: "Monthly community calls, office hours, and recognition for teams that reduce recurring vulnerability classes." },
  { title: "Identity lifecycle joiner-mover-leaver automation audit", description: "Sample HR events against provisioned accounts, detect orphan accounts, and reconcile with authoritative directories." },
  { title: "Container registry vulnerability gate enforcement", description: "Block images that exceed CVE thresholds, require signed images, and document waiver governance." },
  { title: "Customer-facing status page integrity review", description: "Protect administrative access to status communications and validate incident messaging accuracy under stress." },
  { title: "Regulatory evidence collection for control testing", description: "Gather artifacts for sampled controls, map to frameworks, and store with integrity metadata for external audit." },
];

function buildProcesses(): MockProcess[] {
  return PROCESS_SEEDS.map((seed, i) => {
    const rng = mulberry32(0x50726400 + i * 100379 + 11);
    const ownerIdx = 1 + Math.floor(rng() * activeUserCount());
    return {
      id: padId("PRC", i + 1),
      title: seed.title,
      description: seed.description,
      ownerId: padId("USR", ownerIdx),
      relationships: buildProcessRelationships(i),
    };
  });
}

export const processes: MockProcess[] = buildProcesses();

const processById = new Map(processes.map((p) => [p.id, p]));

function rebuildProcessIndex(): void {
  processById.clear();
  for (const p of processes) {
    processById.set(p.id, p);
  }
}

/** Re-wire process relationship ids after catalog replacement (e.g. Pooja migration). */
export function rebuildProcessesFromCurrentCatalog(): void {
  processes.length = 0;
  processes.push(...buildProcesses());
  rebuildProcessIndex();
}

export function getProcessById(id: string): MockProcess | undefined {
  return processById.get(id);
}
