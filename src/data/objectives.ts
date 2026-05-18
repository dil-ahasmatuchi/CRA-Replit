import { padId } from "./types.js";
import type { MockObjective, MockObjectiveRelationships } from "./types.js";
import { assets, getAssetById } from "./assets.js";
import { orgUnits } from "./orgUnits.js";
import { threats } from "./threats.js";
import { vulnerabilities } from "./vulnerabilities.js";
import { controls } from "./controls.js";
import { cyberRisks } from "./cyberRisks.js";
import { scenarios } from "./scenarios.js";
import { riskAssessments } from "./riskAssessments.js";
import { mitigationPlans } from "./mitigationPlans.js";
import { users } from "./users.js";
import { mulberry32 } from "./relationshipHeuristics.js";

const PROCESS_CATALOG = 35;

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

function buildObjectiveRelationships(index: number): MockObjectiveRelationships {
  const rng = mulberry32(0x4f424a00 + index * 7919 + 13);

  const nCr = 3 + Math.floor(rng() * 4);
  const startCr = Math.floor(rng() * cyberRisks.length);
  const crIndices: number[] = [];
  for (let k = 0; k < nCr; k++) {
    const step = 1 + Math.floor(rng() * 7);
    crIndices.push((startCr + k * step) % cyberRisks.length);
  }

  const fromCyberRisks: string[] = [];
  for (const ci of crIndices) {
    fromCyberRisks.push(...cyberRiskAt(ci).assetIds);
  }

  const extraAssetCount = 12 + Math.floor(rng() * 18);
  const extraRandomAssets = pickRandomAssetIds(rng, extraAssetCount);

  const assetIds = dedupeIds([...fromCyberRisks, ...extraRandomAssets]);

  const buFromAssets = assetIds
    .map((id) => getAssetById(id)?.orgUnitId)
    .filter((x): x is string => Boolean(x));
  const extraBu = pickDistinctInts(rng, orgUnits.length, 2 + Math.floor(rng() * 4)).map(
    (k) => orgUnits[k]!.id,
  );
  const orgUnitIds = dedupeIds([
    ...buFromAssets,
    ...crIndices.map((ci) => cyberRiskAt(ci).orgUnitId),
    ...extraBu,
  ]);

  const fromThreats: string[] = [];
  for (const ci of crIndices) {
    fromThreats.push(...cyberRiskAt(ci).threatIds);
  }
  const extraThreats = pickDistinctInts(rng, threats.length, 4 + Math.floor(rng() * 8)).map(
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
    4 + Math.floor(rng() * 10),
  ).map((k) => vulnerabilities[k]!.id);
  const vulnerabilityIds = dedupeIds([...fromVulns, ...extraVulns]);

  const controlIdsFromAssets = assetIds
    .slice(0, 24)
    .flatMap((aid) => getAssetById(aid)?.controlIds.slice(0, 3) ?? []);
  const extraControls = pickDistinctInts(rng, controls.length, 5 + Math.floor(rng() * 10)).map(
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
      .slice(0, 8 + Math.floor(rng() * 6))
      .map((s) => s.id),
    ...pickDistinctInts(rng, scenarios.length, 2).map((k) => scenarios[k]!.id),
  ]);

  const assessmentIds = dedupeIds([
    ...riskAssessments
      .filter((a) => a.cyberRiskIds.some((id) => cyberRiskIds.includes(id)))
      .slice(0, 5 + Math.floor(rng() * 5))
      .map((a) => a.id),
    ...pickDistinctInts(rng, riskAssessments.length, 2).map((k) => riskAssessments[k]!.id),
  ]);

  const mitigationPlanIds = dedupeIds([
    ...mitigationPlans
      .filter((mp) => mp.cyberRiskIds.some((id) => cyberRiskIds.includes(id)))
      .map((mp) => mp.id)
      .slice(0, 5 + Math.floor(rng() * 4)),
    ...pickDistinctInts(rng, mitigationPlans.length, 2).map((k) => mitigationPlans[k]!.id),
  ]);

  const nProc = 4 + Math.floor(rng() * 5);
  const processNums = pickDistinctInts(rng, PROCESS_CATALOG, nProc).map((n) => padId("PRC", n + 1));
  const processIds = dedupeIds(processNums);

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
    processIds,
  };
}

const OBJECTIVE_SEEDS: readonly { title: string; description: string }[] = [
  {
    title: "Resilient digital operations under sustained cyber pressure",
    description:
      "Ensure critical revenue and customer-facing services remain available and recoverable during ransomware, denial-of-service, and major infrastructure incidents, aligned to board risk appetite and regulatory expectations.",
  },
  {
    title: "Trustworthy identity and privileged access for the hybrid workforce",
    description:
      "Reduce credential theft and lateral movement by enforcing least privilege, strong authentication, and consistent lifecycle controls across cloud, on-premises, and partner-managed systems.",
  },
  {
    title: "Data protection and privacy by design across the information estate",
    description:
      "Classify sensitive data, enforce encryption and access boundaries, and demonstrate accountability for customer, employee, and regulated datasets in every major processing workflow.",
  },
  {
    title: "Secure software delivery and third-party technology risk",
    description:
      "Embed security into CI/CD, dependency management, and vendor onboarding so exploitable defects and supply-chain compromises are detected before production and contractual obligations are clear.",
  },
  {
    title: "Operational visibility, detection, and response at enterprise scale",
    description:
      "Invest in correlated telemetry, tuned detections, and rehearsed playbooks so security operations can contain high-impact incidents within agreed time objectives across major org. units.",
  },
  {
    title: "Payment integrity and fraud resilience",
    description:
      "Protect treasury, accounts payable, and customer payment channels from business email compromise, account takeover, and manipulation of payment rails through layered controls and staff awareness.",
  },
  {
    title: "Cloud and platform security posture that matches on-prem rigor",
    description:
      "Apply consistent guardrails, configuration baselines, and workload hardening across multi-cloud estates, including shared responsibility clarity with hyperscalers and managed service providers.",
  },
  {
    title: "Insider risk and human-factor resilience",
    description:
      "Combine people policies, monitoring, and compassionate interventions to deter malicious insiders and reduce harm from mistakes, social engineering, and unsafe shadow IT practices.",
  },
  {
    title: "Network and perimeter modernization toward zero trust principles",
    description:
      "Progressively segment critical assets, retire implicit trust on the internal network, and align remote access, wireless, and partner connectivity to explicit policy and device health signals.",
  },
  {
    title: "Business continuity and crisis communications readiness",
    description:
      "Integrate cyber scenarios into enterprise continuity plans, alternate processing sites, and executive communications so stakeholders receive accurate guidance during prolonged outages or breaches.",
  },
  {
    title: "Compliance and assurance for evolving regulatory landscapes",
    description:
      "Maintain evidence packs, control mappings, and attestation cycles that satisfy GDPR, sector regulators, and customer audit clauses without duplicative manual effort across teams.",
  },
  {
    title: "Secure collaboration and information sharing with partners",
    description:
      "Enable controlled data exchange with suppliers, joint ventures, and regulators through standards-based integrations, contractual security requirements, and periodic assurance of partner controls.",
  },
  {
    title: "Physical and OT convergence risk management",
    description:
      "Extend cyber governance to facilities, industrial control environments, and IoT fleets where safety and availability constraints differ from traditional IT systems but share common adversaries.",
  },
  {
    title: "Metrics-driven cyber risk governance for leadership decisions",
    description:
      "Provide transparent KPIs on exposure reduction, control effectiveness, and incident learning so executives can prioritize investments and track progress against enterprise risk tolerances.",
  },
  {
    title: "Sustainable security culture and skills for a distributed organization",
    description:
      "Scale role-based training, champions programs, and secure-by-default tooling so every employee understands their part in reducing phishing, data mishandling, and unsafe configuration drift.",
  },
] as const;

function buildObjectives(): MockObjective[] {
  return OBJECTIVE_SEEDS.map((seed, i) => {
    const rng = mulberry32(0x4f424b00 + i * 104729 + 3);
    const ownerIdx = 1 + Math.floor(rng() * activeUserCount());
    return {
      id: padId("OBJ", i + 1),
      title: seed.title,
      description: seed.description,
      ownerId: padId("USR", ownerIdx),
      relationships: buildObjectiveRelationships(i),
    };
  });
}

export const objectives: MockObjective[] = buildObjectives();

const objectiveById = new Map(objectives.map((o) => [o.id, o]));

function rebuildObjectiveIndex(): void {
  objectiveById.clear();
  for (const o of objectives) {
    objectiveById.set(o.id, o);
  }
}

/** Re-wire objective relationship ids after catalog replacement (e.g. Pooja migration). */
export function rebuildObjectivesFromCurrentCatalog(): void {
  objectives.length = 0;
  objectives.push(...buildObjectives());
  rebuildObjectiveIndex();
}

export function getObjectiveById(id: string): MockObjective | undefined {
  return objectiveById.get(id);
}
