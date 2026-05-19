import { padId } from "./types.js";
import type { MockCyberRiskAssessment, AssessmentStatus } from "./types.js";
import {
  assessmentScopedCyberRisks,
  assessmentScopedScenarios,
  assessmentScopedThreats,
  assessmentScopedVulnerabilities,
} from "./assessmentScopeRollup.js";
import { users } from "./users.js";
import { assets } from "./assets.js";
import { markCatalogDirty } from "./persistence/catalogStore.js";
import { scenarios } from "./scenarios.js";

function dedupeIdsPreserveOrder(ids: string[]): string[] {
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

export type ComputeAssessmentRollupOptions = {
  excludedScopeCyberRiskIds?: readonly string[];
  excludedScopeThreatIds?: readonly string[];
  excludedScopeVulnerabilityIds?: readonly string[];
  excludedScopeControlIds?: readonly string[];
  excludedScopeScenarioIds?: readonly string[];
  /** When set, scenario ids only include scenarios tagged for this CRA or untagged (seed) scenarios. */
  scenarioScopeAssessmentId?: string;
};

/**
 * Recompute linked cyber risk / threat / vulnerability / scenario ids from in-scope assets
 * and optional scope exclusions (assessment scope UI).
 */
export function computeAssessmentRollupForAssetIds(
  assetIds: readonly string[],
  options?: ComputeAssessmentRollupOptions,
): Pick<
  MockCyberRiskAssessment,
  | "assetIds"
  | "cyberRiskIds"
  | "threatIds"
  | "vulnerabilityIds"
  | "scenarioIds"
  | "excludedScopeCyberRiskIds"
  | "excludedScopeThreatIds"
  | "excludedScopeVulnerabilityIds"
  | "excludedScopeControlIds"
  | "excludedScopeScenarioIds"
> {
  const excludedCr = new Set(options?.excludedScopeCyberRiskIds ?? []);
  const excludedThreat = new Set(options?.excludedScopeThreatIds ?? []);
  const excludedVuln = new Set(options?.excludedScopeVulnerabilityIds ?? []);
  const excludedControl = new Set(options?.excludedScopeControlIds ?? []);
  const excludedScenario = new Set(options?.excludedScopeScenarioIds ?? []);
  const scenarioScopeAssessmentId = options?.scenarioScopeAssessmentId?.trim();
  const sortedAssetIds = dedupeIdsPreserveOrder([...assetIds]);
  if (sortedAssetIds.length === 0) {
    return {
      assetIds: [],
      cyberRiskIds: [],
      threatIds: [],
      vulnerabilityIds: [],
      scenarioIds: [],
      excludedScopeCyberRiskIds: dedupeIdsPreserveOrder([...excludedCr]),
      excludedScopeThreatIds: dedupeIdsPreserveOrder([...excludedThreat]),
      excludedScopeVulnerabilityIds: dedupeIdsPreserveOrder([...excludedVuln]),
      excludedScopeControlIds: dedupeIdsPreserveOrder([...excludedControl]),
      excludedScopeScenarioIds: dedupeIdsPreserveOrder([...excludedScenario]),
    };
  }
  const assetSet = new Set(sortedAssetIds);
  const cyberRiskIds = dedupeIdsPreserveOrder(
    assessmentScopedCyberRisks(assetSet, excludedCr).map((cr) => cr.id),
  );
  const threatIds = dedupeIdsPreserveOrder(
    assessmentScopedThreats(assetSet, excludedCr, excludedThreat).map((t) => t.id),
  );
  const vulnerabilityIds = dedupeIdsPreserveOrder(
    assessmentScopedVulnerabilities(assetSet, excludedVuln).map((v) => v.id),
  );
  const scenarioIds = dedupeIdsPreserveOrder(
    assessmentScopedScenarios(assetSet, excludedCr, excludedScenario, scenarioScopeAssessmentId).map(
      (s) => s.id,
    ),
  );
  return {
    assetIds: sortedAssetIds,
    cyberRiskIds,
    threatIds,
    vulnerabilityIds,
    scenarioIds,
    excludedScopeCyberRiskIds: dedupeIdsPreserveOrder([...excludedCr]),
    excludedScopeThreatIds: dedupeIdsPreserveOrder([...excludedThreat]),
    excludedScopeVulnerabilityIds: dedupeIdsPreserveOrder([...excludedVuln]),
    excludedScopeControlIds: dedupeIdsPreserveOrder([...excludedControl]),
    excludedScopeScenarioIds: dedupeIdsPreserveOrder([...excludedScenario]),
  };
}

/** 3–7 asset indices in 1..assets.length, deterministic per assessment index. */
function pickAssetIdxs(i: number): number[] {
  const { length } = assets;
  if (length === 0) return [];
  const n = Math.min(3 + (i % 5), length);
  const acc = new Set<number>();
  let k = 0;
  while (acc.size < n) {
    acc.add(1 + ((i * 19 + k * 41) % length));
    k += 1;
  }
  return [...acc].sort((a, b) => a - b);
}

type Meta = {
  name: string;
  ownerIdx: number;
  status: AssessmentStatus;
  assessmentType: string;
  startDate: string;
  dueDate: string;
};

const ASSESSMENT_META: Meta[] = [
  { name: "Q1 2026 enterprise risk assessment", ownerIdx: 7, status: "Approved", assessmentType: "Full assessment", startDate: "2026-01-06", dueDate: "2026-03-31" },
  { name: "Annual cybersecurity review 2026", ownerIdx: 14, status: "Scoring", assessmentType: "Annual review", startDate: "2026-01-15", dueDate: "2026-06-30" },
  { name: "Payment systems security assessment", ownerIdx: 9, status: "Approved", assessmentType: "Targeted assessment", startDate: "2025-11-01", dueDate: "2026-01-31" },
  { name: "Cloud infrastructure risk evaluation", ownerIdx: 29, status: "Overdue", assessmentType: "Infrastructure review", startDate: "2026-02-01", dueDate: "2026-04-30" },
  { name: "Third-party vendor risk assessment", ownerIdx: 9, status: "Scoring", assessmentType: "Vendor assessment", startDate: "2026-01-20", dueDate: "2026-05-15" },
  { name: "Data privacy compliance audit", ownerIdx: 33, status: "Approved", assessmentType: "Compliance audit", startDate: "2025-10-01", dueDate: "2025-12-31" },
  { name: "Network security penetration test", ownerIdx: 15, status: "Approved", assessmentType: "Penetration test", startDate: "2026-02-15", dueDate: "2026-03-15" },
  { name: "Application security review", ownerIdx: 27, status: "Overdue", assessmentType: "Code review", startDate: "2026-03-01", dueDate: "2026-05-31" },
  { name: "Incident response readiness assessment", ownerIdx: 49, status: "Scoping", assessmentType: "Tabletop exercise", startDate: "2026-04-01", dueDate: "2026-06-30" },
  { name: "Business continuity risk evaluation", ownerIdx: 20, status: "Scoring", assessmentType: "BCP review", startDate: "2026-02-01", dueDate: "2026-04-15" },
  { name: "Endpoint security assessment", ownerIdx: 39, status: "Approved", assessmentType: "Technical assessment", startDate: "2025-12-01", dueDate: "2026-02-28" },
  { name: "Identity and access management review", ownerIdx: 7, status: "Scoring", assessmentType: "IAM review", startDate: "2026-03-01", dueDate: "2026-05-31" },
  { name: "Database security assessment", ownerIdx: 17, status: "Approved", assessmentType: "Technical assessment", startDate: "2025-09-15", dueDate: "2025-11-30" },
  { name: "Supply chain security review", ownerIdx: 9, status: "Draft", assessmentType: "Vendor assessment", startDate: "2026-04-15", dueDate: "2026-07-31" },
  { name: "Q2 2026 risk assessment cycle", ownerIdx: 14, status: "Draft", assessmentType: "Full assessment", startDate: "2026-04-01", dueDate: "2026-06-30" },
  { name: "Mobile application security test", ownerIdx: 13, status: "Approved", assessmentType: "Penetration test", startDate: "2026-01-10", dueDate: "2026-02-10" },
  { name: "Email system security evaluation", ownerIdx: 3, status: "Approved", assessmentType: "Targeted assessment", startDate: "2025-08-01", dueDate: "2025-10-31" },
  { name: "Financial systems risk assessment", ownerIdx: 16, status: "Scoring", assessmentType: "Full assessment", startDate: "2026-02-15", dueDate: "2026-05-15" },
  { name: "Regulatory compliance assessment", ownerIdx: 33, status: "Scoring", assessmentType: "Compliance audit", startDate: "2026-01-01", dueDate: "2026-03-31" },
  { name: "Container security review", ownerIdx: 29, status: "Draft", assessmentType: "Technical assessment", startDate: "2026-04-01", dueDate: "2026-06-15" },
  { name: "API security assessment", ownerIdx: 13, status: "Approved", assessmentType: "Penetration test", startDate: "2025-11-15", dueDate: "2026-01-15" },
  { name: "Physical security review", ownerIdx: 38, status: "Scoring", assessmentType: "Physical assessment", startDate: "2026-03-01", dueDate: "2026-04-30" },
  { name: "Social engineering resilience test", ownerIdx: 36, status: "Approved", assessmentType: "Penetration test", startDate: "2025-10-15", dueDate: "2025-12-15" },
  { name: "Disaster recovery assessment", ownerIdx: 10, status: "Overdue", assessmentType: "BCP review", startDate: "2026-02-01", dueDate: "2026-04-30" },
  { name: "Encryption standards review", ownerIdx: 40, status: "Approved", assessmentType: "Technical assessment", startDate: "2025-12-15", dueDate: "2026-02-15" },
  { name: "Insider threat assessment", ownerIdx: 20, status: "Scoring", assessmentType: "Full assessment", startDate: "2026-03-15", dueDate: "2026-06-15" },
  { name: "Web application security review", ownerIdx: 27, status: "Approved", assessmentType: "Penetration test", startDate: "2025-09-01", dueDate: "2025-11-30" },
  { name: "Cloud storage security audit", ownerIdx: 8, status: "Approved", assessmentType: "Technical assessment", startDate: "2026-01-01", dueDate: "2026-02-28" },
  { name: "Zero trust architecture assessment", ownerIdx: 15, status: "Draft", assessmentType: "Architecture review", startDate: "2026-05-01", dueDate: "2026-08-31" },
  { name: "GDPR readiness assessment", ownerIdx: 33, status: "Approved", assessmentType: "Compliance audit", startDate: "2025-07-01", dueDate: "2025-09-30" },
  { name: "Ransomware preparedness review", ownerIdx: 7, status: "Scoring", assessmentType: "Tabletop exercise", startDate: "2026-03-01", dueDate: "2026-04-30" },
  { name: "DevOps pipeline security assessment", ownerIdx: 28, status: "Scoring", assessmentType: "Technical assessment", startDate: "2026-02-15", dueDate: "2026-04-30" },
  { name: "Customer data protection review", ownerIdx: 7, status: "Approved", assessmentType: "Full assessment", startDate: "2025-10-01", dueDate: "2025-12-31" },
  { name: "Network perimeter assessment", ownerIdx: 15, status: "Approved", assessmentType: "Penetration test", startDate: "2026-01-15", dueDate: "2026-02-15" },
  { name: "Wireless network security assessment", ownerIdx: 37, status: "Overdue", assessmentType: "Technical assessment", startDate: "2026-03-15", dueDate: "2026-04-30" },
];

function buildAssessmentRow(meta: Meta, index: number): MockCyberRiskAssessment {
  const assetIdxs = pickAssetIdxs(index);
  const assetIds = assetIdxs.map((n) => padId("AST", n));
  const craId = padId("CRA", index + 1);
  const rollup = computeAssessmentRollupForAssetIds(assetIds, {
    scenarioScopeAssessmentId: craId,
  });

  return {
    id: craId,
    name: meta.name,
    ownerId: padId("USR", meta.ownerIdx),
    status: meta.status,
    assessmentType: meta.assessmentType,
    startDate: meta.startDate,
    dueDate: meta.dueDate,
    assetIds: rollup.assetIds,
    cyberRiskIds: rollup.cyberRiskIds,
    threatIds: rollup.threatIds,
    vulnerabilityIds: rollup.vulnerabilityIds,
    scenarioIds: rollup.scenarioIds,
    excludedScopeCyberRiskIds: [],
    excludedScopeThreatIds: [],
    excludedScopeVulnerabilityIds: [],
    excludedScopeControlIds: [],
    excludedScopeScenarioIds: [],
    aiScoringPhase: "idle",
  };
}

/** Mutable catalog (session lifetime); newest `CRA-*` numeric id first for list UIs. */
export const riskAssessments: MockCyberRiskAssessment[] = ASSESSMENT_META.map((m, i) =>
  buildAssessmentRow(m, i),
);

function craNumericSuffix(id: string): number {
  const m = /^CRA-(\d+)$/.exec(id);
  return m ? Number.parseInt(m[1]!, 10) : 0;
}

riskAssessments.sort((a, b) => craNumericSuffix(b.id) - craNumericSuffix(a.id));

const assessmentById = new Map(riskAssessments.map((a) => [a.id, a]));

function rebuildAssessmentIndex(): void {
  assessmentById.clear();
  for (const a of riskAssessments) {
    assessmentById.set(a.id, a);
  }
}

export function replaceRiskAssessmentsFromPersistence(next: MockCyberRiskAssessment[]): void {
  riskAssessments.length = 0;
  riskAssessments.push(...next);
  riskAssessments.sort((a, b) => craNumericSuffix(b.id) - craNumericSuffix(a.id));
  rebuildAssessmentIndex();
  notifyRiskAssessmentListeners();
}

export function updateRiskAssessment(id: string, patch: Partial<MockCyberRiskAssessment>): void {
  const row = assessmentById.get(id);
  if (!row) return;
  Object.assign(row, patch);
  notifyRiskAssessmentListeners();
  markCatalogDirty();
}

/** Removes a catalog row by id (session store). Returns whether a row was removed. */
export function removeRiskAssessmentById(id: string): boolean {
  const idx = riskAssessments.findIndex((a) => a.id === id);
  if (idx === -1) return false;
  riskAssessments.splice(idx, 1);
  rebuildAssessmentIndex();
  notifyRiskAssessmentListeners();
  markCatalogDirty();
  return true;
}

const riskAssessmentListeners = new Set<() => void>();
let riskAssessmentsSnapshotVersion = 0;

function notifyRiskAssessmentListeners(): void {
  riskAssessmentsSnapshotVersion += 1;
  for (const cb of riskAssessmentListeners) cb();
}

export function subscribeRiskAssessments(onStoreChange: () => void): () => void {
  riskAssessmentListeners.add(onStoreChange);
  return () => {
    riskAssessmentListeners.delete(onStoreChange);
  };
}

export function getRiskAssessmentsSnapshotVersion(): number {
  return riskAssessmentsSnapshotVersion;
}

function nextCraNumericId(): number {
  let max = 0;
  for (const a of riskAssessments) {
    max = Math.max(max, craNumericSuffix(a.id));
  }
  return max + 1;
}

/** Next free `CRA-NNN` id (same numbering as {@link addRiskAssessment}). */
export function allocateNextCraId(): string {
  return padId("CRA", nextCraNumericId());
}

/**
 * Adds a new draft assessment at the front of the catalog (threats-style in-memory session store).
 * Call `subscribeRiskAssessments` from UI to refresh lists.
 */
export function addRiskAssessment(): MockCyberRiskAssessment {
  const defaultOwnerId = users[0]?.id ?? "USR-001";
  const id = allocateNextCraId();
  const newRow: MockCyberRiskAssessment = {
    id,
    name: "New cyber risk assessment",
    ownerId: defaultOwnerId,
    status: "Draft",
    assessmentType: "Cyber risk assessment",
    startDate: "",
    dueDate: "",
    assetIds: [],
    cyberRiskIds: [],
    threatIds: [],
    vulnerabilityIds: [],
    scenarioIds: [],
    excludedScopeCyberRiskIds: [],
    excludedScopeThreatIds: [],
    excludedScopeVulnerabilityIds: [],
    excludedScopeControlIds: [],
    excludedScopeScenarioIds: [],
    aiScoringPhase: "idle",
  };
  riskAssessments.unshift(newRow);
  assessmentById.set(newRow.id, newRow);
  notifyRiskAssessmentListeners();
  markCatalogDirty();
  return newRow;
}

export function getRiskAssessmentById(id: string): MockCyberRiskAssessment | undefined {
  return assessmentById.get(id);
}

/**
 * CRA assessments that actually include this threat in their in-scope scenarios: at least one
 * assessment `scenarioIds` entry references a scenario whose `threatIds` contains `threatId`.
 *
 * (Assessments also carry a broad `threatIds` list from asset overlap alone; that is almost every
 * threat for many assessments, so it must not drive this list.)
 */
export function getRiskAssessmentsForThreatId(threatId: string): MockCyberRiskAssessment[] {
  const scenarioIdsForThreat = new Set(
    scenarios.filter((s) => s.threatIds.includes(threatId)).map((s) => s.id),
  );
  return riskAssessments.filter((a) =>
    a.scenarioIds.some((sid) => scenarioIdsForThreat.has(sid)),
  );
}
