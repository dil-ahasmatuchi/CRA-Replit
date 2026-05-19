import {
  linkMitigationPlanToCyberRisks,
  unlinkMitigationPlanFromCyberRisks,
} from "./cyberRisks.js";
import { markCatalogDirty, touchCatalogForImmediateUiRefresh } from "./persistence/catalogStore.js";
import { padId, getFivePointLabel } from "./types.js";
import type {
  MockMitigationPlan,
  MitigationPlanStatus,
  FivePointScaleValue,
  FivePointScaleLabel,
} from "./types.js";

type PlanRow = [
  name: string,
  ownerIdx: number,
  status: MitigationPlanStatus,
  dueDate: string,
  buIdx: number,
  severity: FivePointScaleValue,
  ctlIdxs: number[],
  crIdxs: number[],
  craIdxs: number[],
];

/** 15 mitigation plans; each links to ≥1 cyber risk and ≥1 control; optional CRA references. */
const raw: PlanRow[] = [
  ["Ransomware recovery enhancement", 7, "In progress", "2026-06-30", 15, 5, [1, 2, 3], [1, 2], [1, 2, 31]],
  ["Phishing defense improvement", 9, "In progress", "2026-05-31", 15, 4, [6, 7, 8], [2, 3], [3, 4, 17]],
  ["DDoS mitigation deployment", 15, "In progress", "2026-04-30", 4, 4, [11, 12, 13], [3, 4], [5, 7, 34]],
  ["Insider threat prevention", 20, "In progress", "2026-07-31", 10, 5, [16, 17, 18], [4, 5], [6, 26, 28]],
  ["BEC awareness program", 7, "Completed", "2025-12-31", 2, 4, [21, 22, 23], [5, 6], [17, 23, 33]],
  ["Regulatory compliance remediation", 33, "In progress", "2026-09-30", 9, 3, [26, 27, 28], [6, 7], [19, 30]],
  ["Supply chain risk reduction", 9, "In progress", "2026-08-31", 12, 4, [31, 32, 33], [7, 8], [5, 14, 22]],
  ["Cloud security hardening", 29, "In progress", "2026-05-31", 4, 4, [36, 37, 38], [8, 9], [4, 10, 24]],
  ["Data exfiltration prevention", 20, "In progress", "2026-08-31", 10, 5, [41, 42, 43], [9, 10], [6, 12, 35]],
  ["Malware defense upgrade", 39, "Completed", "2026-01-31", 4, 3, [46, 47, 48], [10, 11], [11, 13, 21]],
  ["APT detection program", 14, "In progress", "2026-09-30", 15, 5, [51, 52, 53], [11, 12], [2, 15, 35]],
  ["Zero-day preparedness", 14, "In progress", "2026-07-31", 5, 5, [56, 57, 58], [12, 13], [8, 16, 27]],
  ["Vendor breach response", 9, "In progress", "2026-06-30", 12, 4, [61, 62, 63], [14, 15], [5, 9, 29]],
  ["Encryption upgrade program", 40, "In progress", "2026-07-31", 15, 5, [66, 67, 68], [16, 17], [1, 12, 25]],
  ["Session security upgrade", 9, "In progress", "2026-04-30", 2, 3, [71, 72, 73], [18, 19], [11, 18, 32]],
];

export const mitigationPlans: MockMitigationPlan[] = raw.map(
  ([name, ownerIdx, status, dueDate, buIdx, severity, ctlIdxs, crIdxs, craIdxs], i) => ({
    id: padId("MP", i + 1),
    name,
    ownerId: padId("USR", ownerIdx),
    status,
    dueDate,
    orgUnitId: padId("BU", buIdx),
    severity,
    severityLabel: getFivePointLabel(severity),
    controlIds: ctlIdxs.map((n) => padId("CTL", n)),
    cyberRiskIds: crIdxs.map((n) => padId("CR", n)),
    assessmentIds: craIdxs.map((n) => padId("CRA", n)),
    createdAt: new Date(Date.UTC(2025, 0, 1 + i)).toISOString(),
  }),
);

const MP_ID_RE = /^MP-0*(\d+)$/i;

const planById = new Map(mitigationPlans.map((p) => [p.id, p]));

function backfillPlanCreatedAtIfMissing(p: MockMitigationPlan): void {
  const rawIso = p.createdAt?.trim();
  if (rawIso && !Number.isNaN(Date.parse(rawIso))) return;
  const m = MP_ID_RE.exec(p.id);
  const seq = m ? parseInt(m[1]!, 10) : 1;
  p.createdAt = new Date(Date.UTC(2024, 0, seq)).toISOString();
}

function rebuildPlanIndex(): void {
  planById.clear();
  for (const p of mitigationPlans) {
    planById.set(p.id, p);
  }
}

export function replaceMitigationPlansFromPersistence(next: MockMitigationPlan[]): void {
  mitigationPlans.length = 0;
  mitigationPlans.push(...next);
  for (const p of mitigationPlans) {
    backfillPlanCreatedAtIfMissing(p);
  }
  rebuildPlanIndex();
}

export function getMitigationPlanById(id: string): MockMitigationPlan | undefined {
  return planById.get(id);
}

/** Sort key for “newest first”; uses `createdAt` when valid, else MP sequence from id. */
export function mitigationPlanSortTimeMs(p: MockMitigationPlan): number {
  const raw = p.createdAt?.trim();
  if (raw) {
    const t = Date.parse(raw);
    if (!Number.isNaN(t)) return t;
  }
  const m = MP_ID_RE.exec(p.id);
  return m ? parseInt(m[1]!, 10) : 0;
}

function nextMitigationPlanSequence(): number {
  let max = 0;
  for (const p of mitigationPlans) {
    const m = MP_ID_RE.exec(p.id);
    if (m) max = Math.max(max, parseInt(m[1]!, 10));
  }
  return max + 1;
}

export type CreateMitigationPlanInput = {
  name: string;
  cyberRiskIds: readonly string[];
  ownerId: string;
  orgUnitId: string;
  severity: FivePointScaleValue;
  severityLabel: FivePointScaleLabel;
  dueDate: string;
  assetIds: readonly string[];
  relatedControlNames: readonly string[];
  actionPlan: string;
  assessmentIds?: readonly string[];
};

export function createMitigationPlan(input: CreateMitigationPlanInput): MockMitigationPlan {
  const id = padId("MP", nextMitigationPlanSequence());
  const trimmedName = input.name.trim();
  const trimmedAction = input.actionPlan.trim();
  const plan: MockMitigationPlan = {
    id,
    name: trimmedName,
    ownerId: input.ownerId,
    status: "In progress",
    dueDate: input.dueDate,
    orgUnitId: input.orgUnitId,
    severity: input.severity,
    severityLabel: input.severityLabel,
    controlIds: [],
    cyberRiskIds: [...input.cyberRiskIds],
    createdAt: new Date().toISOString(),
    assessmentIds: input.assessmentIds?.length ? [...input.assessmentIds] : [],
    assetIds: input.assetIds.length > 0 ? [...input.assetIds] : undefined,
    actionPlan: trimmedAction ? trimmedAction : undefined,
    relatedControlNames:
      input.relatedControlNames.length > 0 ? [...input.relatedControlNames] : undefined,
  };
  mitigationPlans.push(plan);
  planById.set(plan.id, plan);
  linkMitigationPlanToCyberRisks(plan.id, plan.cyberRiskIds);
  touchCatalogForImmediateUiRefresh();
  markCatalogDirty();
  return plan;
}

export type UpdateMitigationPlanInput = {
  name: string;
  cyberRiskIds: readonly string[];
  ownerId: string;
  orgUnitId: string;
  severity: FivePointScaleValue;
  severityLabel: FivePointScaleLabel;
  dueDate: string;
  assetIds: readonly string[];
  relatedControlNames: readonly string[];
  actionPlan: string;
};

export function updateMitigationPlan(planId: string, input: UpdateMitigationPlanInput): void {
  const plan = planById.get(planId);
  if (!plan) return;

  const prevCyberRiskIds = [...plan.cyberRiskIds];
  unlinkMitigationPlanFromCyberRisks(planId, prevCyberRiskIds);

  const trimmedName = input.name.trim();
  const trimmedAction = input.actionPlan.trim();
  const nextCyberRiskIds = [...new Set(input.cyberRiskIds)];

  plan.name = trimmedName;
  plan.ownerId = input.ownerId;
  plan.orgUnitId = input.orgUnitId;
  plan.severity = input.severity;
  plan.severityLabel = input.severityLabel;
  plan.dueDate = input.dueDate;
  plan.cyberRiskIds = nextCyberRiskIds;
  plan.assetIds = input.assetIds.length > 0 ? [...input.assetIds] : undefined;
  plan.relatedControlNames =
    input.relatedControlNames.length > 0 ? [...input.relatedControlNames] : undefined;
  plan.actionPlan = trimmedAction ? trimmedAction : undefined;

  linkMitigationPlanToCyberRisks(planId, plan.cyberRiskIds);
  touchCatalogForImmediateUiRefresh();
  markCatalogDirty();
}

export function deleteMitigationPlan(planId: string): void {
  const plan = planById.get(planId);
  if (!plan) return;

  unlinkMitigationPlanFromCyberRisks(planId, plan.cyberRiskIds);

  const idx = mitigationPlans.findIndex((p) => p.id === planId);
  if (idx !== -1) mitigationPlans.splice(idx, 1);
  planById.delete(planId);

  touchCatalogForImmediateUiRefresh();
  markCatalogDirty();
}
