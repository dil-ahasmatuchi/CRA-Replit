import type { RiskHeatmapLevel } from "../data/ragDataVisualization.js";
import { cyberRisks } from "../data/cyberRisks.js";
import { riskAssessments } from "../data/riskAssessments.js";
import { getUserById } from "../data/users.js";
import type {
  CyberRiskStatus,
  FivePointScaleLabel,
  FivePointScaleValue,
  MockCyberRisk,
} from "../data/types.js";
import {
  heatmapRowIndexToLikelihoodLabel,
  type CyberRiskHeatmapScoreBasis,
} from "./cyberRiskMatrixAggregates.js";

const SCORE_LABEL_TO_HEATMAP: Record<FivePointScaleLabel, RiskHeatmapLevel> = {
  "Very low": "veryLow",
  Low: "low",
  Medium: "medium",
  High: "high",
  "Very high": "veryHigh",
};

export type CyberRiskRow = {
  id: string;
  name: string;
  riskId: string;
  ownerId: string;
  orgUnitId: string;
  cyberRiskScore: string;
  riskLevel: RiskHeatmapLevel | null;
  ownerName: string;
  ownerInitials: string;
  assets: number;
  workflowStatus: CyberRiskStatus;
  cyberRiskScoreLabel: FivePointScaleLabel;
  /** Inherent 1–5 impact (matrix column). */
  impact: FivePointScaleValue;
  likelihoodLabel: FivePointScaleLabel;
  residualLikelihoodLabel: FivePointScaleLabel;
  residualCyberRiskScoreLabel: FivePointScaleLabel;
  assetIds: string[];
  /** Distinct cyber risk assessments whose scope includes this risk. */
  assessmentCount: number;
};

export type CyberRiskMatrixTableFilter =
  | {
      kind: "cell";
      basis: CyberRiskHeatmapScoreBasis;
      rowIdx: number;
      colIdx: number;
    }
  | {
      kind: "legend";
      basis: CyberRiskHeatmapScoreBasis;
      level: RiskHeatmapLevel;
    };

/** Workflow values shown in filter UI (all statuses used in the app). */
export const CYBER_RISK_WORKFLOW_FILTER_OPTIONS: readonly CyberRiskStatus[] = [
  "Draft",
  "Identification",
  "Assessment",
  "Mitigation",
  "Monitoring",
] as const;

/** Residual cyber risk score (label) options for the filter UI. */
export const CYBER_RISK_SCORE_FILTER_OPTIONS: readonly FivePointScaleLabel[] = [
  "Very low",
  "Low",
  "Medium",
  "High",
  "Very high",
] as const;

export type CyberRiskTableFilters = {
  /** Empty = no restriction (all statuses). */
  workflowStatuses: CyberRiskStatus[];
  /** Empty = no restriction (all owners). */
  ownerIds: string[];
  /** Empty = no restriction; otherwise matches residual score labels shown in the table. */
  scoreLabels: FivePointScaleLabel[];
  /** Empty = no restriction; otherwise row must include at least one of these assets. */
  assetIds: string[];
  /** From heatmap cell/legend; `null` = not filtering by matrix slice. */
  matrixFilter: CyberRiskMatrixTableFilter | null;
  /** `null` = all org. units. */
  orgUnitId: string | null;
};

export const EMPTY_CYBER_RISK_TABLE_FILTERS: CyberRiskTableFilters = {
  workflowStatuses: [],
  ownerIds: [],
  scoreLabels: [],
  assetIds: [],
  matrixFilter: null,
  orgUnitId: null,
};

function buildCyberRiskIdAssessmentCounts(): Map<string, number> {
  const byRiskId = new Map<string, Set<string>>();
  for (const a of riskAssessments) {
    for (const crId of a.cyberRiskIds) {
      let ids = byRiskId.get(crId);
      if (!ids) {
        ids = new Set();
        byRiskId.set(crId, ids);
      }
      ids.add(a.id);
    }
  }
  const out = new Map<string, number>();
  for (const [crId, ids] of byRiskId) {
    out.set(crId, ids.size);
  }
  return out;
}

export function buildCyberRiskRows(): CyberRiskRow[] {
  const assessmentCountByRiskId = buildCyberRiskIdAssessmentCounts();
  return cyberRisks.map((r) => {
    const owner = getUserById(r.ownerId);
    return {
      id: r.id,
      name: r.name,
      riskId: r.id,
      ownerId: r.ownerId,
      orgUnitId: r.orgUnitId,
      cyberRiskScore: `${r.residualCyberRiskScore} - ${r.residualCyberRiskScoreLabel}`,
      riskLevel: SCORE_LABEL_TO_HEATMAP[r.residualCyberRiskScoreLabel],
      ownerName: owner?.fullName ?? "Unassigned",
      ownerInitials: owner?.initials ?? "",
      assets: r.assetIds.length,
      workflowStatus: r.status,
      cyberRiskScoreLabel: r.cyberRiskScoreLabel,
      impact: r.impact,
      likelihoodLabel: r.likelihoodLabel,
      residualLikelihoodLabel: r.residualLikelihoodLabel,
      residualCyberRiskScoreLabel: r.residualCyberRiskScoreLabel,
      assetIds: [...r.assetIds],
      assessmentCount: assessmentCountByRiskId.get(r.id) ?? 0,
    };
  });
}

/** Same rules as the cyber risks list heatmap filter; used for assessment Results tree filtering. */
export function mockCyberRiskMatchesMatrixFilter(
  risk: Pick<
    MockCyberRisk,
    | "impact"
    | "likelihoodLabel"
    | "residualLikelihoodLabel"
    | "cyberRiskScoreLabel"
    | "residualCyberRiskScoreLabel"
    | "residualImpact"
  >,
  matrix: CyberRiskMatrixTableFilter,
): boolean {
  if (matrix.kind === "cell") {
    const { basis, rowIdx, colIdx } = matrix;
    const impactForCell =
      basis === "residual" && risk.residualImpact != null ? risk.residualImpact : risk.impact;
    if (impactForCell !== colIdx + 1) return false;
    const expectedL = heatmapRowIndexToLikelihoodLabel(rowIdx);
    if (expectedL == null) return false;
    const lik =
      basis === "inherent" ? risk.likelihoodLabel : risk.residualLikelihoodLabel;
    return lik === expectedL;
  }
  const level =
    matrix.basis === "inherent"
      ? SCORE_LABEL_TO_HEATMAP[risk.cyberRiskScoreLabel]
      : SCORE_LABEL_TO_HEATMAP[risk.residualCyberRiskScoreLabel];
  return level === matrix.level;
}

function rowMatchesMatrixFilter(
  row: CyberRiskRow,
  matrix: CyberRiskMatrixTableFilter,
): boolean {
  return mockCyberRiskMatchesMatrixFilter(row, matrix);
}

function matchesCyberRiskTableFilters(
  workflowStatus: CyberRiskStatus,
  ownerId: string,
  residualCyberRiskScoreLabel: FivePointScaleLabel,
  assetIds: readonly string[],
  filters: CyberRiskTableFilters,
): boolean {
  const statusSet =
    filters.workflowStatuses.length > 0 ? new Set(filters.workflowStatuses) : null;
  const ownerSet = filters.ownerIds.length > 0 ? new Set(filters.ownerIds) : null;
  const scoreSet = filters.scoreLabels.length > 0 ? new Set(filters.scoreLabels) : null;
  const assetSet = filters.assetIds.length > 0 ? new Set(filters.assetIds) : null;

  if (statusSet && !statusSet.has(workflowStatus)) return false;
  if (ownerSet && !ownerSet.has(ownerId)) return false;
  if (scoreSet && !scoreSet.has(residualCyberRiskScoreLabel)) return false;
  if (assetSet) {
    const hasOverlap = assetIds.some((id) => assetSet.has(id));
    if (!hasOverlap) return false;
  }
  return true;
}

export function applyCyberRiskFilters(
  rows: CyberRiskRow[],
  filters: CyberRiskTableFilters,
): CyberRiskRow[] {
  return rows.filter((row) => {
    if (
      !matchesCyberRiskTableFilters(
        row.workflowStatus,
        row.ownerId,
        row.residualCyberRiskScoreLabel,
        row.assetIds,
        filters,
      )
    ) {
      return false;
    }
    if (filters.orgUnitId != null && row.orgUnitId !== filters.orgUnitId) {
      return false;
    }
    if (filters.matrixFilter != null && !rowMatchesMatrixFilter(row, filters.matrixFilter)) {
      return false;
    }
    return true;
  });
}

/** Strips heatmap and org. unit; catalog scope only uses the four main filter dimensions. */
export function catalogFilterSliceFrom(
  filters: CyberRiskTableFilters,
): CyberRiskTableFilters {
  return {
    ...filters,
    matrixFilter: null,
    orgUnitId: null,
  };
}

/** Same semantics as `applyCyberRiskFilters` for catalog/mock rows using `status` as workflow. */
export function applyCyberRiskTableFiltersToCatalogRows<
  T extends {
    status: CyberRiskStatus;
    ownerId: string;
    residualCyberRiskScoreLabel: FivePointScaleLabel;
    assetIds: readonly string[];
  },
>(rows: T[], filters: CyberRiskTableFilters): T[] {
  const basic = catalogFilterSliceFrom(filters);
  return rows.filter((row) =>
    matchesCyberRiskTableFilters(
      row.status,
      row.ownerId,
      row.residualCyberRiskScoreLabel,
      row.assetIds,
      basic,
    ),
  );
}


/** Counts filter categories with any selection (for toolbar badge). */
export function countCyberRiskFilterCriteria(filters: CyberRiskTableFilters): number {
  let n = 0;
  if (filters.workflowStatuses.length > 0) n++;
  if (filters.ownerIds.length > 0) n++;
  if (filters.scoreLabels.length > 0) n++;
  if (filters.assetIds.length > 0) n++;
  if (filters.matrixFilter != null) n++;
  if (filters.orgUnitId != null) n++;
  return n;
}
