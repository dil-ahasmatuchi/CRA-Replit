import { describe, expect, it } from "vitest";
import bundledCatalog from "../generated/pooja-migrated-catalog.v3.json";
import type { MockScenario } from "../types.js";
import { buildHeatmapCyberRisksForResultsTab } from "../../utils/assessmentResultsHeatmapRisks.js";
import { parentResultChipsFromScenarios } from "../../utils/craAssessmentParentRowChips.js";
import { buildCyberRiskHeatmapAggregates } from "../../utils/cyberRiskMatrixAggregates.js";
import type { AssessmentCyberResultsRow } from "../../pages/craAssessmentScopeRows.js";
import type { PersistedCatalogV3 } from "./catalogTypes.js";
import { parsePersistedCatalog } from "./catalogStore.js";

describe("pooja migrated catalog bundle", () => {
  it("parses as persisted catalog v3", () => {
    const json = JSON.stringify(bundledCatalog);
    const parsed = parsePersistedCatalog(json);
    expect(parsed).not.toBeNull();
    expect(parsed!.schemaVersion).toBe(3);
  });

  it("every cyber risk has threatIds that intersect its assetIds", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    const threatById = new Map(c.threats.map((t) => [t.id, t]));
    const riskAssets = (ids: readonly string[]) => new Set(ids);

    for (const cr of c.cyberRisks) {
      expect(cr.threatIds.length, `${cr.id} threatIds`).toBeGreaterThan(0);
      const assets = riskAssets(cr.assetIds);
      for (const tid of cr.threatIds) {
        const t = threatById.get(tid);
        expect(t, `${cr.id} → ${tid}`).toBeDefined();
        const intersects = t!.assetIds.some((aid) => assets.has(aid));
        expect(intersects, `${cr.id} threat ${tid} must share an asset`).toBe(true);
      }
    }
  });

  it("has referential integrity for core links", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    expect(c.users.length).toBeGreaterThan(0);
    expect(c.assets.length).toBeGreaterThan(0);
    expect(c.scenarios.length).toBeGreaterThan(0);

    const assetIds = new Set(c.assets.map((a) => a.id));
    const crIds = new Set(c.cyberRisks.map((r) => r.id));
    const thrIds = new Set(c.threats.map((t) => t.id));
    const vulnIds = new Set(c.vulnerabilities.map((v) => v.id));
    const userIds = new Set(c.users.map((u) => u.id));
    const scenarioIds = new Set(c.scenarios.map((s) => s.id));

    for (const s of c.scenarios) {
      expect(assetIds.has(s.assetId), `scenario ${s.id} asset`).toBe(true);
      expect(crIds.has(s.cyberRiskId), `scenario ${s.id} cyber risk`).toBe(true);
      for (const tid of s.threatIds) {
        expect(thrIds.has(tid), `scenario ${s.id} threat ${tid}`).toBe(true);
      }
      for (const vid of s.vulnerabilityIds) {
        expect(vulnIds.has(vid), `scenario ${s.id} vuln ${vid}`).toBe(true);
      }
      expect(userIds.has(s.ownerId), `scenario ${s.id} owner`).toBe(true);
    }

    for (const cr of c.cyberRisks) {
      for (const aid of cr.assetIds) {
        expect(assetIds.has(aid), `cyber risk ${cr.id} asset`).toBe(true);
      }
      for (const sid of cr.scenarioIds) {
        expect(scenarioIds.has(sid), `cyber risk ${cr.id} scenario`).toBe(true);
      }
    }

    for (const a of c.riskAssessments) {
      expect(userIds.has(a.ownerId), `assessment ${a.id} owner`).toBe(true);
      for (const sid of a.scenarioIds) {
        expect(scenarioIds.has(sid), `assessment ${a.id} scenario`).toBe(true);
      }
    }
  });

  it("vulnerabilities link to valid assets with full multi-asset lists", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    const assetIds = new Set(c.assets.map((a) => a.id));
    const multi = c.vulnerabilities.filter((v) => v.assetIds.length > 1);
    expect(multi.length).toBeGreaterThan(0);

    for (const v of c.vulnerabilities) {
      expect(v.assetIds.length).toBeGreaterThan(0);
      for (const aid of v.assetIds) {
        expect(assetIds.has(aid), `vulnerability ${v.id} asset ${aid}`).toBe(true);
      }
      expect(v.assetIds.includes(v.relationships.assetId), `vulnerability ${v.id} primary asset`).toBe(
        true,
      );
    }
  });

  it("scenarios carry CRA assessmentId and duplicate template rows split by assessment", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    const craIds = new Set(c.riskAssessments.map((a) => a.id));
    for (const s of c.scenarios) {
      expect(s.assessmentId, `scenario ${s.id}`).toBeDefined();
      expect(craIds.has(s.assessmentId!), `scenario ${s.id} assessment`).toBe(true);
    }
    const sameNameCrAsset = c.scenarios.filter(
      (s) =>
        s.cyberRiskId === "CR-003" &&
        s.assetId === "AST-055" &&
        s.name === "Ransomware and destructive malware on Antivirus Management",
    );
    const byCra = new Set(sameNameCrAsset.map((s) => s.assessmentId));
    expect(byCra.size).toBeGreaterThan(1);
    expect(sameNameCrAsset.length).toBeGreaterThanOrEqual(byCra.size);
  });

  it("CR-001 library inherent matches CRA-029 Highest parent chips (80 High)", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    const cr1 = c.cyberRisks.find((r) => r.id === "CR-001");
    expect(cr1).toBeDefined();
    expect(cr1!.impact).toBe(4);
    expect(cr1!.impactLabel).toBe("High");
    expect(cr1!.likelihood).toBe(20);
    expect(cr1!.likelihoodLabel).toBe("High");
    expect(cr1!.cyberRiskScore).toBe(80);
    expect(cr1!.cyberRiskScoreLabel).toBe("High");

    const s029 = c.scenarios.filter(
      (s) => s.assessmentId === "CRA-029" && s.cyberRiskId === "CR-001",
    ) as MockScenario[];
    const chips = parentResultChipsFromScenarios(s029, "highest");
    expect(chips.impact.numeric).toBe("4");
    expect(chips.likelihood.numeric).toBe("20");
    expect(chips.cyberRiskScore.numeric).toBe("80");
    expect(chips.cyberRiskScore.label).toBe("High");
  });

  it("CRA-030 residual: CR-010 top-right; CR-002 low-likelihood band; heatmap merge preserves inherent", () => {
    const c = bundledCatalog as PersistedCatalogV3;
    const s030 = c.scenarios.filter((s) => s.assessmentId === "CRA-030") as MockScenario[];
    const byCr = (crId: string) => s030.filter((s) => s.cyberRiskId === crId);

    const chips002 = parentResultChipsFromScenarios(byCr("CR-002"), "highest");
    expect(chips002.impact.label).toBe("Very high");
    expect(chips002.likelihood.label).toBe("Low");
    expect(chips002.cyberRiskScore.numeric).toBe("45");
    expect(chips002.cyberRiskScore.label).toBe("Low");

    const chips010 = parentResultChipsFromScenarios(byCr("CR-010"), "highest");
    expect(chips010.impact.label).toBe("Very high");
    expect(chips010.likelihood.label).toBe("Very high");

    const chips001 = parentResultChipsFromScenarios(byCr("CR-001"), "highest");

    function cyberRiskRow(
      id: string,
      name: string,
      chips: ReturnType<typeof parentResultChipsFromScenarios>,
    ): AssessmentCyberResultsRow {
      return {
        id,
        kind: "cyberRisk",
        groupId: id,
        name,
        impact: chips.impact,
        threat: chips.threat,
        vulnerability: chips.vulnerability,
        likelihood: chips.likelihood,
        cyberRiskScore: chips.cyberRiskScore,
      };
    }

    const parents: AssessmentCyberResultsRow[] = [
      cyberRiskRow("CR-010", c.cyberRisks.find((r) => r.id === "CR-010")!.name, chips010),
      cyberRiskRow("CR-002", c.cyberRisks.find((r) => r.id === "CR-002")!.name, chips002),
      cyberRiskRow("CR-001", c.cyberRisks.find((r) => r.id === "CR-001")!.name, chips001),
    ];

    const scoped = (["CR-010", "CR-002", "CR-001"] as const).map((id) => {
      const r = c.cyberRisks.find((x) => x.id === id);
      expect(r, id).toBeDefined();
      return r!;
    });

    const merged = buildHeatmapCyberRisksForResultsTab(scoped, parents);
    const cr002Merged = merged.find((r) => r.id === "CR-002")!;
    const cr002Scoped = scoped.find((r) => r.id === "CR-002")!;
    expect(cr002Merged.impact).toBe(cr002Scoped.impact);
    expect(cr002Merged.likelihood).toBe(cr002Scoped.likelihood);
    expect(cr002Merged.cyberRiskScore).toBe(cr002Scoped.cyberRiskScore);
    expect(cr002Merged.residualCyberRiskScore).toBe(45);
    expect(cr002Merged.residualLikelihoodLabel).toBe("Low");
    expect(cr002Merged.residualImpact).toBe(5);

    const { grid: gridRes } = buildCyberRiskHeatmapAggregates(merged, "residual");
    expect(gridRes[0]![4]).toBe(1);
    expect(gridRes[3]![4]).toBe(1);
    expect(gridRes[2]![3]).toBe(1);
    const flatRes = gridRes.flat();
    expect(Math.max(...flatRes)).toBe(1);
    expect(flatRes.reduce((a, b) => a + b, 0)).toBe(3);
  });
});
