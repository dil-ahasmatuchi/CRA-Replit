import { describe, expect, it } from "vitest";
import bundledCatalog from "../generated/pooja-migrated-catalog.v3.json";
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
});
