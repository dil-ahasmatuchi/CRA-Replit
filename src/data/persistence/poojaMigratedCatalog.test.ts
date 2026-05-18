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
});
