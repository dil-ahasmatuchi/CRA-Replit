import { describe, expect, it } from "vitest";
import { candidateScopedThreats } from "./assessmentScopeRollup.js";
import { cyberRisks, replaceCyberRisksFromPersistence } from "./cyberRisks.js";
import { threats } from "./threats.js";

describe("replaceCyberRisksFromPersistence relinks threats", () => {
  it("repopulates threat cyberRiskIds from persisted risk.threatIds", () => {
    const crWithThreats = cyberRisks.find((r) => r.threatIds.length > 0);
    expect(crWithThreats).toBeDefined();

    for (const t of threats) {
      t.cyberRiskIds.length = 0;
      t.relationships.cyberRiskIds.length = 0;
    }

    const clone = cyberRisks.map((r) => structuredClone(r));
    replaceCyberRisksFromPersistence(clone);

    const tid = crWithThreats!.threatIds[0]!;
    const threat = threats.find((t) => t.id === tid);
    expect(threat?.cyberRiskIds).toContain(crWithThreats!.id);

    const assetId =
      crWithThreats!.assetIds.find((id) => threat?.assetIds.includes(id)) ?? threat?.assetIds[0];
    expect(assetId).toBeDefined();
    const scoped = candidateScopedThreats(new Set([assetId!]));
    expect(scoped.some((t) => t.id === tid)).toBe(true);
  });
});
