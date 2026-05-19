import { afterAll, describe, expect, it } from "vitest";
import { assessmentScopedScenarios } from "./assessmentScopeRollup.js";
import { cyberRisks } from "./cyberRisks.js";
import { getScenariosForPersistence, replaceScenariosFromPersistence } from "./scenarios.js";
import type { MockScenario } from "./types.js";

function cloneScenario(s: MockScenario): MockScenario {
  return JSON.parse(JSON.stringify(s)) as MockScenario;
}

describe("assessmentScopedScenarios CRA filter", () => {
  const backup = getScenariosForPersistence();

  afterAll(() => {
    replaceScenariosFromPersistence(backup);
  });

  it("when craAssessmentId is set, keeps scenarios for that CRA and untagged scenarios", () => {
    const template = backup.find((s) =>
      cyberRisks.some((cr) => cr.id === s.cyberRiskId && cr.assetIds.includes(s.assetId)),
    );
    expect(template).toBeDefined();

    const sTaggedA = cloneScenario(template!);
    sTaggedA.id = "SC-ZZ-SCOPE-TAG-A";
    sTaggedA.assessmentId = "CRA-001";

    const sTaggedB = cloneScenario(template!);
    sTaggedB.id = "SC-ZZ-SCOPE-TAG-B";
    sTaggedB.assessmentId = "CRA-002";

    const sUntagged = cloneScenario(template!);
    sUntagged.id = "SC-ZZ-SCOPE-UNTAG";
    delete sUntagged.assessmentId;

    const rest = backup.filter((s) => !String(s.id).startsWith("SC-ZZ-SCOPE"));
    replaceScenariosFromPersistence([sTaggedA, sTaggedB, sUntagged, ...rest]);

    const assetIds = new Set([template!.assetId]);
    const excludedCr = new Set<string>();
    const excludedSc = new Set<string>();

    const forCra1 = assessmentScopedScenarios(assetIds, excludedCr, excludedSc, "CRA-001");
    expect(forCra1.some((s) => s.id === "SC-ZZ-SCOPE-TAG-A")).toBe(true);
    expect(forCra1.some((s) => s.id === "SC-ZZ-SCOPE-TAG-B")).toBe(false);
    expect(forCra1.some((s) => s.id === "SC-ZZ-SCOPE-UNTAG")).toBe(true);

    const unscoped = assessmentScopedScenarios(assetIds, excludedCr, excludedSc);
    expect(unscoped.some((s) => s.id === "SC-ZZ-SCOPE-TAG-A")).toBe(true);
    expect(unscoped.some((s) => s.id === "SC-ZZ-SCOPE-TAG-B")).toBe(true);
  });
});
