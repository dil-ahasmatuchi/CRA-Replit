import { describe, expect, it } from "vitest";
import { buildScoringRationale, buildVulnsByAssetIdMap, formatThreatPhrase } from "./buildScoringRationale.js";

describe("buildScoringRationale", () => {
  it("joins template sections and includes cyber risk and asset names", () => {
    const vuln = {
      id: "VUL-001",
      name: "Weak patching",
      domain: "Operations",
      primaryCIAImpact: ["Integrity"],
      assetIds: ["AST-001"],
    };
    const maps = {
      threatById: new Map([["THR-001", { name: "Phishing" }]]),
      vulnById: new Map([[vuln.id, vuln]]),
      vulnsByAssetId: buildVulnsByAssetIdMap([vuln]),
    };
    const text = buildScoringRationale(
      "Data breach",
      "Phishing",
      "Customer DB",
      "Database",
      "High",
      "Medium",
      "Low",
      "Medium",
      "High",
      ["THR-001"],
      ["VUL-001"],
      "AST-001",
      maps,
    );
    expect(text.split("\n\n").length).toBeGreaterThanOrEqual(6);
    expect(text).toContain("Cyber risk (library) — Data breach");
    expect(text).toContain("Customer DB");
    expect(text).toContain("Weak patching");
    expect(text).toContain("Other vulnerabilities recorded on Customer DB");
  });
});

describe("formatThreatPhrase", () => {
  it("formats multiple threats with Oxford comma", () => {
    expect(formatThreatPhrase(["A", "B", "C"])).toBe("A, B, and C");
  });
});
