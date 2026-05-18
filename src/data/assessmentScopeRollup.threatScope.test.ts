import { describe, expect, it } from "vitest";
import {
  assessmentScopedThreats,
  candidateScopedThreats,
} from "./assessmentScopeRollup.js";
import { threats } from "./threats.js";

describe("asset-only threat scoping", () => {
  it("includes threats by asset intersection only", () => {
    const t = threats.find((th) => th.assetIds.length > 0);
    expect(t).toBeDefined();
    const aid = t!.assetIds[0]!;
    const cand = candidateScopedThreats(new Set([aid]));
    expect(cand.some((x) => x.id === t!.id)).toBe(true);
  });

  it("assessmentScopedThreats applies threat exclusions only", () => {
    const t = threats.find((th) => th.assetIds.length > 0);
    expect(t).toBeDefined();
    const aid = t!.assetIds[0]!;
    const withEx = assessmentScopedThreats(new Set([aid]), new Set(), new Set([t!.id]));
    expect(withEx.some((x) => x.id === t!.id)).toBe(false);
  });
});
