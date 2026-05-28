import { describe, expect, it } from "vitest";

import {
  craScoringTypeChoiceFromCatalogAssessmentType,
  normalizeAiScoringPhaseForHydrate,
} from "./craAssessmentDraftTypes.js";

describe("normalizeAiScoringPhaseForHydrate", () => {
  it("returns complete and idle unchanged", () => {
    expect(normalizeAiScoringPhaseForHydrate("complete")).toBe("complete");
    expect(normalizeAiScoringPhaseForHydrate("idle")).toBe("idle");
  });

  it("maps processing to idle", () => {
    expect(normalizeAiScoringPhaseForHydrate("processing")).toBe("idle");
  });

  it("defaults unknown or missing to idle", () => {
    expect(normalizeAiScoringPhaseForHydrate(undefined)).toBe("idle");
    expect(normalizeAiScoringPhaseForHydrate(null)).toBe("idle");
    expect(normalizeAiScoringPhaseForHydrate("")).toBe("idle");
    expect(normalizeAiScoringPhaseForHydrate(1)).toBe("idle");
  });
});

describe("craScoringTypeChoiceFromCatalogAssessmentType", () => {
  it("maps catalog assessmentType strings to scoring tab basis", () => {
    expect(craScoringTypeChoiceFromCatalogAssessmentType("Inherent scoring")).toBe("inherent");
    expect(craScoringTypeChoiceFromCatalogAssessmentType("Residual scoring")).toBe("residual");
    expect(craScoringTypeChoiceFromCatalogAssessmentType("Cyber risk assessment")).toBe("residual");
  });
});
