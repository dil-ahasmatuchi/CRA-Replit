import { describe, expect, it } from "vitest";

import { getCellLevel } from "./RisksMatrix.js";

describe("getCellLevel", () => {
  it("corners: VL×VL and VH×VH extremes", () => {
    expect(getCellLevel(4, 0)).toBe("veryLow"); // score 5
    expect(getCellLevel(0, 4)).toBe("veryHigh"); // score 125
  });

  it("VH×VL and VL×VH (symmetric score 25) map to very low", () => {
    expect(getCellLevel(0, 0)).toBe("veryLow");
    expect(getCellLevel(4, 4)).toBe("veryLow");
  });

  it("bracket edges on achievable scores", () => {
    expect(getCellLevel(0, 0)).toBe("veryLow"); // 25 — upper bound of very low
    expect(getCellLevel(0, 1)).toBe("low"); // 50 — upper bound of low
    expect(getCellLevel(0, 2)).toBe("medium"); // 75 — upper bound of medium
    expect(getCellLevel(0, 3)).toBe("high"); // 100 — upper bound of high
    expect(getCellLevel(0, 4)).toBe("veryHigh"); // 125
  });

  it("score 30 (first step above 25) is low", () => {
    expect(getCellLevel(2, 1)).toBe("low"); // 5*3*2 = 30
  });
});
