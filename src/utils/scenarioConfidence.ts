import { seededRandom } from "./vulnerabilityListMetrics.js";

/** Stable positive integer seed from a scenario library id. */
export function hashScenarioId(id: string): number {
  let h = 0;
  for (let i = 0; i < id.length; i += 1) {
    h = (Math.imul(31, h) + id.charCodeAt(i)) | 0;
  }
  const n = Math.abs(h);
  return n === 0 ? 1 : n;
}

/** Deterministic AI confidence for a scenario (1–100), stable across reloads for the same id. */
export function generateScenarioConfidencePercent(scenarioId: string): number {
  const seed = hashScenarioId(scenarioId);
  return Math.floor(seededRandom(seed) * 100) + 1;
}

export function isValidConfidencePercent(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 1 && value <= 100;
}

export function formatScenarioConfidencePercent(n: number): string {
  return `${Math.round(n)}%`;
}

/** Deterministic mock AI confidence for a scoring metric field (1–100), stable per seed key. */
export function generateMetricFieldConfidencePercent(seedKey: string): number {
  const seed = hashScenarioId(`metric:${seedKey}`);
  return Math.floor(seededRandom(seed) * 100) + 1;
}

export function formatMetricConfidenceHelpText(percent: number): string {
  return `${formatScenarioConfidencePercent(percent)} confidence`;
}
