import { useCallback, useId, useMemo } from "react";
import {
  Box,
  FormControl,
  FormHelperText,
  MenuItem,
  Select,
  type SelectChangeEvent,
  Stack,
  Typography,
} from "@mui/material";

import {
  formatMetricConfidenceHelpText,
  generateMetricFieldConfidencePercent,
  isValidConfidencePercent,
} from "../utils/scenarioConfidence.js";

import {
  formatBandRangeEnDash,
  getActiveCyberRiskScoreBands,
  getActiveLikelihoodBands,
  resolveCyberRiskScoreBandOrFallback,
  resolveLikelihoodBandOrFallback,
} from "../data/cyberRiskScoringScales.js";
import { ragDataVizColor, type RagDataVizKey } from "../data/ragDataVisualization.js";

/** Score payload for metric dropdowns (numeric band, label, RAG key). */
export type ScoreValue = {
  numeric: string;
  label: string;
  rag: RagDataVizKey;
} | null;

export const SCORE_OPTIONS: NonNullable<ScoreValue>[] = [
  { numeric: "1", label: "Very low", rag: "pos05" },
  { numeric: "2", label: "Low", rag: "pos04" },
  { numeric: "3", label: "Medium", rag: "neu03" },
  { numeric: "4", label: "High", rag: "neg03" },
  { numeric: "5", label: "Very high", rag: "neg05" },
];

export function getActiveLikelihoodOptions(): NonNullable<ScoreValue>[] {
  return getActiveLikelihoodBands().map((row) => ({
    numeric: formatBandRangeEnDash(row),
    label: row.name,
    rag: row.rag,
  }));
}

export function getActiveCyberRiskScoreOptions(): NonNullable<ScoreValue>[] {
  return getActiveCyberRiskScoreBands().map((row) => ({
    numeric: formatBandRangeEnDash(row),
    label: row.name,
    rag: row.rag,
  }));
}

export function likelihoodFromProduct(product: number): NonNullable<ScoreValue> {
  const row = resolveLikelihoodBandOrFallback(product, getActiveLikelihoodBands());
  return {
    numeric: formatBandRangeEnDash(row),
    label: row.name,
    rag: row.rag,
  };
}

export function cyberRiskFromProduct(product: number): NonNullable<ScoreValue> {
  const row = resolveCyberRiskScoreBandOrFallback(product, getActiveCyberRiskScoreBands());
  return {
    numeric: formatBandRangeEnDash(row),
    label: row.name,
    rag: row.rag,
  };
}

export function numericOf(v: ScoreValue): number {
  if (!v) return 0;
  const n = Number(v.numeric);
  return Number.isFinite(n) ? n : 0;
}

export function rangeUpperBound(v: ScoreValue): number {
  if (!v) return 0;
  const dashIdx = v.numeric.indexOf("–");
  if (dashIdx >= 0) {
    const n = Number(v.numeric.slice(dashIdx + 1));
    return Number.isFinite(n) ? n : 0;
  }
  const n = Number(v.numeric);
  return Number.isFinite(n) ? n : 0;
}

export function RagSwatch({ rag }: { rag: RagDataVizKey }) {
  return (
    <Box
      sx={({ tokens: t }) => ({
        width: 16,
        height: 16,
        borderRadius: t.semantic.radius.sm.value,
        flexShrink: 0,
        bgcolor: ragDataVizColor(t, rag),
      })}
      aria-hidden
    />
  );
}

export default function ScoringMetricField({
  label,
  value,
  onChange,
  options = SCORE_OPTIONS,
  confidencePercent,
}: {
  label: string;
  value: ScoreValue;
  onChange: (next: ScoreValue) => void;
  options?: NonNullable<ScoreValue>[];
  /** AI confidence for this metric (1–100). Mocked per label when omitted. */
  confidencePercent?: number;
}) {
  const confidenceHelperId = useId();

  const resolvedConfidencePercent = useMemo(() => {
    if (isValidConfidencePercent(confidencePercent)) return confidencePercent;
    return generateMetricFieldConfidencePercent(label);
  }, [confidencePercent, label]);

  const showConfidenceHelp = value != null;
  const confidenceHelpText = showConfidenceHelp
    ? formatMetricConfidenceHelpText(resolvedConfidencePercent)
    : null;

  const handleChange = useCallback(
    (e: SelectChangeEvent<string>) => {
      const selected = options.find((o) => o.numeric === e.target.value) ?? null;
      onChange(selected);
    },
    [onChange, options],
  );

  return (
    <Stack gap={0.5} sx={{ flex: 1, minWidth: 0 }}>
      <Typography
        variant="caption"
        component="p"
        sx={({ tokens: t }) => ({
          m: 0,
          fontWeight: 600,
          letterSpacing: t.semantic.font.label.sm.letterSpacing.value,
          fontSize: t.semantic.font.label.sm.fontSize.value,
          lineHeight: t.semantic.font.label.sm.lineHeight.value,
          color: t.semantic.color.type.default.value,
        })}
      >
        {label}
      </Typography>
      <FormControl fullWidth>
        <Select
          displayEmpty
          value={value?.numeric ?? ""}
          onChange={handleChange}
          inputProps={{
            "aria-label": label,
            ...(showConfidenceHelp ? { "aria-describedby": confidenceHelperId } : {}),
          }}
          renderValue={(selected) => {
            const opt = options.find((o) => o.numeric === selected);
            if (!opt) {
              return (
                <Typography
                  component="span"
                  sx={({ tokens: t }) => ({
                    color: t.semantic.color.type.muted.value,
                    fontSize: t.semantic.font.text.md.fontSize.value,
                  })}
                >
                  Not scored
                </Typography>
              );
            }
            return (
              <Stack direction="row" alignItems="center" gap={1}>
                <RagSwatch rag={opt.rag} />
                <span>
                  {opt.numeric} {opt.label}
                </span>
              </Stack>
            );
          }}
        >
          {options.map((opt) => (
            <MenuItem key={opt.numeric} value={opt.numeric}>
              <Stack direction="row" alignItems="center" gap={1}>
                <RagSwatch rag={opt.rag} />
                <span>
                  {opt.numeric} {opt.label}
                </span>
              </Stack>
            </MenuItem>
          ))}
        </Select>
        {confidenceHelpText ? (
          <FormHelperText
            id={confidenceHelperId}
            sx={({ tokens: t }) => ({
              m: 0,
              mt: 0.5,
              pl: 0,
              fontSize: t.semantic.font.text.md.fontSize.value,
              lineHeight: t.semantic.font.text.md.lineHeight.value,
              letterSpacing: t.semantic.font.text.md.letterSpacing.value,
              color: t.semantic.color.type.default.value,
            })}
          >
            {confidenceHelpText}
          </FormHelperText>
        ) : null}
      </FormControl>
    </Stack>
  );
}
