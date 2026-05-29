import { useMemo, useState } from "react";
import { Box, Stack, Typography } from "@mui/material";

import { useCyberRiskScoringConfig } from "../context/CyberRiskScoringConfigContext.js";
import ScoringMetricField, {
  getActiveCyberRiskScoreOptions,
  getActiveLikelihoodOptions,
  SCORE_OPTIONS,
  type ScoreValue,
} from "./ScoringMetricField.js";

export type ScoringRationaleDropdownsControlled = {
  impact: ScoreValue;
  threat: ScoreValue;
  vulnerability: ScoreValue;
  likelihood: ScoreValue;
  cyberRiskScore: ScoreValue;
  onImpactChange: (v: ScoreValue) => void;
  onThreatChange: (v: ScoreValue) => void;
  onVulnerabilityChange: (v: ScoreValue) => void;
  onLikelihoodChange: (v: ScoreValue) => void;
  onCyberRiskScoreChange: (v: ScoreValue) => void;
};

export type ScoringRationaleDropdownsProps = {
  /** Section heading (semantic title / H4 md emphasis). */
  title?: string;
  /** When false, the block heading is not rendered. */
  showTitle?: boolean;
  /** When set, dropdowns are controlled (e.g. scenario page with override flow). */
  controlled?: ScoringRationaleDropdownsControlled;
};

/**
 * Surface-subtle container with a row of scoring metric dropdowns, matching the
 * scenario scoring rationale layout in {@link ScoringRationalePage}.
 */
export default function ScoringRationaleDropdowns({
  title = "Scoring rationale",
  showTitle = true,
  controlled,
}: ScoringRationaleDropdownsProps) {
  const { cyberScoreBands, likelihoodBands } = useCyberRiskScoringConfig();
  const likelihoodOptions = useMemo(() => getActiveLikelihoodOptions(), [likelihoodBands]);
  const cyberRiskOptions = useMemo(() => getActiveCyberRiskScoreOptions(), [cyberScoreBands]);

  const [impact, setImpact] = useState<ScoreValue>(SCORE_OPTIONS[2] ?? null);
  const [threat, setThreat] = useState<ScoreValue>(SCORE_OPTIONS[2] ?? null);
  const [vulnerability, setVulnerability] = useState<ScoreValue>(SCORE_OPTIONS[2] ?? null);
  const [likelihood, setLikelihood] = useState<ScoreValue>(
    () => getActiveLikelihoodOptions()[2] ?? null,
  );
  const [cyberRiskScore, setCyberRiskScore] = useState<ScoreValue>(
    () => getActiveCyberRiskScoreOptions()[2] ?? null,
  );

  const c = controlled;
  const i = c?.impact ?? impact;
  const th = c?.threat ?? threat;
  const v = c?.vulnerability ?? vulnerability;
  const l = c?.likelihood ?? likelihood;
  const crs = c?.cyberRiskScore ?? cyberRiskScore;
  const onImpact = c?.onImpactChange ?? setImpact;
  const onThreat = c?.onThreatChange ?? setThreat;
  const onVuln = c?.onVulnerabilityChange ?? setVulnerability;
  const onLikelihood = c?.onLikelihoodChange ?? setLikelihood;
  const onCrs = c?.onCyberRiskScoreChange ?? setCyberRiskScore;

  return (
    <Box
      sx={({ tokens: t }) => ({
        width: "100%",
        boxSizing: "border-box",
        p: 3,
        borderRadius: t.semantic.radius.lg.value,
        bgcolor: t.semantic.color.surface.subtle.value,
        border: "none",
        borderImage: "none",
      })}
    >
      <Stack
        gap={2}
        sx={{
          width: "100%",
          alignItems: "stretch",
        }}
      >
        {showTitle ? (
          <Typography
            component="h2"
            sx={({ tokens: t }) => ({
              m: 0,
              fontFamily: t.semantic.font.title.h4Md.fontFamily.value,
              fontSize: t.semantic.font.title.h4Md.fontSize.value,
              lineHeight: t.semantic.font.title.h4Md.lineHeight.value,
              letterSpacing: t.semantic.font.title.h4Md.letterSpacing.value,
              fontWeight: t.semantic.fontWeight.emphasis.value,
              color: t.semantic.color.type.default.value,
            })}
          >
            {title}
          </Typography>
        ) : null}
        <Stack direction="row" gap={2}>
          <ScoringMetricField label="Asset criticality" value={i} onChange={onImpact} />
          <ScoringMetricField label="Threat severity" value={th} onChange={onThreat} />
          <ScoringMetricField
            label="Vulnerability severity"
            value={v}
            onChange={onVuln}
          />
          <ScoringMetricField
            label="Likelihood"
            value={l}
            onChange={onLikelihood}
            options={likelihoodOptions}
          />
          <ScoringMetricField
            label="Cyber risk score"
            value={crs}
            onChange={onCrs}
            options={cyberRiskOptions}
          />
        </Stack>
      </Stack>
    </Box>
  );
}
