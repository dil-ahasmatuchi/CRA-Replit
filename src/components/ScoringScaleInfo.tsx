import { Box, Link, Stack, Typography, useTheme } from "@mui/material";
import { Link as RouterLink } from "react-router";

import { ragDataVizColor, type RagDataVizKey } from "../data/ragDataVisualization.js";

/** Left-to-right segments for the CRA 5-point criticality scale (Figma: ITRM — Scoring scale). */
const SCALE_SEGMENT_RAG: readonly RagDataVizKey[] = ["pos05", "pos04", "neu03", "neg04", "neg05"] as const;

const BAR_WIDTH_PX = 4;

export type ScoringScaleInfoProps = {
  /** Router path for “View scoring scales”. */
  scalesHref?: string;
};

/**
 * Scoring scale summary: label, five vertical RAG bars, and link (Figma: ITRM Cyber Risk Management — Scoring scale).
 */
export default function ScoringScaleInfo({
  scalesHref = "/settings/cyber-risk-settings",
}: ScoringScaleInfoProps) {
  const { tokens: t } = useTheme();

  return (
    <Box
      component="section"
      aria-labelledby="scoring-scale-info-heading"
      sx={({ tokens: tok }) => ({
        display: "flex",
        flexDirection: "column",
        alignItems: "flex-start",
        gap: tok.core.spacing["1_5"].value,
        width: "100%",
        height: 77,
      })}
    >
      <Typography
        id="scoring-scale-info-heading"
        component="h2"
        variant="caption"
        sx={({ tokens: tok }) => ({
          m: 0,
          fontFamily: tok.semantic.font.label.sm.fontFamily.value,
          fontSize: tok.semantic.font.label.sm.fontSize.value,
          lineHeight: tok.semantic.font.label.sm.lineHeight.value,
          letterSpacing: tok.semantic.font.label.sm.letterSpacing.value,
          fontWeight: tok.semantic.fontWeight.emphasis.value,
          color: tok.semantic.color.type.default.value,
        })}
      >
        Scoring scale
      </Typography>

      <Stack
        direction="row"
        alignItems="center"
        sx={({ tokens: tok }) => ({
          gap: tok.core.spacing["1"].value,
          minWidth: 0,
          width: "100%",
          height: "100%",
        })}
      >
        <Stack
          direction="row"
          aria-hidden
          sx={({ tokens: tok }) => ({
            gap: tok.core.spacing["0_25"].value,
            py: tok.core.spacing["0_5"].value,
            height: 28,
            flexShrink: 0,
            alignItems: "stretch",
          })}
        >
          {SCALE_SEGMENT_RAG.map((rag) => (
            <Box
              key={rag}
              sx={{
                width: BAR_WIDTH_PX,
                flexShrink: 0,
                alignSelf: "stretch",
                borderRadius: t.semantic.radius.md.value,
                bgcolor: ragDataVizColor(t, rag),
              }}
            />
          ))}
        </Stack>

        <Link
          component={RouterLink}
          to={scalesHref}
          underline="always"
          sx={({ tokens: tok }) => ({
            fontFamily: tok.semantic.font.label.sm.fontFamily.value,
            fontSize: tok.semantic.font.label.sm.fontSize.value,
            lineHeight: tok.semantic.font.label.sm.lineHeight.value,
            letterSpacing: tok.semantic.font.label.sm.letterSpacing.value,
            fontWeight: tok.semantic.fontWeight.emphasis.value,
            color: tok.semantic.color.type.default.value,
            textDecorationColor: "currentcolor",
            minWidth: 0,
          })}
        >
          View scoring scales
        </Link>
      </Stack>
    </Box>
  );
}
