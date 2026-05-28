import { useMemo } from "react";
import { Card, CardContent, Stack, Typography } from "@mui/material";
import { useTheme } from "@mui/material/styles";

import { useCyberRiskScoringConfig } from "../context/CyberRiskScoringConfigContext.js";
import AssetsByCyberRiskScoreDonut from "./AssetsByCyberRiskScoreDonut.js";
import RisksMatrix, { type AssessmentMatrixMode, type MatrixSelectionPayload } from "./RisksMatrix.js";
import type { MockCyberRisk } from "../data/types.js";
import type { AssessmentAssetResultRow } from "../pages/craAssessmentScopeRows.js";
import type { CraScoringTypeChoice } from "../pages/craNewAssessmentDraftStorage.js";
import { buildAssetCyberRiskDonutSegmentsFromAssessmentAssetRows } from "../utils/assetsByCyberRiskScoreDonutData.js";

function assessmentMatrixModeFromScoringType(scoringType: CraScoringTypeChoice): AssessmentMatrixMode {
  if (scoringType === "inherent") return "inherentOnly";
  return "residualPreferred";
}

export type ResultsHeroProps = {
  /**
   * Cyber risks shown in the likelihood × impact matrix. On Assessment Results this should be the
   * scenario-aligned slice (see `buildHeatmapCyberRisksForResultsTab`), not library rows alone.
   */
  scopedRisks: readonly MockCyberRisk[];
  assetResultRows: readonly AssessmentAssetResultRow[];
  /** Details-tab scoring type: drives Inherent-only vs Residual-default matrix. */
  scoringType: CraScoringTypeChoice;
  /**
   * When set, matrix count clicks filter in-page (e.g. assessment Results table) instead of navigating
   * to the global cyber risks route.
   */
  onMatrixSelection?: (payload: MatrixSelectionPayload) => void;
  /**
   * When true, hides the matrix and donut so overview visuals do not contradict masked scenario scores
   * on the Results table (new CRA draft before catalog release / full reveal).
   */
  suppressScenarioDerivedOverview?: boolean;
};

/** Assessment results overview: scoped likelihood/impact matrix and assets-by-score donut (aligned with Assets grid). */
export default function ResultsHero({
  scopedRisks,
  assetResultRows,
  scoringType,
  onMatrixSelection,
  suppressScenarioDerivedOverview = false,
}: ResultsHeroProps) {
  const { tokens: themeTokens } = useTheme();
  const { cyberScoreBands, likelihoodBands } = useCyberRiskScoringConfig();
  const donutSegments = useMemo(
    () => buildAssetCyberRiskDonutSegmentsFromAssessmentAssetRows(assetResultRows),
    [assetResultRows, cyberScoreBands, likelihoodBands],
  );

  return (
    <Card
      sx={({ tokens }) => ({
        backgroundColor: tokens.semantic.color.surface.variant.value,
        border: "none",
      })}
    >
      <CardContent>
        {suppressScenarioDerivedOverview ? (
          <Typography
            variant="body1"
            sx={({ tokens: t }) => ({
              color: t.semantic.color.type.muted.value,
              maxWidth: 720,
            })}
          >
            Overview charts stay hidden until AI scoring finishes or every in-scope scenario score is
            revealed, so they match the scores in the tables below.
          </Typography>
        ) : (
        <Stack
          direction={{ xs: "column", lg: "row" }}
          gap={3}
          alignItems="stretch"
          sx={{ width: "100%" }}
        >
          <RisksMatrix
            risks={scopedRisks}
            assessmentMatrixMode={assessmentMatrixModeFromScoringType(scoringType)}
            onMatrixSelection={onMatrixSelection}
            sx={({ tokens: t }) => ({
              flex: { lg: "1.5 1 0" },
              minWidth: 0,
              width: "100%",
              border: "none",
              bgcolor: t.semantic.color.background.base.value,
              borderRadius: "16px",
              boxShadow: "none",
            })}
          />
          <AssetsByCyberRiskScoreDonut
            segmentsOverride={donutSegments}
            sx={{
              flex: { lg: "1 1 480px" },
              minWidth: { lg: 320 },
              width: "100%",
              maxWidth: { lg: 480 },
              border: "none",
              bgcolor: themeTokens.semantic.color.background.base.value,
              borderRadius: "16px",
              boxShadow: "none",
            }}
          />
        </Stack>
        )}
      </CardContent>
    </Card>
  );
}
