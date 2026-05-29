import { useEffect, useId, useState, type ReactNode } from "react";
import {
  Box,
  Button,
  Stack,
  Typography,
  useTheme,
} from "@mui/material";

import AiSparkleIcon from "@diligentcorp/atlas-react-bundle/icons/AiSparkle";
import CheckCircleLiteIcon from "@diligentcorp/atlas-react-bundle/icons/CheckCircleLite";

import ScoringInfo, { type ScoringInfoProps } from "./ScoringInfo.js";
import { ScoringStatusBar } from "./ScoringStatusBar.js";

const COMPLETE_TITLE = "AI scoring completed";

function formatElapsedMinutes(elapsedSeconds: number): string {
  return `${String(Math.floor(elapsedSeconds / 60)).padStart(2, "0")} min`;
}

type AiGradientDefsProps = {
  gradientId: string;
  gradientStart: string;
  gradientMiddle: string;
  gradientEnd: string;
};

function AiGradientDefs({
  gradientId,
  gradientStart,
  gradientMiddle,
  gradientEnd,
}: AiGradientDefsProps) {
  return (
    <svg width="0" height="0" aria-hidden style={{ position: "absolute" }}>
      <defs>
        <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stopColor={gradientStart} />
          <stop offset="50%" stopColor={gradientMiddle} />
          <stop offset="100%" stopColor={gradientEnd} />
        </linearGradient>
      </defs>
    </svg>
  );
}

export type ScoringInfoCardProps = ScoringInfoProps & {
  /**
   * When true, only the card chrome and scoring row are shown (no title, subtitle, or AI button).
   * Use when the AI scoring header is not applicable for the current assessment phase.
   */
  omitHeader?: boolean;
  /** Primary heading (Figma: AI scoring). Ignored when `omitHeader` is true. */
  title?: string;
  /**
   * Supporting copy below the title. Ignored when `omitHeader` is true.
   * Pass `null` to hide the subtitle while keeping the title.
   */
  description?: ReactNode | null;
  /** Button label (Figma: Start AI scoring). Ignored when `omitHeader` is true. */
  actionLabel?: string;
  /** Invoked when the primary action is activated. Omit to hide the button. */
  onAction?: () => void;
  /** When true, the action button shows a loading state (hides the sparkle icon). */
  actionLoading?: boolean;
  /** Total in-scope scenarios; used by the processing status bar when actionLoading is true. */
  processingScenariosTotal?: number;
};

/**
 * AI scoring card from Figma (ITRM — Cyber Risk Management, node 11172:76267): header row with title,
 * subtitle, and AI button; bordered container with {@link ScoringInfo} below.
 */
export default function ScoringInfoCard({
  omitHeader = false,
  title = "AI scoring",
  description = "Our AI agent will automatically score all the scenarios.",
  actionLabel = "Start AI scoring",
  onAction,
  actionLoading = false,
  processingScenariosTotal,
  aggregationMethodRadio,
  scoringFormulas,
  scoringScaleInfo,
}: ScoringInfoCardProps = {}) {
  const { tokens } = useTheme();
  const titleId = useId();
  const aiGradientId = useId().replace(/:/g, "");
  const [elapsedSeconds, setElapsedSeconds] = useState(0);

  const aiGradient = tokens.semantic.gradients.ai.default.value;
  const gradientStart = tokens.semantic.color.ai.default.gradientStart.value;
  const gradientMiddle = tokens.semantic.color.ai.default.gradientMiddle.value;
  const gradientEnd = tokens.semantic.color.ai.default.gradientEnd.value;

  useEffect(() => {
    if (!actionLoading) {
      setElapsedSeconds(0);
      return;
    }

    const timer = setInterval(() => {
      setElapsedSeconds((current) => current + 1);
    }, 1000);

    return () => clearInterval(timer);
  }, [actionLoading]);

  const isProcessing = actionLoading;
  const isComplete = !isProcessing && title === COMPLETE_TITLE;
  const displayedTitle = isProcessing ? "Scoring in progress" : title;
  const showDescription = !isProcessing && !isComplete && description != null;

  const titleTypographySx = ({ tokens: t }: { tokens: typeof tokens }) => ({
    fontFamily: t.semantic.font.text.body.fontFamily.value,
    fontSize: t.semantic.font.text.body.fontSize.value,
    lineHeight: t.semantic.font.text.body.lineHeight.value,
    letterSpacing: t.semantic.font.text.body.letterSpacing.value,
    fontWeight: t.semantic.fontWeight.emphasis.value,
  });

  const completeTitleRow = (
    <>
      <AiGradientDefs
        gradientId={aiGradientId}
        gradientStart={gradientStart}
        gradientMiddle={gradientMiddle}
        gradientEnd={gradientEnd}
      />
      <Stack
        direction="row"
        alignItems="center"
        sx={({ tokens: t }) => ({
          width: "100%",
          minWidth: 0,
          gap: t.core.spacing["1"].value,
        })}
      >
        <Box
          sx={{
            display: "inline-flex",
            flexShrink: 0,
            width: 24,
            height: 24,
            lineHeight: 0,
            color: "transparent",
            "& svg": {
              width: 24,
              height: 24,
            },
            "& path": {
              fill: `url(#${aiGradientId})`,
              stroke: "none",
            },
          }}
        >
          <CheckCircleLiteIcon aria-hidden />
        </Box>
        <Box
          component="h2"
          id={titleId}
          sx={{
            m: 0,
            p: 0,
            minWidth: 0,
            maxWidth: "100%",
            border: "none",
            overflow: "hidden",
            textOverflow: "ellipsis",
            whiteSpace: "nowrap",
          }}
        >
          <Box
            component="span"
            style={{
              display: "inline-block",
              maxWidth: "100%",
              backgroundImage: aiGradient,
              backgroundSize: "100% 100%",
              backgroundRepeat: "no-repeat",
              backgroundColor: "transparent",
              WebkitBackgroundClip: "text",
              backgroundClip: "text",
              color: "transparent",
              WebkitTextFillColor: "transparent",
            }}
            sx={titleTypographySx}
          >
            {displayedTitle}
          </Box>
        </Box>
      </Stack>
    </>
  );

  const defaultTitleRow = (
    <Typography
      id={titleId}
      component="h2"
      variant="body1"
      sx={({ tokens: t }) => ({
        m: 0,
        width: "100%",
        ...titleTypographySx({ tokens: t }),
        color: t.semantic.color.type.default.value,
      })}
    >
      {displayedTitle}
    </Typography>
  );

  return (
    <Box
      component="section"
      aria-labelledby={omitHeader ? undefined : titleId}
      sx={({ tokens: t }) => ({
        width: "100%",
        minWidth: 0,
        maxWidth: "100%",
        boxSizing: "border-box",
        borderRadius: t.semantic.radius.lg.value,
        borderWidth: t.semantic.borderWidth.thin.value,
        borderStyle: "solid",
        borderColor: t.semantic.color.ui.divider.default.value,
        backgroundColor: t.semantic.color.background.base.value,
        px: t.core.spacing["3"].value,
        py: t.core.spacing["2"].value,
        display: "flex",
        flexDirection: "column",
        alignItems: "stretch",
        gap: t.core.spacing["4"].value,
      })}
    >
      {omitHeader ? null : (
        <Stack
          direction="row"
          alignItems="center"
          justifyContent="space-between"
          sx={({ tokens: t }) => ({
            width: "100%",
            minWidth: 0,
            flexWrap: "wrap",
            gap: t.core.spacing["2"].value,
          })}
        >
          <Stack
            sx={({ tokens: t }) => ({
              flex: "1 1 0",
              minWidth: 0,
              gap: isProcessing
                ? t.core.spacing["2"].value
                : t.core.spacing["0_5"].value,
              alignItems: "flex-start",
            })}
          >
            {isComplete ? completeTitleRow : defaultTitleRow}
            {isProcessing ? (
              <ScoringStatusBar
                scenariosComplete={0}
                scenariosTotal={processingScenariosTotal ?? 0}
                elapsedTime={formatElapsedMinutes(elapsedSeconds)}
                animateScenariosProgress
              />
            ) : showDescription ? (
              typeof description === "string" ? (
                <Typography
                  component="p"
                  variant="textMd"
                  sx={({ tokens: t }) => ({
                    m: 0,
                    width: "100%",
                    fontFamily: t.semantic.font.text.md.fontFamily.value,
                    fontSize: t.semantic.font.text.md.fontSize.value,
                    lineHeight: t.semantic.font.text.md.lineHeight.value,
                    letterSpacing: t.semantic.font.text.md.letterSpacing.value,
                    fontWeight: t.core.fontWeight.regular.value,
                    color: t.semantic.color.type.default.value,
                  })}
                >
                  {description}
                </Typography>
              ) : (
                <Box
                  sx={({ tokens: t }) => ({
                    width: "100%",
                    minWidth: 0,
                    fontFamily: t.semantic.font.text.md.fontFamily.value,
                    fontSize: t.semantic.font.text.md.fontSize.value,
                    lineHeight: t.semantic.font.text.md.lineHeight.value,
                    letterSpacing: t.semantic.font.text.md.letterSpacing.value,
                    fontWeight: t.core.fontWeight.regular.value,
                    color: t.semantic.color.type.default.value,
                  })}
                >
                  {description}
                </Box>
              )
            ) : null}
          </Stack>

          {onAction && !actionLoading ? (
            <Button
              type="button"
              variant="outlined"
              color="ai"
              size="medium"
              startIcon={<AiSparkleIcon aria-hidden />}
              onClick={onAction}
              sx={({ tokens: t }) => ({
                flexShrink: 0,
                alignSelf: { xs: "stretch", sm: "center" },
                minHeight: 40,
                px: t.core.spacing["1_5"].value,
                py: t.core.spacing["0_5"].value,
                borderRadius: t.semantic.radius.lg.value,
              })}
            >
              {actionLabel}
            </Button>
          ) : null}
        </Stack>
      )}

      <ScoringInfo
        aggregationMethodRadio={aggregationMethodRadio}
        scoringFormulas={scoringFormulas}
        scoringScaleInfo={scoringScaleInfo}
      />
    </Box>
  );
}
