import { useEffect, useState } from "react";
import { Box, Stack, Typography } from "@mui/material";
import type { Theme } from "@mui/material/styles";
import { ScoringLoading } from "./ScoringLoading.js";

export interface ScoringStatusBarProps {
  scenariosComplete: number;
  scenariosTotal: number;
  elapsedTime: string;
  /** Animates the completed count from 0 to `scenariosTotal`, +1 per interval. */
  animateScenariosProgress?: boolean;
  /** Milliseconds between progress increments when `animateScenariosProgress` is true. */
  progressIntervalMs?: number;
}

export function ScoringStatusBar({
  scenariosComplete,
  scenariosTotal,
  elapsedTime,
  animateScenariosProgress = false,
  progressIntervalMs = 1000,
}: ScoringStatusBarProps) {
  const [animatedScenariosComplete, setAnimatedScenariosComplete] = useState(0);

  useEffect(() => {
    if (!animateScenariosProgress) return;

    setAnimatedScenariosComplete(0);
    const timer = setInterval(() => {
      setAnimatedScenariosComplete((current) =>
        current < scenariosTotal ? current + 1 : current,
      );
    }, progressIntervalMs);

    return () => clearInterval(timer);
  }, [animateScenariosProgress, scenariosTotal, progressIntervalMs]);

  const displayedScenariosComplete = animateScenariosProgress
    ? animatedScenariosComplete
    : scenariosComplete;
  return (
    <Stack
      direction="row"
      alignItems="center"
      gap={2}
      sx={{
        fontSize: 14,
        lineHeight: "20px",
        letterSpacing: "0.010em",
        whiteSpace: "nowrap",
      }}
    >
      <ScoringLoading />

      <Box
        sx={({ tokens: t }: Theme) => ({
          width: "2px",
          height: 12,
          bgcolor: t.semantic.color.ui.divider.default.value,
          flexShrink: 0,
        })}
      />

      <Typography
        component="span"
        sx={({ tokens: t }: Theme) => ({
          fontSize: 14,
          lineHeight: "20px",
          letterSpacing: "0.010em",
        })}
      >
        <Typography
          component="span"
          sx={({ tokens: t }: Theme) => ({
            color: t.semantic.color.type.muted.value,
          })}
        >
          Scenarios:{" "}
        </Typography>
        <Typography
          component="span"
          sx={({ tokens: t }: Theme) => ({
            color: t.semantic.color.type.default.value,
            fontWeight: 700,
          })}
        >
          {displayedScenariosComplete} / {scenariosTotal}
        </Typography>
      </Typography>

      <Box
        sx={({ tokens: t }: Theme) => ({
          width: "2px",
          height: 12,
          bgcolor: t.semantic.color.ui.divider.default.value,
          flexShrink: 0,
        })}
      />

      <Typography
        component="span"
        sx={({ tokens: t }: Theme) => ({
          fontSize: 14,
          lineHeight: "20px",
          letterSpacing: "0.010em",
        })}
      >
        <Typography
          component="span"
          sx={({ tokens: t }: Theme) => ({
            color: t.semantic.color.type.muted.value,
          })}
        >
          Elapsed time:{" "}
        </Typography>
        <Typography
          component="span"
          sx={({ tokens: t }: Theme) => ({
            color: t.semantic.color.type.default.value,
            fontWeight: 700,
          })}
        >
          {elapsedTime}
        </Typography>
      </Typography>
    </Stack>
  );
}
