import { useEffect, useState } from "react";
import { Box } from "@mui/material";

const BAR_COLORS = {
  idle: "rgb(218,218,218)",
  beforeIdle: "rgb(165,171,192)",
  postActive: "rgb(113,118,139)",
  active: "rgb(76,82,101)",
};

type BarState = "idle" | "beforeIdle" | "postActive" | "active";

export interface ScoringLoadingProps {
  barCount?: number;
  stepDuration?: number;
  fadeDuration?: number;
  size?: "small" | "large";
}

function getBarState(barIndex: number, headPosition: number, barCount: number): BarState {
  const distance = ((headPosition - barIndex) % barCount + barCount) % barCount;
  if (distance === 0) return "active";
  if (distance === 1) return "postActive";
  if (distance === 2) return "beforeIdle";
  return "idle";
}

export function ScoringLoading({
  barCount = 6,
  stepDuration = 380,
  fadeDuration = 360,
  size = "small",
}: ScoringLoadingProps) {
  const [head, setHead] = useState(0);

  useEffect(() => {
    const timer = setInterval(() => {
      setHead((prev) => (prev + 1) % barCount);
    }, stepDuration);
    return () => clearInterval(timer);
  }, [barCount, stepDuration]);

  const barWidth = size === "large" ? 14 : 4;
  const barHeight = size === "large" ? 44 : 12;
  const barGap = size === "large" ? 14 : 4;

  return (
    <Box
      role="img"
      aria-label="Loading scenarios"
      sx={{
        display: "inline-flex",
        alignItems: "center",
        gap: `${barGap}px`,
        flexShrink: 0,
      }}
    >
      {Array.from({ length: barCount }, (_, i) => {
        const state = getBarState(i, head, barCount);
        return (
          <Box
            key={i}
            sx={{
              width: barWidth,
              height: barHeight,
              borderRadius: "100px",
              backgroundColor:
                state === "active"
                  ? BAR_COLORS.active
                  : state === "postActive"
                    ? BAR_COLORS.postActive
                    : state === "beforeIdle"
                      ? BAR_COLORS.beforeIdle
                      : BAR_COLORS.idle,
              transition: `background-color ${fadeDuration}ms cubic-bezier(0.33, 0, 0.2, 1)`,
              willChange: "background-color",
            }}
          />
        );
      })}
    </Box>
  );
}
