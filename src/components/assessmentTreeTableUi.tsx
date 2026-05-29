import type { ReactNode } from "react";
import { Box, IconButton, Stack, Typography } from "@mui/material";
import type { Theme } from "@mui/material/styles";

import ExpandDownIcon from "@diligentcorp/atlas-react-bundle/icons/ExpandDown";

/** Name column fixed width (sticky first column) for assessment tree tables. */
export const ASSESSMENT_TREE_NAME_COL_WIDTH_PX = 400;

export const ASSESSMENT_IMPACT_MIN_PX = 80;
export const ASSESSMENT_THREAT_MIN_PX = 132;
export const ASSESSMENT_VULNERABILITY_MIN_PX = 164;
export const ASSESSMENT_LIKELIHOOD_MIN_PX = 110;
export const ASSESSMENT_CYBER_RISK_SCORE_MIN_PX = 134;
export const ASSESSMENT_MITIGATION_MIN_PX = 176;
export const ASSESSMENT_CONFIDENCE_MIN_PX = 110;

const assessmentMetricThBase = {
  px: 2,
  width: "0.01%",
  maxWidth: "max-content",
  boxSizing: "border-box" as const,
  overflow: "visible",
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
};

const assessmentMetricTdBase = {
  px: 2,
  py: 0,
  width: "0.01%",
  maxWidth: "max-content",
  verticalAlign: "middle" as const,
  boxSizing: "border-box" as const,
  overflow: "visible",
  whiteSpace: "nowrap" as const,
};

export const assessmentMetricThSx = (minWidth: number) => ({
  ...assessmentMetricThBase,
  minWidth,
});

export const assessmentMetricTdSx = (minWidth: number) => ({
  ...assessmentMetricTdBase,
  minWidth,
});

export const assessmentTreeNameHeadCellSx = ({ tokens: t }: Theme) => ({
  position: "sticky" as const,
  left: 0,
  zIndex: 3,
  width: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  minWidth: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  maxWidth: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  boxSizing: "border-box" as const,
  bgcolor: t.semantic.color.background.container.value,
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
  overflow: "visible" as const,
});

export const assessmentTreeNameBodyCellSx = ({ tokens: t }: Theme) => ({
  position: "sticky" as const,
  left: 0,
  zIndex: 2,
  bgcolor: t.semantic.color.background.base.value,
  width: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  minWidth: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  maxWidth: ASSESSMENT_TREE_NAME_COL_WIDTH_PX,
  boxSizing: "border-box" as const,
  whiteSpace: "normal" as const,
  wordBreak: "break-word" as const,
  overflowWrap: "break-word" as const,
  overflow: "visible" as const,
  py: 0,
  height: 1,
});

export const assessmentTreeRowBodyCellBgSx = ({ tokens: t }: Theme) => ({
  bgcolor: t.semantic.color.background.base.value,
});

export const scoreTableCellContentSx = {
  display: "flex",
  alignItems: "center",
  width: "max-content",
  maxWidth: "100%",
  minWidth: 0,
  overflow: "visible",
  boxSizing: "border-box" as const,
};

export type TreeConnectorRow = {
  id: string;
  kind: "cyberRisk" | "scenario";
  groupId: string;
};

export type ConnectorType = "none" | "first" | "middle" | "last";

export function getConnectorType(
  row: TreeConnectorRow,
  visibleRows: TreeConnectorRow[],
  currentIndex: number,
): ConnectorType {
  if (row.kind === "cyberRisk") return "none";

  const prevRow = visibleRows[currentIndex - 1];
  const nextRow = visibleRows[currentIndex + 1];

  const isFirstInGroup = prevRow?.kind === "cyberRisk" && prevRow.id === row.groupId;
  const hasNextSibling = nextRow?.kind === "scenario" && nextRow.groupId === row.groupId;

  if (isFirstInGroup && hasNextSibling) return "first";
  if (isFirstInGroup && !hasNextSibling) return "last";
  if (!isFirstInGroup && hasNextSibling) return "middle";
  return "last";
}

export function TreeConnector({ type, height }: { type: ConnectorType; height: number }) {
  if (type === "none") return null;

  const SVG_WIDTH = 32;
  const CORNER_RADIUS = 10;
  const LINE_X = 12;
  const STUB_END_X = 20;
  const centerY = height / 2;

  return (
    <Box
      component="svg"
      width={SVG_WIDTH}
      height="100%"
      viewBox={`0 0 ${SVG_WIDTH} ${height}`}
      preserveAspectRatio="none"
      sx={({ tokens: t }) => ({
        position: "absolute",
        left: 0,
        top: 0,
        zIndex: 0,
        pointerEvents: "none",
        overflow: "visible",
        "& path": {
          stroke: t.semantic.color.ui.divider.default.value,
          strokeWidth: t.semantic.borderWidth.thin.value,
          fill: "none",
        },
      })}
      aria-hidden="true"
    >
      {(type === "first" || type === "middle") && (
        <>
          <path d={`M ${LINE_X} 0 V ${height}`} />
          <path
            d={`M ${LINE_X} ${centerY - CORNER_RADIUS} Q ${LINE_X} ${centerY} ${
              LINE_X + CORNER_RADIUS
            } ${centerY} H ${STUB_END_X}`}
          />
        </>
      )}
      {type === "last" && (
        <path
          d={`M ${LINE_X} 0 V ${centerY - CORNER_RADIUS} Q ${LINE_X} ${centerY} ${
            LINE_X + CORNER_RADIUS
          } ${centerY} H ${STUB_END_X}`}
        />
      )}
    </Box>
  );
}

export type AssessmentTreeNameCellProps = {
  kind: "cyberRisk" | "scenario";
  tag: string;
  title: ReactNode;
  expanded: boolean;
  onToggle: () => void;
  connectorType: ConnectorType;
};

export function AssessmentTreeNameCell({
  kind,
  tag,
  title,
  expanded,
  onToggle,
  connectorType,
}: AssessmentTreeNameCellProps) {
  const isGroup = kind === "cyberRisk";
  const rowHeight = 56;
  return (
    <Box sx={{ position: "relative", height: "100%", minHeight: rowHeight }}>
      {connectorType !== "none" && <TreeConnector type={connectorType} height={rowHeight} />}
      <Stack
        direction="row"
        alignItems={isGroup ? "center" : "flex-start"}
        gap={1}
        sx={(theme) => ({
          py: 2,
          minHeight: 56,
          pl: isGroup ? 0 : `calc(${theme.spacing(4)} + 10px)`,
          position: "relative",
          zIndex: 1,
        })}
      >
        {isGroup ? (
          <IconButton
            size="small"
            onClick={(e) => {
              e.stopPropagation();
              onToggle();
            }}
            aria-expanded={expanded}
            aria-label={expanded ? "Collapse cyber risk" : "Expand cyber risk"}
            sx={{ p: 0.5 }}
          >
            <Box
              component="span"
              aria-hidden
              sx={{
                display: "inline-flex",
                transform: expanded ? "rotate(0deg)" : "rotate(-90deg)",
                transition: "transform 0.2s",
              }}
            >
              <ExpandDownIcon />
            </Box>
          </IconButton>
        ) : null}
        <Stack gap={0.25} sx={{ minWidth: 0, flex: 1 }}>
          <Box
            sx={({ tokens: t }) => ({
              alignSelf: "flex-start",
              px: 0.5,
              py: 0.25,
              borderRadius: t.semantic.radius.sm.value,
              bgcolor: t.semantic.color.surface.variant.value,
            })}
          >
            <Typography
              sx={({ tokens: t }) => ({
                fontSize: t.semantic.font.label.sm.fontSize.value,
                lineHeight: t.semantic.font.label.sm.lineHeight.value,
                letterSpacing: t.semantic.font.label.sm.letterSpacing.value,
                fontWeight: 600,
                color: t.semantic.color.type.default.value,
              })}
            >
              {tag}
            </Typography>
          </Box>
          <Box
            sx={{
              minWidth: 0,
              whiteSpace: "normal",
              wordBreak: "break-word",
              overflowWrap: "break-word",
              "& .MuiTypography-root": { whiteSpace: "normal" },
              "& .MuiLink-root": { whiteSpace: "normal" },
            }}
          >
            {title}
          </Box>
        </Stack>
      </Stack>
    </Box>
  );
}
