import { PageHeader } from "@diligentcorp/atlas-react-bundle";
import { Button, Stack, useTheme } from "@mui/material";
import type { ReactNode } from "react";

import MetaTag from "./MetaTag.js";
import { formatScenarioConfidencePercent } from "../utils/scenarioConfidence.js";

export type ScoringRationaleHeaderProps = {
  /** Scenario display name (page title). */
  scenarioName: string;
  /** Shown below the title when set (e.g. scenario primary id). */
  scenarioId?: string;
  /** AI scoring confidence (1–100); shown as a percentage next to scenario metadata. */
  confidencePercent?: number;
  breadcrumbs: ReactNode;
  onBack: () => void;
  backButtonAriaLabel: string;
  onSave?: () => void;
};

export default function ScoringRationaleHeader({
  scenarioName,
  scenarioId,
  confidencePercent,
  breadcrumbs,
  onBack,
  backButtonAriaLabel,
  onSave,
}: ScoringRationaleHeaderProps) {
  const { tokens } = useTheme();
  const metaRowInset = `calc(${tokens.component.button.iconOnly.medium.width.value} + ${tokens.component.pageHeader.desktop.mainContent.gap.value})`;

  return (
    <Stack
      component="section"
      spacing={0}
      sx={{ width: "100%", alignSelf: "stretch", minWidth: 0 }}
    >
      <PageHeader
        pageTitle={scenarioName}
        breadcrumbs={breadcrumbs}
        moreButton={
          onSave ? (
            <Button variant="text" size="medium" onClick={onSave}>
              Save changes
            </Button>
          ) : undefined
        }
        slotProps={{
          backButton: {
            "aria-label": backButtonAriaLabel,
            onClick: onBack,
          },
        }}
      />
      {scenarioId != null || confidencePercent != null ? (
        <Stack
          direction="row"
          component="div"
          flexWrap="wrap"
          gap={1}
          sx={{
            alignItems: "center",
            marginBottom: tokens.core.spacing["2"].value,
            paddingInlineStart: metaRowInset,
          }}
        >
          {scenarioId ? <MetaTag label="Scenario ID" value={scenarioId} /> : null}
          {confidencePercent != null ? (
            <MetaTag
              label="Confidence"
              value={formatScenarioConfidencePercent(confidencePercent)}
            />
          ) : null}
        </Stack>
      ) : null}
    </Stack>
  );
}
