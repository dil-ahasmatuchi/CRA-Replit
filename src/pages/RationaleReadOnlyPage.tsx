import { useCallback, useEffect, useMemo, useState } from "react";
import { OverflowBreadcrumbs } from "@diligentcorp/atlas-react-bundle";
import AiSparkleIcon from "@diligentcorp/atlas-react-bundle/icons/AiSparkle";
import { Alert, AlertTitle, Box, Container, Stack, Typography } from "@mui/material";
import { visuallyHidden } from "@mui/utils";
import { NavLink, useLocation, useNavigate, useParams } from "react-router";

import ScoringRationaleHeader from "../components/ScoringRationaleHeader.js";
import ScoringWide from "../components/ScoringWide.js";
import {
  type ScenarioHistoryEntry,
  ScenarioHistorySection,
} from "../components/ScenarioHistorySection.js";
import { buildScenarioHistorySnapshot } from "../components/ScenarioHistoryReadOnlyPanel.js";
import type { ScenarioScoringInitialScores } from "../components/ScenarioScoringDropdownsBlock.js";
import {
  cyberRiskFromProduct,
  likelihoodFromProduct,
  SCORE_OPTIONS,
} from "../components/ScoringMetricField.js";
import { NEW_CRA_SCORING_TAB_INDEX, type CraScenarioDetailLocationState } from "./craNewAssessmentDraftStorage.js";
import { getScenarioById } from "../data/scenarios.js";
import { users } from "../data/users.js";

const NEW_CRA_PATH = "/cyber-risk/cyber-risk-assessments/new";
const ASSESSMENTS_PATH = "/cyber-risk/cyber-risk-assessments";

const SCENARIO_HISTORY_BASELINE_LATEST_OWNER = users[1]!.fullName;
const SCENARIO_HISTORY_BASELINE_PRIOR_OWNER = users[2]!.fullName;

/**
 * Read-only view of scenario scoring rationale history: same page chrome as
 * {@link ScoringRationalePage} (no Save), History only, most recent entry expanded.
 */
export default function RationaleReadOnly() {
  const { scenarioId } = useParams<{ scenarioId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const nav = location.state as CraScenarioDetailLocationState | null;
  const assessmentNameFromNav = nav?.assessmentName;

  const scenario = scenarioId ? getScenarioById(scenarioId) : undefined;
  const assessmentTitle = (assessmentNameFromNav ?? "").trim() || "New cyber risk assessment";

  const initialScores = useMemo((): ScenarioScoringInitialScores => {
    if (!scenario) {
      return {
        impact: null,
        threat: null,
        vulnerability: null,
        likelihood: null,
        cyberRiskScore: null,
      };
    }
    return {
      impact: SCORE_OPTIONS[scenario.impact - 1] ?? null,
      threat: SCORE_OPTIONS[scenario.threatSeverity - 1] ?? null,
      vulnerability: SCORE_OPTIONS[scenario.vulnerabilitySeverity - 1] ?? null,
      likelihood: likelihoodFromProduct(scenario.likelihood),
      cyberRiskScore: cyberRiskFromProduct(scenario.cyberRiskScore),
    };
  }, [scenario]);

  const historyEntries = useMemo((): ScenarioHistoryEntry[] => {
    if (!scenario) return [];
    const latest = buildScenarioHistorySnapshot(scenario, initialScores);
    const prior = buildScenarioHistorySnapshot(scenario, initialScores, {
      rationaleBody: scenario.scoringRationale.split(/\n\n/).slice(0, 3).join("\n\n"),
    });
    return [
      {
        id: "latest",
        owner: SCENARIO_HISTORY_BASELINE_LATEST_OWNER,
        at: new Date("2026-04-23T15:30:30"),
        snapshot: latest,
      },
      {
        id: "prior",
        owner: SCENARIO_HISTORY_BASELINE_PRIOR_OWNER,
        at: new Date("2026-04-22T10:00:00"),
        snapshot: prior,
      },
    ];
  }, [scenario, initialScores]);

  const [expandedHistoryEntryId, setExpandedHistoryEntryId] = useState<string | false>(false);

  useEffect(() => {
    if (historyEntries.length === 0) return;
    setExpandedHistoryEntryId((prev) => (prev === false ? historyEntries[0]!.id : prev));
  }, [historyEntries]);

  const breadcrumbs = useMemo(
    () => (
      <OverflowBreadcrumbs
        leadingElement={<span>Asset manager</span>}
        hideLastItem
        items={[
          { id: "crm", label: "Cyber risk management", url: ASSESSMENTS_PATH },
          { id: "cra", label: "Cyber risk analysis", url: ASSESSMENTS_PATH },
          {
            id: "assessment",
            label: assessmentTitle,
            url: nav?.returnToAssessmentPath?.trim() || NEW_CRA_PATH,
          },
        ]}
        aria-label="Breadcrumbs"
      >
        {({ label, url }) => <NavLink to={url}>{label}</NavLink>}
      </OverflowBreadcrumbs>
    ),
    [assessmentTitle, nav?.returnToAssessmentPath],
  );

  const goBackToAssessment = useCallback(() => {
    const returnPath = nav?.returnToAssessmentPath?.trim() || NEW_CRA_PATH;
    const tabIndex = nav?.craReturnToTabIndex ?? NEW_CRA_SCORING_TAB_INDEX;
    navigate(returnPath, { state: { craReturnToTabIndex: tabIndex } });
  }, [navigate, nav?.returnToAssessmentPath, nav?.craReturnToTabIndex]);

  if (!scenario) {
    return (
      <Container sx={{ py: 2 }}>
        <Stack gap={0}>
          <ScoringRationaleHeader
            scenarioName="Scenario not found"
            scenarioId={scenarioId}
            breadcrumbs={breadcrumbs}
            onBack={goBackToAssessment}
            backButtonAriaLabel="Back"
          />
          <Typography variant="body1" sx={{ py: 4 }}>
            We could not find that scenario. Use the back control to return to the assessment.
          </Typography>
        </Stack>
      </Container>
    );
  }

  return (
    <Container sx={{ py: 2 }}>
      <Stack gap={0}>
        <ScoringRationaleHeader
          scenarioName={scenario.name.trim() || scenario.id}
          scenarioId={scenario.id}
          confidencePercent={scenario.confidencePercent}
          breadcrumbs={breadcrumbs}
          onBack={goBackToAssessment}
          backButtonAriaLabel="Back to assessment"
        />

        <Stack gap={3} sx={{ pt: 3, pb: 6, width: "100%", maxWidth: "none" }}>
          <Alert
            severity="info"
            icon={<AiSparkleIcon />}
            aria-live="off"
            role={undefined}
            sx={{
              backgroundColor: "var(--lens-component-avatar-purple-background-color)",
              color: "var(--lens-component-accordion-active-color)",
              py: 2,
            }}
          >
            <Box sx={visuallyHidden}>AI</Box>
            <AlertTitle>Generated by Diligent Scoring AI</AlertTitle>
            The scoring and the rationale for this scenario were generated by the Diligent Scoring AI agent. Review the results in the history below.
          </Alert>

          <ScoringWide />

          <ScenarioHistorySection
            scenarioId={scenario.id}
            entries={historyEntries}
            expandedEntryId={expandedHistoryEntryId}
            onExpandedEntryChange={setExpandedHistoryEntryId}
          />
        </Stack>
      </Stack>
    </Container>
  );
}
