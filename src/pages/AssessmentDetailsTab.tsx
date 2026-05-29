import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import {
  Autocomplete,
  Box,
  Container,
  FormControl,
  Stack,
  TextField,
  Typography,
  useTheme,
} from "@mui/material";
import { LocalizationProvider } from "@mui/x-date-pickers-pro";
import { AdapterDateFns } from "@mui/x-date-pickers-pro/AdapterDateFns";
import { DesktopDatePicker } from "@mui/x-date-pickers";
import { format, isValid, parseISO } from "date-fns";
import { useBeforeUnload, useLocation, useNavigate, useNavigationType, useParams } from "react-router";

import NewCyberRiskAssessmentMethodSection from "./NewCyberRiskAssessmentMethodSection.js";
import AssessmentScoringTab from "./AssessmentScoringTab.js";
import AssessmentResultsTab from "./AssessmentResultsTab.js";
import AssessmentScopeTab, {
  type ScopeSubView,
} from "./AssessmentScopeTab.js";
import {
  craScoringTypeChoiceFromCatalogAssessmentType,
  normalizeAiScoringPhaseForHydrate,
} from "../data/craAssessmentDraftTypes.js";
import {
  assessmentPhaseToAssessmentStatus,
  assessmentStatusToPhase,
  clearCraNewAssessmentDraft,
  loadCraNewAssessmentDraft,
  NEW_CRA_RESULTS_TAB_INDEX,
  saveCraNewAssessmentDraft,
  type AiScoringPhase,
  type AssessmentPhase,
  type CraScenarioScoreAggregationMethod,
  type CraScoringTypeChoice,
} from "./craNewAssessmentDraftStorage.js";
import {
  assessmentScopedScenarios,
  candidateScopedCyberRisks,
  candidateScopedControls,
  candidateScopedThreats,
  candidateScopedVulnerabilities,
} from "../data/assessmentScopeRollup.js";
import {
  allocateNextCraId,
  computeAssessmentRollupForAssetIds,
  getRiskAssessmentById,
  removeRiskAssessmentById,
  updateRiskAssessment,
} from "../data/riskAssessments.js";
import { syncAssessmentOwnedScenarios } from "../data/assessmentScenarioSync.js";
import { applyApprovedAssessmentCyberRiskWriteback } from "../data/applyApprovedAssessmentCyberRiskWriteback.js";
import AssessmentDetailHeader from "../components/AssessmentDetailHeader.js";
import {
  useSavedChangesToast,
  type PendingSaveNavigationHandlers,
} from "../context/SavedChangesToastContext.js";
import { ASSESSMENT_DELETED_TOAST_STATE_KEY } from "../constants/assessmentNavigationState.js";
import UnsavedChangesDialog from "../components/UnsavedChangesDialog.js";
import RadioButtonArray from "../components/RadioButtonArray.js";
import { joinUserFullNames, mockUserEmail, users } from "../data/users.js";

const DEFAULT_ASSESSMENT_TYPE = "Cyber risk assessment";
const DEFAULT_NEW_ASSESSMENT_NAME = "New cyber risk assessment";
const DEFAULT_NEW_OWNER_ID = users[0]!.id;

function dueDateStringToValue(s: string): Date | null {
  const t = s.trim();
  if (!t) return null;
  if (t.length >= 10) {
    const fromIso = parseISO(t.slice(0, 10));
    if (isValid(fromIso)) return fromIso;
  }
  const parsed = new Date(t);
  return isValid(parsed) ? parsed : null;
}

function valueToDueDateString(d: Date | null): string {
  if (!d || !isValid(d)) return "";
  return format(d, "yyyy-MM-dd");
}

/** Atlas user-lookup `Autocomplete` option shape (`OptionType.user`). */
type AssessmentOwnerLookupOption = {
  id: string;
  label: string;
  email: string;
  type: "user";
};

const SCOPE_DETAIL_PAGE: Record<
  Exclude<ScopeSubView, "overview">,
  { title: string; subtitle: string; crumb: string }
> = {
  assets: {
    title: "Assets",
    subtitle: "Choose which assets to include in this assessment.",
    crumb: "Assets",
  },
  scopedCyberRisks: {
    title: "Cyber risks",
    subtitle: "Cyber risks linked to assets included in this assessment.",
    crumb: "Cyber risks",
  },
  scopedThreats: {
    title: "Threats",
    subtitle: "Threats linked to assets included in this assessment.",
    crumb: "Threats",
  },
  scopedVulnerabilities: {
    title: "Vulnerabilities",
    subtitle: "Vulnerabilities linked to assets included in this assessment.",
    crumb: "Vulnerabilities",
  },
  scopedControls: {
    title: "Controls",
    subtitle: "Controls linked to assets included in this assessment.",
    crumb: "Controls",
  },
};

const SCOPE_TAB_INDEX = 1;
const SCORING_TAB_INDEX = 2;

const CRA_SCORING_TYPE_RADIO_OPTIONS = [
  { value: "inherent" satisfies CraScoringTypeChoice, label: "Inherent" },
  { value: "residual" satisfies CraScoringTypeChoice, label: "Residual" },
] as const;

function TabPanel({
  children,
  value,
  index,
  sx,
}: {
  children: React.ReactNode;
  value: number;
  index: number;
  sx?: React.ComponentProps<typeof Box>["sx"];
}) {
  return (
    <Box
      component="div"
      role="tabpanel"
      hidden={value !== index}
      id={`new-cra-tabpanel-${index}`}
      aria-labelledby={`new-cra-tab-${index}`}
      sx={sx}
    >
      {value === index ? children : null}
    </Box>
  );
}

type ScopeSetsSnapshot = {
  includedScopeAssetIds: string[];
  excludedScopeCyberRiskIds: string[];
  excludedScopeThreatIds: string[];
  excludedScopeVulnerabilityIds: string[];
  excludedScopeControlIds: string[];
};

function captureScopeSnapshot(
  included: Set<string>,
  exCr: Set<string>,
  exT: Set<string>,
  exV: Set<string>,
  exC: Set<string>,
): ScopeSetsSnapshot {
  return {
    includedScopeAssetIds: [...included],
    excludedScopeCyberRiskIds: [...exCr],
    excludedScopeThreatIds: [...exT],
    excludedScopeVulnerabilityIds: [...exV],
    excludedScopeControlIds: [...exC],
  };
}

function scopeSnapshotEqualsLive(
  snap: ScopeSetsSnapshot,
  included: Set<string>,
  exCr: Set<string>,
  exT: Set<string>,
  exV: Set<string>,
  exC: Set<string>,
): boolean {
  const same = (a: string[], b: Set<string>) =>
    a.length === b.size && a.every((id) => b.has(id));
  return (
    same(snap.includedScopeAssetIds, included) &&
    same(snap.excludedScopeCyberRiskIds, exCr) &&
    same(snap.excludedScopeThreatIds, exT) &&
    same(snap.excludedScopeVulnerabilityIds, exV) &&
    same(snap.excludedScopeControlIds, exC)
  );
}

export default function AssessmentDetailsTab() {
  const location = useLocation();
  const navigate = useNavigate();
  const navigationType = useNavigationType();
  const { assessmentId: routeAssessmentId } = useParams();
  const { presets } = useTheme();
  const { AutocompletePresets } = presets;
  const { notifySavedChanges } = useSavedChangesToast();

  const isReturningFromScenario = (() => {
    const st = location.state as
      | { craReturnToScoring?: boolean; craReturnToTabIndex?: number }
      | null;
    return st?.craReturnToScoring === true || typeof st?.craReturnToTabIndex === "number";
  })();

  const mockFromRoute =
    routeAssessmentId != null && routeAssessmentId !== ""
      ? getRiskAssessmentById(routeAssessmentId)
      : undefined;

  /** Clear stale draft on fresh entry to `/new`, but not when the user pops back (browser-style back preserves remounted state + draft). */
  const needsInitialDraftClear =
    !routeAssessmentId &&
    mockFromRoute == null &&
    !isReturningFromScenario &&
    navigationType !== "POP";

  const isNewCraDraftFlow =
    !(routeAssessmentId != null && routeAssessmentId !== "") && mockFromRoute == null;

  const [initialDraft] = useState(() => {
    if (routeAssessmentId != null && routeAssessmentId !== "") return null;
    if (mockFromRoute != null) return null;
    return loadCraNewAssessmentDraft();
  });

  const [activeTab, setActiveTab] = useState(() => {
    if (initialDraft) return initialDraft.activeTab;
    if (mockFromRoute) return 0;
    return 0;
  });
  /** Draft → Scoping → Scoring → Approved → Done (navigate to list). */
  const [assessmentPhase, setAssessmentPhase] = useState<AssessmentPhase>(() => {
    if (initialDraft) return initialDraft.assessmentPhase;
    if (mockFromRoute) return assessmentStatusToPhase(mockFromRoute.status);
    return "draft";
  });
  const assessmentPhaseRef = useRef<AssessmentPhase>(assessmentPhase);
  useEffect(() => {
    assessmentPhaseRef.current = assessmentPhase;
  }, [assessmentPhase]);

  useEffect(() => {
    if (!routeAssessmentId) {
      setAssessmentInstructions("");
      return;
    }
    const row = getRiskAssessmentById(routeAssessmentId);
    setAssessmentInstructions(row?.instructions ?? "");
  }, [routeAssessmentId]);
  const [name, setName] = useState(() => {
    if (initialDraft) return initialDraft.name;
    if (mockFromRoute) return mockFromRoute.name;
    return DEFAULT_NEW_ASSESSMENT_NAME;
  });
  const [assessmentId, setAssessmentId] = useState(() => {
    if (initialDraft) return initialDraft.assessmentId;
    if (mockFromRoute) return mockFromRoute.id;
    return "";
  });
  const [persistedAssessmentType] = useState(() => {
    if (initialDraft) return initialDraft.assessmentType;
    if (mockFromRoute) return mockFromRoute.assessmentType;
    return DEFAULT_ASSESSMENT_TYPE;
  });
  const [dueDate, setDueDate] = useState(() => {
    if (initialDraft) return initialDraft.dueDate;
    if (mockFromRoute) return mockFromRoute.dueDate;
    return "";
  });
  const [assessmentInstructions, setAssessmentInstructions] = useState(() => {
    if (mockFromRoute) return mockFromRoute.instructions ?? "";
    return "";
  });
  const [ownerIds, setOwnerIds] = useState<string[]>(() => {
    if (initialDraft) return initialDraft.ownerIds.slice(0, 1);
    if (mockFromRoute) return [mockFromRoute.ownerId];
    return [DEFAULT_NEW_OWNER_ID];
  });
  /** Scope tab: card overview vs assets data grid (drives PageHeader). */
  const [scopeSubView, setScopeSubView] = useState<ScopeSubView>(() => {
    if (initialDraft) return initialDraft.scopeSubView;
    if (mockFromRoute) return "overview";
    return "overview";
  });

  const [includedScopeAssetIds, setIncludedScopeAssetIds] = useState<Set<string>>(() => {
    if (initialDraft) return new Set(initialDraft.includedScopeAssetIds ?? []);
    if (mockFromRoute) return new Set(mockFromRoute.assetIds);
    return new Set();
  });

  const [excludedScopeCyberRiskIds, setExcludedScopeCyberRiskIds] = useState<Set<string>>(() => {
    if (initialDraft) return new Set(initialDraft.excludedScopeCyberRiskIds ?? []);
    if (mockFromRoute) return new Set(mockFromRoute.excludedScopeCyberRiskIds ?? []);
    return new Set();
  });

  const [excludedScopeScenarioIds, setExcludedScopeScenarioIds] = useState<Set<string>>(() => {
    if (initialDraft) return new Set(initialDraft.excludedScopeScenarioIds ?? []);
    if (mockFromRoute) return new Set(mockFromRoute.excludedScopeScenarioIds ?? []);
    return new Set();
  });

  const [excludedScopeThreatIds, setExcludedScopeThreatIds] = useState<Set<string>>(() => {
    if (initialDraft) return new Set(initialDraft.excludedScopeThreatIds ?? []);
    if (mockFromRoute) return new Set(mockFromRoute.excludedScopeThreatIds ?? []);
    return new Set();
  });

  const [excludedScopeVulnerabilityIds, setExcludedScopeVulnerabilityIds] = useState<Set<string>>(
    () => {
      if (initialDraft) return new Set(initialDraft.excludedScopeVulnerabilityIds ?? []);
      if (mockFromRoute) return new Set(mockFromRoute.excludedScopeVulnerabilityIds ?? []);
      return new Set();
    },
  );

  const [excludedScopeControlIds, setExcludedScopeControlIds] = useState<Set<string>>(() => {
    if (initialDraft) return new Set(initialDraft.excludedScopeControlIds ?? []);
    if (mockFromRoute) return new Set(mockFromRoute.excludedScopeControlIds ?? []);
    return new Set();
  });

  const scenarioScopeAssessmentId = useMemo((): string | undefined => {
    if (routeAssessmentId != null && routeAssessmentId !== "") return routeAssessmentId;
    if (/^CRA-\d+$/.test(assessmentId)) return assessmentId;
    return undefined;
  }, [routeAssessmentId, assessmentId]);

  const [aiScoringPhase, setAiScoringPhase] = useState<AiScoringPhase>(() => {
    if (mockFromRoute) return normalizeAiScoringPhaseForHydrate(mockFromRoute.aiScoringPhase);
    if (initialDraft) return initialDraft.aiScoringPhase;
    return "idle";
  });

  const [scoringType, setScoringType] = useState<CraScoringTypeChoice>(() => {
    if (initialDraft) return initialDraft.scoringType;
    if (mockFromRoute) {
      return craScoringTypeChoiceFromCatalogAssessmentType(mockFromRoute.assessmentType);
    }
    return "residual";
  });

  const [scenarioScoreAggregationMethod, setScenarioScoreAggregationMethod] =
    useState<CraScenarioScoreAggregationMethod>(() => {
      if (initialDraft) return initialDraft.scenarioScoreAggregationMethod;
      return "highest";
    });

  const [scenarioNotApplicableIds, setScenarioNotApplicableIds] = useState<Set<string>>(() => {
    if (initialDraft?.scenarioNotApplicableIds?.length)
      return new Set(initialDraft.scenarioNotApplicableIds);
    return new Set();
  });

  const [scenarioCatalogScoresReleased, setScenarioCatalogScoresReleased] = useState(() => {
    if (!isNewCraDraftFlow || needsInitialDraftClear) return !isNewCraDraftFlow;
    if (initialDraft) return initialDraft.scenarioCatalogScoresReleased;
    return false;
  });

  const [scenarioManuallyRevealedScoreIds, setScenarioManuallyRevealedScoreIds] = useState<
    Set<string>
  >(() => {
    if (!isNewCraDraftFlow || needsInitialDraftClear) return new Set<string>();
    if (initialDraft?.scenarioManuallyRevealedScoreIds?.length) {
      return new Set(initialDraft.scenarioManuallyRevealedScoreIds);
    }
    return new Set<string>();
  });

  const autoAllocatedCraRef = useRef(false);

  const assessmentScenarioScopeSignature = useMemo(
    () =>
      [
        [...includedScopeAssetIds].sort().join("\0"),
        [...excludedScopeCyberRiskIds].sort().join("\0"),
        [...excludedScopeThreatIds].sort().join("\0"),
        [...excludedScopeScenarioIds].sort().join("\0"),
      ].join("|"),
    [includedScopeAssetIds, excludedScopeCyberRiskIds, excludedScopeThreatIds, excludedScopeScenarioIds],
  );

  /** `/new` draft: allocate next CRA id once scope has assets so owned scenarios can be tagged. */
  useEffect(() => {
    if (!isNewCraDraftFlow) return;
    if (routeAssessmentId != null && routeAssessmentId !== "") return;
    if (/^CRA-\d+$/.test(assessmentId.trim())) return;
    if (includedScopeAssetIds.size === 0) return;
    if (assessmentPhase === "assessmentApproved") return;
    if (autoAllocatedCraRef.current) return;
    autoAllocatedCraRef.current = true;
    setAssessmentId(allocateNextCraId());
  }, [
    isNewCraDraftFlow,
    routeAssessmentId,
    assessmentId,
    assessmentPhase,
    includedScopeAssetIds.size,
  ]);

  /** Keep assessment-owned catalog scenarios aligned with scope (add/update/remove; persists via catalog snapshot). */
  useEffect(() => {
    if (assessmentPhase === "assessmentApproved") return;
    if (includedScopeAssetIds.size === 0) return;
    const craKey =
      routeAssessmentId != null && routeAssessmentId !== ""
        ? routeAssessmentId.trim()
        : /^CRA-\d+$/.test(assessmentId.trim())
          ? assessmentId.trim()
          : "";
    if (!craKey) return;

    const result = syncAssessmentOwnedScenarios({
      craId: craKey,
      includedAssetIds: includedScopeAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeScenarioIds,
      excludedScopeThreatIds,
    });

    if (result.removedIds.length > 0) {
      const purge = new Set(result.removedIds);
      setExcludedScopeScenarioIds((prev) => {
        let changed = false;
        const next = new Set(prev);
        for (const id of purge) {
          if (next.delete(id)) changed = true;
        }
        return changed ? next : prev;
      });
      setScenarioNotApplicableIds((prev) => {
        let changed = false;
        const next = new Set(prev);
        for (const id of purge) {
          if (next.delete(id)) changed = true;
        }
        return changed ? next : prev;
      });
      setScenarioManuallyRevealedScoreIds((prev) => {
        let changed = false;
        const next = new Set(prev);
        for (const id of purge) {
          if (next.delete(id)) changed = true;
        }
        return changed ? next : prev;
      });
    }
  }, [
    assessmentPhase,
    routeAssessmentId,
    assessmentId,
    assessmentScenarioScopeSignature,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeScenarioIds,
  ]);

  const aiScoringTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Detects newly included scope assets (vs initial snapshot) to move workflow back to Scoping. */
  const prevIncludedScopeAssetIdsRef = useRef<Set<string> | null>(null);

  const scopeDetailSnapshotRef = useRef<ScopeSetsSnapshot | null>(null);
  const prevScopeSubViewForCaptureRef = useRef<ScopeSubView | null>(null);
  const pendingAfterScopeUnsavedRef = useRef<PendingSaveNavigationHandlers | null>(null);
  const [scopeUnsavedDialogOpen, setScopeUnsavedDialogOpen] = useState(false);

  const isScopeDetailView = activeTab === SCOPE_TAB_INDEX && scopeSubView !== "overview";

  useLayoutEffect(() => {
    const prev = prevScopeSubViewForCaptureRef.current;
    const enteredDetailFromOverview = prev === "overview" && scopeSubView !== "overview";
    const initialLoadIntoDetail = prev === null && scopeSubView !== "overview";
    if (enteredDetailFromOverview || initialLoadIntoDetail) {
      scopeDetailSnapshotRef.current = captureScopeSnapshot(
        includedScopeAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeThreatIds,
        excludedScopeVulnerabilityIds,
        excludedScopeControlIds,
      );
    }
    prevScopeSubViewForCaptureRef.current = scopeSubView;
  }, [
    scopeSubView,
    includedScopeAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
  ]);

  const scopeDetailDirty = useMemo(() => {
    if (!isScopeDetailView) return false;
    const snap = scopeDetailSnapshotRef.current;
    if (!snap) return false;
    return !scopeSnapshotEqualsLive(
      snap,
      includedScopeAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeThreatIds,
      excludedScopeVulnerabilityIds,
      excludedScopeControlIds,
    );
  }, [
    isScopeDetailView,
    includedScopeAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
  ]);

  const includedScopeAssetIdsForWorkflow = useMemo(() => {
    if (isScopeDetailView && scopeDetailDirty && scopeDetailSnapshotRef.current) {
      return new Set(scopeDetailSnapshotRef.current.includedScopeAssetIds);
    }
    return includedScopeAssetIds;
  }, [isScopeDetailView, scopeDetailDirty, includedScopeAssetIds]);

  useBeforeUnload(
    useCallback(
      (event: BeforeUnloadEvent) => {
        if (scopeDetailDirty) {
          event.preventDefault();
        }
      },
      [scopeDetailDirty],
    ),
  );

  const restoreScopeFromSnapshot = useCallback(() => {
    const snap = scopeDetailSnapshotRef.current;
    if (!snap) return;
    setIncludedScopeAssetIds(new Set(snap.includedScopeAssetIds));
    setExcludedScopeCyberRiskIds(new Set(snap.excludedScopeCyberRiskIds));
    setExcludedScopeThreatIds(new Set(snap.excludedScopeThreatIds));
    setExcludedScopeVulnerabilityIds(new Set(snap.excludedScopeVulnerabilityIds));
    setExcludedScopeControlIds(new Set(snap.excludedScopeControlIds));
  }, []);

  const requestScopeDetailExit = useCallback(
    (after?: () => void) => {
      if (scopeDetailDirty) {
        pendingAfterScopeUnsavedRef.current = null;
        setScopeUnsavedDialogOpen(true);
        return;
      }
      setScopeSubView("overview");
      after?.();
    },
    [scopeDetailDirty],
  );

  const requestScopeNavigateAway = useCallback(
    (handlers: PendingSaveNavigationHandlers) => {
      if (scopeDetailDirty) {
        pendingAfterScopeUnsavedRef.current = handlers;
        setScopeUnsavedDialogOpen(true);
        return;
      }
      handlers.onDiscard();
    },
    [scopeDetailDirty],
  );

  const handleDeletePersistedAssessment = useCallback(() => {
    if (!routeAssessmentId) return;
    removeRiskAssessmentById(routeAssessmentId);
    navigate("/cyber-risk/cyber-risk-assessments", {
      state: { [ASSESSMENT_DELETED_TOAST_STATE_KEY]: true },
    });
  }, [routeAssessmentId, navigate]);

  const handleScopeSubViewChange = useCallback(
    (view: ScopeSubView) => {
      if (view === "overview") {
        requestScopeDetailExit();
        return;
      }
      setScopeSubView(view);
    },
    [requestScopeDetailExit],
  );

  /** Clear stale draft on fresh entry to `/new`, but not when the user pops back (browser-style back preserves remounted state + draft). */
  useLayoutEffect(() => {
    if (!needsInitialDraftClear) return;
    clearCraNewAssessmentDraft();
  }, [needsInitialDraftClear]);

  const toggleAssetIncluded = useCallback((assetId: string, included: boolean) => {
    setIncludedScopeAssetIds((prev) => {
      const next = new Set(prev);
      if (included) next.add(assetId);
      else next.delete(assetId);
      return next;
    });
  }, []);

  const bulkSetAssetsIncluded = useCallback((assetIds: string[], included: boolean) => {
    setIncludedScopeAssetIds((prev) => {
      const next = new Set(prev);
      for (const id of assetIds) {
        if (included) next.add(id);
        else next.delete(id);
      }
      return next;
    });
  }, []);

  /** Drop exclusions that no longer apply when asset scope changes. */
  useEffect(() => {
    setExcludedScopeCyberRiskIds((prev) => {
      const candidateIds = new Set(
        candidateScopedCyberRisks(includedScopeAssetIds).map((cr) => cr.id),
      );
      const next = new Set<string>();
      for (const id of prev) {
        if (candidateIds.has(id)) next.add(id);
      }
      if (next.size === prev.size) {
        for (const id of prev) {
          if (!next.has(id)) return next;
        }
        return prev;
      }
      return next;
    });
  }, [includedScopeAssetIds]);

  /** Drop threat / vulnerability / control exclusions that no longer apply when asset scope changes. */
  useEffect(() => {
    const threatCand = new Set(candidateScopedThreats(includedScopeAssetIds).map((t) => t.id));
    setExcludedScopeThreatIds((prev) => {
      const next = new Set<string>();
      for (const id of prev) {
        if (threatCand.has(id)) next.add(id);
      }
      if (next.size === prev.size) {
        for (const id of prev) {
          if (!next.has(id)) return next;
        }
        return prev;
      }
      return next;
    });

    const vulnCand = new Set(candidateScopedVulnerabilities(includedScopeAssetIds).map((v) => v.id));
    setExcludedScopeVulnerabilityIds((prev) => {
      const next = new Set<string>();
      for (const id of prev) {
        if (vulnCand.has(id)) next.add(id);
      }
      if (next.size === prev.size) {
        for (const id of prev) {
          if (!next.has(id)) return next;
        }
        return prev;
      }
      return next;
    });

    const controlCand = new Set(candidateScopedControls(includedScopeAssetIds).map((c) => c.id));
    setExcludedScopeControlIds((prev) => {
      const next = new Set<string>();
      for (const id of prev) {
        if (controlCand.has(id)) next.add(id);
      }
      if (next.size === prev.size) {
        for (const id of prev) {
          if (!next.has(id)) return next;
        }
        return prev;
      }
      return next;
    });
  }, [includedScopeAssetIds]);

  const setCyberRiskScopeIncluded = useCallback((cyberRiskId: string, included: boolean) => {
    setExcludedScopeCyberRiskIds((prev) => {
      const next = new Set(prev);
      if (included) next.delete(cyberRiskId);
      else next.add(cyberRiskId);
      return next;
    });
  }, []);

  const handleRemoveScenarioFromAssessment = useCallback((scenarioId: string) => {
    setExcludedScopeScenarioIds((prev) => new Set([...prev, scenarioId]));
    setScenarioNotApplicableIds((prev) => {
      const next = new Set(prev);
      next.delete(scenarioId);
      return next;
    });
  }, []);

  const bulkSetCyberRisksScopeIncluded = useCallback((cyberRiskIds: string[], included: boolean) => {
    setExcludedScopeCyberRiskIds((prev) => {
      const next = new Set(prev);
      for (const id of cyberRiskIds) {
        if (included) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  }, []);

  const setThreatScopeIncluded = useCallback((threatId: string, included: boolean) => {
    setExcludedScopeThreatIds((prev) => {
      const next = new Set(prev);
      if (included) next.delete(threatId);
      else next.add(threatId);
      return next;
    });
  }, []);

  const bulkSetThreatsScopeIncluded = useCallback((threatIds: string[], included: boolean) => {
    setExcludedScopeThreatIds((prev) => {
      const next = new Set(prev);
      for (const id of threatIds) {
        if (included) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  }, []);

  const setVulnerabilityScopeIncluded = useCallback((vulnerabilityId: string, included: boolean) => {
    setExcludedScopeVulnerabilityIds((prev) => {
      const next = new Set(prev);
      if (included) next.delete(vulnerabilityId);
      else next.add(vulnerabilityId);
      return next;
    });
  }, []);

  const bulkSetVulnerabilitiesScopeIncluded = useCallback(
    (vulnerabilityIds: string[], included: boolean) => {
      setExcludedScopeVulnerabilityIds((prev) => {
        const next = new Set(prev);
        for (const id of vulnerabilityIds) {
          if (included) next.delete(id);
          else next.add(id);
        }
        return next;
      });
    },
    [],
  );

  const setControlScopeIncluded = useCallback((controlId: string, included: boolean) => {
    setExcludedScopeControlIds((prev) => {
      const next = new Set(prev);
      if (included) next.delete(controlId);
      else next.add(controlId);
      return next;
    });
  }, []);

  const bulkSetControlsScopeIncluded = useCallback((controlIds: string[], included: boolean) => {
    setExcludedScopeControlIds((prev) => {
      const next = new Set(prev);
      for (const id of controlIds) {
        if (included) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  }, []);

  const assessmentOwnerLookupOptions = useMemo((): AssessmentOwnerLookupOption[] => {
    return users.map((u) => ({
      id: u.id,
      label: u.fullName,
      email: mockUserEmail(u),
      type: "user" as const,
    }));
  }, []);

  const selectedAssessmentOwner = useMemo((): AssessmentOwnerLookupOption | null => {
    const id = ownerIds[0];
    if (id == null || id === "") return null;
    return assessmentOwnerLookupOptions.find((o) => o.id === id) ?? null;
  }, [ownerIds, assessmentOwnerLookupOptions]);

  const createdByDisplay = useMemo(() => joinUserFullNames(ownerIds, "—"), [ownerIds]);

  /** Adding scope assets moves the workflow from Draft → Scoping (including on `/…/:assessmentId`). */
  useEffect(() => {
    if (assessmentPhase !== "draft") return;
    if (includedScopeAssetIdsForWorkflow.size === 0) return;
    setAssessmentPhase("scoping");
    setScenarioScoreAggregationMethod("highest");
  }, [assessmentPhase, includedScopeAssetIdsForWorkflow]);

  /** Any new asset added to scope moves the assessment back to Scoping (except while in Scoring or Review). */
  useEffect(() => {
    const prev = prevIncludedScopeAssetIdsRef.current;
    const current = includedScopeAssetIdsForWorkflow;
    if (prev === null) {
      prevIncludedScopeAssetIdsRef.current = new Set(current);
      return;
    }
    let addedNewAsset = false;
    for (const id of current) {
      if (!prev.has(id)) {
        addedNewAsset = true;
        break;
      }
    }
    prevIncludedScopeAssetIdsRef.current = new Set(current);
    if (!addedNewAsset) return;
    if (
      assessmentPhaseRef.current === "inProgress" ||
      assessmentPhaseRef.current === "review"
    ) {
      return;
    }
    setAssessmentPhase("scoping");
    setScenarioScoreAggregationMethod("highest");
  }, [includedScopeAssetIdsForWorkflow]);

  const handleAssessmentPhaseChange = useCallback(
    (phase: AssessmentPhase) => {
      if (phase === "assessmentApproved") {
        applyApprovedAssessmentCyberRiskWriteback({
          includedAssetIds: includedScopeAssetIds,
          excludedScopeCyberRiskIds,
          excludedScopeScenarioIds,
          scenarioNotApplicableIds,
          scenarioScopeAssessmentId,
          scoringType,
          scenarioScoreAggregationMethod,
        });
      }
      setAssessmentPhase(phase);
      if (phase === "scoping") {
        setScenarioScoreAggregationMethod("highest");
      }
    },
    [
      includedScopeAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeScenarioIds,
      scenarioNotApplicableIds,
      scenarioScopeAssessmentId,
      scoringType,
      scenarioScoreAggregationMethod,
    ],
  );

  const showAiScoringAction = useMemo(() => {
    if (
      assessmentPhase === "inProgress" ||
      assessmentPhase === "review" ||
      assessmentPhase === "overdue"
    )
      return true;
    if (assessmentPhase === "scoping") {
      return (
        includedScopeAssetIds.size >= 1 &&
        assessmentScopedScenarios(
          includedScopeAssetIds,
          excludedScopeCyberRiskIds,
          excludedScopeScenarioIds,
          scenarioScopeAssessmentId,
        ).length >= 1
      );
    }
    return false;
  }, [assessmentPhase, includedScopeAssetIds, excludedScopeCyberRiskIds, excludedScopeScenarioIds, scenarioScopeAssessmentId]);

  const handleSaveDraft = useCallback(() => {
    const catalogAssessmentId =
      routeAssessmentId != null && routeAssessmentId !== ""
        ? routeAssessmentId
        : /^CRA-\d+$/.test(assessmentId)
          ? assessmentId
          : undefined;

    const snap = scopeDetailSnapshotRef.current;
    const usePersistedSnapshot =
      activeTab === SCOPE_TAB_INDEX &&
      scopeSubView !== "overview" &&
      snap != null &&
      !scopeSnapshotEqualsLive(
        snap,
        includedScopeAssetIds,
        excludedScopeCyberRiskIds,
        excludedScopeThreatIds,
        excludedScopeVulnerabilityIds,
        excludedScopeControlIds,
      );

    const includedForPersist = usePersistedSnapshot
      ? snap.includedScopeAssetIds
      : [...includedScopeAssetIds];
    const exCrForPersist = usePersistedSnapshot
      ? snap.excludedScopeCyberRiskIds
      : [...excludedScopeCyberRiskIds];
    const exTForPersist = usePersistedSnapshot
      ? snap.excludedScopeThreatIds
      : [...excludedScopeThreatIds];
    const exVForPersist = usePersistedSnapshot
      ? snap.excludedScopeVulnerabilityIds
      : [...excludedScopeVulnerabilityIds];
    const exCForPersist = usePersistedSnapshot
      ? snap.excludedScopeControlIds
      : [...excludedScopeControlIds];

    if (catalogAssessmentId) {
      const row = getRiskAssessmentById(catalogAssessmentId);
      if (row) {
        const trimmedName = name.trim();
        const rollup = computeAssessmentRollupForAssetIds(includedForPersist, {
          excludedScopeCyberRiskIds: exCrForPersist,
          excludedScopeThreatIds: exTForPersist,
          excludedScopeVulnerabilityIds: exVForPersist,
          excludedScopeControlIds: exCForPersist,
          excludedScopeScenarioIds: [...excludedScopeScenarioIds],
          scenarioScopeAssessmentId: catalogAssessmentId,
        });
        updateRiskAssessment(catalogAssessmentId, {
          name: trimmedName || row.name,
          ownerId: ownerIds[0] ?? row.ownerId,
          status: assessmentPhaseToAssessmentStatus(assessmentPhase),
          assessmentType: row.assessmentType,
          dueDate,
          startDate: row.startDate,
          aiScoringPhase,
          instructions: assessmentInstructions,
          ...rollup,
        });
      }
    }

    if (!routeAssessmentId) {
      saveCraNewAssessmentDraft({
        activeTab,
        assessmentPhase,
        name,
        assessmentId,
        assessmentType: persistedAssessmentType,
        startDate: "",
        dueDate,
        ownerIds,
        scopeSubView,
        includedScopeAssetIds: includedForPersist,
        excludedScopeCyberRiskIds: exCrForPersist,
        excludedScopeThreatIds: exTForPersist,
        excludedScopeVulnerabilityIds: exVForPersist,
        excludedScopeControlIds: exCForPersist,
        aiScoringPhase,
        scoringType,
        scenarioScoreAggregationMethod,
        scenarioNotApplicableIds: [...scenarioNotApplicableIds],
        excludedScopeScenarioIds: [...excludedScopeScenarioIds],
        scenarioCatalogScoresReleased,
        scenarioManuallyRevealedScoreIds: [...scenarioManuallyRevealedScoreIds],
      });
    }
  }, [
    routeAssessmentId,
    activeTab,
    assessmentPhase,
    name,
    assessmentId,
    persistedAssessmentType,
    dueDate,
    ownerIds,
    scopeSubView,
    includedScopeAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
    excludedScopeScenarioIds,
    aiScoringPhase,
    assessmentInstructions,
    scoringType,
    scenarioScoreAggregationMethod,
    scenarioNotApplicableIds,
    scenarioCatalogScoresReleased,
    scenarioManuallyRevealedScoreIds,
  ]);

  const handleSaveDraftWithToast = useCallback(() => {
    handleSaveDraft();
    notifySavedChanges();
  }, [handleSaveDraft, notifySavedChanges]);

  const handleSaveDraftRef = useRef(handleSaveDraft);
  handleSaveDraftRef.current = handleSaveDraft;

  const handleScopeUnsavedClose = useCallback(() => {
    pendingAfterScopeUnsavedRef.current = null;
    setScopeUnsavedDialogOpen(false);
  }, []);

  const handleScopeUnsavedDiscard = useCallback(() => {
    restoreScopeFromSnapshot();
    const pending = pendingAfterScopeUnsavedRef.current;
    pendingAfterScopeUnsavedRef.current = null;
    setScopeUnsavedDialogOpen(false);
    setScopeSubView("overview");
    if (pending) {
      queueMicrotask(() => pending.onDiscard());
    }
  }, [restoreScopeFromSnapshot]);

  const handleScopeUnsavedSave = useCallback(() => {
    scopeDetailSnapshotRef.current = captureScopeSnapshot(
      includedScopeAssetIds,
      excludedScopeCyberRiskIds,
      excludedScopeThreatIds,
      excludedScopeVulnerabilityIds,
      excludedScopeControlIds,
    );
    const pending = pendingAfterScopeUnsavedRef.current;
    pendingAfterScopeUnsavedRef.current = null;
    setScopeUnsavedDialogOpen(false);
    setScopeSubView("overview");
    queueMicrotask(() => {
      handleSaveDraftRef.current();
      if (pending) {
        pending.onAfterSave();
      } else {
        notifySavedChanges();
      }
    });
  }, [
    includedScopeAssetIds,
    excludedScopeCyberRiskIds,
    excludedScopeThreatIds,
    excludedScopeVulnerabilityIds,
    excludedScopeControlIds,
    notifySavedChanges,
  ]);

  const handleAiScoringClick = useCallback(() => {
    if (assessmentPhase === "scoping") {
      if (
        includedScopeAssetIds.size < 1 ||
        assessmentScopedScenarios(
          includedScopeAssetIds,
          excludedScopeCyberRiskIds,
          excludedScopeScenarioIds,
          scenarioScopeAssessmentId,
        ).length < 1
      ) {
        return;
      }
      setAssessmentPhase("inProgress");
    }
    setAiScoringPhase((prev) => {
      if (prev === "processing") return prev;
      if (aiScoringTimerRef.current) {
        clearTimeout(aiScoringTimerRef.current);
      }
      aiScoringTimerRef.current = setTimeout(() => {
        aiScoringTimerRef.current = null;
        setScenarioCatalogScoresReleased(true);
        setAiScoringPhase("complete");
      }, 7000);
      return "processing";
    });
  }, [assessmentPhase, includedScopeAssetIds, excludedScopeCyberRiskIds, excludedScopeScenarioIds, scenarioScopeAssessmentId]);

  useEffect(() => {
    return () => {
      if (aiScoringTimerRef.current) {
        clearTimeout(aiScoringTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    handleSaveDraft();
  }, [handleSaveDraft]);

  useEffect(() => {
    if (!routeAssessmentId) return;
    const a = getRiskAssessmentById(routeAssessmentId);
    if (!a) {
      navigate("/cyber-risk/cyber-risk-assessments", { replace: true });
    }
  }, [routeAssessmentId, navigate]);

  useEffect(() => {
    const st = location.state as
      | { craReturnToScoring?: boolean; craReturnToTabIndex?: number }
      | null;
    if (st?.craReturnToTabIndex != null || st?.craReturnToScoring) {
      if (!(routeAssessmentId != null && routeAssessmentId !== "") && mockFromRoute == null) {
        const d = loadCraNewAssessmentDraft();
        if (d) {
          setScenarioCatalogScoresReleased(d.scenarioCatalogScoresReleased);
          setScenarioManuallyRevealedScoreIds(new Set(d.scenarioManuallyRevealedScoreIds ?? []));
        }
      }
    }
    if (st?.craReturnToTabIndex != null) {
      setActiveTab(st.craReturnToTabIndex);
      navigate(location.pathname, { replace: true, state: null });
    } else if (st?.craReturnToScoring) {
      setActiveTab(SCORING_TAB_INDEX);
      navigate(location.pathname, { replace: true, state: null });
    }
  }, [location.state, location.pathname, navigate, routeAssessmentId, mockFromRoute]);

  const scopeDetail =
    isScopeDetailView
      ? SCOPE_DETAIL_PAGE[scopeSubView as Exclude<ScopeSubView, "overview">]
      : undefined;

  useEffect(() => {
    if (activeTab === SCOPE_TAB_INDEX) return;
    if (scopeSubView !== "overview" && scopeDetailDirty && scopeDetailSnapshotRef.current) {
      restoreScopeFromSnapshot();
    }
    setScopeSubView("overview");
  }, [activeTab, scopeSubView, scopeDetailDirty, restoreScopeFromSnapshot]);

  const isApproved = assessmentPhase === "assessmentApproved";
  const isScoringStatus =
    assessmentPhaseToAssessmentStatus(assessmentPhase) === "Scoring" ||
    assessmentPhaseToAssessmentStatus(assessmentPhase) === "Review";

  return (
    <Container sx={{ py: 2 }}>
      <Stack gap={0}>
        <AssessmentDetailHeader
          assessmentName={name}
          assessmentId={assessmentId}
          dueDate={dueDate}
          createdAtDisplay={mockFromRoute ? mockFromRoute.startDate : "—"}
          createdBy={createdByDisplay}
          lastUpdatedAtDisplay={mockFromRoute ? mockFromRoute.dueDate : "—"}
          lastUpdatedByDisplay={
            mockFromRoute ? joinUserFullNames([mockFromRoute.ownerId]) : "—"
          }
          assessmentPhase={assessmentPhase}
          onPhaseChange={handleAssessmentPhaseChange}
          activeTab={activeTab}
          onActiveTabChange={setActiveTab}
          scopeDetail={scopeDetail}
          scopeDetailHasUnsavedChanges={scopeDetailDirty}
          onScopeDetailNavigateRequest={requestScopeNavigateAway}
          onScopeSubViewBack={() => requestScopeDetailExit()}
          onScopeDetailDone={() => {
            scopeDetailSnapshotRef.current = captureScopeSnapshot(
              includedScopeAssetIds,
              excludedScopeCyberRiskIds,
              excludedScopeThreatIds,
              excludedScopeVulnerabilityIds,
              excludedScopeControlIds,
            );
            setScopeSubView("overview");
            queueMicrotask(() => {
              handleSaveDraftRef.current();
              notifySavedChanges();
            });
          }}
          onSave={
            isApproved || activeTab === NEW_CRA_RESULTS_TAB_INDEX ? undefined : handleSaveDraftWithToast
          }
          aiScoringPhase={aiScoringPhase}
          onResetScores={() => setScenarioScoreAggregationMethod("highest")}
          onReassess={() => {}}
          onDeletePersistedAssessment={
            mockFromRoute && routeAssessmentId ? handleDeletePersistedAssessment : undefined
          }
        />

        <UnsavedChangesDialog
          open={scopeUnsavedDialogOpen}
          onClose={handleScopeUnsavedClose}
          onDiscard={handleScopeUnsavedDiscard}
          onSave={handleScopeUnsavedSave}
        />

        <TabPanel value={activeTab} index={0}>
          <Stack gap={6} sx={{ pt: 3, pb: 4, width: "100%" }}>
            <Box sx={{ width: "100%" }}>
              <Stack gap={1}>
                <Typography
                  variant="caption"
                  fontWeight={600}
                  sx={({ tokens: t }) => ({
                    color: t.semantic.color.type.default.value,
                    letterSpacing: "0.3px",
                  })}
                >
                  Name
                </Typography>
                <TextField
                  fullWidth
                  size="small"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="Assessment name"
                  aria-label="Assessment name"
                  slotProps={{ input: { readOnly: isApproved } }}
                />
              </Stack>
            </Box>

            <Box
              sx={({ tokens: t }) => ({
                display: "flex",
                flexDirection: { xs: "column", sm: "row" },
                gap: t.core.spacing["3"].value,
                flexWrap: "wrap",
                width: "100%",
                alignItems: { xs: "stretch", sm: "flex-end" },
              })}
            >
              <Box sx={{ flex: { sm: "2 1 0" }, minWidth: { xs: "100%", sm: 0 }, minHeight: 0 }}>
                <FormControl fullWidth margin="none">
                  <Autocomplete
                    id="cra-new-assessment-owner-lookup"
                    options={assessmentOwnerLookupOptions as never}
                    value={(selectedAssessmentOwner ?? null) as never}
                    onChange={(_, newValue) => setOwnerIds(newValue ? [newValue.id] : [])}
                    getOptionLabel={(option) => option.label}
                    isOptionEqualToValue={(a, b) => a.id === b.id}
                    disabled={isApproved}
                    renderInput={(params) => (
                      <TextField
                        {...params}
                        label="Owner"
                        placeholder="Select a user..."
                        margin="none"
                      />
                    )}
                    renderOption={AutocompletePresets.userLookup.renderOption}
                  />
                </FormControl>
              </Box>
              <Box sx={{ flex: { sm: "1 1 0" }, minWidth: { xs: "100%", sm: 0 }, minHeight: 0 }}>
                <LocalizationProvider dateAdapter={AdapterDateFns}>
                  <DesktopDatePicker
                    label="Due date"
                    value={dueDateStringToValue(dueDate)}
                    onChange={(d) => setDueDate(valueToDueDateString(d))}
                    dayOfWeekFormatter={(day: Date) => format(day, "EEEEEE")}
                    readOnly={isApproved}
                    disabled={isApproved}
                    slotProps={{
                      textField: {
                        size: "small",
                        fullWidth: true,
                      },
                    }}
                  />
                </LocalizationProvider>
              </Box>
              <Box sx={{ flex: { sm: "1 1 0" }, minWidth: { xs: "100%", sm: 0 }, minHeight: 0 }}>
                <Stack gap={1}>
                  <Typography
                    variant="caption"
                    fontWeight={600}
                    sx={({ tokens: t }) => ({
                      color: t.semantic.color.type.default.value,
                      letterSpacing: "0.3px",
                    })}
                  >
                    Custom ID
                  </Typography>
                  <TextField
                    fullWidth
                    size="small"
                    value={assessmentId}
                    onChange={(e) => setAssessmentId(e.target.value)}
                    placeholder="e.g. CRA-001"
                    aria-label="Custom ID"
                    slotProps={{ input: { readOnly: isApproved } }}
                  />
                </Stack>
              </Box>
            </Box>

            <NewCyberRiskAssessmentMethodSection
              readOnly={isApproved}
              instructionsValue={routeAssessmentId ? assessmentInstructions : undefined}
              onInstructionsChange={routeAssessmentId ? setAssessmentInstructions : undefined}
              assessmentTypeSlot={
                <RadioButtonArray
                  label="Assessment type"
                  name="new-cra-scoring-type"
                  options={CRA_SCORING_TYPE_RADIO_OPTIONS}
                  value={scoringType}
                  onChange={(v) => {
                    if (v === "inherent" || v === "residual") {
                      setScoringType(v);
                    }
                  }}
                  showAction
                  showIcon={false}
                  showActionText
                  actionTextPlain
                  actionText="Select whether assessment scores contribute to the inherent or residual risk score."
                  disabled={isApproved || isScoringStatus}
                />
              }
            />
          </Stack>
        </TabPanel>

        <TabPanel value={activeTab} index={1}>
          <AssessmentScopeTab
            scopeSubView={scopeSubView}
            onScopeSubViewChange={handleScopeSubViewChange}
            includedAssetIds={includedScopeAssetIds}
            excludedScopeCyberRiskIds={excludedScopeCyberRiskIds}
            onSetCyberRiskScopeIncluded={setCyberRiskScopeIncluded}
            onBulkCyberRisksScopeIncluded={bulkSetCyberRisksScopeIncluded}
            excludedScopeThreatIds={excludedScopeThreatIds}
            onSetThreatScopeIncluded={setThreatScopeIncluded}
            onBulkThreatsScopeIncluded={bulkSetThreatsScopeIncluded}
            excludedScopeVulnerabilityIds={excludedScopeVulnerabilityIds}
            onSetVulnerabilityScopeIncluded={setVulnerabilityScopeIncluded}
            onBulkVulnerabilitiesScopeIncluded={bulkSetVulnerabilitiesScopeIncluded}
            excludedScopeControlIds={excludedScopeControlIds}
            onSetControlScopeIncluded={setControlScopeIncluded}
            onBulkControlsScopeIncluded={bulkSetControlsScopeIncluded}
            onToggleAssetIncluded={toggleAssetIncluded}
            onBulkAssetIdsIncluded={bulkSetAssetsIncluded}
            scopeTogglesReadOnly={isApproved}
          />
        </TabPanel>
        <TabPanel
          value={activeTab}
          index={2}
          sx={{
            display: "flex",
            flexDirection: "column",
            gap: 6,
          }}
        >
          <AssessmentScoringTab
            assessmentName={name}
            returnToAssessmentPath={location.pathname}
            aggregationMethod={scenarioScoreAggregationMethod}
            onAggregationMethodChange={setScenarioScoreAggregationMethod}
            includedAssetIds={includedScopeAssetIds}
            excludedScopeCyberRiskIds={excludedScopeCyberRiskIds}
            excludedScopeScenarioIds={excludedScopeScenarioIds}
            scenarioScopeAssessmentId={scenarioScopeAssessmentId}
            assessmentPhase={assessmentPhase}
            aiScoringPhase={aiScoringPhase}
            scoringType={scoringType}
            showAiScoringAction={showAiScoringAction}
            onAiScoringClick={handleAiScoringClick}
            onGoToScope={() => setActiveTab(SCOPE_TAB_INDEX)}
            scenarioNotApplicableIds={scenarioNotApplicableIds}
            isNewCraDraftFlow={isNewCraDraftFlow}
            scenarioCatalogScoresReleased={scenarioCatalogScoresReleased}
            scenarioManuallyRevealedScoreIds={scenarioManuallyRevealedScoreIds}
            scenarioNavFromNewCraDraft={isNewCraDraftFlow}
            scenarioNavCatalogScoresReleased={scenarioCatalogScoresReleased}
            scenarioNavManuallyRevealedScoreIds={scenarioManuallyRevealedScoreIds}
            onRemoveCyberRiskFromAssessment={(id) => setCyberRiskScopeIncluded(id, false)}
            onRemoveScenarioFromAssessment={handleRemoveScenarioFromAssessment}
            rowActionsDisabled={isApproved}
          />
        </TabPanel>
        <TabPanel value={activeTab} index={3}>
          <AssessmentResultsTab
            includedAssetIds={includedScopeAssetIds}
            excludedScopeCyberRiskIds={excludedScopeCyberRiskIds}
            excludedScopeScenarioIds={excludedScopeScenarioIds}
            scenarioScopeAssessmentId={scenarioScopeAssessmentId}
            onGoToScoring={() => setActiveTab(SCORING_TAB_INDEX)}
            assessmentName={name}
            returnToAssessmentPath={location.pathname}
            assessmentPhase={assessmentPhase}
            scoringType={scoringType}
            aiScoringPhase={aiScoringPhase}
            aggregationMethod={scenarioScoreAggregationMethod}
            isNewCraDraftFlow={isNewCraDraftFlow}
            scenarioCatalogScoresReleased={scenarioCatalogScoresReleased}
            scenarioManuallyRevealedScoreIds={scenarioManuallyRevealedScoreIds}
            scenarioNotApplicableIds={scenarioNotApplicableIds}
          />
        </TabPanel>
      </Stack>
    </Container>
  );
}
