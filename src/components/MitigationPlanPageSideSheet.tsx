import { useCallback, useEffect, useMemo, useRef, useState, useSyncExternalStore } from "react";
import { Footer } from "@diligentcorp/atlas-react-bundle";
import {
  Autocomplete,
  Box,
  Button,
  Checkbox,
  Chip,
  Drawer,
  FormControl,
  FormLabel,
  IconButton,
  Link,
  ListItemText,
  MenuItem,
  Select,
  type SelectChangeEvent,
  Stack,
  TextField,
  Typography,
  useTheme,
} from "@mui/material";
import { LocalizationProvider } from "@mui/x-date-pickers-pro";
import { AdapterDateFns } from "@mui/x-date-pickers-pro/AdapterDateFns";
import { DesktopDatePicker } from "@mui/x-date-pickers";
import { format } from "date-fns";

import ClearIcon from "@diligentcorp/atlas-react-bundle/icons/Clear";
import ExpandDownIcon from "@diligentcorp/atlas-react-bundle/icons/ExpandDown";
import UploadIcon from "@diligentcorp/atlas-react-bundle/icons/Upload";

import { cyberRisks, findCyberRiskByExactName, getCyberRiskById } from "../data/cyberRisks.js";
import { getControlById } from "../data/controls.js";
import {
  createMitigationPlan,
  deleteMitigationPlan,
  getMitigationPlanById,
  updateMitigationPlan,
} from "../data/mitigationPlans.js";
import {
  getCatalogSnapshotVersion,
  subscribeCatalog,
} from "../data/persistence/catalogStore.js";
import type { MockMitigationPlan } from "../data/types.js";
import {
  getFivePointLabel,
  padId,
  type FivePointScaleLabel,
  type FivePointScaleValue,
} from "../data/types.js";
import { mockUserEmail, users } from "../data/users.js";

export const SEVERITY_OPTIONS = [
  "1 - Very low",
  "2 - Low",
  "3 - Medium",
  "4 - High",
  "5 - Very high",
];
export const ORG_UNIT_OPTIONS = [
  "Chicago - Operations division - Incident response implementation",
  "New York - IT division - Security operations",
  "London - Engineering - Cloud infrastructure",
];
export const RELATED_CONTROLS_OPTIONS = [
  "Role-based access",
  "Communication protocols",
  "Performance metrics",
  "Business continuity plans",
  "Vendor Risk Management",
  "Data Loss Prevention",
  "Network Security Monitoring",
  "Physical Security Controls",
  "Third-Party Risk Assessment",
  "Business Impact Analysis",
];

/** Maps side-sheet “Related Org. unit” labels to catalog `orgUnitId` values. */
const ORG_UNIT_OPTION_TO_BU_ID: Record<string, string> = {
  "Chicago - Operations division - Incident response implementation": "BU-006",
  "New York - IT division - Security operations": "BU-002",
  "London - Engineering - Cloud infrastructure": "BU-003",
};

/** Inverse map for hydrating the org unit `Select` from persisted `orgUnitId`. */
const ORG_UNIT_BU_ID_TO_OPTION: Record<string, string> = Object.fromEntries(
  Object.entries(ORG_UNIT_OPTION_TO_BU_ID).map(([label, buId]) => [buId, label]),
);

const DEFAULT_ORG_UNIT_ID = "BU-015";

function parseMitigationPlanSeverity(raw: string): {
  value: FivePointScaleValue;
  label: FivePointScaleLabel;
} {
  if (!raw.trim()) {
    const value = 3 as FivePointScaleValue;
    return { value, label: getFivePointLabel(value) };
  }
  const m = /^(\d)/.exec(raw);
  const n = m ? parseInt(m[1]!, 10) : 3;
  const clamped = (n >= 1 && n <= 5 ? n : 3) as FivePointScaleValue;
  return { value: clamped, label: getFivePointLabel(clamped) };
}

function buildRiskAutocompleteOptions(
  extraName: string,
  catalogRiskNames: readonly string[],
): string[] {
  const trimmed = extraName.trim();
  if (trimmed && !catalogRiskNames.includes(trimmed)) {
    return [trimmed, ...catalogRiskNames];
  }
  return [...catalogRiskNames];
}

/** Ensures persisted control labels appear as `MenuItem`s even when not in the default library list. */
function buildRelatedControlsMenuOptions(selected: readonly string[]): string[] {
  const extras = selected.filter((c) => !RELATED_CONTROLS_OPTIONS.includes(c));
  return [...RELATED_CONTROLS_OPTIONS, ...extras];
}

function PlaceholderText({ text = "Choose an option" }: { text?: string }) {
  const {
    tokens: {
      component: { input },
    },
  } = useTheme();
  return (
    <Box
      component="span"
      sx={{ color: input.outlined.default.placeholder.color.value, pointerEvents: "none" }}
    >
      {text}
    </Box>
  );
}

type UserLookupOption = {
  id: string;
  label: string;
  email: string;
  type: "user";
};

/** Asset rows for the mitigation plan “Assets” multiselect (parent supplies full catalog or a scoped subset). */
export type MitigationPlanAssetOption = { id: string; label: string };

export type MitigationPlanPageSideSheetProps = {
  open: boolean;
  onClose: () => void;
  /** When set (e.g. opened from a cyber risk row), pre-fills the risk Autocomplete. */
  cyberRiskName: string;
  /** When set with the sheet open, form is hydrated from the catalog plan (edit mode). */
  editingPlanId?: string | null;
  /** Selectable assets (e.g. full catalog from Mitigation plans page, or assessment-scoped ids from results tab). */
  assetOptions: MitigationPlanAssetOption[];
  /** Called after a plan is persisted to the catalog (e.g. show a success toast). */
  onMitigationPlanCreated?: (plan: MockMitigationPlan) => void;
  /** Called after an existing plan is updated (e.g. show a success toast). */
  onMitigationPlanUpdated?: () => void;
  /** Called after an existing plan is deleted (e.g. show a success toast). */
  onMitigationPlanDeleted?: () => void;
};

export default function MitigationPlanPageSideSheet({
  open,
  onClose,
  cyberRiskName,
  editingPlanId = null,
  assetOptions,
  onMitigationPlanCreated,
  onMitigationPlanUpdated,
  onMitigationPlanDeleted,
}: MitigationPlanPageSideSheetProps) {
  const { presets } = useTheme();
  const { AutocompletePresets, SideSheetPresets } = presets;
  const { size, components } = SideSheetPresets;
  const { Header, Content } = components;

  const [selectedRisk, setSelectedRisk] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("");
  const [dueDate, setDueDate] = useState<Date | null>(null);
  const [ownerIds, setOwnerIds] = useState<string[]>([]);
  const [orgUnit, setOrgUnit] = useState("");
  const [relatedAssetIds, setRelatedAssetIds] = useState<string[]>([]);
  const [relatedControls, setRelatedControls] = useState<string[]>([]);
  const [actionPlan, setActionPlan] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);
  /** Primary related risk name when edit mode hydrated; used to preserve multi–cyber-risk links if unchanged. */
  const initialPrimaryRiskNameRef = useRef("");

  const catalogVersion = useSyncExternalStore(
    subscribeCatalog,
    getCatalogSnapshotVersion,
    () => 0,
  );

  const riskAutocompleteOptions = useMemo(() => {
    const names = cyberRisks.map((r) => r.name);
    const extra = editingPlanId ? (selectedRisk ?? "") : cyberRiskName;
    return buildRiskAutocompleteOptions(extra, names);
  }, [cyberRiskName, editingPlanId, selectedRisk, catalogVersion]);

  const userLookupOptions = useMemo((): UserLookupOption[] => {
    return users.map((u) => ({
      id: u.id,
      label: u.fullName,
      email: mockUserEmail(u),
      type: "user" as const,
    }));
  }, [catalogVersion]);

  const selectedOwners = useMemo((): UserLookupOption[] => {
    return ownerIds
      .map((id) => userLookupOptions.find((o) => o.id === id))
      .filter((o): o is UserLookupOption => o != null);
  }, [ownerIds, userLookupOptions]);

  const assetLabelById = useMemo(() => {
    return new Map(assetOptions.map((o) => [o.id, o.label] as const));
  }, [assetOptions]);

  const relatedControlsMenuOptions = useMemo(
    () => buildRelatedControlsMenuOptions(relatedControls),
    [relatedControls],
  );

  const isEditMode = Boolean(open && editingPlanId);

  useEffect(() => {
    if (!open) return;
    if (editingPlanId) return;
    const trimmed = cyberRiskName.trim();
    setSelectedRisk(trimmed === "" ? null : trimmed);
  }, [open, cyberRiskName, editingPlanId]);

  useEffect(() => {
    if (!open || !editingPlanId) return;
    const plan = getMitigationPlanById(editingPlanId);
    if (!plan) return;

    setName(plan.name);
    setSeverity(`${plan.severity} - ${plan.severityLabel}`);
    const rawDue = plan.dueDate?.trim() ?? "";
    if (rawDue && /^\d{4}-\d{2}-\d{2}/.test(rawDue)) {
      const parsed = new Date(`${rawDue.slice(0, 10)}T12:00:00`);
      setDueDate(Number.isNaN(parsed.getTime()) ? null : parsed);
    } else {
      setDueDate(null);
    }
    setOwnerIds(plan.ownerId ? [plan.ownerId] : []);
    setOrgUnit(ORG_UNIT_BU_ID_TO_OPTION[plan.orgUnitId] ?? "");
    setRelatedAssetIds(plan.assetIds?.length ? [...plan.assetIds] : []);
    const controlLabels =
      plan.relatedControlNames?.length && plan.relatedControlNames.some((s) => s.trim())
        ? [...plan.relatedControlNames]
        : plan.controlIds
            .map((cid) => getControlById(cid)?.name)
            .filter((n): n is string => Boolean(n?.trim()));
    setRelatedControls(controlLabels);
    setActionPlan(plan.actionPlan ?? "");

    const primary = getCyberRiskById(plan.cyberRiskIds[0] ?? "");
    initialPrimaryRiskNameRef.current = primary?.name ?? "";
    setSelectedRisk(primary?.name ?? null);
  }, [open, editingPlanId, catalogVersion]);

  const resetLocalForm = useCallback(() => {
    initialPrimaryRiskNameRef.current = "";
    setSelectedRisk(null);
    setName("");
    setSeverity("");
    setDueDate(null);
    setOwnerIds([]);
    setOrgUnit("");
    setRelatedAssetIds([]);
    setRelatedControls([]);
    setActionPlan("");
  }, []);

  const handleClose = useCallback(() => {
    resetLocalForm();
    onClose();
  }, [onClose, resetLocalForm]);

  const resolvedRisk = useMemo(() => {
    if (!selectedRisk?.trim()) return undefined;
    return findCyberRiskByExactName(selectedRisk);
  }, [selectedRisk, catalogVersion]);

  const canSubmit = Boolean(name.trim() && resolvedRisk);

  const handleAddMitigationPlan = useCallback(() => {
    const trimmedName = name.trim();
    if (!trimmedName || !resolvedRisk) return;

    const { value: severityValue, label: severityLabel } = parseMitigationPlanSeverity(severity);
    const orgUnitId =
      orgUnit && ORG_UNIT_OPTION_TO_BU_ID[orgUnit] ? ORG_UNIT_OPTION_TO_BU_ID[orgUnit]! : DEFAULT_ORG_UNIT_ID;
    const ownerId = ownerIds[0] ?? padId("USR", 7);
    const dueDateIso = dueDate ? dueDate.toISOString().slice(0, 10) : "";

    const plan = createMitigationPlan({
      name: trimmedName,
      cyberRiskIds: [resolvedRisk.id],
      ownerId,
      orgUnitId,
      severity: severityValue,
      severityLabel,
      dueDate: dueDateIso,
      assetIds: relatedAssetIds,
      relatedControlNames: relatedControls,
      actionPlan,
    });
    onMitigationPlanCreated?.(plan);
    resetLocalForm();
    onClose();
  }, [
    name,
    resolvedRisk,
    severity,
    orgUnit,
    ownerIds,
    dueDate,
    relatedAssetIds,
    relatedControls,
    actionPlan,
    onMitigationPlanCreated,
    resetLocalForm,
    onClose,
  ]);

  const handleSaveChanges = useCallback(() => {
    const trimmedName = name.trim();
    if (!trimmedName || !resolvedRisk || !editingPlanId) return;

    const plan = getMitigationPlanById(editingPlanId);
    if (!plan) return;

    const primaryAtOpen = initialPrimaryRiskNameRef.current.trim();
    const selectedTrimmed = (selectedRisk ?? "").trim();
    // Single-select related risk: keep all linked cyber risks if the user left the primary name unchanged; otherwise replace with the selected risk only.
    const nextCyberRiskIds =
      primaryAtOpen !== "" && selectedTrimmed === primaryAtOpen
        ? [...plan.cyberRiskIds]
        : [resolvedRisk.id];

    const { value: severityValue, label: severityLabel } = parseMitigationPlanSeverity(severity);
    const orgUnitId =
      orgUnit && ORG_UNIT_OPTION_TO_BU_ID[orgUnit] ? ORG_UNIT_OPTION_TO_BU_ID[orgUnit]! : DEFAULT_ORG_UNIT_ID;
    const ownerId = ownerIds[0] ?? padId("USR", 7);
    const dueDateIso = dueDate ? dueDate.toISOString().slice(0, 10) : "";

    updateMitigationPlan(editingPlanId, {
      name: trimmedName,
      cyberRiskIds: nextCyberRiskIds,
      ownerId,
      orgUnitId,
      severity: severityValue,
      severityLabel,
      dueDate: dueDateIso,
      assetIds: relatedAssetIds,
      relatedControlNames: relatedControls,
      actionPlan,
    });
    onMitigationPlanUpdated?.();
    resetLocalForm();
    onClose();
  }, [
    name,
    resolvedRisk,
    editingPlanId,
    selectedRisk,
    severity,
    orgUnit,
    ownerIds,
    dueDate,
    relatedAssetIds,
    relatedControls,
    actionPlan,
    onMitigationPlanUpdated,
    resetLocalForm,
    onClose,
  ]);

  const handleDeleteMitigationPlan = useCallback(() => {
    if (!editingPlanId) return;
    deleteMitigationPlan(editingPlanId);
    onMitigationPlanDeleted?.();
    resetLocalForm();
    onClose();
  }, [editingPlanId, onMitigationPlanDeleted, resetLocalForm, onClose]);

  const handleRelatedAssetsChange = useCallback(
    (event: SelectChangeEvent<string[]>) => {
      const value = event.target.value;
      setRelatedAssetIds(typeof value === "string" ? value.split(",") : value);
    },
    [],
  );

  const handleDeleteAsset = useCallback((assetId: string) => {
    setRelatedAssetIds((prev) => prev.filter((id) => id !== assetId));
  }, []);

  const handleDeleteControl = useCallback(
    (controlToDelete: string) => {
      setRelatedControls((prev) => prev.filter((c) => c !== controlToDelete));
    },
    [],
  );

  const handleRelatedControlsChangeFixed = useCallback(
    (event: SelectChangeEvent<string[]>) => {
      const value = event.target.value;
      setRelatedControls(typeof value === "string" ? value.split(",") : value);
    },
    [],
  );

  return (
    <Drawer
      anchor="right"
      open={open}
      onClose={handleClose}
      sx={{ ...size.large.sx }}
      slotProps={{
        paper: {
          role: "dialog",
          "aria-labelledby": "mitigation-page-side-sheet-title",
        },
      }}
    >
      <Header
        variant="default"
        onClose={handleClose}
        title={isEditMode ? "Edit mitigation plan" : "Add mitigation plan"}
        componentProps={{
          closeButton: { "aria-label": "Close side sheet" },
          title: { component: "h2", id: "mitigation-page-side-sheet-title" },
        }}
      />

      <Content ariaLabel="Mitigation plan form">
        <Stack gap={2}>
          <FormControl fullWidth>
            <FormLabel htmlFor="mp-page-related-risk">Related risk</FormLabel>
            <Autocomplete
              id="mp-page-related-risk"
              options={riskAutocompleteOptions}
              value={selectedRisk}
              onChange={(_, newValue) => setSelectedRisk(newValue)}
              renderInput={(params) => <TextField {...params} placeholder="Search risks" />}
            />
          </FormControl>

          {/* Row 1: Name */}
          <FormControl fullWidth>
            <FormLabel htmlFor="mp-name">Name</FormLabel>
            <TextField
              id="mp-name"
              placeholder="Enter issue name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              slotProps={{
                input: {
                  "aria-label": "Name",
                },
              }}
            />
          </FormControl>

          {/* Row 2: Severity + Due date */}
          <Stack direction="row" gap={3}>
            <FormControl sx={{ flex: 7 }}>
              <FormLabel id="mp-severity-label">Severity</FormLabel>
              <Select
                displayEmpty
                value={severity}
                onChange={(e: SelectChangeEvent) => setSeverity(e.target.value)}
                labelId="mp-severity-label"
                renderValue={(selected) => {
                  if (!selected) return <PlaceholderText />;
                  return selected;
                }}
              >
                {SEVERITY_OPTIONS.map((opt) => (
                  <MenuItem key={opt} value={opt}>
                    {opt}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
            <FormControl sx={{ flex: 5 }}>
              <FormLabel htmlFor="mp-due-date">Due date</FormLabel>
              <LocalizationProvider dateAdapter={AdapterDateFns}>
                <DesktopDatePicker
                  value={dueDate}
                  onChange={setDueDate}
                  dayOfWeekFormatter={(day: Date) => format(day, "EEEEEE")}
                  slotProps={{
                    textField: {
                      placeholder: "MM/DD/YYYY",
                      id: "mp-due-date",
                    },
                  }}
                />
              </LocalizationProvider>
            </FormControl>
          </Stack>

          {/* Row 3: Owner(s) */}
          <FormControl fullWidth margin="none">
            <FormLabel htmlFor="mp-owners">Owner(s)</FormLabel>
            <Autocomplete
              multiple
              id="mp-owners-lookup"
              options={userLookupOptions as never}
              value={selectedOwners as never}
              onChange={(_, newValue) =>
                setOwnerIds((newValue as UserLookupOption[]).map((o) => o.id))
              }
              getOptionLabel={(option) => (option as UserLookupOption).label}
              isOptionEqualToValue={(a, b) =>
                (a as UserLookupOption).id === (b as UserLookupOption).id
              }
              renderInput={(params) => (
                <TextField
                  {...params}
                  placeholder="Select users..."
                  margin="none"
                  inputProps={{ ...params.inputProps, id: "mp-owners" }}
                />
              )}
              renderOption={AutocompletePresets.userLookup.renderOption}
              renderTags={AutocompletePresets.userLookup.type.multiple.renderTags}
            />
          </FormControl>

          {/* Row 4: Related Org. unit */}
          <FormControl fullWidth>
            <FormLabel id="mp-org-unit-label">Related Org. unit</FormLabel>
            <Select
              displayEmpty
              value={orgUnit}
              onChange={(e: SelectChangeEvent) => setOrgUnit(e.target.value)}
              labelId="mp-org-unit-label"
              renderValue={(selected) => {
                if (!selected) return <PlaceholderText />;
                return selected;
              }}
            >
              {ORG_UNIT_OPTIONS.map((opt) => (
                <MenuItem key={opt} value={opt}>
                  {opt}
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Row 5: Assets */}
          <FormControl fullWidth>
            <FormLabel id="mp-related-assets-label">Assets</FormLabel>
            <Select
              multiple
              displayEmpty
              value={relatedAssetIds}
              onChange={handleRelatedAssetsChange}
              labelId="mp-related-assets-label"
              IconComponent={ExpandDownIcon}
              endAdornment={
                relatedAssetIds.length > 0 ? (
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      setRelatedAssetIds([]);
                    }}
                    aria-label="Clear all selected assets"
                    sx={{ mr: 2 }}
                  >
                    <ClearIcon aria-hidden />
                  </IconButton>
                ) : null
              }
              renderValue={(selected) => {
                const ids = selected as string[];
                if (ids.length === 0) {
                  return <PlaceholderText text="Choose assets" />;
                }
                return (
                  <Stack direction="row" flexWrap="wrap" gap={1}>
                    {ids.map((id) => (
                      <Chip
                        key={id}
                        label={assetLabelById.get(id) ?? id}
                        variant="outlined"
                        size="small"
                        onDelete={() => handleDeleteAsset(id)}
                        onMouseDown={(e) => e.stopPropagation()}
                      />
                    ))}
                  </Stack>
                );
              }}
              sx={{
                "& .MuiSelect-select": {
                  whiteSpace: "normal",
                  height: "auto !important",
                  minHeight: 92,
                  display: "flex",
                  alignItems: "flex-start",
                  flexWrap: "wrap",
                  pt: 1,
                  pb: 1,
                },
              }}
            >
              {assetOptions.map((opt) => (
                <MenuItem key={opt.id} value={opt.id}>
                  <Checkbox checked={relatedAssetIds.includes(opt.id)} />
                  <ListItemText primary={opt.label} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Row 6: Related controls */}
          <FormControl fullWidth>
            <FormLabel id="mp-related-controls-label">Related controls</FormLabel>
            <Select
              multiple
              displayEmpty
              value={relatedControls}
              onChange={handleRelatedControlsChangeFixed}
              labelId="mp-related-controls-label"
              IconComponent={ExpandDownIcon}
              endAdornment={
                relatedControls.length > 0 ? (
                  <IconButton
                    size="small"
                    onClick={(e) => {
                      e.stopPropagation();
                      setRelatedControls([]);
                    }}
                    aria-label="Clear all selected controls"
                    sx={{ mr: 2 }}
                  >
                    <ClearIcon aria-hidden />
                  </IconButton>
                ) : null
              }
              renderValue={(selected) => {
                if (selected.length === 0) {
                  return <PlaceholderText text="Choose controls" />;
                }
                return (
                  <Stack direction="row" flexWrap="wrap" gap={1}>
                    {selected.map((value) => (
                      <Chip
                        key={value}
                        label={value}
                        variant="outlined"
                        size="small"
                        onDelete={() => handleDeleteControl(value)}
                        onMouseDown={(e) => e.stopPropagation()}
                      />
                    ))}
                  </Stack>
                );
              }}
              sx={{
                "& .MuiSelect-select": {
                  whiteSpace: "normal",
                  height: "auto !important",
                  minHeight: 92,
                  display: "flex",
                  alignItems: "flex-start",
                  flexWrap: "wrap",
                  pt: 1,
                  pb: 1,
                },
              }}
            >
              {relatedControlsMenuOptions.map((opt) => (
                <MenuItem key={opt} value={opt}>
                  <Checkbox checked={relatedControls.includes(opt)} />
                  <ListItemText primary={opt} />
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          {/* Row 7: Action plan */}
          <FormControl fullWidth>
            <FormLabel htmlFor="mp-action-plan">Action plan</FormLabel>
            <TextField
              multiline
              minRows={3}
              placeholder="Describe the action plan"
              value={actionPlan}
              onChange={(e) => setActionPlan(e.target.value)}
              slotProps={{ input: { id: "mp-action-plan" } }}
            />
          </FormControl>

          {/* Row 8: File uploader */}
          <Box>
            <input
              ref={fileInputRef}
              type="file"
              hidden
              multiple
              accept=".jpg,.jpeg,.pdf,.xls,.xlsx"
            />
            <Box
              onClick={() => fileInputRef.current?.click()}
              sx={({ tokens: t }) => ({
                borderStyle: "dashed",
                borderWidth: t.semantic.borderWidth.thin.value,
                borderColor: t.semantic.color.outline.default.value,
                borderRadius: t.semantic.radius.lg.value,
                px: 3,
                py: 3,
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                gap: 1,
                cursor: "pointer",
                "&:hover": {
                  borderColor: t.semantic.color.outline.hover.value,
                  backgroundColor: t.semantic.color.action.secondary.hoverFill.value,
                },
              })}
            >
              <Stack direction="row" alignItems="center" gap={1}>
                <UploadIcon aria-hidden />
                <Typography
                  sx={({ tokens: t }) => ({
                    fontSize: t.semantic.font.text.md.fontSize.value,
                    lineHeight: t.semantic.font.text.md.lineHeight.value,
                    letterSpacing: t.semantic.font.text.md.letterSpacing.value,
                    color: t.semantic.color.type.default.value,
                  })}
                >
                  Drag files here or{" "}
                  <Link component="span" underline="always" sx={{ fontWeight: 600, cursor: "pointer" }}>
                    select files to upload
                  </Link>
                </Typography>
              </Stack>
              <Stack direction="row" gap={2}>
                <Typography
                  sx={({ tokens: t }) => ({
                    fontSize: t.semantic.font.text.sm.fontSize.value,
                    lineHeight: t.semantic.font.text.sm.lineHeight.value,
                    letterSpacing: t.semantic.font.text.sm.letterSpacing.value,
                    color: t.semantic.color.type.muted.value,
                  })}
                >
                  Formats: JPG, PDF, XLS
                </Typography>
                <Typography
                  sx={({ tokens: t }) => ({
                    fontSize: t.semantic.font.text.sm.fontSize.value,
                    lineHeight: t.semantic.font.text.sm.lineHeight.value,
                    letterSpacing: t.semantic.font.text.sm.letterSpacing.value,
                    color: t.semantic.color.type.muted.value,
                  })}
                >
                  Max. file size: 5 MB
                </Typography>
              </Stack>
            </Box>
          </Box>
        </Stack>
      </Content>

      <Footer
        horizontalPadding="medium"
        secondaryAction={
          isEditMode ? (
            <Button
              variant="text"
              onClick={handleDeleteMitigationPlan}
              sx={(theme) => ({ color: theme.palette.error.main })}
            >
              Delete
            </Button>
          ) : undefined
        }
        tertiaryAction={
          <Button variant="text" onClick={handleClose}>
            Discard
          </Button>
        }
        primaryAction={
          <Button
            variant="contained"
            disabled={!canSubmit}
            onClick={isEditMode ? handleSaveChanges : handleAddMitigationPlan}
          >
            {isEditMode ? "Save changes" : "Add mitigation plan"}
          </Button>
        }
      />
    </Drawer>
  );
}
