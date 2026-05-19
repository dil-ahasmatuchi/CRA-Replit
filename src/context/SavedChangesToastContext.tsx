import { Alert, Snackbar } from "@mui/material";
import type { SnackbarCloseReason } from "@mui/material/Snackbar";
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
  type SyntheticEvent,
} from "react";
import { useLocation, useNavigate } from "react-router";

export const SAVED_CHANGES_TOAST_STATE_KEY = "showSavedChangesToast" as const;

/** Discard vs save-then-navigate branches when leaving a page with unsaved edits. */
export type PendingSaveNavigationHandlers = {
  onDiscard: () => void;
  onAfterSave: () => void;
};

/** Merge into `navigate(..., { state })` so the destination route can show the saved-changes toast. */
export function mergeSavedChangesNavigateState(
  base?: Record<string, unknown> | null,
): Record<string, unknown> {
  return { ...(base ?? {}), [SAVED_CHANGES_TOAST_STATE_KEY]: true };
}

type SavedChangesToastContextValue = {
  notifySavedChanges: () => void;
  showSuccessToast: (message: string) => void;
};

const SavedChangesToastContext = createContext<SavedChangesToastContextValue | null>(null);

export function useSavedChangesToast(): SavedChangesToastContextValue {
  const ctx = useContext(SavedChangesToastContext);
  if (!ctx) {
    throw new Error("useSavedChangesToast must be used within SavedChangesToastProvider");
  }
  return ctx;
}

export function SavedChangesToastProvider({ children }: { children: ReactNode }) {
  const [toast, setToast] = useState<{ open: boolean; message: string }>({
    open: false,
    message: "",
  });
  const location = useLocation();
  const navigate = useNavigate();

  const showSuccessToast = useCallback((message: string) => {
    setToast({ open: true, message });
  }, []);

  const notifySavedChanges = useCallback(() => {
    showSuccessToast("Changes were saved.");
  }, [showSuccessToast]);

  const handleClose = useCallback(
    (_event: SyntheticEvent | Event, reason: SnackbarCloseReason) => {
      if (reason === "clickaway") return;
      setToast((t) => ({ ...t, open: false }));
    },
    [],
  );

  const value = useMemo(
    () => ({ notifySavedChanges, showSuccessToast }),
    [notifySavedChanges, showSuccessToast],
  );

  useEffect(() => {
    const raw = location.state;
    if (raw == null || typeof raw !== "object" || Array.isArray(raw)) return;
    const record = raw as Record<string, unknown>;
    if (!record[SAVED_CHANGES_TOAST_STATE_KEY]) return;

    setToast({ open: true, message: "Changes were saved." });
    const { [SAVED_CHANGES_TOAST_STATE_KEY]: _removed, ...rest } = record;
    const nextState = Object.keys(rest).length ? rest : undefined;
    void navigate(
      { pathname: location.pathname, search: location.search, hash: location.hash },
      { replace: true, state: nextState },
    );
  }, [location.pathname, location.search, location.hash, location.state, navigate]);

  return (
    <SavedChangesToastContext.Provider value={value}>
      {children}
      <Snackbar open={toast.open} autoHideDuration={5000} onClose={handleClose}>
        <Alert severity="success" aria-live="polite">
          {toast.message}
        </Alert>
      </Snackbar>
    </SavedChangesToastContext.Provider>
  );
}
