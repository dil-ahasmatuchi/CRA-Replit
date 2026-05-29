import { useCallback, useState, type MouseEvent } from "react";
import {
  Box,
  Button,
  Checkbox,
  InputAdornment,
  ListItemText,
  Menu,
  MenuItem,
  TextField,
} from "@mui/material";
import type { SxProps, Theme } from "@mui/material/styles";
import {
  Toolbar,
  QuickFilter,
  QuickFilterControl,
  ColumnsPanelTrigger,
} from "@mui/x-data-grid-pro";

import SearchIcon from "@diligentcorp/atlas-react-bundle/icons/Search";
import FilterIcon from "@diligentcorp/atlas-react-bundle/icons/Filter";
import ColumnsIcon from "@diligentcorp/atlas-react-bundle/icons/Columns";

export const DEFAULT_SEARCH_LABEL = "Search by";
export const DEFAULT_SEARCH_PLACEHOLDER = "Search by";
export const DEFAULT_SEARCH_FIELD_SX: SxProps<Theme> = {
  minWidth: { xs: 1, sm: 300 },
  maxWidth: 400,
};

type NewToolbarBaseProps = {
  /**
   * MUI `TextField` `label`. Omitted or `null`: no floating label (placeholder only).
   */
  searchLabel?: string | null;
  /**
   * @default "Search by"
   */
  searchPlaceholder?: string;
  /**
   * `sx` for the quick-filter search `TextField`. Defaults match
   * [`ThreatDetailAssessmentsTab`](src/components/ThreatDetailAssessmentsTab.tsx) (responsive min width, max 400px).
   */
  searchFieldSx?: SxProps<Theme>;
  /**
   * Number of filter **criteria** (categories with any selection), same idea as [`ScopeToolbar`](./ScopeToolbar.tsx).
   * When &gt; 0, the **Filter** label shows `Filter (n)` and the icon uses the **filled** variant (when Filter is shown).
   */
  filterCriteriaCount?: number;
  /**
   * Clears applied page filters (e.g. same handler as **Clear filters** in [`FilterSideSheet`](./FilterSideSheet.tsx)).
   * When set and `filterCriteriaCount` &gt; 0, **Clear filters** is shown after **Columns**.
   */
  onClearFilters?: () => void;
};

/**
 * Discriminated union for the Filter button:
 *
 * - **`showFilterButton: false`** — omit **Filter** (search + Columns only). `onOpenFilters` is unused.
 * - **`showFilterButton` omitted or `true`** — **Filter** is shown; **`onOpenFilters` is required** (parent
 *   should open [`FilterSideSheet`](src/components/FilterSideSheet.tsx) or equivalent).
 *
 * **Search field:** no floating label by default; placeholder remains `DEFAULT_SEARCH_PLACEHOLDER`.
 * Pass `searchLabel` as a string when a label is required.
 */
export type NewToolbarProps = NewToolbarBaseProps &
  (
    | { showFilterButton: false; onOpenFilters?: () => void }
    | { showFilterButton?: true; onOpenFilters: () => void }
  );

/**
 * DataGrid Pro **toolbar** slot: quick text search (MUI `QuickFilter`), optional **Filter** button that
 * should open the page’s [`FilterSideSheet`](src/components/FilterSideSheet.tsx) via `onOpenFilters`, and
 * MUI **Columns** panel (`ColumnsPanelTrigger`). Optional **Clear filters** when `filterCriteriaCount` &gt; 0
 * and `onClearFilters` is set (same pattern as [`ScopeToolbar`](./ScopeToolbar.tsx)). Does not use MUI’s
 * `FilterPanelTrigger`.
 *
 * Use as `slots={{ toolbar: NewToolbar }}` and pass the same props the toolbar needs (see `NewToolbarProps`).
 */
export default function NewToolbar({
  searchLabel,
  searchPlaceholder = DEFAULT_SEARCH_PLACEHOLDER,
  searchFieldSx = DEFAULT_SEARCH_FIELD_SX,
  filterCriteriaCount = 0,
  onClearFilters,
  showFilterButton: showFilterButtonProp,
  onOpenFilters,
}: NewToolbarProps) {
  const showFilterButton = showFilterButtonProp !== false;

  const textFieldLabel: string | undefined =
    searchLabel != null && searchLabel !== "" ? searchLabel : undefined;

  const hasFilterCriteria = filterCriteriaCount > 0;
  const filterButtonLabel = hasFilterCriteria ? `Filter (${filterCriteriaCount})` : "Filter";
  const filterButtonAriaLabel = hasFilterCriteria
    ? `Show filters, ${filterCriteriaCount} filter criteria applied`
    : "Show filters";

  const showClearFilters = hasFilterCriteria && Boolean(onClearFilters);

  const filterButton = showFilterButton ? (
    <Button
      type="button"
      startIcon={
        <FilterIcon variant={hasFilterCriteria ? "filled" : "outlined"} size="lg" aria-hidden />
      }
      aria-label={filterButtonAriaLabel}
      onClick={() => onOpenFilters?.()}
      sx={{
        display: "inline-flex",
        flexDirection: "row",
        alignItems: "center",
        px: 0.5,
        columnGap: 0.5,
      }}
    >
      {filterButtonLabel}
    </Button>
  ) : null;

  return (
    <Toolbar
      style={{
        minHeight: 40,
        height: 40,
        boxSizing: "border-box",
        display: "flex",
        alignItems: "center",
      }}
    >
      <QuickFilter expanded>
        <QuickFilterControl
          render={({ ref, value, ...other }) => (
            <TextField
              {...other}
              inputRef={ref}
              value={value ?? ""}
              label={textFieldLabel}
              placeholder={searchPlaceholder}
              size="small"
              sx={searchFieldSx}
              slotProps={{
                input: {
                  startAdornment: (
                    <InputAdornment position="start">
                      <SearchIcon />
                    </InputAdornment>
                  ),
                  ...other.slotProps?.input,
                },
                ...other.slotProps,
              }}
            />
          )}
        />
      </QuickFilter>
      {filterButton}
      <ColumnsPanelTrigger
        render={(props) => (
          <Button {...props} startIcon={<ColumnsIcon />} aria-label="Select columns">
            Columns
          </Button>
        )}
      />
      {showClearFilters ? (
        <Button
          type="button"
          variant="text"
          onClick={onClearFilters}
          aria-label="Clear filters"
          sx={{ ml: 0.5, whiteSpace: "nowrap" }}
        >
          Clear filters
        </Button>
      ) : null}
    </Toolbar>
  );
}

export type StandaloneToolbarColumnDef = {
  field: string;
  headerName: string;
};

type NewToolbarStandaloneBaseProps = NewToolbarBaseProps & {
  searchValue: string;
  onSearchChange: (value: string) => void;
  columns: StandaloneToolbarColumnDef[];
  hiddenColumns: ReadonlySet<string>;
  onHiddenColumnsChange: (hiddenColumns: Set<string>) => void;
};

export type NewToolbarStandaloneProps = NewToolbarStandaloneBaseProps &
  (
    | { showFilterButton: false; onOpenFilters?: () => void }
    | { showFilterButton?: true; onOpenFilters: () => void }
  );

const standaloneToolbarSx = {
  minHeight: 40,
  height: 40,
  boxSizing: "border-box" as const,
  display: "flex",
  alignItems: "center",
  gap: 1,
  pl: 0,
  pr: 1,
  flexWrap: "wrap" as const,
};

/**
 * Toolbar for tables that are not MUI DataGrid: controlled quick search, optional Filter /
 * Clear filters, and a column-visibility menu (checkboxes per hideable column).
 */
export function NewToolbarStandalone({
  searchLabel,
  searchPlaceholder = DEFAULT_SEARCH_PLACEHOLDER,
  searchFieldSx = DEFAULT_SEARCH_FIELD_SX,
  filterCriteriaCount = 0,
  onClearFilters,
  showFilterButton: showFilterButtonProp,
  onOpenFilters,
  searchValue,
  onSearchChange,
  columns,
  hiddenColumns,
  onHiddenColumnsChange,
}: NewToolbarStandaloneProps) {
  const showFilterButton = showFilterButtonProp !== false;
  const [columnsMenuAnchor, setColumnsMenuAnchor] = useState<HTMLElement | null>(null);

  const textFieldLabel: string | undefined =
    searchLabel != null && searchLabel !== "" ? searchLabel : undefined;

  const hasFilterCriteria = filterCriteriaCount > 0;
  const filterButtonLabel = hasFilterCriteria ? `Filter (${filterCriteriaCount})` : "Filter";
  const filterButtonAriaLabel = hasFilterCriteria
    ? `Show filters, ${filterCriteriaCount} filter criteria applied`
    : "Show filters";

  const showClearFilters = hasFilterCriteria && Boolean(onClearFilters);

  const openColumnsMenu = useCallback((e: MouseEvent<HTMLElement>) => {
    setColumnsMenuAnchor(e.currentTarget);
  }, []);

  const closeColumnsMenu = useCallback(() => {
    setColumnsMenuAnchor(null);
  }, []);

  const toggleColumn = useCallback(
    (field: string) => {
      const next = new Set(hiddenColumns);
      if (next.has(field)) {
        next.delete(field);
      } else {
        next.add(field);
      }
      onHiddenColumnsChange(next);
    },
    [hiddenColumns, onHiddenColumnsChange],
  );

  const filterButton = showFilterButton ? (
    <Button
      type="button"
      startIcon={
        <FilterIcon variant={hasFilterCriteria ? "filled" : "outlined"} size="lg" aria-hidden />
      }
      aria-label={filterButtonAriaLabel}
      onClick={() => onOpenFilters?.()}
      sx={{
        display: "inline-flex",
        flexDirection: "row",
        alignItems: "center",
        px: 0.5,
        columnGap: 0.5,
      }}
    >
      {filterButtonLabel}
    </Button>
  ) : null;

  return (
    <Box sx={standaloneToolbarSx}>
      <TextField
        value={searchValue}
        onChange={(e) => onSearchChange(e.target.value)}
        label={textFieldLabel}
        placeholder={searchPlaceholder}
        size="small"
        sx={searchFieldSx}
        slotProps={{
          input: {
            startAdornment: (
              <InputAdornment position="start">
                <SearchIcon />
              </InputAdornment>
            ),
          },
        }}
      />
      {filterButton}
      <Button
        type="button"
        startIcon={<ColumnsIcon />}
        aria-label="Select columns"
        aria-haspopup="true"
        aria-expanded={columnsMenuAnchor != null ? true : undefined}
        aria-controls={columnsMenuAnchor != null ? "new-toolbar-columns-menu" : undefined}
        onClick={openColumnsMenu}
        sx={{
          display: "inline-flex",
          flexDirection: "row",
          alignItems: "center",
          px: 0.5,
          columnGap: 0.5,
        }}
      >
        Columns
      </Button>
      <Menu
        id="new-toolbar-columns-menu"
        anchorEl={columnsMenuAnchor}
        open={columnsMenuAnchor != null}
        onClose={closeColumnsMenu}
        anchorOrigin={{ vertical: "bottom", horizontal: "left" }}
        transformOrigin={{ vertical: "top", horizontal: "left" }}
      >
        {columns.map((col) => {
          const visible = !hiddenColumns.has(col.field);
          return (
            <MenuItem key={col.field} dense onClick={() => toggleColumn(col.field)}>
              <Checkbox size="small" checked={visible} tabIndex={-1} disableRipple />
              <ListItemText primary={col.headerName} />
            </MenuItem>
          );
        })}
      </Menu>
      {showClearFilters ? (
        <Button
          type="button"
          variant="text"
          onClick={onClearFilters}
          aria-label="Clear filters"
          sx={{ ml: 0.5, whiteSpace: "nowrap" }}
        >
          Clear filters
        </Button>
      ) : null}
    </Box>
  );
}
