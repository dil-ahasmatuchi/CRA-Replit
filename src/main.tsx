import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";

import { AtlasThemeProvider } from "@diligentcorp/atlas-react-bundle";
import { applyCatalogFromStorageWithFallback } from "./data/persistence/applyCatalogSnapshot.js";
import {
  resetCatalogStorage,
  resetPrototypeCatalogAsync,
} from "./data/persistence/catalogStore.js";
import type { PersistedCatalog } from "./data/persistence/catalogTypes.js";
import bundledCatalog from "./data/generated/pooja-migrated-catalog.v3.json";
import App from "./App";

/** Dev-only: open `/?resetCatalog=1` once to clear localStorage / IndexedDB / CRA draft before hydration. */
async function resetPersistedCatalogIfRequestedInDev(): Promise<void> {
  if (!import.meta.env.DEV) return;
  try {
    const url = new URL(globalThis.location.href);
    if (url.searchParams.get("resetCatalog") !== "1") return;
    await resetPrototypeCatalogAsync();
    url.searchParams.delete("resetCatalog");
    const qs = url.searchParams.toString();
    const next = `${url.pathname}${qs ? `?${qs}` : ""}${url.hash}`;
    globalThis.history.replaceState(null, "", next);
  } catch (e) {
    console.error("Dev resetCatalog=1 failed.", e);
  }
}

void (async () => {
  await resetPersistedCatalogIfRequestedInDev();
  try {
    await applyCatalogFromStorageWithFallback(bundledCatalog as PersistedCatalog);
  } catch (e) {
    console.error("Catalog hydration failed; clearing persisted catalog.", e);
    resetCatalogStorage();
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <BrowserRouter>
        <AtlasThemeProvider tokenMode="lens">
          <App />
        </AtlasThemeProvider>
      </BrowserRouter>
    </StrictMode>,
  );
})();
