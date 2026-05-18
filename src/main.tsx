import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";

import { AtlasThemeProvider } from "@diligentcorp/atlas-react-bundle";
import { applyCatalogFromStorageWithFallback } from "./data/persistence/applyCatalogSnapshot.js";
import { resetCatalogStorage } from "./data/persistence/catalogStore.js";
import type { PersistedCatalog } from "./data/persistence/catalogTypes.js";
import bundledCatalog from "./data/generated/pooja-migrated-catalog.v3.json";
import App from "./App";

void (async () => {
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
