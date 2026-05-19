import type { CraNewAssessmentPersistedDraft } from "../craAssessmentDraftTypes.js";
import {
  CATALOG_STORAGE_KEY,
  LEGACY_CATALOG_STORAGE_KEY,
  type PersistedCatalog,
} from "./catalogTypes.js";

const DEBOUNCE_MS = 350;

let craDraftMemory: CraNewAssessmentPersistedDraft | null = null;

export function getPersistedCraDraft(): CraNewAssessmentPersistedDraft | null {
  return craDraftMemory;
}

/** Sets in-memory CRA draft and schedules catalog persist (user save). */
export function setPersistedCraDraft(draft: CraNewAssessmentPersistedDraft | null): void {
  craDraftMemory = draft;
  markCatalogDirty();
}

/** Hydration only — does not enqueue persist. */
export function hydratePersistedCraDraft(draft: CraNewAssessmentPersistedDraft | null): void {
  craDraftMemory = draft;
}

const catalogListeners = new Set<() => void>();
let catalogVersion = 0;

export function getCatalogSnapshotVersion(): number {
  return catalogVersion;
}

export function subscribeCatalog(onChange: () => void): () => void {
  catalogListeners.add(onChange);
  return () => {
    catalogListeners.delete(onChange);
  };
}

function notifyCatalogListeners(): void {
  catalogVersion += 1;
  for (const cb of catalogListeners) cb();
}

/** Bump catalog version so subscribers re-read in-memory catalogs before debounced persist finishes. */
export function touchCatalogForImmediateUiRefresh(): void {
  notifyCatalogListeners();
}

let persistTimer: ReturnType<typeof setTimeout> | null = null;
let dirty = false;

export function markCatalogDirty(): void {
  dirty = true;
  if (persistTimer != null) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    void flushPersist();
  }, DEBOUNCE_MS);
}

async function flushPersist(): Promise<void> {
  if (!dirty) return;
  dirty = false;
  try {
    const { buildPersistedCatalogSnapshot } = await import("./catalogSnapshotBuilder.js");
    const snapshot = buildPersistedCatalogSnapshot();
    const json = JSON.stringify(snapshot);
    try {
      localStorage.setItem(CATALOG_STORAGE_KEY, json);
    } catch (e) {
      if (e instanceof DOMException && e.name === "QuotaExceededError") {
        await saveToIndexedDB(CATALOG_STORAGE_KEY, json);
      } else {
        throw e;
      }
    }
    notifyCatalogListeners();
  } catch {
    // ignore persist failures (private mode, etc.)
  }
}

function openIdb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open("cra_proto_db", 1);
    req.onerror = () => reject(req.error);
    req.onsuccess = () => resolve(req.result);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains("kv")) {
        db.createObjectStore("kv");
      }
    };
  });
}

async function saveToIndexedDB(key: string, value: string): Promise<void> {
  const db = await openIdb();
  await new Promise<void>((resolve, reject) => {
    const tx = db.transaction("kv", "readwrite");
    tx.objectStore("kv").put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
  db.close();
}

async function deleteIndexedDbKv(key: string): Promise<void> {
  try {
    const db = await openIdb();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("kv", "readwrite");
      tx.objectStore("kv").delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
    db.close();
  } catch {
    // ignore
  }
}

async function loadFromIndexedDB(key: string): Promise<string | null> {
  try {
    const db = await openIdb();
    const v = await new Promise<string | undefined>((resolve, reject) => {
      const tx = db.transaction("kv", "readonly");
      const req = tx.objectStore("kv").get(key);
      req.onsuccess = () => resolve(req.result as string | undefined);
      req.onerror = () => reject(req.error);
    });
    db.close();
    return v ?? null;
  } catch {
    return null;
  }
}

export function loadRawCatalogJson(): string | null {
  try {
    const ls = localStorage.getItem(CATALOG_STORAGE_KEY);
    if (ls) return ls;
  } catch {
    // ignore
  }
  return null;
}

export async function loadRawCatalogJsonAsync(): Promise<string | null> {
  const sync = loadRawCatalogJson();
  if (sync) return sync;
  return loadFromIndexedDB(CATALOG_STORAGE_KEY);
}

export function parsePersistedCatalog(json: string): PersistedCatalog | null {
  try {
    const o = JSON.parse(json) as unknown;
    if (o == null || typeof o !== "object") return null;
    const p = o as PersistedCatalog;
    if (p.schemaVersion !== 2 && p.schemaVersion !== 3) return null;
    if (p.schemaVersion === 3 && !Array.isArray((p as { scenarios?: unknown }).scenarios)) return null;
    return p;
  } catch {
    return null;
  }
}

function removeCatalogKeysFromLocalStorage(): void {
  try {
    localStorage.removeItem(CATALOG_STORAGE_KEY);
    localStorage.removeItem(LEGACY_CATALOG_STORAGE_KEY);
  } catch {
    // ignore
  }
}

/** Clears persisted catalog + CRA draft memory and notifies listeners; reload the app to re-seed. */
export function resetPrototypeCatalog(): void {
  try {
    sessionStorage.removeItem("cra_new_assessment_draft_v1");
  } catch {
    // ignore
  }
  resetCatalogStorage();
}

export function resetCatalogStorage(): void {
  removeCatalogKeysFromLocalStorage();
  void (async () => {
    await deleteIndexedDbKv(CATALOG_STORAGE_KEY);
    await deleteIndexedDbKv(LEGACY_CATALOG_STORAGE_KEY);
  })();
  craDraftMemory = null;
  notifyCatalogListeners();
}

/**
 * Same as {@link resetCatalogStorage} but waits for IndexedDB deletes to finish (avoids reload winning the race).
 */
export async function resetCatalogStorageAsync(): Promise<void> {
  removeCatalogKeysFromLocalStorage();
  await deleteIndexedDbKv(CATALOG_STORAGE_KEY);
  await deleteIndexedDbKv(LEGACY_CATALOG_STORAGE_KEY);
  craDraftMemory = null;
  notifyCatalogListeners();
}

/** Like {@link resetPrototypeCatalog} but awaits IndexedDB cleanup — use before `location.reload()`. */
export async function resetPrototypeCatalogAsync(): Promise<void> {
  try {
    sessionStorage.removeItem("cra_new_assessment_draft_v1");
  } catch {
    // ignore
  }
  await resetCatalogStorageAsync();
}
