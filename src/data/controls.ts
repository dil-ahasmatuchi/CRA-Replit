import { padId, getFivePointLabel } from "./types.js";
import type {
  MockAsset,
  MockControl,
  ControlStatus,
  ControlType,
  ControlFrequency,
  FivePointScaleValue,
} from "./types.js";
import { assets, getAssetById } from "./assets.js";

const STATUS: ControlStatus[] = ["Active", "Active", "Active", "Draft"];
const TYPES: ControlType[] = ["Preventive", "Detective"];
const FREQS: ControlFrequency[] = [
  "Daily",
  "Weekly",
  "Bi-weekly",
  "Monthly",
  "Quarterly",
  "Annually",
];

const OWNER_ROTATION = [7, 9, 14, 15, 20, 33, 39, 49, 1, 5, 28, 13, 17, 22, 40, 11, 36, 44, 6, 31];

function dedupePush(arr: string[], id: string): void {
  if (!arr.includes(id)) arr.push(id);
}

/** Clears and repopulates `asset.controlIds` / `relationships.controlIds` from the controls catalog. */
export function wireControlsToAssets(): void {
  for (const a of assets) {
    if (!Array.isArray(a.controlIds)) {
      (a as MockAsset).controlIds = [];
    } else {
      a.controlIds.length = 0;
    }
    if (!Array.isArray(a.relationships.controlIds)) {
      a.relationships.controlIds = [];
    } else {
      a.relationships.controlIds.length = 0;
    }
  }
  for (const c of controls) {
    const assetIds = Array.isArray(c.assetIds) ? c.assetIds : [];
    for (const aid of assetIds) {
      const a = getAssetById(aid);
      if (!a) continue;
      if (!Array.isArray(a.controlIds)) (a as MockAsset).controlIds = [];
      if (!Array.isArray(a.relationships.controlIds)) a.relationships.controlIds = [];
      dedupePush(a.controlIds, c.id);
      dedupePush(a.relationships.controlIds, c.id);
    }
  }
}

/** 100 controls: each attached to one asset (rotating through the current asset catalog), asset-centric. */
function buildControls(): MockControl[] {
  const assetCount = Math.max(1, assets.length);
  const out: MockControl[] = [];
  const prefixes = [
    "Multi-factor authentication",
    "Network intrusion detection",
    "Web application firewall",
    "Endpoint detection",
    "Data encryption",
    "Vulnerability scanning",
    "Privileged access management",
    "Security awareness",
    "Network segmentation",
    "Patch management",
    "Data loss prevention",
    "Backup testing",
    "Access certification",
    "Log monitoring",
    "Incident response",
    "Vendor assessment",
    "Change management",
    "Secure code review",
    "Database monitoring",
    "CSPM",
    "Container scanning",
    "API gateway",
    "Email filtering",
    "Certificate lifecycle",
    "Identity governance",
    "Physical access",
    "Mobile device management",
    "Disaster recovery test",
    "SIEM correlation",
    "Zero trust access",
    "Data classification",
    "Secrets management",
    "Compliance monitoring",
    "Application control",
    "DNS security",
    "Wireless hardening",
    "File integrity",
    "Browser isolation",
    "Supply chain verification",
    "CASB",
    "Dark web monitoring",
    "Tabletop exercises",
    "Compliance audit",
    "Data retention",
    "Threat intelligence",
    "Red team",
    "SOC monitoring",
    "Business continuity",
    "Key rotation",
    "UEBA",
  ];

  for (let i = 0; i < 100; i++) {
    const assetNum = (i % assetCount) + 1;
    const assetId = padId("AST", assetNum);
    const effectiveness = ((i % 5) + 1) as FivePointScaleValue;
    const name = `${prefixes[i % prefixes.length]} control`;
    out.push({
      id: padId("CTL", i + 1),
      name,
      ownerId: padId("USR", OWNER_ROTATION[i % OWNER_ROTATION.length]!),
      status: STATUS[i % STATUS.length]!,
      controlType: TYPES[i % 2]!,
      keyControl: i % 3 !== 0,
      controlFrequency: FREQS[i % FREQS.length]!,
      assetIds: [assetId],
      effectiveness,
      effectivenessLabel: getFivePointLabel(effectiveness),
    });
  }
  return out;
}

export const controls: MockControl[] = buildControls();

wireControlsToAssets();

const controlById = new Map(controls.map((c) => [c.id, c]));

function rebuildControlIndex(): void {
  controlById.clear();
  for (const c of controls) {
    controlById.set(c.id, c);
  }
}

/** Backfill asset-centric fields for catalogs saved before controls were keyed by `assetIds`. */
function normalizePersistedControl(c: MockControl, index: number): void {
  if (!Array.isArray(c.assetIds) || c.assetIds.length === 0) {
    const m = /^CTL-0*(\d+)$/i.exec(c.id);
    const n = m ? Math.max(1, parseInt(m[1]!, 10)) : index + 1;
    const mod = Math.max(1, assets.length);
    c.assetIds = [padId("AST", ((n - 1) % mod) + 1)];
  }
  const raw = c.effectiveness;
  const ok = typeof raw === "number" && raw >= 1 && raw <= 5;
  const eff = (ok ? raw : (index % 5) + 1) as FivePointScaleValue;
  c.effectiveness = eff;
  c.effectivenessLabel = getFivePointLabel(eff);
}

export function replaceControlsFromPersistence(next: MockControl[]): void {
  controls.length = 0;
  controls.push(...next);
  controls.forEach((c, i) => normalizePersistedControl(c, i));
  rebuildControlIndex();
  wireControlsToAssets();
}

export function getControlById(id: string): MockControl | undefined {
  return controlById.get(id);
}
