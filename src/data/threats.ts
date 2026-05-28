import { padId } from "./types.js";
import type {
  MockThreat,
  MockThreatAttachment,
  ThreatActor,
  ThreatAttackVector,
  ThreatSource,
  ThreatStatus,
  ThreatDomain,
} from "./types.js";
import { assets } from "./assets.js";
import { markCatalogDirty } from "./persistence/catalogStore.js";
import { keywordSimilarity, mulberry32 } from "./relationshipHeuristics.js";
import { vulnerabilities } from "./vulnerabilities.js";
import { users } from "./users.js";

/**
 * Library threats from `LIBRARY_THREATS`. Threat↔asset links are generated with **variable** degrees per threat using
 * keyword similarity (name/type vs threat title/domain) plus noise — no fixed per-asset threat count.
 * `applyCrossEntityLinks` syncs asset ↔ vulnerability ↔ threat. Cyber risk mirrors: `cyberRisks.ts`.
 */

type ThreatSeed = {
  title: string;
  sources: ThreatSource[];
  status: ThreatStatus;
  domain: ThreatDomain;
};

/**
 * For each threat, pick a **variable** number of assets (breadth) using name/type vs threat title/domain
 * similarity, with random jitter. Asset-side degree emerges naturally (wide spread vs fixed 2–5).
 */
function buildThreatAssetEdges(): Array<[number, number]> {
  const rng = mulberry32(99_001);
  const edges: Array<[number, number]> = [];

  for (let ti = 0; ti < LIBRARY_THREATS.length; ti++) {
    const seed = LIBRARY_THREATS[ti]!;
    const threatText = `${seed.title} ${seed.domain}`;
    const breadth = 2 + Math.floor(rng() * 29);

    const scored = assets.map((a, ai) => ({
      ai,
      s: keywordSimilarity(`${a.name} ${a.assetType}`, threatText) + rng() * 0.2,
    }));
    scored.sort((x, y) => y.s - x.s);

    const nPick = Math.min(breadth, assets.length);
    for (let k = 0; k < nPick; k++) {
      edges.push([ti, scored[k]!.ai]);
    }
  }

  return edges;
}

const LIBRARY_THREATS: ThreatSeed[] = [
  { title: "Account takeover and session abuse", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Automated credential stuffing campaigns", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Ransomware and destructive malware", sources: ["Deliberate"], status: "Active", domain: "Endpoint & Device" },
  { title: "Phishing and business email compromise", sources: ["Deliberate"], status: "Active", domain: "People & Workforce" },
  { title: "API abuse and excessive data harvesting", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Distributed denial-of-service attacks", sources: ["Deliberate", "Environmental"], status: "Active", domain: "Network & Infrastructure" },
  { title: "Supply chain and third-party software compromise", sources: ["Accidental", "Deliberate"], status: "Active", domain: "Supply Chain & Third Party" },
  { title: "Cloud misconfiguration and public exposure", sources: ["Accidental"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Insider data exfiltration", sources: ["Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Physical intrusion and device theft", sources: ["Deliberate"], status: "Draft", domain: "Physical & Facilities" },
  { title: "OT and industrial protocol exploitation", sources: ["Deliberate"], status: "Active", domain: "Operational Technology (OT/ICS)" },
  { title: "Cryptojacking and resource hijacking", sources: ["Deliberate"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Wireless and rogue access point abuse", sources: ["Deliberate"], status: "Active", domain: "Network & Infrastructure" },
  { title: "SQL injection and injection-style attacks", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Privilege escalation via misconfiguration", sources: ["Accidental", "Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Data loss through misdelivery and human error", sources: ["Accidental"], status: "Active", domain: "People & Workforce" },
  { title: "Natural disaster and site loss impacting systems", sources: ["Environmental"], status: "Active", domain: "Physical & Facilities" },
  { title: "DNS and routing manipulation", sources: ["Deliberate"], status: "Active", domain: "Network & Infrastructure" },
  { title: "Container escape and host breakout", sources: ["Deliberate"], status: "Draft", domain: "Cloud & Virtualisation" },
  {
    title: "AI-Assisted Social Engineering at Scale",
    sources: ["Deliberate", "Accidental"],
    status: "Active",
    domain: "People & Workforce",
  },
  { title: "Payment fraud and invoice manipulation", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Legacy protocol and cleartext credential exposure", sources: ["Accidental"], status: "Active", domain: "Network & Infrastructure" },
  { title: "IoT botnet recruitment and lateral movement", sources: ["Deliberate"], status: "Active", domain: "Operational Technology (OT/ICS)" },
  { title: "SaaS tenant isolation failure", sources: ["Accidental"], status: "Draft", domain: "Cloud & Virtualisation" },
  { title: "Nation-state espionage and long dwell time", sources: ["Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Loss of devices, storage media, and documents", sources: ["Accidental", "Deliberate"], status: "Active", domain: "Physical & Facilities" },
  { title: "Firmware-level ransomware and pre-encryption persistence", sources: ["Deliberate"], status: "Active", domain: "Endpoint & Device" },
  { title: "SMS and OTT phishing targeting mobile-first users", sources: ["Deliberate"], status: "Active", domain: "People & Workforce" },
  { title: "Voice phishing (vishing) and callback fraud against service desks", sources: ["Deliberate"], status: "Active", domain: "People & Workforce" },
  { title: "Application-layer denial of service against business APIs", sources: ["Deliberate", "Environmental"], status: "Active", domain: "Application & API" },
  { title: "Resource exhaustion via slow connection and protocol abuse", sources: ["Deliberate"], status: "Active", domain: "Network & Infrastructure" },
  { title: "Unauthorized data exfiltration via removable media", sources: ["Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Negligent exposure of secrets in public source repositories", sources: ["Accidental"], status: "Active", domain: "People & Workforce" },
  { title: "Invoice and payment fraud via compromised supplier communications", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Failure to meet regulatory breach notification deadlines", sources: ["Accidental", "Environmental"], status: "Active", domain: "Data & Information" },
  { title: "Compromise through counterfeit or substituted hardware", sources: ["Deliberate"], status: "Active", domain: "Supply Chain & Third Party" },
  { title: "Tampered third-party packages in CI/CD pipelines", sources: ["Deliberate"], status: "Active", domain: "Supply Chain & Third Party" },
  { title: "Mass assignment and excessive data exposure in APIs", sources: ["Deliberate", "Accidental"], status: "Active", domain: "Application & API" },
  { title: "Broken authentication on internet-facing microservices", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Polymorphic malware and evasive packers on endpoints", sources: ["Deliberate"], status: "Active", domain: "Endpoint & Device" },
  { title: "Illicit cryptomining on compromised virtual machines", sources: ["Deliberate"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Long-lived account takeover after credential or session reuse", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "OAuth consent phishing and token theft for cloud services", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Cloud control-plane API abuse and quota exhaustion", sources: ["Deliberate"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Regional or zone-wide dependency outage of cloud services", sources: ["Environmental", "Accidental"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Covert exfiltration via browser extensions and copilot tools", sources: ["Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Model poisoning and backdoors in training data", sources: ["Deliberate"], status: "Draft", domain: "Application & API" },
  { title: "Supply-chain compromise of open-source dependencies", sources: ["Deliberate", "Accidental"], status: "Active", domain: "Supply Chain & Third Party" },
  { title: "BGP and routing manipulation affecting service reachability", sources: ["Deliberate"], status: "Active", domain: "Network & Infrastructure" },
  {
    title: "Adversary-in-the-Middle (AitM)",
    sources: ["Deliberate"],
    status: "Active",
    domain: "Network & Infrastructure",
  },
  { title: "Credential stuffing and password spraying at scale", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Theft of trade secrets via departing employees and contractors", sources: ["Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Unauthorized secondary use and resale of personal data", sources: ["Deliberate", "Accidental"], status: "Active", domain: "Data & Information" },
  { title: "Undocumented shadow IT integrations bridging trust zones", sources: ["Accidental"], status: "Active", domain: "Cloud & Virtualisation" },
  { title: "Critical exposure on unpatchable or legacy infrastructure", sources: ["Environmental", "Accidental"], status: "Active", domain: "Network & Infrastructure" },
  { title: "API rate-limit bypass and unsanctioned bulk data export", sources: ["Deliberate"], status: "Active", domain: "Application & API" },
  { title: "Fraudulent onboarding with synthetic identities", sources: ["Deliberate"], status: "Active", domain: "Identity & Access Management" },
  { title: "Long-term bit rot and loss of readable legacy archives", sources: ["Accidental", "Environmental"], status: "Active", domain: "Data & Information" },
  { title: "Improper cross-border transfer without adequate safeguards", sources: ["Accidental", "Deliberate"], status: "Active", domain: "Data & Information" },
  { title: "Inability to produce audit evidence due to logging or clock failures", sources: ["Accidental", "Environmental"], status: "Active", domain: "Application & API" },
];

function buildThreatLibraryDescription(
  title: string,
  domain: ThreatDomain,
  sources: ThreatSource[],
): string {
  const sourceSummary =
    sources.length === 0
      ? "unspecified source drivers"
      : sources.length === 1
        ? `${sources[0]!.toLowerCase()} drivers`
        : `${sources.map((s) => s.toLowerCase()).join(", ")} drivers`;
  return (
    `${title} is a curated enterprise threat category in the ${domain} domain. ` +
    `It describes how loss scenarios can manifest across in-scope assets. ` +
    `Source profile: ${sourceSummary}. Aligned with ISO 27005 / NIST CSF–style libraries.`
  );
}

function pickThreatActors(seq: number, sources: ThreatSource[]): ThreatActor[] {
  const pool: ThreatActor[] = [
    "Organised Cybercriminal Group",
    "Nation-State / State-Sponsored Actor",
    "Malicious Insider (employee, contractor)",
    "Hacktivist",
    "Opportunistic / Script Kiddie",
    "Competitor (corporate espionage)",
  ];
  const out = new Set<ThreatActor>();
  if (sources.includes("Deliberate")) {
    out.add(pool[seq % pool.length]!);
    if (seq % 5 === 0) out.add("Malicious Insider (employee, contractor)");
  }
  if (sources.includes("Accidental")) out.add("Negligent / Untrained Employee");
  if (sources.includes("Environmental")) {
    out.add("Natural / Environmental Event");
    out.add("System / Process Failure (non-human)");
  }
  if (out.size === 0) out.add("System / Process Failure (non-human)");
  return [...out];
}

function pickAttackVectors(seq: number, domain: ThreatDomain): ThreatAttackVector[] {
  const byDomain: Partial<Record<ThreatDomain, ThreatAttackVector[]>> = {
    "Identity & Access Management": [
      "Insider / Privileged Access Abuse",
      "Network & Remote Access (VPN, RDP, open ports)",
    ],
    "Endpoint & Device": [
      "Physical Access & Removable Media",
      "Email & Messaging (phishing, BEC, malicious attachments)",
    ],
    "Network & Infrastructure": [
      "Network & Remote Access (VPN, RDP, open ports)",
      "Wireless & Mobile (Wi-Fi, Bluetooth, SMS)",
    ],
    "Application & API": ["Web Application & Browser", "Cloud Services & APIs"],
    "Data & Information": ["Insider / Privileged Access Abuse", "Cloud Services & APIs"],
    "Cloud & Virtualisation": ["Cloud Services & APIs", "Supply Chain & Third-Party Software"],
    "Physical & Facilities": ["Physical Access & Removable Media"],
    "Supply Chain & Third Party": [
      "Supply Chain & Third-Party Software",
      "Email & Messaging (phishing, BEC, malicious attachments)",
    ],
    "Operational Technology (OT/ICS)": [
      "Operational Technology / Industrial Interfaces",
      "Network & Remote Access (VPN, RDP, open ports)",
    ],
    "People & Workforce": [
      "Email & Messaging (phishing, BEC, malicious attachments)",
      "Social Media & Public Channels",
    ],
  };
  const primary = byDomain[domain] ?? [
    "Web Application & Browser",
    "Network & Remote Access (VPN, RDP, open ports)",
  ];
  const extra: ThreatAttackVector[] = [
    "Email & Messaging (phishing, BEC, malicious attachments)",
    "Web Application & Browser",
  ];
  const merged = [...primary];
  merged.push(extra[seq % extra.length]!);
  return [...new Set(merged)];
}

function mockAttachmentsForSeq(seq: number): MockThreatAttachment[] {
  if (seq % 7 !== 0) return [];
  return [
    { id: `thr-att-${seq}-1`, fileName: "Threat intelligence bulletin (sample).pdf" },
    { id: `thr-att-${seq}-2`, fileName: "Internal incident summary — redacted.docx" },
  ];
}

function buildThreatRelationships(
  cyberRiskIds: string[],
  assetIds: string[],
  vulnerabilityIds: string[],
): MockThreat["relationships"] {
  return {
    assetIds,
    vulnerabilityIds,
    cyberRiskIds,
    controlIds: [],
    mitigationPlanIds: [],
    scenarioIds: [],
  };
}

function vulnIdsForAssets(assetIds: string[]): string[] {
  const set = new Set<string>();
  const byAsset = new Map<string, string[]>();
  for (const v of vulnerabilities) {
    for (const aid of v.assetIds) {
      const list = byAsset.get(aid) ?? [];
      list.push(v.id);
      byAsset.set(aid, list);
    }
  }
  for (const aid of assetIds) {
    for (const vid of byAsset.get(aid) ?? []) set.add(vid);
  }
  return [...set];
}

function buildThreats(): MockThreat[] {
  const nThreats = LIBRARY_THREATS.length;
  if (assets.length === 0) {
    throw new Error("assets catalog is empty; cannot build default threats.");
  }
  const edges = buildThreatAssetEdges();
  const assetIdxByThreat: string[][] = Array.from({ length: nThreats }, () => []);

  for (const [ti, ai] of edges) {
    assetIdxByThreat[ti]!.push(assets[ai]!.id);
  }

  const defaultOwnerId = users[0]?.id ?? "USR-001";
  const out: MockThreat[] = [];

  for (let i = 0; i < nThreats; i++) {
    const seed = LIBRARY_THREATS[i]!;
    const assetIds = [...assetIdxByThreat[i]!].sort();
    const vulnerabilityIds = vulnIdsForAssets(assetIds);
    const seq = i + 1;
    const description = buildThreatLibraryDescription(seed.title, seed.domain, seed.sources);

    out.push({
      id: padId("THR", seq),
      displayId: `T-${String(seq).padStart(4, "0")}`,
      name: seed.title,
      ownerIds: [defaultOwnerId],
      domain: seed.domain,
      description,
      sources: seed.sources,
      threatActors: pickThreatActors(seq, seed.sources),
      attackVectors: pickAttackVectors(seq, seed.domain),
      status: seed.status,
      attachments: mockAttachmentsForSeq(seq),
      cyberRiskIds: [],
      assetIds,
      vulnerabilityIds,
      relationships: buildThreatRelationships([], assetIds, vulnerabilityIds),
    });
  }

  return out;
}

function applyCrossEntityLinks(threatList: MockThreat[]): void {
  const vulnById = new Map(vulnerabilities.map((v) => [v.id, v]));
  const assetById = new Map(assets.map((a) => [a.id, a]));

  for (const v of vulnerabilities) {
    v.threatIds.length = 0;
    v.relationships.threatIds.length = 0;
  }
  for (const a of assets) {
    a.vulnerabilityIds.length = 0;
    a.threatIds.length = 0;
    a.relationships.vulnerabilityIds.length = 0;
    a.relationships.threatIds.length = 0;
  }

  for (const v of vulnerabilities) {
    for (const aid of v.assetIds) {
      const a = assetById.get(aid);
      if (a && !a.vulnerabilityIds.includes(v.id)) {
        a.vulnerabilityIds.push(v.id);
        a.relationships.vulnerabilityIds.push(v.id);
      }
    }
  }

  for (const t of threatList) {
    for (const vid of t.vulnerabilityIds) {
      const v = vulnById.get(vid);
      if (v && !v.threatIds.includes(t.id)) {
        v.threatIds.push(t.id);
        v.relationships.threatIds.push(t.id);
      }
    }
    for (const aid of t.assetIds) {
      const a = assetById.get(aid);
      if (a && !a.threatIds.includes(t.id)) {
        a.threatIds.push(t.id);
        a.relationships.threatIds.push(t.id);
      }
    }
  }
}

const threatsBuilt = buildThreats();

/** Maps assessment seed indices to `THR-###` ids (1-based index). */
export function remapThreatIdFromLegacySequential(legacyIndex: number): string {
  return padId("THR", legacyIndex);
}

export const threats: MockThreat[] = threatsBuilt;
applyCrossEntityLinks(threats);

const threatById = new Map(threats.map((t) => [t.id, t]));

const NEW_THREAT_NAME_RE = /^New threat (\d+)$/i;

function nextThreatNumericId(): number {
  let max = 0;
  for (const t of threats) {
    const m = /^THR-(\d+)$/.exec(t.id);
    if (m) max = Math.max(max, Number.parseInt(m[1]!, 10));
  }
  return max + 1;
}

function nextNewThreatDisplayName(): string {
  let max = 0;
  for (const t of threats) {
    const m = NEW_THREAT_NAME_RE.exec(t.name.trim());
    if (m) max = Math.max(max, Number.parseInt(m[1]!, 10));
  }
  const n = max + 1;
  return `New threat ${String(n).padStart(3, "0")}`;
}

const threatListeners = new Set<() => void>();
let threatsSnapshotVersion = 0;

function notifyThreatListeners(): void {
  threatsSnapshotVersion += 1;
  for (const cb of threatListeners) cb();
}

export function subscribeThreats(onStoreChange: () => void): () => void {
  threatListeners.add(onStoreChange);
  return () => {
    threatListeners.delete(onStoreChange);
  };
}

export function getThreatsSnapshotVersion(): number {
  return threatsSnapshotVersion;
}

const DEFAULT_NEW_THREAT_DOMAIN: ThreatDomain = "Identity & Access Management";

export function replaceThreatsFromPersistence(next: MockThreat[]): void {
  threats.length = 0;
  threats.push(...next);
  threatById.clear();
  for (const t of threats) {
    threatById.set(t.id, t);
  }
  applyCrossEntityLinks(threats);
  notifyThreatListeners();
}

export function updateThreat(id: string, patch: Partial<MockThreat>): void {
  const t = threatById.get(id);
  if (!t) return;
  const { relationships, ...rest } = patch;
  Object.assign(t, rest);
  if (relationships) {
    Object.assign(t.relationships, relationships);
  }
  applyCrossEntityLinks(threats);
  notifyThreatListeners();
  markCatalogDirty();
}

export function addThreat(): MockThreat {
  const defaultOwnerId = users[0]?.id ?? "USR-001";
  const nextNum = nextThreatNumericId();
  const newThreat: MockThreat = {
    id: padId("THR", nextNum),
    displayId: `T-${String(nextNum).padStart(4, "0")}`,
    name: nextNewThreatDisplayName(),
    ownerIds: [defaultOwnerId],
    domain: DEFAULT_NEW_THREAT_DOMAIN,
    description: "",
    sources: ["Deliberate"],
    threatActors: [],
    attackVectors: [],
    status: "Draft",
    attachments: [],
    cyberRiskIds: [],
    assetIds: [],
    vulnerabilityIds: [],
    relationships: buildThreatRelationships([], [], []),
  };
  threats.push(newThreat);
  threatById.set(newThreat.id, newThreat);
  applyCrossEntityLinks(threats);
  notifyThreatListeners();
  markCatalogDirty();
  return newThreat;
}

export function getThreatById(id: string): MockThreat | undefined {
  return threatById.get(id);
}
