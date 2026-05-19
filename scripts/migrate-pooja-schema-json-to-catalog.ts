/**
 * One-time: Resources/Pooja_SCHEMA_OBJECTS.json → src/data/generated/pooja-migrated-catalog.v3.json
 * Run: npm run migrate:pooja
 *
 * Assessment display IDs ASM-* are normalized to CRA-* (same numeric suffix).
 * Threat display T-* maps to meta id THR-* (same numeric suffix, 3-digit THR pad).
 * Vulnerability display VUL-CAT-* maps to meta id VUL-### (table order).
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { FivePointScaleLabel } from "../src/data/types.js";
import { applyCyberRiskThreatInference } from "../src/data/cyberRiskThreatInference.js";
import { buildScoringRationale, buildVulnsByAssetIdMap, formatThreatPhrase } from "../src/data/buildScoringRationale.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const srcRoot = path.join(repoRoot, "src");

const IN_JSON = path.join(repoRoot, "Resources", "Pooja_SCHEMA_OBJECTS.json");
const OUT_JSON = path.join(srcRoot, "data", "generated", "pooja-migrated-catalog.v3.json");

const DEFAULT_CYBER_SCORE_BANDS = [
  { level: 1, name: "Very low", rag: "pos05", from: 1, to: 25, description: "" },
  { level: 2, name: "Low", rag: "pos04", from: 26, to: 50, description: "" },
  { level: 3, name: "Medium", rag: "neu03", from: 51, to: 75, description: "" },
  { level: 4, name: "High", rag: "neg03", from: 76, to: 100, description: "" },
  { level: 5, name: "Very high", rag: "neg05", from: 101, to: 125, description: "" },
];
const DEFAULT_LIKELIHOOD_BANDS = [
  { level: 1, name: "Very low", rag: "pos05", from: 1, to: 5, description: "" },
  { level: 2, name: "Low", rag: "pos04", from: 6, to: 10, description: "" },
  { level: 3, name: "Medium", rag: "neu03", from: 11, to: 15, description: "" },
  { level: 4, name: "High", rag: "neg03", from: 16, to: 20, description: "" },
  { level: 5, name: "Very high", rag: "neg05", from: 21, to: 25, description: "" },
];

const ASSET_TYPE_MAP = {
  "IT Asset - Software": "Application",
  "IT Asset - Information system": "Database",
  "IT Asset - Hardware": "Server",
  "IT Asset - Cloud": "Cloud service",
};

const ASSESSMENT_PHASE_MAP = {
  draft: "Draft",
  scoping: "Scoping",
  inProgress: "Scoring",
};

const CYBER_RISK_STATUS = new Set(["Draft", "Identification", "Assessment", "Mitigation", "Monitoring"]);

const CONTROL_FREQ_MAP = {
  Continuous: "Daily",
  "Real-time": "Daily",
  Weekly: "Weekly",
  "Bi-weekly": "Bi-weekly",
  Monthly: "Monthly",
  Quarterly: "Quarterly",
  Annually: "Annually",
};

function fail(msg) {
  throw new Error(`[migrate-pooja] ${msg}`);
}

function pad(prefix, n, w = 3) {
  return `${prefix}-${String(n).padStart(w, "0")}`;
}

function asmToCra(asmId) {
  const m = /^ASM-(\d+)$/.exec(asmId?.trim() ?? "");
  if (!m) return null;
  return pad("CRA", Number.parseInt(m[1], 10));
}

function tDisplayToThr(displayId) {
  const m = /^T-(\d+)$/.exec(displayId?.trim() ?? "");
  if (!m) return null;
  return pad("THR", Number.parseInt(m[1], 10));
}

function firstIdToken(s) {
  if (!s || typeof s !== "string") return null;
  const t = s.trim();
  if (t === "—" || t === "— (self)") return null;
  const m = t.match(/^((?:AST|ASM|SC|CR|CTL|VUL-CAT|VUL|THR|T|CRA|USR|MP)-[A-Za-z0-9-]+)/);
  return m ? m[1] : null;
}

function parseIdList(cell) {
  if (!cell || cell === "—") return [];
  const parts = String(cell).split(";").map((x) => x.trim()).filter(Boolean);
  const out = [];
  for (const p of parts) {
    const id = firstIdToken(p);
    if (id) out.push(id);
  }
  return [...new Set(out)];
}

function fiveLabel(n) {
  const m = { 1: "Very low", 2: "Low", 3: "Medium", 4: "High", 5: "Very high" };
  return m[n] ?? "Medium";
}

function likelihoodLabel(v) {
  if (v <= 5) return "Very low";
  if (v <= 10) return "Low";
  if (v <= 15) return "Medium";
  if (v <= 20) return "High";
  return "Very high";
}

function cyberScoreLabel(s) {
  if (s <= 25) return "Very low";
  if (s <= 50) return "Low";
  if (s <= 75) return "Medium";
  if (s <= 100) return "High";
  return "Very high";
}

function tableBySlug(doc, slug) {
  const sec = doc.sections.find((s) => s.slug === slug);
  if (!sec) fail(`missing section ${slug}`);
  const t = sec.parts.find((p) => p.type === "table");
  if (!t) fail(`missing table in ${slug}`);
  return t.rows;
}

function buildOrgUnits() {
  const txt = fs.readFileSync(path.join(srcRoot, "data", "orgUnits.ts"), "utf8");
  const names = [];
  const re = /\["([^"]+)",\s*"([^"]+)"\]/g;
  let m;
  while ((m = re.exec(txt)) !== null) {
    names.push([m[1], m[2]]);
  }
  return names.map(([dept, loc], i) => ({
    id: `BU-${String(i + 1).padStart(3, "0")}`,
    name: `${dept} – ${loc}`,
  }));
}

function buildUsers(ownerTokens) {
  const firstNames = [
    "Sarah",
    "Marcus",
    "Elena",
    "David",
    "Priya",
    "James",
    "Fatima",
    "Thomas",
    "Aisha",
    "Robert",
    "Maria",
    "Kevin",
    "Laura",
    "Ahmed",
    "Rachel",
    "Carlos",
    "Yuki",
    "Michael",
    "Nadia",
    "Brian",
    "Amara",
    "Stefan",
    "Mei",
    "Daniel",
    "Isabelle",
    "Raj",
    "Samantha",
    "Patrick",
    "Leila",
    "Christopher",
    "Zara",
    "Oliver",
    "Hannah",
    "William",
    "Sofia",
    "Jason",
    "Beatrice",
    "George",
    "Ines",
    "Nathan",
    "Chloe",
    "Victor",
    "Emma",
    "Andrew",
    "Dina",
    "Frank",
    "Keiko",
    "Lucas",
    "Olivia",
    "Ryan",
  ];
  const lastNames = [
    "Chen",
    "Johnson",
    "Rodriguez",
    "Kim",
    "Sharma",
    "O'Brien",
    "Al-Hassan",
    "Mueller",
    "Patel",
    "Williams",
    "Santos",
    "Nakamura",
    "Johansson",
    "Mansour",
    "Green",
    "Mendoza",
    "Tanaka",
    "Thompson",
    "Kozlov",
    "Mitchell",
    "Okafor",
    "Bergmann",
    "Wong",
    "Fraser",
    "Dubois",
    "Krishnamurthy",
    "Lee",
    "Doyle",
    "Khoury",
    "Anderson",
    "Ibrahim",
    "Petersen",
    "Novak",
    "Chang",
    "Moretti",
    "Park",
    "Fournier",
    "Papadopoulos",
    "da Silva",
    "Brooks",
    "Zimmermann",
    "Reyes",
    "Lindqvist",
    "Scott",
    "Rashid",
    "Weber",
    "Sato",
    "Ferreira",
    "Martin",
    "Cooper",
  ];
  const users = firstNames.map((firstName, i) => {
    const lastName = lastNames[i % lastNames.length];
    return {
      id: `USR-${String(i + 1).padStart(3, "0")}`,
      initials: `${firstName[0]}${lastName[0]}`,
      firstName,
      lastName,
      fullName: `${firstName} ${lastName}`,
    };
  });
  users.push({
    id: "USR-UNASSIGNED",
    initials: "—",
    firstName: "Unassigned",
    lastName: "Owner",
    fullName: "Unassigned owner",
  });
  const ownerMap = new Map();
  ownerMap.set("—", "USR-UNASSIGNED");
  ownerMap.set("", "USR-UNASSIGNED");
  ownerMap.set("user-1", "USR-001");
  for (const t of ownerTokens) {
    const s = String(t).trim();
    if (!s || s === "—") continue;
    const um = /^USR-(\d+)$/i.exec(s);
    if (um) ownerMap.set(s.toUpperCase(), `USR-${String(Number.parseInt(um[1], 10)).padStart(3, "0")}`);
    else if (!ownerMap.has(s)) ownerMap.set(s, "USR-001");
  }
  return { users, ownerMap };
}

function mapOwner(raw, ownerMap) {
  const s = String(raw ?? "").trim();
  if (!s || s === "—") return ownerMap.get("—");
  if (ownerMap.has(s)) return ownerMap.get(s);
  const um = /^USR-(\d+)$/i.exec(s);
  if (um) return `USR-${String(Number.parseInt(um[1], 10)).padStart(3, "0")}`;
  return ownerMap.get("user-1") ?? "USR-001";
}

function main() {
  const doc = JSON.parse(fs.readFileSync(IN_JSON, "utf8"));
  const orgUnits = buildOrgUnits();

  const assessmentRows = tableBySlug(doc, "cyber_risk_assessments");
  const assetRows = tableBySlug(doc, "assets");
  const threatRows = tableBySlug(doc, "threats");
  const vulnRows = tableBySlug(doc, "vulnerability_categories");
  const cyberRows = tableBySlug(doc, "cyber_risks");
  const controlRows = tableBySlug(doc, "controls");
  const scenarioRows = tableBySlug(doc, "scenarios");

  const ownerTokens = new Set();
  for (const r of assessmentRows) ownerTokens.add(r.Owner);
  for (const r of controlRows) {
    /* controls may not list owner in json */
  }
  const { users, ownerMap } = buildUsers(ownerTokens);

  const vulnDisplayToMeta = new Map();
  vulnRows.forEach((row, i) => {
    vulnDisplayToMeta.set(row["Display ID"].trim(), pad("VUL", i + 1));
  });

  const assets = assetRows.map((row, i) => {
    const id = row["Display ID"].trim();
    const name = row.Name.trim();
    const rawType = row["Asset type"].trim();
    const assetType = ASSET_TYPE_MAP[rawType] ?? fail(`unknown asset type: ${rawType}`);
    const crit = Number.parseInt(row.Criticality, 10);
    if (crit < 1 || crit > 5) fail(`bad criticality ${id}`);
    const status = row.Status.trim() === "Inactive" ? "Inactive" : "Active";
    const buIdx = (i % orgUnits.length) + 1;
    return {
      id,
      name,
      ownerId: `USR-${String((i % 50) + 1).padStart(3, "0")}`,
      assetType,
      criticality: crit,
      criticalityLabel: fiveLabel(crit),
      orgUnitId: pad("BU", buIdx),
      status,
      vulnerabilityIds: [],
      threatIds: [],
      controlIds: [],
      relationships: {
        vulnerabilityIds: [],
        threatIds: [],
        cyberRiskIds: [],
        scenarioIds: [],
        controlIds: [],
      },
    };
  });

  const assetById = new Map(assets.map((a) => [a.id, a]));

  const threats = threatRows.map((row, i) => {
    const displayId = row["Display ID"].trim();
    const thrId = tDisplayToThr(displayId);
    if (!thrId) fail(`bad threat display ${displayId}`);
    const sources = row.Sources.split(/[,;]/).map((x) => x.trim()).filter(Boolean);
    const actors = row.Actors.split(";").map((x) => x.trim()).filter(Boolean);
    const vectors = row["Attack vectors"].split(";").map((x) => x.trim()).filter(Boolean);
    const status = row.Status.trim() === "Draft" ? "Draft" : "Active";
    const sev = Number.parseInt(row.Severity, 10);
    if (Number.isNaN(sev)) fail(`threat severity ${displayId}`);
    const assetCellIds = parseIdList(row.Assets).filter((x) => x.startsWith("AST-"));
    const vulnCell = parseIdList(row["Vulnerability categories"]).filter((x) => x.startsWith("VUL-CAT"));
    const vulnMeta = vulnCell.map((d) => vulnDisplayToMeta.get(d)).filter(Boolean);
    return {
      id: thrId,
      displayId,
      name: row.Name.trim(),
      domain: row.Domain.trim(),
      description: row.Name.trim(),
      sources,
      threatActors: actors,
      attackVectors: vectors,
      status,
      ownerIds: [`USR-${String((i % 49) + 1).padStart(3, "0")}`],
      attachments: [],
      cyberRiskIds: [],
      assetIds: assetCellIds,
      vulnerabilityIds: vulnMeta,
      relationships: {
        assetIds: [...assetCellIds],
        vulnerabilityIds: [...vulnMeta],
        cyberRiskIds: [],
        controlIds: [],
        mitigationPlanIds: [],
        scenarioIds: [],
      },
      _severity: sev,
    };
  });

  const threatByThr = new Map(threats.map((t) => [t.id, t]));

  const vulnerabilities = vulnRows.map((row, i) => {
    const displayId = row["Display ID"].trim();
    const id = vulnDisplayToMeta.get(displayId);
    const assetIdsParsed = parseIdList(row.Assets).filter((x) => x.startsWith("AST-"));
    const primaryAssetId = assetIdsParsed[0] ?? fail(`vuln ${displayId} missing asset`);
    const ciaParts = row["CIA impacts"].split(/[,;]/).map((x) => x.trim()).filter(Boolean);
    return {
      id,
      displayId,
      name: row.Name.trim(),
      description: undefined,
      domain: row.Domain.trim(),
      vulnerabilityType: row["Vulnerability type"].trim(),
      status: "Active",
      primaryCIAImpact: ciaParts,
      ownerIds: [`USR-${String((i % 49) + 1).padStart(3, "0")}`],
      attachments: [],
      cyberRiskIds: [],
      assetIds: assetIdsParsed,
      threatIds: [],
      relationships: {
        assetId: primaryAssetId,
        cyberRiskIds: [],
        threatIds: [],
        controlIds: [],
        mitigationPlanIds: [],
        scenarioIds: [],
      },
    };
  });

  const controls = controlRows.map((row, i) => {
    const id = row["Display ID"].trim();
    const effStr = String(row.Effectiveness);
    const em = /(\d)/.exec(effStr);
    const eff = em ? Number.parseInt(em[1], 10) : 3;
    const freqRaw = row.Frequency.trim();
    const controlFrequency = CONTROL_FREQ_MAP[freqRaw] ?? "Monthly";
    const assetIds = parseIdList(row.Assets).filter((x) => x.startsWith("AST-"));
    return {
      id,
      name: row.Name.trim(),
      ownerId: `USR-${String((i % 49) + 1).padStart(3, "0")}`,
      status: row.Status.trim() === "Archived" ? "Archived" : "Active",
      controlType: row.Type.trim() === "Detective" ? "Detective" : "Preventive",
      keyControl: String(row.Key).trim().toLowerCase() === "yes",
      controlFrequency,
      assetIds,
      effectiveness: Math.min(5, Math.max(1, eff)),
      effectivenessLabel: fiveLabel(Math.min(5, Math.max(1, eff))),
    };
  });

  const cyberRisks = cyberRows.map((row, i) => {
    const id = row["Display ID"].trim();
    const statusRaw = row.Status.trim();
    const status = CYBER_RISK_STATUS.has(statusRaw) ? statusRaw : "Assessment";
    const threatDisplays = parseIdList(row.Threats).filter((x) => x.startsWith("T-"));
    const threatIds = threatDisplays.map((d) => tDisplayToThr(d)).filter(Boolean);
    const assetIds = parseIdList(row.Assets).filter((x) => x.startsWith("AST-"));
    const vulnDisplays = parseIdList(row["Vulnerability categories"]).filter((x) => x.startsWith("VUL-CAT"));
    const vulnerabilityIds = vulnDisplays.map((d) => vulnDisplayToMeta.get(d)).filter(Boolean);
    const rng = ((i * 7919) % 23) + 3;
    const impact = (((i + rng) % 5) + 1);
    const likelihood = 1 + ((i * 17) % 25);
    const score = impact * likelihood;
    const buIdx = (i % orgUnits.length) + 1;
    const scopedAsm = parseIdList(row["Scoped"] ?? "");
    const assessmentIds = scopedAsm
      .map((x) => (String(x).startsWith("ASM-") ? asmToCra(x) : null))
      .filter(Boolean);
    return {
      id,
      name: row.Name.trim(),
      ownerId: `USR-${String((i % 49) + 1).padStart(3, "0")}`,
      status,
      orgUnitId: pad("BU", buIdx),
      likelihood,
      likelihoodLabel: likelihoodLabel(likelihood),
      impact,
      impactLabel: fiveLabel(impact),
      cyberRiskScore: score,
      cyberRiskScoreLabel: cyberScoreLabel(score),
      residualLikelihood: likelihood,
      residualLikelihoodLabel: likelihoodLabel(likelihood),
      residualCyberRiskScore: score,
      residualCyberRiskScoreLabel: cyberScoreLabel(score),
      assetIds,
      threatIds,
      vulnerabilityIds,
      scenarioIds: [],
      mitigationPlanIds: [pad("MP", 1 + (i % 15)), pad("MP", 1 + ((i + 7) % 15))],
      relationships: {
        assetIds: [...assetIds],
        threatIds: [...threatIds],
        vulnerabilityIds: [...vulnerabilityIds],
        scenarioIds: [],
        mitigationPlanIds: [pad("MP", 1 + (i % 15)), pad("MP", 1 + ((i + 7) % 15))],
        assessmentIds: [...assessmentIds],
      },
    };
  });

  for (const r of cyberRisks) {
    applyCyberRiskThreatInference(r, threats);
  }

  const craIds = [];
  const riskAssessments = assessmentRows.map((row, i) => {
    const asm = row["Display ID"].trim();
    const cra = asmToCra(asm) ?? fail(`bad assessment ${asm}`);
    craIds.push(cra);
    const phase = ASSESSMENT_PHASE_MAP[row.Phase.trim()] ?? "Draft";
    const assetIds = parseIdList(row.Assets).filter((x) => x.startsWith("AST-"));
    const threatIds = parseIdList(row.Threats)
      .filter((x) => x.startsWith("T-"))
      .map((d) => tDisplayToThr(d))
      .filter(Boolean);
    const vulnIds = parseIdList(row["Vulnerability categories"])
      .filter((x) => x.startsWith("VUL-CAT"))
      .map((d) => vulnDisplayToMeta.get(d))
      .filter(Boolean);
    const crIds = parseIdList(row["Cyber risks"]).filter((x) => x.startsWith("CR-"));
    const scIds = parseIdList(row.Scenarios).filter((x) => x.startsWith("SC-"));
    return {
      id: cra,
      name: row.Name.trim(),
      ownerId: mapOwner(row.Owner, ownerMap),
      status: phase,
      assessmentType: row["Scoring type"] === "residual" ? "Residual scoring" : "Inherent scoring",
      startDate: (row.Created || "").slice(0, 10),
      dueDate: (row.Updated || row.Created || "").slice(0, 10),
      assetIds,
      cyberRiskIds: crIds,
      threatIds,
      vulnerabilityIds: vulnIds,
      scenarioIds: scIds,
      excludedScopeCyberRiskIds: [],
      excludedScopeThreatIds: [],
      excludedScopeVulnerabilityIds: [],
      excludedScopeControlIds: [],
      excludedScopeScenarioIds: [],
      aiScoringPhase: row["AI phase"] === "complete" ? "complete" : "idle",
    };
  });

  const mitigationPlans = [];
  for (let i = 0; i < 15; i++) {
    const n = i + 1;
    mitigationPlans.push({
      id: pad("MP", n),
      name: `Mitigation plan ${pad("MP", n)}`,
      ownerId: `USR-${String((n % 49) + 1).padStart(3, "0")}`,
      status: "In progress",
      dueDate: "2026-12-31",
      orgUnitId: pad("BU", (n % 52) + 1),
      severity: ((n % 5) + 1),
      severityLabel: fiveLabel((n % 5) + 1),
      controlIds: [pad("CTL", ((n - 1) % 35) + 1), pad("CTL", (n % 35) + 1)],
      cyberRiskIds: [pad("CR", n), pad("CR", ((n % 15) + 1))],
      assessmentIds: craIds.slice(0, Math.min(3, craIds.length)),
    });
  }

  const cyberRiskById = new Map(cyberRisks.map((r) => [r.id, r.name.trim()]));
  const threatByIdRationale = new Map(threats.map((t) => [t.id, { name: t.name }]));
  const vulnByIdRationale = new Map(vulnerabilities.map((v) => [v.id, v]));
  const vulnsByAssetId = buildVulnsByAssetIdMap(vulnerabilities);

  const scenarios = scenarioRows.map((row) => {
    const id = row["Display ID"].trim();
    const name = row.Name.trim();
    const asmToken = firstIdToken(row.Assessment) ?? fail(`scenario ${id} missing Assessment`);
    const assessmentId = asmToCra(asmToken) ?? fail(`scenario ${id} bad Assessment ${asmToken}`);
    const assetId = firstIdToken(row.Asset) ?? fail(`scenario ${id} asset`);
    const asset = assetById.get(assetId);
    const crCell = firstIdToken(row["Cyber risk"]);
    const thrDisp = firstIdToken(row.Threat);
    const thrId = thrDisp ? tDisplayToThr(thrDisp) : null;
    const threat = thrId ? threatByThr.get(thrId) : null;
    const impact = asset?.criticality ?? 3;
    const threatSeverity = threat?._severity ?? 3;
    const vulnDisp = firstIdToken(row.Vulnerability);
    const vulnId = vulnDisp ? vulnDisplayToMeta.get(vulnDisp) : null;
    const vulnerabilitySeverity = 3;
    const likelihood = Math.min(25, Math.max(1, threatSeverity * vulnerabilitySeverity));
    const cyberRiskScore = Math.min(125, Math.max(1, impact * likelihood));
    const ctlIds = parseIdList(row.Controls).filter((x) => x.startsWith("CTL-"));
    const scenarioThreatIds = thrId ? [thrId] : [];
    const scenarioVulnIds = vulnId ? [vulnId] : [];
    const threatNamesForTitle = scenarioThreatIds
      .map((tid) => threatByIdRationale.get(tid)?.name)
      .filter(Boolean) as string[];
    const scenarioThreatPhrase = formatThreatPhrase(threatNamesForTitle);
    const cyberRiskName = (crCell && cyberRiskById.get(crCell)) || crCell || "Cyber risk";
    const assetName = asset?.name ?? assetId;
    const assetType = asset?.assetType ?? "Asset";
    const impactLabel = fiveLabel(impact) as FivePointScaleLabel;
    const threatSeverityLabel = fiveLabel(threatSeverity) as FivePointScaleLabel;
    const vulnerabilitySeverityLabel = fiveLabel(vulnerabilitySeverity) as FivePointScaleLabel;
    const likelihoodLabelValue = likelihoodLabel(likelihood) as FivePointScaleLabel;
    const cyberRiskScoreLabelValue = cyberScoreLabel(cyberRiskScore) as FivePointScaleLabel;
    const mapsRationale = {
      threatById: threatByIdRationale,
      vulnById: vulnByIdRationale,
      vulnsByAssetId,
    };
    return {
      id,
      name,
      ownerId: asset?.ownerId ?? "USR-001",
      cyberRiskId: crCell ?? fail(`scenario ${id} cr`),
      assetId,
      assessmentId,
      impact,
      impactLabel,
      threatSeverity,
      threatSeverityLabel,
      vulnerabilitySeverity,
      vulnerabilitySeverityLabel,
      likelihood,
      likelihoodLabel: likelihoodLabelValue,
      cyberRiskScore,
      cyberRiskScoreLabel: cyberRiskScoreLabelValue,
      threatIds: scenarioThreatIds,
      vulnerabilityIds: scenarioVulnIds,
      scoringRationale: buildScoringRationale(
        cyberRiskName,
        scenarioThreatPhrase,
        assetName,
        assetType,
        impactLabel,
        threatSeverityLabel,
        vulnerabilitySeverityLabel,
        likelihoodLabelValue,
        cyberRiskScoreLabelValue,
        scenarioThreatIds,
        scenarioVulnIds,
        assetId,
        mapsRationale,
      ),
      relationships: {
        cyberRiskId: crCell,
        assetId,
        threatIds: thrId ? [thrId] : [],
        vulnerabilityIds: vulnId ? [vulnId] : [],
        controlIds: ctlIds,
        mitigationPlanIds: [],
      },
    };
  });

  for (const s of scenarios) {
    const r = cyberRisks.find((x) => x.id === s.cyberRiskId);
    if (r && !r.scenarioIds.includes(s.id)) r.scenarioIds.push(s.id);
  }

  for (const t of threats) {
    delete t._severity;
  }

  const catalog = {
    schemaVersion: 3,
    users,
    orgUnits,
    assets,
    vulnerabilities,
    threats,
    controls,
    mitigationPlans,
    cyberRisks,
    riskAssessments,
    scenarios,
    scenarioOverrides: {},
    craDraft: null,
    cyberScoreBands: DEFAULT_CYBER_SCORE_BANDS,
    likelihoodBands: DEFAULT_LIKELIHOOD_BANDS,
  };

  fs.mkdirSync(path.dirname(OUT_JSON), { recursive: true });
  fs.writeFileSync(OUT_JSON, JSON.stringify(catalog, null, 2), "utf8");
  console.log("Wrote", OUT_JSON);
}

main();
