import { getFivePointLabel, padId } from "./types.js";
import type { MockAsset, AssetType, FivePointScaleValue, AssetStatus } from "./types.js";

/** Canonical asset catalog. `threatIds` / `relationships.*` are populated in `threats.ts` / `cyberRisks.ts`. */

type AssetRow = [
  name: string,
  assetType: AssetType,
  criticality: FivePointScaleValue,
  ownerIdx: number,
  buIdx: number,
  status: AssetStatus,
];

const ASSET_TYPES: AssetType[] = [
  "Application",
  "Database",
  "Server",
  "Network device",
  "Cloud service",
  "Endpoint",
  "IoT device",
];

/** Short display names only — one unique title per catalog row. */
const ASSET_NAMES: string[] = [
  "Customer Database Server",
  "Active Directory Service",
  "ERP System",
  "Corporate VPN Gateway",
  "Employee Laptops",
  "Payment Processing Service",
  "Microsoft 365 Tenant",
  "Data Warehouse",
  "Kubernetes Cluster",
  "Web Application Tier",
  "DNS and DHCP Services",
  "SIEM Platform",
  "Backup Vault",
  "Privileged Access Workstations",
  "CRM System",
  "HRIS",
  "Code Repository",
  "Warehouse Management System",
  "Access Control System",
  "SCADA Network Segment",
  "File Shares",
  "Cloud Landing Zone",
  "Certificate Authority",
  "Video Conferencing",
  "Secrets Vault",
  "Mainframe LPAR",
  "Mobile Device Management",
  "API Gateway",
  "Data Lake",
  "Perimeter Firewalls",
  "Wireless Controllers",
  "IT Service Desk Platform",
  "Vendor Jump Service",
  "Reporting Database",
  "E-commerce Storefront",
  "Print Servers",
  "IoT Sensors",
  "Disaster Recovery Site",
  "Identity Federation",
  "Patch Servers",
  "EDR Console",
  "Intrusion Detection System",
  "Network Load Balancers",
  "Bastion Host Farm",
  "Container Registry",
  "Artifact Repository",
  "CI Runner Pool",
  "Test Automation Service",
  "Staging Web Cluster",
  "Production Web Cluster",
  "Marketing Website",
  "Partner Portal",
  "Customer Portal",
  "Licensing Server",
  "Antivirus Management",
  "Email Archiving",
  "Spam Filter Appliance",
  "Web Application Firewall",
  "DDoS Mitigation Service",
  "CDN Edge Nodes",
  "Internet Edge Routers",
  "Core Network Switches",
  "Data Center Interconnect",
  "MPLS Routers",
  "SD-WAN Orchestrator",
  "NAC Service",
  "Guest Wi-Fi Portal",
  "Room Booking System",
  "Visitor Management Kiosk",
  "Physical Security Cameras",
  "BMS Controllers",
  "UPS Management",
  "Environmental Monitoring",
  "Network Time Service",
  "IP Address Management",
  "Network Analytics",
  "VoIP Call Manager",
  "Contact Center Platform",
  "Collaboration Rooms",
  "Screen Sharing Service",
  "File Transfer Service",
  "Secure File Exchange",
  "Data Loss Prevention",
  "Cloud Access Security Broker",
  "Remote Browser Isolation",
  "Enterprise Password Manager",
  "Key Management Service",
  "HSM Cluster",
  "Log Shipper Pool",
  "Metrics Collection Service",
  "APM Platform",
  "Incident Response Toolkit",
  "Forensic Workstation Pool",
  "Legal Hold Archive",
  "Records Management System",
  "Document Management System",
  "Contract Lifecycle System",
  "Procurement Portal",
  "Travel and Expense System",
  "Time Tracking System",
  "Learning Management System",
  "Benefits Administration",
  "Payroll Engine",
  "Equity Management Platform",
  "Investor Relations Website",
  "Press Release Distribution",
  "Brand Asset Library",
  "Digital Asset Management",
  "Product Information Management",
  "Release Engineering Service",
  "Feature Flag Service",
  "Configuration Management Database",
  "Service Discovery",
  "Message Queue Cluster",
  "Event Streaming Platform",
  "Workflow Orchestration",
  "RPA Bot Farm",
  "OCR Document Service",
  "Translation Service",
  "Customer Data Platform",
  "Marketing Automation",
  "Sales Engagement Tool",
  "Subscription Billing Engine",
  "Usage Metering Service",
  "Tax Calculation Engine",
  "Fraud Detection Service",
  "Credit Check Integration",
  "KYC Verification Service",
  "Sanctions Screening",
  "Trade Compliance System",
  "ERP Sandbox Environment",
  "Data Science Workbench",
  "Model Training Cluster",
  "BI Reporting Server",
  "Executive Dashboard",
  "Regulatory Filing Archive",
  "Audit Evidence Vault",
  "Privacy Request Portal",
  "Consent Management Platform",
  "Cookie Compliance Scanner",
  "Endpoint Backup Fleet",
  "VDI Farm",
  "Thin Client Pool",
  "Mac Management Service",
  "Linux Standard Image Build",
  "Retail Kiosk Fleet",
  "Point of Sale Terminals",
  "Warehouse Handheld Scanners",
  "Lab Instruments Network",
  "Dev Test IoT Devices",
];

/** Default seed rows: short names, rotating types, criticality 2–5, USR 1–50, BU 1–52. */
function buildRawRows(): AssetRow[] {
  const n = ASSET_NAMES.length;
  if (n === 0) {
    throw new Error("ASSET_NAMES must define at least one title.");
  }
  const out: AssetRow[] = [];
  const ownerCount = 50;
  const buCount = 52;

  for (let i = 0; i < n; i++) {
    const assetType = ASSET_TYPES[i % ASSET_TYPES.length];
    const criticality = (2 + (i % 4)) as FivePointScaleValue;
    const ownerIdx = 1 + (i % ownerCount);
    const buIdx = 1 + (i % buCount);
    const status: AssetStatus = i % 23 === 0 ? "Inactive" : "Active";
    const name = ASSET_NAMES[i]!;
    out.push([name, assetType, criticality, ownerIdx, buIdx, status]);
  }
  return out;
}

const raw: AssetRow[] = buildRawRows();

function emptyAssetRelationships(): MockAsset["relationships"] {
  return {
    vulnerabilityIds: [],
    threatIds: [],
    cyberRiskIds: [],
    scenarioIds: [],
    controlIds: [],
  };
}

export const assets: MockAsset[] = raw.map(
  ([name, assetType, criticality, ownerIdx, buIdx, status], i) => ({
    id: padId("AST", i + 1),
    name,
    ownerId: padId("USR", ownerIdx),
    assetType,
    criticality,
    criticalityLabel: getFivePointLabel(criticality),
    orgUnitId: padId("BU", buIdx),
    status,
    vulnerabilityIds: [],
    threatIds: [],
    controlIds: [],
    relationships: emptyAssetRelationships(),
  }),
);

const assetById = new Map(assets.map((a) => [a.id, a]));

function rebuildAssetIndex(): void {
  assetById.clear();
  for (const a of assets) {
    assetById.set(a.id, a);
  }
}

/** Ensures fields added after schema v1 so older localStorage snapshots do not throw at runtime. */
export function normalizeCatalogAssetsInPlace(): void {
  for (const a of assets) {
    if (!Array.isArray(a.controlIds)) {
      (a as MockAsset).controlIds = [];
    }
    if (!Array.isArray(a.relationships.controlIds)) {
      a.relationships.controlIds = [];
    }
  }
}

export function replaceAssetsFromPersistence(next: MockAsset[]): void {
  assets.length = 0;
  assets.push(...next);
  rebuildAssetIndex();
  normalizeCatalogAssetsInPlace();
}

export function getAssetById(id: string): MockAsset | undefined {
  return assetById.get(id);
}
