/**
 * Vulnerability catalog (two Active/Draft rows per asset). If you import this module
 * without loading `threats.js` first, `threatIds` / `relationships.threatIds` stay empty.
 * Import `../data/threats.js` (side effect) or use the data barrel that pulls in threats.
 */
import { padId } from "./types.js";
import type {
  AssetType,
  CIAImpact,
  MockThreatAttachment,
  MockVulnerability,
  VulnerabilityDomain,
  VulnerabilityStatus,
  VulnerabilityType,
} from "./types.js";
import { assets } from "./assets.js";

type VulnTemplate = {
  name: string;
  domain: VulnerabilityDomain;
  status: VulnerabilityStatus;
  primaryCIAImpact: CIAImpact[];
  vulnerabilityType?: VulnerabilityType;
  /** When true, mock row has no owner assignment (optional field demo). */
  omitOwner?: boolean;
  description?: string;
};

function defaultDescription(name: string, domain: VulnerabilityDomain): string {
  return `Library category describing ${name.toLowerCase()} within the ${domain} domain. Scope is limited to weaknesses that can be assessed consistently across in-scope assets; it does not replace asset-specific findings.`;
}

function mockVulnAttachments(seq: number): MockThreatAttachment[] {
  if (seq % 6 !== 0) return [];
  return [
    {
      id: `vul-att-${seq}-1`,
      fileName: "Threat intelligence bulletin — sample excerpt.pdf",
    },
    {
      id: `vul-att-${seq}-2`,
      fileName: "Internal incident report — redacted summary.docx",
    },
  ];
}

function vt(
  partial: Omit<VulnTemplate, "description"> & { description?: string },
): VulnTemplate {
  return {
    ...partial,
    description: partial.description ?? defaultDescription(partial.name, partial.domain),
  };
}

/** Six rotating templates per asset class (names stay generic; asset link is via assetIds). */
const TEMPLATES: Record<AssetType, VulnTemplate[]> = {
  Application: [
    vt({
      name: "Inadequate access control reviews",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality", "Integrity"],
      vulnerabilityType: "Identity and Privilege Management",
    }),
    vt({
      name: "Missing security regression testing",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Change and Release Management Weakness",
    }),
    vt({
      name: "Weak session timeout configuration",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Security Configuration",
    }),
    vt({
      name: "Unpatched application dependencies",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity", "Availability"],
      vulnerabilityType: "Patch / Update Management",
    }),
    vt({
      name: "Insufficient input validation",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Application Security Defect",
    }),
    vt({
      name: "Gaps in security logging coverage",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Logging, Monitoring and Detection Gap",
      omitOwner: true,
    }),
  ],
  Database: [
    vt({
      name: "Weak database authentication configuration",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Authentication and Access Control",
    }),
    vt({
      name: "Missing encryption at rest",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Data Protection Weakness",
    }),
    vt({
      name: "Excessive privileged database accounts",
      domain: "People",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Insider Risk and Human Error",
    }),
    vt({
      name: "Immature backup and recovery testing",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Incident Response Readiness Gap",
    }),
    vt({
      name: "Incomplete data classification enforcement",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Policy and Governance Gap",
    }),
    vt({
      name: "Slow vulnerability patching cadence",
      domain: "Technology",
      status: "Draft",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Patch / Update Management",
    }),
  ],
  Server: [
    vt({
      name: "Delayed operating system patching",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Patch / Update Management",
      description:
        "Category covers operating systems and hypervisors that lag approved patch levels, including deferred security updates and long maintenance windows.",
    }),
    vt({
      name: "Insecure default service configuration",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Availability", "Confidentiality"],
      vulnerabilityType: "Security Configuration",
    }),
    vt({
      name: "Weak administrative access governance",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Identity and Privilege Management",
    }),
    vt({
      name: "Missing host-based monitoring",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Logging, Monitoring and Detection Gap",
    }),
    vt({
      name: "Insufficient hardening against lateral movement",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality", "Integrity"],
      vulnerabilityType: "Network Security Weakness",
    }),
    vt({
      name: "Inadequate separation of production and non-production",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Change and Release Management Weakness",
      omitOwner: true,
    }),
  ],
  "Network device": [
    vt({
      name: "Outdated firmware on managed appliances",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Patch / Update Management",
    }),
    vt({
      name: "Weak or shared administrative credentials",
      domain: "People",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Authentication and Access Control",
    }),
    vt({
      name: "Incomplete network segmentation design",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Network Security Weakness",
    }),
    vt({
      name: "Missing centralized configuration backup",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Asset Visibility and Inventory Gap",
    }),
    vt({
      name: "Insufficient traffic inspection coverage",
      domain: "Technology",
      status: "Archived",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Logging, Monitoring and Detection Gap",
      description:
        "Superseded by consolidated “Network detection coverage” category. Retained for audit history only.",
    }),
    vt({
      name: "Gaps in change approval documentation",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Policy and Governance Gap",
    }),
  ],
  "Cloud service": [
    vt({
      name: "Overly permissive identity and access policies",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Cloud Security Misconfiguration",
    }),
    vt({
      name: "Misconfigured public exposure settings",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality", "Integrity"],
      vulnerabilityType: "Cloud Security Misconfiguration",
    }),
    vt({
      name: "Weak secrets and key rotation practices",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Cryptographic Weakness",
    }),
    vt({
      name: "Underused data loss prevention controls",
      domain: "Technology",
      status: "Archived",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Data Protection Weakness",
      description:
        "Retired after DLP program redesign; historical assessments may still reference this label.",
    }),
    vt({
      name: "Immature SaaS governance and app approval",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Third-Party and Vendor Risk",
    }),
    vt({
      name: "Limited visibility into provider-side incidents",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Logging, Monitoring and Detection Gap",
      omitOwner: true,
    }),
  ],
  Endpoint: [
    vt({
      name: "Inconsistent endpoint protection coverage",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Security Configuration",
    }),
    vt({
      name: "Weak local administrator controls",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Identity and Privilege Management",
    }),
    vt({
      name: "Outdated endpoint agent versions",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Unsupported / End-of-Life Technology",
    }),
    vt({
      name: "Insufficient lost-device response procedures",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Confidentiality", "Availability"],
      vulnerabilityType: "Incident Response Readiness Gap",
    }),
    vt({
      name: "Gaps in removable media restrictions",
      domain: "Physical",
      status: "Active",
      primaryCIAImpact: ["Integrity", "Confidentiality"],
      vulnerabilityType: "Physical and Environmental Security Gap",
    }),
    vt({
      name: "Weak patch compliance reporting",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Patch / Update Management",
    }),
  ],
  "IoT device": [
    vt({
      name: "Default or unchanged device credentials",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Authentication and Access Control",
    }),
    vt({
      name: "Limited firmware update channel",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Unsupported / End-of-Life Technology",
    }),
    vt({
      name: "Weak network isolation for device VLANs",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Availability"],
      vulnerabilityType: "Network Security Weakness",
    }),
    vt({
      name: "Insufficient device inventory accuracy",
      domain: "Process",
      status: "Active",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Asset Visibility and Inventory Gap",
    }),
    vt({
      name: "Missing anomaly detection for device traffic",
      domain: "Technology",
      status: "Active",
      primaryCIAImpact: ["Confidentiality"],
      vulnerabilityType: "Logging, Monitoring and Detection Gap",
    }),
    vt({
      name: "Immature IoT vendor risk reviews",
      domain: "Process",
      status: "Draft",
      primaryCIAImpact: ["Integrity"],
      vulnerabilityType: "Software Supply Chain Risk",
    }),
  ],
};

/** Exactly two vulnerability categories per asset (count = 2 × assets.length for the default seed). */
const VULNERABILITIES_PER_ASSET = 2;

function emptyRelationshipPlaceholders(assetId: string, cyberRiskIds: string[]) {
  return {
    assetId,
    cyberRiskIds,
    threatIds: [] as string[],
    controlIds: [] as string[],
    mitigationPlanIds: [] as string[],
    scenarioIds: [] as string[],
  };
}

function buildVulnerabilities(): MockVulnerability[] {
  const out: MockVulnerability[] = [];
  let vulnSeq = 0;

  for (let assetIndex = 0; assetIndex < assets.length; assetIndex++) {
    const asset = assets[assetIndex]!;
    const pool = TEMPLATES[asset.assetType];

    for (let j = 0; j < VULNERABILITIES_PER_ASSET; j++) {
      vulnSeq += 1;
      const template = pool[(assetIndex + j) % pool.length]!;
      const cyberRiskIds: string[] = [];
      const metaId = padId("VUL", vulnSeq);
      const displayId = `VUL-CAT-${String(vulnSeq).padStart(3, "0")}`;
      const ownerIds = template.omitOwner ? [] : [asset.ownerId];

      out.push({
        id: metaId,
        displayId,
        name: `${template.name} · ${asset.name}`,
        description: template.description,
        domain: template.domain,
        vulnerabilityType: template.vulnerabilityType,
        status: template.status,
        primaryCIAImpact: template.primaryCIAImpact,
        ownerIds,
        attachments: mockVulnAttachments(vulnSeq),
        cyberRiskIds,
        assetIds: [asset.id],
        threatIds: [],
        relationships: emptyRelationshipPlaceholders(asset.id, cyberRiskIds),
      });
    }
  }

  return out;
}

export const vulnerabilities: MockVulnerability[] = buildVulnerabilities();

const vulnById = new Map(vulnerabilities.map((v) => [v.id, v]));

function rebuildVulnIndex(): void {
  vulnById.clear();
  for (const v of vulnerabilities) {
    vulnById.set(v.id, v);
  }
}

export function replaceVulnerabilitiesFromPersistence(next: MockVulnerability[]): void {
  vulnerabilities.length = 0;
  vulnerabilities.push(...next);
  rebuildVulnIndex();
}

export function getVulnerabilityById(id: string): MockVulnerability | undefined {
  return vulnById.get(id);
}

/** Lifecycle: only Active entries are selectable in new risk assessments (ISO 27005 / NIST CSF alignment). */
export function isVulnerabilityActiveForAssessment(v: MockVulnerability): boolean {
  return v.status === "Active";
}
