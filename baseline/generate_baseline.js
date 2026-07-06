const {
  Document, Packer, Paragraph, TextRun, HeadingLevel, Table, TableRow, TableCell,
  WidthType, ShadingType, BorderStyle, AlignmentType, PageBreak, VerticalAlign,
} = require("docx");

const NAVY = "1F3B57";
const LIGHT_GRAY = "F2F2F2";
const BORDER = { style: BorderStyle.SINGLE, size: 2, color: "BFBFBF" };
const CELL_BORDERS = { top: BORDER, bottom: BORDER, left: BORDER, right: BORDER };

function headerCell(text, width) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    shading: { type: ShadingType.CLEAR, fill: NAVY },
    verticalAlign: VerticalAlign.CENTER,
    borders: CELL_BORDERS,
    margins: { top: 80, bottom: 80, left: 100, right: 100 },
    children: [new Paragraph({ children: [new TextRun({ text, bold: true, color: "FFFFFF", size: 20 })] })],
  });
}

function cell(text, width, opts = {}) {
  return new TableCell({
    width: { size: width, type: WidthType.DXA },
    borders: CELL_BORDERS,
    shading: opts.shade ? { type: ShadingType.CLEAR, fill: LIGHT_GRAY } : undefined,
    margins: { top: 80, bottom: 80, left: 100, right: 100 },
    children: [new Paragraph({
      children: [new TextRun({ text: String(text), bold: !!opts.bold, size: 20 })],
    })],
  });
}

function kvTable(rows) {
  // rows: [ [label, value], ... ] -- 2-column spec-sheet style table for one control domain
  return new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [2400, 6960],
    rows: rows.map(([label, value]) =>
      new TableRow({
        children: [cell(label, 2400, { bold: true, shade: true }), cell(value, 6960)],
      })
    ),
  });
}

function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, spacing: { before: 320, after: 160 }, children: [new TextRun(text)] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, spacing: { before: 240, after: 120 }, children: [new TextRun(text)] });
}
function p(text, opts = {}) {
  return new Paragraph({ spacing: { after: 160 }, children: [new TextRun({ text, ...opts })] });
}
function bullet(text) {
  return new Paragraph({ text, bullet: { level: 0 }, spacing: { after: 60 } });
}

// ---------------------------------------------------------------------------
// Control domain data -- severities and SLA windows here are the SAME
// constants used in collector/risk.py (SLA_DAYS), and the same control IDs
// referenced in mock_data/generate_mock_data.py. The baseline document and
// the pipeline are describing the same policy, not two unrelated artifacts.
// ---------------------------------------------------------------------------
const domains = [
  {
    title: "4.1 Identity & Access Management (IAM)",
    objective: "Ensure human and programmatic access to the AWS account follows least privilege, with no standing root credential use.",
    rows: [
      ["Baseline Requirement", "Root account has no active access keys; MFA enforced on root and all IAM users with console access; IAM users >90 days without credential use are disabled."],
      ["AWS Implementation", "IAM credential report reviewed monthly; SCP denies root API actions except account recovery; Access Analyzer enabled account-wide."],
      ["Mapped Security Hub Control(s)", "IAM.1 (root access key exists), IAM.22 (unused credentials >90 days)"],
      ["Severity if Violated", "IAM.1: Critical  |  IAM.22: Medium"],
      ["Remediation SLA", "IAM.1: 15 days  |  IAM.22: 60 days"],
    ],
  },
  {
    title: "4.2 Logging & Audit Trail (CloudTrail)",
    objective: "Maintain a complete, tamper-evident record of account activity across every region for forensic and audit purposes.",
    rows: [
      ["Baseline Requirement", "CloudTrail enabled in all regions with log file validation on; trail delivers to a dedicated, access-restricted S3 bucket with MFA delete."],
      ["AWS Implementation", "Organization-level trail; CloudWatch Logs integration for near-real-time alerting; 400-day retention minimum."],
      ["Mapped Security Hub Control(s)", "CloudTrail.1 (not enabled in all regions)"],
      ["Severity if Violated", "High"],
      ["Remediation SLA", "30 days"],
    ],
  },
  {
    title: "4.3 Threat Detection (GuardDuty)",
    objective: "Provide continuous, automated threat detection across accounts without relying on manual log review.",
    rows: [
      ["Baseline Requirement", "GuardDuty enabled in every region in use, with findings routed to the central Security Hub aggregator."],
      ["AWS Implementation", "Delegated administrator account manages member accounts; S3/EKS/Malware Protection data sources enabled where applicable."],
      ["Mapped Security Hub Control(s)", "GuardDuty.1 (not enabled)"],
      ["Severity if Violated", "High"],
      ["Remediation SLA", "30 days"],
    ],
  },
  {
    title: "4.4 Cloud Security Posture Management (Security Hub / Config)",
    objective: "Continuously evaluate the account against a recognized configuration standard rather than relying on point-in-time audits.",
    rows: [
      ["Baseline Requirement", "Security Hub enabled with the CIS AWS Foundations Benchmark standard active; AWS Config recording all supported resource types."],
      ["AWS Implementation", "Security Hub findings exported hourly into this pipeline's collector; Config recorder covers all regions in use."],
      ["Mapped Security Hub Control(s)", "Config.1 (AWS Config not enabled)"],
      ["Severity if Violated", "Medium"],
      ["Remediation SLA", "60 days"],
    ],
  },
  {
    title: "4.5 Key Management (KMS)",
    objective: "Ensure encryption keys protecting data at rest are managed with rotation and access control, not left as static secrets.",
    rows: [
      ["Baseline Requirement", "Customer-managed KMS keys have automatic annual rotation enabled; key policies follow least privilege (no wildcard principals)."],
      ["AWS Implementation", "Rotation status reviewed via Config rule cmk-backing-key-rotation-enabled; key usage logged via CloudTrail data events."],
      ["Mapped Security Hub Control(s)", "KMS.4 (key rotation not enabled)"],
      ["Severity if Violated", "Medium"],
      ["Remediation SLA", "60 days"],
    ],
  },
  {
    title: "4.6 Network Security (VPC)",
    objective: "Limit network exposure by default and require explicit justification for any broadly-scoped access rule.",
    rows: [
      ["Baseline Requirement", "Default security groups deny all traffic; no security group permits unrestricted (0.0.0.0/0) inbound SSH/RDP; flow logs enabled on all VPCs."],
      ["AWS Implementation", "VPC Flow Logs delivered to CloudWatch Logs; security group changes trigger Config rule evaluation within minutes."],
      ["Mapped Security Hub Control(s)", "VPC.1 (default security group allows traffic), EC2.19 (unrestricted SSH access)"],
      ["Severity if Violated", "VPC.1: Low  |  EC2.19: High"],
      ["Remediation SLA", "VPC.1: 90 days  |  EC2.19: 30 days"],
    ],
  },
  {
    title: "4.7 Storage Security (S3)",
    objective: "Prevent unintended public exposure of object storage, which remains one of the most common cloud breach vectors.",
    rows: [
      ["Baseline Requirement", "S3 Block Public Access enabled at the account level; bucket policies denying non-TLS (HTTP) requests; versioning enabled on buckets holding regulated data."],
      ["AWS Implementation", "Account-level Block Public Access setting enforced by SCP so it cannot be disabled by an individual bucket owner."],
      ["Mapped Security Hub Control(s)", "S3.8 (bucket-level Block Public Access disabled)"],
      ["Severity if Violated", "Critical"],
      ["Remediation SLA", "15 days"],
    ],
  },
  {
    title: "4.8 Compute & Serverless Security (EC2, Lambda)",
    objective: "Reduce the attack surface of compute resources and prevent serverless functions from being reachable or configured beyond their intended scope.",
    rows: [
      ["Baseline Requirement", "IMDSv2 required on all EC2 instances (IMDSv1 disabled); Lambda function resource policies never grant public/anonymous invoke access."],
      ["AWS Implementation", "Launch templates enforce HttpTokens=required; Lambda resource policies reviewed via Config rule lambda-function-public-access-prohibited."],
      ["Mapped Security Hub Control(s)", "EC2.8 (IMDSv1 permitted), Lambda.1 (function policy grants public access)"],
      ["Severity if Violated", "EC2.8: Medium  |  Lambda.1: Critical"],
      ["Remediation SLA", "EC2.8: 60 days  |  Lambda.1: 15 days"],
    ],
  },
  {
    title: "4.9 Database Security (RDS)",
    objective: "Ensure data persisted in managed database services is encrypted at rest by default, not opt-in per instance.",
    rows: [
      ["Baseline Requirement", "All RDS instances and snapshots encrypted at rest using a customer-managed or AWS-managed KMS key; automated backups enabled."],
      ["AWS Implementation", "Encryption enforced at the parameter-group/organization level; Config rule rds-storage-encrypted evaluates continuously."],
      ["Mapped Security Hub Control(s)", "RDS.3 (instance not encrypted at rest)"],
      ["Severity if Violated", "High"],
      ["Remediation SLA", "30 days"],
    ],
  },
];

const raciRows = [
  ["Identity & Access Management", "Cloud Infra", "AppSec (application-layer IAM roles)"],
  ["Logging, Detection & Posture (CloudTrail, GuardDuty, Security Hub, Config)", "Cloud Infra", "IT Ops (alert triage)"],
  ["Key Management & Storage (KMS, S3)", "Cloud Infra", "AppSec (data classification input)"],
  ["Network Security (VPC)", "Cloud Infra", "IT Ops"],
  ["Compute & Serverless (EC2, Lambda)", "Platform Eng", "Cloud Infra"],
  ["Database Security (RDS)", "Platform Eng", "Cloud Infra"],
  ["Exception & Risk Acceptance Approval", "Security Leadership", "Cloud Infra"],
];

const appendixRows = [
  ["IAM.1", "IAM", "Critical", "15"],
  ["IAM.22", "IAM", "Medium", "60"],
  ["CloudTrail.1", "Logging", "High", "30"],
  ["GuardDuty.1", "Threat Detection", "High", "30"],
  ["Config.1", "Posture Mgmt", "Medium", "60"],
  ["KMS.4", "Key Management", "Medium", "60"],
  ["VPC.1", "Network", "Low", "90"],
  ["EC2.19", "Network", "High", "30"],
  ["S3.8", "Storage", "Critical", "15"],
  ["EC2.8", "Compute", "Medium", "60"],
  ["Lambda.1", "Serverless", "Critical", "15"],
  ["RDS.3", "Database", "High", "30"],
];

const children = [];

// ---- Title page ----
children.push(
  new Paragraph({ spacing: { before: 2200 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "AWS SECURITY BASELINE", bold: true, size: 56, color: NAVY })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { before: 200, after: 100 },
    children: [new TextRun({ text: "Reference Standard for Cloud Infrastructure", size: 28, color: "555555" })] }),
  new Paragraph({ alignment: AlignmentType.CENTER, spacing: { after: 1600 },
    children: [new TextRun({ text: "Mapped to the AWS Security Hub controls monitored by the Security Automation & Compliance pipeline", italics: true, size: 22, color: "777777" })] }),
);

children.push(
  new Table({
    width: { size: 9360, type: WidthType.DXA },
    columnWidths: [2400, 6960],
    rows: [
      ["Document Owner", "Cloud Infra (Security Engineering)"],
      ["Classification", "Internal — Portfolio Reference Sample"],
      ["Version", "1.0"],
      ["Effective Date", "July 1, 2026"],
      ["Review Cadence", "Semi-annual, or on major AWS account architecture change"],
      ["Related Systems", "Security Automation & Compliance Dashboard (this repository)"],
    ].map(([l, v]) => new TableRow({ children: [cell(l, 2400, { bold: true, shade: true }), cell(v, 6960)] })),
  })
);

children.push(new Paragraph({ children: [new PageBreak()] }));

// ---- Contents (manual, no field-update dependency) ----
children.push(h1("Contents"));
[
  "1. Purpose & Scope",
  "2. Reference Frameworks",
  "3. Roles & Responsibilities",
  "4. Control Domains",
  "5. Continuous Compliance Automation",
  "6. Incident Response",
  "7. Exceptions & Risk Acceptance",
  "8. Review Cadence & Change Log",
  "Appendix A: Control-to-SLA Summary",
].forEach((t) => children.push(bullet(t)));

children.push(new Paragraph({ children: [new PageBreak()] }));

// ---- 1. Purpose & Scope ----
children.push(h1("1. Purpose & Scope"));
children.push(p(
  "This baseline defines the minimum security configuration required across every AWS account in scope, and the control mechanism used to verify it. It is written to be enforced by automation, not just read: every requirement below maps to a specific AWS Security Hub control ID that this program's collector pipeline ingests, risk-scores, and tracks to remediation."
));
children.push(p(
  "Scope covers identity and access management, logging and detection, network and storage configuration, key management, and compute/database hardening for all production and staging AWS accounts. Development and sandbox accounts are expected to meet a reduced subset noted per domain."
));

// ---- 2. Reference Frameworks ----
children.push(h1("2. Reference Frameworks"));
children.push(p("This baseline is informed by, and intended to be traceable to, the following external frameworks:"));
children.push(bullet("CIS AWS Foundations Benchmark v3.0 — primary source for control thresholds (IAM, logging, networking)."));
children.push(bullet("AWS Well-Architected Framework, Security Pillar — design principles for defense in depth."));
children.push(bullet("NIST Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover) — used to structure Sections 4–6."));
children.push(bullet("ISO/IEC 27001:2022 Annex A — control domains below are written to map cleanly to Annex A.8 (Asset Management), A.5.15 (Access Control), and A.8.16 (Monitoring) for organizations layering this baseline into a certified ISMS."));

// ---- 3. Roles & Responsibilities ----
children.push(h1("3. Roles & Responsibilities"));
children.push(p("Ownership below reflects who fixes a violation, not who merely gets notified of one — a distinction this baseline treats as load-bearing, since \"everyone's alert\" findings are the ones that go unresolved."));
children.push(new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [4160, 2600, 2600],
  rows: [
    new TableRow({ children: [headerCell("Control Domain", 4160), headerCell("Primary Owner", 2600), headerCell("Support / Consulted", 2600)] }),
    ...raciRows.map(([d, own, sup]) => new TableRow({ children: [cell(d, 4160), cell(own, 2600), cell(sup, 2600)] })),
  ],
}));

children.push(new Paragraph({ children: [new PageBreak()] }));

// ---- 4. Control Domains ----
children.push(h1("4. Control Domains"));
children.push(p("Each domain below states the requirement, how it's implemented in AWS, and which Security Hub control(s) this program relies on to detect a violation — including the severity and remediation SLA that violation carries once it reaches the pipeline."));
domains.forEach((d) => {
  children.push(h2(d.title));
  children.push(p(d.objective, { italics: true, color: "555555" }));
  children.push(kvTable(d.rows));
  children.push(new Paragraph({ spacing: { after: 120 }, children: [] }));
});

children.push(new Paragraph({ children: [new PageBreak()] }));

// ---- 5. Continuous Compliance Automation ----
children.push(h1("5. Continuous Compliance Automation"));
children.push(p(
  "This baseline is enforced continuously, not audited quarterly. AWS Security Hub evaluates every control above on an ongoing basis; findings are pulled by this program's Python collector alongside GitHub code-scanning alerts and network scanner output, normalized into one schema, and written to a SQLite datastore."
));
children.push(p(
  "Each finding is assigned a risk score (severity x asset criticality x SLA age) and an SLA due date derived from the severity table in Appendix A. The Security Automation & Compliance Dashboard reads directly from that datastore, so the compliance posture shown at any moment reflects the last collector run — not a stale spreadsheet."
));
children.push(p(
  "Every collector run is itself logged to an audit trail table (run ID, timestamp, sources pulled, finding counts). That audit trail is the primary input to the evidence-generation step described in the program's evidence automation workflow, which produces timestamped, control-mapped evidence artifacts suitable for an auditor request without manual screenshot collection."
));

// ---- 6. Incident Response ----
children.push(h1("6. Incident Response"));
children.push(p("Baseline violations that indicate active exploitation (not just drift) follow the incident response path below rather than the standard remediation SLA:"));
children.push(bullet("Detect — GuardDuty or Security Hub finding tagged as an active-threat indicator, or a critical finding with evidence of exploitation, triggers this path instead of standard SLA queuing."));
children.push(bullet("Triage — Cloud Infra on-call confirms scope and severity within 1 hour of detection; escalates to Security Leadership for anything touching production customer data."));
children.push(bullet("Contain — isolate the affected resource (security group lockdown, IAM key revocation, or instance quarantine) before root-causing, to stop the bleeding first."));
children.push(bullet("Eradicate & Recover — remove the root cause (patch, rotate, reconfigure), verify via a fresh Security Hub/scanner pass that the specific finding has cleared."));
children.push(bullet("Post-Incident Review — documented within 5 business days; any new detection gap gets a corresponding baseline or Security Hub control update, not just a one-off fix."));

// ---- 7. Exceptions & Risk Acceptance ----
children.push(h1("7. Exceptions & Risk Acceptance"));
children.push(p(
  "Not every finding can or should be remediated on the standard SLA — a finding on a decommissioning-in-progress asset is a common example. In those cases, the finding owner documents a risk acceptance rather than letting it silently age past due."
));
children.push(p(
  "An accepted-risk exception requires: (1) a named approver at or above the Primary Owner level from Section 3, (2) a written justification, and (3) a re-review date no more than 180 days out. Accepted findings are tracked with an explicit accepted_risk status distinct from resolved, so compliance reporting never conflates \"fixed\" with \"knowingly deferred.\""
));

// ---- 8. Review Cadence & Change Log ----
children.push(h1("8. Review Cadence & Change Log"));
children.push(p("This baseline is reviewed semi-annually by the Cloud Infra team, and immediately upon any material AWS account architecture change (new account vending, new region adoption, major service migration)."));
children.push(new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [1800, 1800, 5760],
  rows: [
    new TableRow({ children: [headerCell("Version", 1800), headerCell("Date", 1800), headerCell("Change", 5760)] }),
    new TableRow({ children: [cell("1.0", 1800), cell("2026-07-01", 1800), cell("Initial baseline, mapped to pipeline's 12 monitored Security Hub controls.", 5760)] }),
  ],
}));

children.push(new Paragraph({ children: [new PageBreak()] }));

// ---- Appendix A ----
children.push(h1("Appendix A: Control-to-SLA Summary"));
children.push(p("This table is the single source of truth this baseline and the pipeline's risk-scoring logic both draw from. If these SLA windows change, they should change here first."));
children.push(new Table({
  width: { size: 9360, type: WidthType.DXA },
  columnWidths: [2200, 3160, 2000, 2000],
  rows: [
    new TableRow({ children: [headerCell("Control ID", 2200), headerCell("Domain", 3160), headerCell("Severity", 2000), headerCell("Remediation SLA (days)", 2000)] }),
    ...appendixRows.map(([id, dom, sev, sla], i) =>
      new TableRow({ children: [cell(id, 2200, { shade: i % 2 === 0 }), cell(dom, 3160, { shade: i % 2 === 0 }), cell(sev, 2000, { shade: i % 2 === 0 }), cell(sla, 2000, { shade: i % 2 === 0 })] })
    ),
  ],
}));

const doc = new Document({
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 }, margin: { top: 1440, bottom: 1440, left: 1440, right: 1440 } } },
    children,
  }],
  styles: {
    default: { heading1: { run: { color: NAVY, size: 30, bold: true } }, heading2: { run: { color: NAVY, size: 24, bold: true } } },
  },
});

Packer.toBuffer(doc).then((buf) => {
  require("fs").writeFileSync("AWS_Security_Baseline.docx", buf);
  console.log("Wrote AWS_Security_Baseline.docx");
});
