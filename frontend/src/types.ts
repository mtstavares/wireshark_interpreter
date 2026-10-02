export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type AnalysisStatus =
  | "queued"
  | "running"
  | "completed"
  | "completed_with_warnings"
  | "failed"
  | "canceled";

export interface Capture {
  id: string;
  original_filename: string;
  sha256: string;
  size_bytes: number;
  capture_format: "pcap" | "pcapng";
  status: string;
  created_at: string;
}

export interface Artifact {
  path: string;
  size_bytes: number;
}

export interface AnalyzerRun {
  id: string;
  analyzer: string;
  status: string;
  version: string | null;
  duration_ms: number | null;
  exit_code: number | null;
  diagnostic: string | null;
  artifacts: Artifact[];
}

export interface StageSummary {
  status: string;
  flow_count?: number;
  event_count?: number;
  finding_count?: number;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface Analysis {
  id: string;
  capture_id: string;
  status: AnalysisStatus;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  analyzer_runs: AnalyzerRun[];
  normalization: StageSummary | null;
  detection: StageSummary | null;
}

export interface Evidence {
  kind: string;
  reference: string;
  source: string;
}

export interface Finding {
  id: string;
  analysis_id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  assertion_status: string;
  summary: string;
  first_seen: string | null;
  last_seen: string | null;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  evidence: Evidence[];
  mitigations: string[];
  mitre_attack: string[];
  detector_name: string;
  detector_version: string;
}

export interface Host {
  ip: string;
  first_seen: string;
  last_seen: string;
  sent_bytes: number;
  received_bytes: number;
  transports: string[];
  applications: string[];
}

export interface Service {
  ip: string;
  port: number;
  transport: string;
  application: string | null;
  flow_count: number;
}

export interface Inventory {
  hosts: Host[];
  services: Service[];
}

export interface Flow {
  id: string;
  start_time: string;
  end_time: string;
  src_ip: string;
  src_port: number | null;
  dest_ip: string;
  dest_port: number | null;
  transport: string;
  application: string | null;
  src_bytes: number;
  dest_bytes: number;
  src_packets: number;
  dest_packets: number;
  sources: string[];
}

export interface NetworkEvent {
  id: string;
  source: string;
  event_type: string;
  occurred_at: string | null;
  src_ip: string | null;
  src_port: number | null;
  dest_ip: string | null;
  dest_port: number | null;
  transport: string | null;
  application: string | null;
  evidence_ref: string;
  details: Record<string, unknown>;
}

export interface Enrichment {
  id: string;
  analysis_id: string;
  finding_id: string | null;
  subject_type: "finding" | "ip";
  subject_value: string;
  kind: "technique" | "weakness" | "vulnerability" | "platform" | "reputation";
  namespace: string;
  value: string;
  title: string;
  description: string;
  confidence: number;
  provider: string;
  source_url: string | null;
  retrieved_at: string;
  expires_at: string | null;
  cache_hit: boolean;
  influence: "context_only";
}

export interface AssetContext {
  analysis_id: string;
  ip: string;
  scope: string;
  allowlisted: boolean;
  name: string | null;
  role: string | null;
  owner: string | null;
  criticality: string | null;
  labels: string[];
  provenance: string;
}

export type ValidationStatus =
  | "awaiting_approval"
  | "blocked"
  | "approved"
  | "running"
  | "completed"
  | "failed";

export type AnalystConclusion =
  | "pending"
  | "confirmed"
  | "false_positive"
  | "inconclusive";

export interface ValidationAuditEntry {
  id: string;
  validation_id: string;
  action: string;
  actor: string;
  occurred_at: string;
  details: Record<string, string | number | boolean | null>;
}

export interface Validation {
  id: string;
  analysis_id: string;
  finding_id: string;
  validator: "tcp-connect";
  target_ip: string;
  target_port: number;
  status: ValidationStatus;
  policy_allowed: boolean;
  policy_reason: string;
  scope_reference: string;
  requested_by: string;
  approved_by: string | null;
  created_at: string;
  approved_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  technical_result: "not_executed" | "reachable" | "not_reachable" | "error";
  analyst_conclusion: AnalystConclusion;
  result_summary: string | null;
  review_rationale: string | null;
  reviewed_by: string | null;
  reviewed_at: string | null;
  audit: ValidationAuditEntry[];
}

export interface ReportFinding extends Omit<Finding, "analysis_id"> {
  wireshark_filter: string | null;
}

export interface TimelineEntry {
  occurred_at: string | null;
  finding_id: string;
  severity: Severity;
  title: string;
}

export interface ReportActivity {
  occurred_at: string | null;
  finding_id: string;
  severity: Severity;
  assertion_status: string;
  statement: string;
  source_ip: string | null;
  destination_ip: string | null;
  destination_port: number | null;
  confidence: number;
  evidence_refs: string[];
}

export interface SecurityReport {
  schema_version: string;
  report_id: string;
  generated_at: string;
  analysis_id: string;
  analysis_status: AnalysisStatus;
  capture: Pick<
    Capture,
    "id" | "original_filename" | "sha256" | "size_bytes" | "capture_format"
  >;
  executive_summary: string;
  conclusion: string;
  next_steps: string[];
  integrity_sha256: string;
  summary: {
    flow_count: number;
    event_count: number;
    host_count: number;
    service_count: number;
    finding_count: number;
    enrichment_count: number;
    severity_counts: Record<Severity, number>;
    first_seen: string | null;
    last_seen: string | null;
  };
  analyzers: Array<{
    name: string;
    status: string;
    version: string | null;
    diagnostic: string | null;
  }>;
  activities: ReportActivity[];
  findings: ReportFinding[];
  hosts: Host[];
  services: Service[];
  timeline: TimelineEntry[];
  indicators: Array<{ type: string; value: string; finding_ids: string[] }>;
  enrichments: Enrichment[];
  assets: AssetContext[];
  validations: Validation[];
  limitations: string[];
}

export interface RecentAnalysis extends Analysis {
  capture_name: string;
}
