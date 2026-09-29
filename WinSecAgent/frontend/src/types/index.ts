export interface Alert {
  id: number;
  title: string;
  raw_content?: string;
  source_type: string;
  severity: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export interface Incident {
  source_record?: EvidenceRecord | null;
  correlation?: CorrelationResult | null;
  queue: 'logs' | 'alerts';
  assessment?: {
    classification: 'benign' | 'unknown' | 'suspicious' | 'malicious';
    label: string;
    queue: 'logs' | 'alerts';
    findings: {quote: string; reason: string}[];
    missing_evidence: string[];
  };
  id: number;
  alert_id: number;
  event_type?: string;
  risk_level?: string;
  confidence?: number;
  summary?: string;
  attack_stage?: string;
  status: string;
  created_at: string;
  updated_at: string;
  alert?: Alert;
  agent_runs?: AgentRun[];
  evidence_items?: EvidenceItem[];
  response_actions?: ResponseAction[];
  reports?: Report[];
}

export interface AgentRun {
  id: number;
  incident_id: number;
  agent_name: string;
  status: string;
  input_data?: any;
  output_data?: any;
  error_message?: string;
  started_at: string;
  finished_at?: string;
}

export interface EvidenceRecord {
  alert_id: number;
  incident_id?: number | null;
  event_id?: string | null;
  record_id?: string | number | null;
  timestamp?: string | null;
  computer?: string | null;
  channel?: string | null;
  username?: string | null;
  account_domain?: string | null;
  source_ip?: string | null;
  service_path?: string | null;
  is_demo: boolean;
  raw_content: string;
  raw_sha256: string;
}

export interface CorrelationResult {
  rule_version: number;
  analyzed_at: string;
  window_minutes: number;
  warnings: string[];
  recommendations: string[];
  records: EvidenceRecord[];
  time_range: {start: string | null; end: string | null};
  findings: {
    rule_id: string; title: string; reason: string; record_refs: number[];
    failure_count?: number; start?: string | null; end?: string | null;
    source_ip?: string; account?: string; missing_evidence: string[];
  }[];
}

export interface EvidenceItem {
  id: number;
  incident_id: number;
  type: string;
  title: string;
  content?: string;
  source?: string;
  confidence?: number;
  created_at: string;
}

export interface ResponseAction {
  id: number;
  incident_id: number;
  action_type: string;
  description: string;
  risk: string;
  approval_required: boolean;
  status: string;
  approved_by?: string;
  result?: any;
  created_at: string;
  updated_at: string;
}

export interface Report {
  id: number;
  incident_id: number;
  content: string;
  format: string;
  created_at: string;
}

export interface DemoCase {
  id: string;
  title: string;
  severity: string;
  raw_content: string;
}

// WinSecAgent new types
export interface LogEvent {
  Computer?: string;
  EventData?: Record<string, unknown>;
  OriginalXml?: string;
  TimeCreated: string;
  EventID: number;
  Level: number;
  Channel: string;
  ProviderName?: string;
  RecordId?: number;
  Message: string;
}

export interface LogReadResult {
  warnings?: string[];
  read_status?: 'success' | 'partial' | 'failed' | 'demo';
  channel_results?: {
    channel: string;
    status: 'success' | 'partial' | 'failed';
    events_read: number;
    error_kind?: string | null;
    error_code?: number | null;
    message?: string | null;
    detail?: string | null;
  }[];
  reader_context?: {account: string | null; elevated: boolean | null} | null;
  events: LogEvent[];
  total_raw: number;
  total_filtered: number;
  event_id_stats: Record<number, number>;
  channel_stats: Record<string, number>;
  timestamp: string;
  is_mock: boolean;
  platform: string;
}

export interface KnowledgeEntry {
  id: string;
  title: string;
  content: string;
  category: string;
  score?: number;
}

export interface MemoryEntry {
  id: number;
  event_data: Record<string, any>;
  analysis_result: Record<string, any>;
  keywords?: string[];
  created_at: string;
}

export interface SchedulerStatus {
  running: boolean;
  paused: boolean;
  scan_interval: number;
  scan_count: number;
  last_scan: string | null;
  auto_threshold: number;
}

export interface SystemInfo {
  warnings?: string[];
  processes: any[];
  network_connections: any[];
  services: any[];
  scheduled_tasks: any[];
  registry: any[];
  is_mock: boolean;
  platform: string;
}
