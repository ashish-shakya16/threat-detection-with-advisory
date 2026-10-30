export interface Threat {
  id: number;
  threat_name: string;
  category: string;
  risk_level: 'Low' | 'Medium' | 'High' | 'Critical';
  risk_score: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  confidence: number;
  source: string;
  description: string;
  detected_at: string;
  last_seen_at?: string;
  occurrence_count?: number;
  status: 'active' | 'resolved' | 'ignored' | 'escalated';
  advisory?: Advisory | null;
  /** JSON-encoded RiskContext, when the threat was scored with context. */
  risk_context?: string | null;
  classification?: string | null;
  detection_method?: 'rule' | 'file_behaviour' | 'anomaly' | null;
  verification_status?: string | null;
  /** JSON-encoded list of evidence strings. */
  evidence?: string | null;
}

export interface PhishingEvidence {
  indicator: string;
  detail: string;
  weight: number;
}

export interface PhishingResult {
  url: string;
  host: string;
  registered_domain: string;
  score: number;
  verdict: 'High-risk URL indicators' | 'Suspicious URL' | 'No known phishing indicators';
  evidence: PhishingEvidence[];
  recommendations: string[];
  limitations: string;
}

export interface DetectionStatus {
  rules: number;
  monitoring_active: boolean;
  anomaly_baseline: {
    state: 'learning' | 'active' | 'disabled';
    samples?: number;
    cycles?: number;
    required_samples?: number;
    required_cycles?: number;
    progress?: number;
    trained_at?: string;
    threshold?: number;
    false_positive_target?: number;
  };
  ransomware_monitor: {
    enabled: boolean;
    running: boolean;
    watching: string[];
    thresholds: Record<string, number>;
    error: string;
  };
}

export interface RiskContext {
  asset_criticality: 'low' | 'medium' | 'high' | 'critical';
  exposure: 'local' | 'internal' | 'internet';
  privileged_user: boolean;
  off_hours: boolean;
  adjustments: string[];
  ml_anomaly_score?: number;
}

export type ResponseStatus = 'proposed' | 'approved' | 'rejected' | 'executed' | 'dry_run' | 'failed' | 'expired' | 'resumed';

export interface ResponseAction {
  id: number;
  threat_id: number;
  action: 'suspend_process' | 'terminate_process';
  response_level: number;
  target_pid: number;
  target_name: string;
  risk_level: string;
  reason: string;
  status: ResponseStatus;
  proposed_at: string;
  expires_at: string;
  decided_by: string | null;
  decided_at: string | null;
  executed_at: string | null;
  result_message: string | null;
}

export interface AuditEntry {
  id: number;
  created_at: string;
  actor: string;
  action: string;
  target_type: string;
  target_id: string;
  outcome: string;
  details: Record<string, unknown>;
  source_ip: string;
  entry_hash: string;
}

export interface AuditVerification {
  valid: boolean;
  checked: number;
  first_invalid_id: number | null;
}

export interface Advisory {
  id: number;
  threat_id: number;
  title: string;
  description: string;
  reason: string;
  recommended_actions: string;
  reference_links: string;
  generated_at: string;
}

export interface ThreatStatistics {
  total_threats: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
  active_critical: number;
  time_window_hours: number;
}

export interface SystemMetrics {
  cpu_percent: number;
  memory_percent: number;
  disk_percent: number;
  network_connections: number;
  process_count: number;
  timestamp: string;
}

export interface TimelinePoint {
  time: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DailyTimelinePoint {
  date: string;
  count: number;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  count?: number;
}

export interface User {
  username: string;
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  warning?: string;
  sources?: string[];
  evidence?: AssistantEvidence[];
  recommendations?: string[];
  uncertain?: boolean;
  mode?: 'llm' | 'local';
}

export interface AssistantEvidence {
  kind: 'knowledge' | 'securex_record';
  source: string;
  excerpt: string;
}

export interface AssistantResponse {
  response: string;
  recommendations: string[];
  evidence: AssistantEvidence[];
  sources: string[];
  confidence?: number;
  uncertain: boolean;
  warning: string;
  mode: 'llm' | 'local';
  timestamp: string;
}

export interface AssistantHistoryEntry {
  id: number;
  query: string;
  response: string;
  confidence: number | null;
  created_at: string;
}

export interface NotificationDelivery {
  id: number;
  recipient: string;
  threat_name: string;
  risk_level: string;
  status: 'sent' | 'failed';
  error_message: string | null;
  sent_at: string;
}

export interface NotificationStatus {
  status: 'enabled' | 'disabled';
  recipients: string[];
  notification_rules: {
    critical: boolean;
    high: boolean;
    medium: boolean;
    low: boolean;
  };
  cooldown_seconds: number;
  smtp_configured: boolean;
}

export interface MLStatus {
  status: string;
  trained: boolean;
  model_path: string;
}

export interface SystemInfo {
  version: string;
  database_type: string;
  rules_loaded: number;
}

export interface ReleaseInfo {
  product: string;
  version: string;
  status: 'preview' | 'stable';
  released_at: string;
  platform: string;
  file: string;
  size_bytes: number;
  sha256: string;
  notes: string[];
  download_url: string;
}

export interface PublicInfo {
  app_version: string;
  release: ReleaseInfo | null;
}
