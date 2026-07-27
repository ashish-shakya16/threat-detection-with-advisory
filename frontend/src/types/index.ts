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
  status: 'active' | 'resolved' | 'ignored' | 'escalated';
  advisory?: Advisory | null;
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
