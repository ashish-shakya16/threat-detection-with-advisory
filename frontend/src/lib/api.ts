import type {
  ApiResponse,
  Threat,
  ThreatStatistics,
  SystemMetrics,
  TimelinePoint,
  DailyTimelinePoint,
  User,
  AssistantResponse,
  AssistantHistoryEntry,
  NotificationDelivery,
  ResponseAction,
  AuditEntry,
  AuditVerification,
  PublicInfo,
  PhishingResult,
  DetectionStatus,
  NotificationStatus,
  MLStatus,
  SystemInfo,
} from '@/types';

const BASE_URL = '';

class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

/**
 * Parse an API response body. A non-JSON body (usually the SPA's index.html)
 * means the route does not exist on this server, which in practice means the
 * running backend is older than the frontend.
 */
async function parseJson(response: Response) {
  try {
    return await response.json();
  } catch {
    throw new ApiError(
      `The SecureX server returned an unexpected response (HTTP ${response.status}). ` +
        'It may be running an older version; restart SecureX and try again.',
      response.status,
    );
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  });

  if (response.status === 401) {
    throw new ApiError('Authentication required', 401);
  }

  const json: ApiResponse<T> = await parseJson(response);

  if (!json.success) {
    throw new ApiError(json.error || 'Request failed', response.status);
  }

  // Older backend builds returned some payloads at the top level. Accepting
  // that shape keeps the client from crashing while a packaged app is updated.
  return (json.data ?? json) as T;
}

/** Like request(), but also returns top-level fields sent next to `data`. */
async function requestWithMeta<T, M>(path: string, options: RequestInit = {}): Promise<{ data: T } & M> {
  const response = await fetch(`${BASE_URL}${path}`, {
    ...options,
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...options.headers },
  });
  if (response.status === 401) {
    throw new ApiError('Authentication required', 401);
  }
  const json = await parseJson(response);
  if (!json.success) {
    throw new ApiError(json.error || 'Request failed', response.status);
  }
  return json;
}

export const api = {
  auth: {
    login: (username: string, password: string) =>
      request<User>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
      }),
    signup: (username: string, email: string, password: string) =>
      request<User>('/api/auth/signup', {
        method: 'POST',
        body: JSON.stringify({ username, email, password }),
      }),
    logout: () => request<void>('/api/auth/logout', { method: 'POST' }),
    me: () => request<User>('/api/auth/me'),
  },
  stats: {
    get: () => request<ThreatStatistics>('/api/stats'),
  },
  threats: {
    list: (params: { limit?: number; hours?: number } = {}) => {
      const query = new URLSearchParams();
      if (params.limit) query.set('limit', String(params.limit));
      if (params.hours) query.set('hours', String(params.hours));
      return request<Threat[]>(`/api/threats?${query.toString()}`);
    },
    get: (id: number) => request<Threat>(`/api/threat/${id}`),
    updateStatus: (id: number, status: string) =>
      request<void>(`/api/threats/${id}/status`, {
        method: 'PUT',
        body: JSON.stringify({ status }),
      }),
  },
  systemMetrics: {
    get: () => request<SystemMetrics>('/api/system-metrics'),
  },
  timeline: {
    hourly: (hours: number) => request<TimelinePoint[]>(`/api/threat-timeline?hours=${hours}`),
    daily: (days: number) => request<DailyTimelinePoint[]>(`/api/analytics/timeline?days=${days}`),
  },
  scan: {
    start: () => request<{ threats: unknown[]; message: string }>('/api/scan/start', { method: 'POST' }),
  },
  monitoring: {
    status: () => request<{ active: boolean }>('/api/monitoring/status'),
    start: () => request<void>('/api/monitoring/start', { method: 'POST' }),
    stop: () => request<void>('/api/monitoring/stop', { method: 'POST' }),
  },
  notifications: {
    status: () => request<NotificationStatus>('/api/notifications/status'),
    addRecipient: (email: string) => request<void>('/api/notifications/recipients', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
    requestRecipientVerification: (email: string) => request<void>('/api/notifications/recipients/verify/request', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }),
    removeRecipient: (email: string) => request<void>(`/api/notifications/recipients/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }),
    sendTest: () => request<{ success: boolean; error: string; results: Record<string, boolean> }>(
      '/api/notifications/test',
      { method: 'POST' },
    ),
    deliveries: () => request<NotificationDelivery[]>('/api/notifications/deliveries'),
    updatePreferences: (preferences: {
      enabled?: boolean;
      critical?: boolean;
      high?: boolean;
      medium?: boolean;
      low?: boolean;
      cooldown_seconds?: number;
    }) => request<void>('/api/notifications/preferences', {
      method: 'PATCH',
      body: JSON.stringify(preferences),
    }),
  },
  assistant: {
    chat: (message: string) => request<AssistantResponse>('/api/assistant/chat', {
      method: 'POST',
      body: JSON.stringify({ message }),
    }),
    history: () => request<AssistantHistoryEntry[]>('/api/assistant/history'),
    clearHistory: () => request<{ deleted: number }>('/api/assistant/history', { method: 'DELETE' }),
    explainThreat: (threatId: number) => request<AssistantResponse>(`/api/assistant/explain/${threatId}`),
  },
  detection: {
    status: () => request<DetectionStatus>('/api/detection/status'),
    resetBaseline: () => request<DetectionStatus['anomaly_baseline']>('/api/detection/baseline/reset', { method: 'POST' }),
    analyzeUrl: (url: string) => request<PhishingResult>('/api/phishing/analyze', {
      method: 'POST',
      body: JSON.stringify({ url }),
    }),
  },
  public: {
    info: () => request<PublicInfo>('/api/public/info'),
  },
  responses: {
    list: (params: { threatId?: number; status?: string } = {}) => {
      const query = new URLSearchParams();
      if (params.threatId !== undefined) query.set('threat_id', String(params.threatId));
      if (params.status) query.set('status', params.status);
      return requestWithMeta<ResponseAction[], { execution_enabled: boolean }>(`/api/responses?${query}`);
    },
    approve: (id: number) => request<ResponseAction>(`/api/responses/${id}/approve`, { method: 'POST' }),
    reject: (id: number) => request<ResponseAction>(`/api/responses/${id}/reject`, { method: 'POST' }),
    resume: (id: number) => request<ResponseAction>(`/api/responses/${id}/resume`, { method: 'POST' }),
  },
  audit: {
    list: (params: { limit?: number; offset?: number; action?: string } = {}) => {
      const query = new URLSearchParams();
      if (params.limit) query.set('limit', String(params.limit));
      if (params.offset) query.set('offset', String(params.offset));
      if (params.action) query.set('action', params.action);
      return request<{ entries: AuditEntry[]; total: number }>(`/api/audit?${query}`);
    },
    verify: () => request<AuditVerification>('/api/audit/verify'),
  },
  ml: {
    status: () => request<MLStatus>('/api/ml/status'),
    train: () => request<{ samples_used: number }>('/api/ml/train', { method: 'POST' }),
  },
  system: {
    info: () => request<SystemInfo>('/api/system-info'),
  },
};

export { ApiError };
