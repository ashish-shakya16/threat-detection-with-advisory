import type {
  ApiResponse,
  Threat,
  ThreatStatistics,
  SystemMetrics,
  TimelinePoint,
  DailyTimelinePoint,
  User,
  NotificationStatus,
  MLStatus,
  SystemInfo,
} from '@/types';

const BASE_URL = '';

class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message);
    this.name = 'ApiError';
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

  const json: ApiResponse<T> = await response.json();

  if (!json.success) {
    throw new ApiError(json.error || 'Request failed', response.status);
  }

  return json.data as T;
}

export const api = {
  auth: {
    login: (username: string, password: string) =>
      request<User>('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
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
    removeRecipient: (email: string) => request<void>(`/api/notifications/recipients/${encodeURIComponent(email)}`, {
      method: 'DELETE',
    }),
    sendTest: () => request<void>('/api/notifications/test', { method: 'POST' }),
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
