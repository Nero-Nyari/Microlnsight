import type { Alert, Incident, AgentRun, EvidenceItem, ResponseAction, Report, LogReadResult, KnowledgeEntry, SchedulerStatus, SystemInfo } from '../types';

const API_BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const detail = Array.isArray(err.detail) ? err.detail.map((item: {msg?: string}) => item.msg || '字段无效').join('；') : err.detail;
    throw new Error(detail || err.error || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<{ ok: boolean }>('/health'),

  alerts: {
    cases: () => request<{ id: string; title: string; severity: string; record_count: number; hint: string }[]>('/alerts/cases'),
    list: () => request<Alert[]>('/alerts'),
    create: (data: Partial<Alert> & { windows_context?: { event_id?: number; channel?: string; computer?: string } }) => request<Alert>('/alerts', { method: 'POST', body: JSON.stringify(data) }),
    delete: (id: number) => request<any>(`/alerts/${id}`, { method: 'DELETE' }),
    fromCase: (caseId: string) => request<Alert>(`/alerts/from-case/${caseId}`, { method: 'POST' }),
  },

  incidents: {
    list: () => request<Incident[]>('/incidents'),
    get: (id: number) => request<Incident>(`/incidents/${id}`),
    create: (data: Partial<Incident>) => request<Incident>('/incidents', { method: 'POST', body: JSON.stringify(data) }),
    analyze: (id: number) => request<any>(`/incidents/${id}/analyze`, { method: 'POST' }),
    correlate: (id: number, windowMinutes: number) => request<{ok: boolean}>(`/incidents/${id}/correlate`, {method: 'POST', body: JSON.stringify({window_minutes: windowMinutes})}),
  },

  agents: {
    list: (incidentId: number) => request<AgentRun[]>(`/incidents/${incidentId}/agents`),
  },

  evidence: {
    list: (incidentId: number) => request<EvidenceItem[]>(`/incidents/${incidentId}/evidence`),
  },

  actions: {
    list: (incidentId: number) => request<ResponseAction[]>(`/incidents/${incidentId}/actions`),
    approve: (incidentId: number, actionId: number, approvedBy: string) =>
      request<any>(`/incidents/${incidentId}/actions/${actionId}/approve`, { method: 'POST', body: JSON.stringify({ approved_by: approvedBy }) }),
    reject: (incidentId: number, actionId: number, approvedBy: string) =>
      request<any>(`/incidents/${incidentId}/actions/${actionId}/reject`, { method: 'POST', body: JSON.stringify({ approved_by: approvedBy }) }),
    simulate: (incidentId: number, actionId: number) =>
      request<any>(`/incidents/${incidentId}/actions/${actionId}/simulate`, { method: 'POST' }),
    execute: (incidentId: number, actionId: number) =>
      request<any>(`/incidents/${incidentId}/actions/${actionId}/execute`, { method: 'POST' }),
    executeDirect: (actionType: string, description: string, params?: Record<string, any>) =>
      request<any>('/incidents/actions/execute-direct', { method: 'POST', body: JSON.stringify({ action_type: actionType, description, params }) }),
    executorStatus: () => request<{ dry_run: boolean; is_windows: boolean; quarantine_dir: string }>('/incidents/actions/executor-status'),
    setDryRun: (dryRun: boolean) => request<any>(`/incidents/actions/set-dry-run?dry_run=${dryRun}`, { method: 'POST' }),
  },

  reports: {
    get: (incidentId: number) => request<Report>(`/incidents/${incidentId}/report`),
    generate: (incidentId: number) => request<Report>(`/incidents/${incidentId}/report`, { method: 'POST' }),
  },

  // WinSecAgent new endpoints
  logs: {
    read: (channels?: string[], suspiciousOnly = true, maxEvents = 200) =>
      request<LogReadResult>('/logs/read', { method: 'POST', body: JSON.stringify({ channels, suspicious_only: suspiciousOnly, max_events: maxEvents }) }),
    import: (channels?: string[], suspiciousOnly = true) =>
      request<any>('/logs/import', { method: 'POST', body: JSON.stringify({ channels, suspicious_only: suspiciousOnly }) }),
    importAndAnalyze: (channels?: string[], suspiciousOnly = true) =>
      request<any>('/logs/import-and-analyze', { method: 'POST', body: JSON.stringify({ channels, suspicious_only: suspiciousOnly }) }),
  },

  knowledge: {
    search: (query: string, topK = 5) =>
      request<KnowledgeEntry[]>('/knowledge/search', { method: 'POST', body: JSON.stringify({ query, top_k: topK }) }),
    entries: () => request<KnowledgeEntry[]>('/knowledge/entries'),
    context: (eventId: number) => request<{ event_id: number; context: string }>(`/knowledge/context/${eventId}`),
  },

  memory: {
    stats: () => request<any>('/memory/stats'),
    recent: (count = 10) => request<{ entries: any[] }>(`/memory/recent?count=${count}`),
    search: (query: string, topK = 5) =>
      request<any>('/memory/search', { method: 'POST', body: JSON.stringify({ query, top_k: topK }) }),
    store: (eventData: any, analysisResult: any) =>
      request<any>('/memory/store', { method: 'POST', body: JSON.stringify({ event_data: eventData, analysis_result: analysisResult }) }),
    clearShort: () => request<any>('/memory/short-term', { method: 'DELETE' }),
    clearLong: () => request<any>('/memory/long-term', { method: 'DELETE' }),
  },

  scheduler: {
    status: () => request<SchedulerStatus>('/scheduler/status'),
    start: () => request<any>('/scheduler/start', { method: 'POST' }),
    stop: () => request<any>('/scheduler/stop', { method: 'POST' }),
    pause: () => request<any>('/scheduler/pause', { method: 'POST' }),
    resume: () => request<any>('/scheduler/resume', { method: 'POST' }),
    config: (scanInterval?: number, autoThreshold?: number) =>
      request<any>('/scheduler/config', { method: 'POST', body: JSON.stringify({ scan_interval: scanInterval, auto_threshold: autoThreshold }) }),
  },

  system: {
    all: () => request<SystemInfo>('/system/all'),
    processes: () => request<any>('/system/processes'),
    network: () => request<any>('/system/network'),
    services: () => request<any>('/system/services'),
    tasks: () => request<any>('/system/tasks'),
    registry: () => request<any>('/system/registry'),
  },

  models: {
    list: () => request<any[]>('/models'),
    create: (data: { name: string; provider: string; model: string; api_key: string; base_url?: string; is_active?: boolean }) =>
      request<any>('/models', { method: 'POST', body: JSON.stringify(data) }),
    delete: (id: string) => request<any>(`/models/${id}`, { method: 'DELETE' }),
    setActive: (id: string) => request<any>(`/models/${id}/activate`, { method: 'POST' }),
    getActive: () => request<any>('/models/active'),
    test: (id: string) => request<any>(`/models/${id}/test`, { method: 'POST' }),
    refresh: () => request<any>('/models/refresh', { method: 'POST' }),
  },
};
