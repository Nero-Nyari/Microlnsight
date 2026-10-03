import { create } from 'zustand';
import type { Alert, Incident, AgentRun, EvidenceItem, ResponseAction, Report } from '../types';
import { sourceScopeFor, type SourceScope } from '../services/logSource';

interface AppState {
  sourceScope: SourceScope;
  setSourceScope: (scope: SourceScope) => void;
  queueTab: 'logs' | 'alerts';
  setQueueTab: (tab: 'logs' | 'alerts') => void;
  alerts: Alert[];
  incidents: Incident[];
  selectedIncidentId: number | null;
  selectedIncident: Incident | null;
  agentRuns: AgentRun[];
  evidence: EvidenceItem[];
  actions: ResponseAction[];
  report: Report | null;
  loading: boolean;
  refreshAlerts: () => Promise<void>;
  refreshIncidents: () => Promise<void>;
  selectIncident: (id: number) => Promise<void>;
  runAnalysis: (incidentId: number) => Promise<void>;
  refreshIncidentDetail: () => Promise<void>;
}

import { api } from '../services/api';

export const useAppStore = create<AppState>((set, get) => ({
  sourceScope: 'actual',
  setSourceScope: (sourceScope) => {
    if (sourceScope === get().sourceScope) return;
    set({ sourceScope, queueTab: 'logs', selectedIncidentId: null, selectedIncident: null,
      agentRuns: [], evidence: [], actions: [], report: null, loading: false });
  },
  queueTab: 'logs',
  setQueueTab: (queueTab) => set({ queueTab }),
  alerts: [],
  incidents: [],
  selectedIncidentId: null,
  selectedIncident: null,
  agentRuns: [],
  evidence: [],
  actions: [],
  report: null,
  loading: false,

  refreshAlerts: async () => {
    const alerts = await api.alerts.list();
    set({ alerts });
  },

  refreshIncidents: async () => {
    const incidents = await api.incidents.list();
    set({ incidents });
  },

  selectIncident: async (id: number) => {
    set({ selectedIncidentId: id, loading: true });
    try {
      const incident = await api.incidents.get(id);
      if (get().selectedIncidentId !== id) return;
      set({
        sourceScope: incident.source_record?.is_demo ? 'demo' : sourceScopeFor(incident.alert),
        queueTab: incident.queue || 'logs',
        selectedIncident: incident,
        agentRuns: incident.agent_runs || [],
        evidence: incident.evidence_items || [],
        actions: incident.response_actions || [],
        report: [...(incident.reports || [])].sort((a, b) => b.id - a.id)[0] || null,
      });
    } finally {
      set({ loading: false });
    }
  },

  runAnalysis: async (incidentId: number) => {
    set(state => ({ loading: true,
      incidents: state.incidents.map(item => item.id === incidentId ? {...item, status: 'analyzing', queue: 'logs'} : item),
      ...(state.selectedIncident?.id === incidentId ? {
        queueTab: 'logs', agentRuns: [], actions: [], evidence: [], report: null,
        selectedIncident: {...state.selectedIncident, status: 'analyzing', queue: 'logs',
          summary: undefined, attack_stage: undefined, risk_level: undefined, confidence: 0, agent_runs: [], correlation: null,
          assessment: {classification: 'unknown', label: '分析中', queue: 'logs', findings: [], missing_evidence: []}},
      } : {}),
    }));
    try {
      await api.incidents.analyze(incidentId);
      if (get().selectedIncidentId === incidentId) await get().selectIncident(incidentId);
      await get().refreshIncidents();
    } catch (error) {
      if (get().selectedIncidentId === incidentId) await get().selectIncident(incidentId);
      await get().refreshIncidents();
      throw error;
    } finally {
      set({ loading: false });
    }
  },

  refreshIncidentDetail: async () => {
    const id = get().selectedIncidentId;
    if (id) await get().selectIncident(id);
  },
}));
