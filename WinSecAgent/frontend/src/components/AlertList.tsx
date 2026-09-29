import { useState, useEffect } from 'react';
import { Bell, Play, FileText } from 'lucide-react';
import { useAppStore } from '../stores/appStore';
import { api } from '../services/api';
import { statusLabels, riskLabels } from '../services/assessment';

export default function AlertList() {
  const { alerts, incidents, selectedIncidentId, selectIncident, refreshAlerts, refreshIncidents, queueTab, setQueueTab } = useAppStore();
  const [filter, setFilter] = useState('');
  const [logStatus, setLogStatus] = useState('all');
  const [cases, setCases] = useState<{id: string; title: string; severity: string}[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.alerts.cases().then(setCases).catch(e => setError(e.message)); }, []);
  const rows = alerts.map(alert => ({alert, incident: incidents.find(i => i.alert_id === alert.id)}));
  const inQueue = (row: typeof rows[number], queue: string) => (row.incident?.queue || 'logs') === queue;
  const filtered = rows.filter(row => inQueue(row, queueTab) && row.alert.title.toLowerCase().includes(filter.toLowerCase()) &&
    (queueTab !== 'logs' || logStatus === 'all' || (row.incident?.status || 'pending') === logStatus));
  const loadCase = async (caseId: string) => {
    setBusy(true); setError(''); setLogStatus('all'); setFilter('');
    try {
      const alert = await api.alerts.fromCase(caseId);
      const incident = await api.incidents.create({alert_id: alert.id, status: 'pending'});
      await Promise.all([refreshAlerts(), refreshIncidents()]);
      await selectIncident(incident.id);
    } catch(e) { setError(e instanceof Error ? e.message : '案例加载失败'); }
    finally {setBusy(false);}
  };
  const openRow = async (row: typeof rows[number]) => {
    setError('');
    try {
      const incident = row.incident || await api.incidents.create({alert_id: row.alert.id, status: 'pending'});
      if (!row.incident) await refreshIncidents();
      await selectIncident(incident.id);
    } catch(e) {setError(e instanceof Error ? e.message : '加载失败');}
  };
  return <div className="flex flex-col h-full min-h-0">
    <details className="px-3 py-2 border-b border-slate-200">
      <summary className="text-xs font-semibold text-slate-600 cursor-pointer">Windows 演示案例</summary>
      <p className="text-[11px] text-amber-700 my-2">模拟输入，分析后按结论分类，不代表本机发生事件。</p>
      {cases.map(c => <button key={c.id} disabled={busy} onClick={()=>loadCase(c.id)} className="w-full flex gap-2 text-left px-2 py-1.5 text-xs rounded hover:bg-slate-100"><Play size={12}/>{c.title}</button>)}
    </details>
    <div className="p-3 border-b space-y-2">
      <div role="tablist" aria-label="日志与告警" className="flex gap-1">
        {(['logs','alerts'] as const).map(queue => <button key={queue} role="tab" aria-selected={queueTab === queue} onClick={()=>setQueueTab(queue)} className={`flex-1 rounded py-2 text-xs font-semibold ${queueTab === queue ? 'bg-primary-100 text-primary-700':'bg-slate-50 text-slate-500'}`}>{queue === 'logs' ? '日志列表' : '告警列表'} ({rows.filter(row=>inQueue(row,queue)).length})</button>)}
      </div>
      <p className="text-[11px] text-slate-500">{queueTab === 'logs' ? '导入记录先在这里分析；正常和待核实记录留在日志列表。' : '仅显示分析发现异常线索且有原文证据的记录，仍需人工复核。'}</p>
      <input aria-label="筛选记录" value={filter} onChange={e=>setFilter(e.target.value)} placeholder="按标题筛选记录" className="w-full text-xs border rounded px-2 py-1"/>
      {queueTab === 'logs' && <select aria-label="日志状态" value={logStatus} onChange={e=>setLogStatus(e.target.value)} className="w-full text-xs border rounded p-1"><option value="all">全部日志</option>{['pending','analyzing','benign','needs_review','failed','interrupted'].map(status=><option key={status} value={status}>{statusLabels[status]}</option>)}</select>}
      {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
    </div>
    <div className="flex-1 overflow-auto">
      {!filtered.length && <p role="status" className="text-xs text-slate-400 text-center p-4">{queueTab === 'logs' ? '没有符合条件的日志' : rows.some(row => inQueue(row, 'alerts')) ? '没有符合筛选条件的告警，请调整筛选条件。' : '当前没有已形成的告警'}</p>}
      {filtered.map(row => <button key={row.alert.id} onClick={()=>openRow(row)} className={`w-full text-left px-3 py-3 border-b hover:bg-slate-50 ${row.incident?.id === selectedIncidentId ? 'bg-primary-50':''}`}>
        <div className="flex items-start gap-2 text-xs font-medium">{queueTab === 'alerts' ? <Bell size={14} className="shrink-0 text-amber-600"/> : <FileText size={14} className="shrink-0 text-slate-400"/>}<span className="min-w-0 break-words">{row.alert.title}</span></div>
        <div className="flex flex-wrap gap-1 text-[10px] text-slate-500 mt-1"><span>{statusLabels[row.incident?.status || 'pending'] || '待核实'}</span><span>·</span><span>{row.alert.source_type.includes('demo') ? '演示数据' : row.alert.source_type === 'windows_log' ? '本机日志' : '导入日志'}</span>{row.incident && <span>· 事件 #{row.incident.id}</span>}</div>
        {queueTab === 'alerts' && <p className="text-[10px] text-amber-700 mt-1">分析风险：{riskLabels[row.incident?.risk_level || ''] || '待定'} · 待复核</p>}
      </button>)}
    </div>
  </div>;
}
