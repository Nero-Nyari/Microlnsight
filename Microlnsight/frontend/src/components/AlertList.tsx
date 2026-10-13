import { useState, useEffect } from 'react';
import { Bell, Play, FileText } from 'lucide-react';
import { useAppStore } from '../stores/appStore';
import { api } from '../services/api';
import { statusLabels, riskLabels } from '../services/assessment';
import { sourceScopeFor, sourceLabelFor, type SourceScope } from '../services/logSource';

export default function AlertList({ showDemos, onToggleDemos, onSelect }: { showDemos: boolean; onToggleDemos: (open: boolean) => void; onSelect: () => void }) {
  const { alerts, incidents, selectedIncidentId, selectIncident, refreshAlerts, refreshIncidents, queueTab, setQueueTab, sourceScope, setSourceScope } = useAppStore();
  const [filter, setFilter] = useState('');
  const [logStatus, setLogStatus] = useState('all');
  const [cases, setCases] = useState<{id: string; title: string; severity: string; record_count: number; hint: string}[]>([]);
  const [caseHint, setCaseHint] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [caseId, setCaseId] = useState('windows_demo_normal');
  useEffect(() => { api.alerts.cases().then(setCases).catch(e => setError(e.message)); }, []);
  useEffect(() => { setFilter(''); setLogStatus('all'); setCaseHint(''); setError(''); }, [sourceScope]);
  const rows = alerts.map(alert => ({alert, incident: incidents.find(i => i.alert_id === alert.id)}));
  const scopedRows = rows.filter(row => sourceScopeFor(row.alert) === sourceScope);
  const inQueue = (row: typeof rows[number], queue: string) => (row.incident?.queue || 'logs') === queue;
  const filtered = scopedRows.filter(row => inQueue(row, queueTab) && row.alert.title.toLowerCase().includes(filter.toLowerCase()) &&
    (queueTab !== 'logs' || logStatus === 'all' || (row.incident?.status || 'pending') === logStatus));
  const loadCase = async (caseId: string) => {
    setBusy(true); setError(''); setCaseHint(''); setLogStatus('all'); setFilter('');
    try {
      const alert = await api.alerts.fromCase(caseId);
      const incident = await api.incidents.create({alert_id: alert.id, status: 'pending'});
      await Promise.all([refreshAlerts(), refreshIncidents()]);
      await selectIncident(incident.id);
      const demo = cases.find(c => c.id === caseId);
      if (demo) setCaseHint(`已导入 ${demo.record_count} 条演示日志。${demo.hint}`);
      onSelect();
    } catch(e) { setError(e instanceof Error ? e.message : '案例加载失败'); }
    finally {setBusy(false);}
  };
  const openRow = async (row: typeof rows[number]) => {
    setError(''); setCaseHint('');
    try {
      const incident = row.incident || await api.incidents.create({alert_id: row.alert.id, status: 'pending'});
      if (!row.incident) await refreshIncidents();
      await selectIncident(incident.id);
      onSelect();
    } catch(e) {setError(e instanceof Error ? e.message : '加载失败');}
  };
  const changeSource = (scope: SourceScope) => {
    setSourceScope(scope);
    onToggleDemos(scope === 'demo');
  };
  return <div className="flex flex-col h-full min-h-0">
    <div className="border-b border-slate-200 p-4 shrink-0">
      <div role="group" aria-label="记录来源" className="grid grid-cols-2 gap-1 rounded-xl bg-slate-100 p-1">
        {(['actual', 'demo'] as const).map(scope => <button key={scope} aria-pressed={sourceScope === scope} onClick={() => changeSource(scope)} className={`rounded-lg px-2 py-2 text-sm font-medium ${sourceScope === scope ? scope === 'demo' ? 'bg-amber-50 text-amber-900 shadow-sm' : 'bg-white text-primary-700 shadow-sm' : 'text-slate-500 hover:text-slate-800'}`}>{scope === 'actual' ? '实际日志' : '演示数据'}<span className="ml-1 text-xs tabular-nums">{rows.filter(row => sourceScopeFor(row.alert) === scope).length}</span></button>)}
      </div>
      <p className={`mt-2 text-xs leading-5 ${sourceScope === 'demo' ? 'text-amber-800' : 'text-slate-500'}`}>{sourceScope === 'demo' ? '仅显示合成演示记录，不代表本机发生的事件。' : '仅显示本机采集与未标记为演示的导入记录。'}</p>
    </div>
    {sourceScope === 'demo' && <>
    <div className="border-b border-slate-200 p-4 shrink-0">
      <button aria-expanded={showDemos} aria-controls="demo-picker" onClick={() => onToggleDemos(!showDemos)} className="flex w-full items-center justify-between text-sm font-medium text-slate-600"><span className="flex items-center gap-2"><Play size={14}/>Windows 演示案例</span><span className="text-xs text-slate-400">{showDemos ? '收起' : '展开'}</span></button>
      {showDemos && <div id="demo-picker" className="mt-3 space-y-3">
        <select aria-label="选择演示案例" value={caseId} onChange={e => setCaseId(e.target.value)} disabled={busy} className="w-full min-w-0 rounded-lg border border-slate-200 bg-white px-2 py-2 text-xs">{cases.map(c => <option key={c.id} value={c.id}>{c.title}</option>)}</select>
        <button disabled={busy || !cases.length} onClick={() => loadCase(caseId)} className="w-full rounded-lg bg-primary-50 py-2 text-xs font-medium text-primary-700 hover:bg-primary-100 disabled:opacity-50">{busy ? '正在载入…' : '载入案例'}</button>
        <p className="text-xs leading-5 text-slate-500">合成日志，无需模型。按 1 → 2 → 3 体验。</p>
      </div>}
    </div>
    </>}
    <div className="p-4 border-b space-y-3 shrink-0">
      <div role="tablist" aria-label="日志与告警" className="flex gap-1">
        {(['logs','alerts'] as const).map(queue => <button key={queue} role="tab" aria-selected={queueTab === queue} onClick={()=>setQueueTab(queue)} className={`flex-1 rounded py-2 text-xs font-semibold ${queueTab === queue ? 'bg-primary-100 text-primary-700':'bg-slate-50 text-slate-500'}`}>{queue === 'logs' ? '日志列表' : '告警列表'} ({scopedRows.filter(row=>inQueue(row,queue)).length})</button>)}
      </div>
      <input aria-label="筛选记录" value={filter} onChange={e=>setFilter(e.target.value)} placeholder="搜索日志标题" className="w-full text-sm border border-slate-200 rounded-lg px-3 py-2"/>
      {queueTab === 'logs' && <select aria-label="日志状态" value={logStatus} onChange={e=>setLogStatus(e.target.value)} className="w-full text-xs border rounded p-1"><option value="all">全部日志</option>{['pending','analyzing','benign','needs_review','failed','interrupted'].map(status=><option key={status} value={status}>{statusLabels[status]}</option>)}</select>}
      {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
      {caseHint && <div role="status" className="flex items-start gap-2 rounded-lg bg-primary-50 p-2 text-xs leading-5 text-primary-700"><p className="flex-1">{caseHint}</p><button aria-label="关闭案例提示" onClick={() => setCaseHint('')} className="px-1">×</button></div>}
    </div>
    <div className="flex-1 min-h-32 overflow-auto">
      {!filtered.length && <p role="status" className="text-xs text-slate-500 text-center p-4">{scopedRows.some(row => inQueue(row, queueTab)) ? '没有符合筛选条件的记录，请调整筛选。' : sourceScope === 'demo' ? queueTab === 'logs' ? '暂无演示日志，可在上方载入案例。' : '演示数据中尚未形成告警。' : queueTab === 'logs' ? '暂无实际日志，请从右上角导入日志。' : '实际日志中尚未形成告警。'}</p>}
      {filtered.map(row => <button key={row.alert.id} onClick={()=>openRow(row)} className={`w-full text-left px-3 py-3 border-b hover:bg-slate-50 ${row.incident?.id === selectedIncidentId ? 'bg-primary-50':''}`}>
        <span className={`mb-2 inline-flex rounded px-2 py-0.5 text-[11px] font-medium ${sourceScope === 'demo' ? 'bg-amber-100 text-amber-900' : 'bg-slate-100 text-slate-600'}`}>{sourceLabelFor(row.alert)}</span>
        <div className="flex items-start gap-2 text-xs font-medium">{queueTab === 'alerts' ? <Bell size={14} className="shrink-0 text-amber-600"/> : <FileText size={14} className="shrink-0 text-slate-400"/>}<span className="min-w-0 break-words">{row.alert.title}</span></div>
        <div className="flex flex-wrap gap-1 text-[10px] text-slate-500 mt-1"><span>{statusLabels[row.incident?.status || 'pending'] || '待核实'}</span>{row.incident && <span>· 事件 #{row.incident.id}</span>}</div>
        {queueTab === 'alerts' && <p className="text-[10px] text-amber-700 mt-1">分析风险：{riskLabels[row.incident?.risk_level || ''] || '待定'} · 待复核</p>}
      </button>)}
    </div>
  </div>;
}
