import { FileText, Loader2, Zap } from 'lucide-react';
import { useState } from 'react';
import { useAppStore } from '../stores/appStore';
import { statusLabels, riskLabels } from '../services/assessment';
import { api } from '../services/api';
import EvidenceTimeline from './EvidenceTimeline';

export default function AlertDetail({ onAnalyze }: { onAnalyze: (id: number) => Promise<void> }) {
  const [analysisError, setAnalysisError] = useState('');
  const [correlating, setCorrelating] = useState(false);
  const [windowMinutes, setWindowMinutes] = useState(15);
  const { selectedIncident: incident, loading } = useAppStore();
  if (!incident) return <div className="flex-1 flex items-center justify-center text-slate-400 text-sm gap-2"><FileText size={20}/>请从左侧选择日志或告警</div>;
  const alert = incident.alert;
  const assessment = incident.assessment;
  const correlation = incident.correlation;
  const records = correlation?.records || (incident.source_record ? [incident.source_record] : []);
  const pending = ['pending', 'analyzing', 'failed', 'interrupted'].includes(incident.status);
  const analyzedRisk = pending ? '待分析' : assessment?.classification === 'unknown' ? '待定' : assessment?.classification === 'benign' ? '未见明确异常' : riskLabels[incident.risk_level || ''] || '待定';
  const recommendations = correlation?.recommendations || (assessment?.classification === 'benign'
    ? ['保留日志并核对操作授权；当前不建议封禁、隔离或删除。']
    : ['核对下方证据与缺失项，确认操作账户和执行结果；证据不足时不执行系统处置。']);
  const disabled = loading || correlating || incident.status === 'analyzing';
  const correlate = async () => {
    const id = incident.id;
    setCorrelating(true); setAnalysisError('');
    try {
      await api.incidents.correlate(id, windowMinutes);
      const store = useAppStore.getState();
      await Promise.all([store.refreshIncidents(), store.refreshAlerts()]);
      if (useAppStore.getState().selectedIncidentId === id) await store.selectIncident(id);
    } catch (e) { setAnalysisError(e instanceof Error ? e.message : '联合分析失败'); }
    finally { setCorrelating(false); }
  };
  return <div className="flex-1 overflow-auto p-4 space-y-4">
    <header className="flex flex-wrap gap-3 items-start justify-between">
      <div><h2 className="font-bold text-base text-slate-800">{alert?.title || '未命名记录'}</h2><p className="text-xs text-slate-500 mt-1">事件 #{incident.id} · 日志 #{incident.alert_id} · {statusLabels[incident.status] || '待核实'}</p></div>
      <span className={`text-xs rounded px-2 py-1 ${incident.queue === 'alerts' ? 'bg-amber-100 text-amber-900' : 'bg-slate-100 text-slate-700'}`}>{assessment?.label || '待分析'}</span>
    </header>
    <section className="grid lg:grid-cols-3 gap-3 text-xs" aria-label="分析摘要">
      <div className="border rounded p-3 bg-slate-50"><h3 className="font-semibold mb-2">发现了什么</h3><p className="leading-6">{pending ? '当前记录尚无本轮有效结论。' : incident.summary || '证据不足，待核实。'}</p><p className="text-slate-500 mt-2">{incident.queue === 'alerts' ? '异常线索待复核，未确认入侵成功。' : '当前属于日志记录，不代表已发生安全事件。'}</p></div>
      <div className="border rounded p-3 bg-slate-50"><h3 className="font-semibold mb-2">依据是什么</h3><p className="leading-6">{correlation ? `${records.length} 条去重记录，${correlation.findings.length} 项规则线索；统计和原文见下方。` : `${assessment?.findings.length || 0} 项原文引用；当前仅分析单条输入，可运行本地联合分析补充上下文。`}</p><p className="text-slate-500 mt-2">未导入的记录和未读通道不在结论范围内。</p></div>
      <div className="border rounded p-3 bg-slate-50"><h3 className="font-semibold mb-2">建议做什么</h3><ul className="list-disc pl-4 space-y-1 leading-6">{recommendations.map(r => <li key={r}>{r}</li>)}</ul></div>
    </section>
    <div className="grid sm:grid-cols-3 gap-3 text-xs">
      <div className="border rounded p-3"><p className="text-slate-500">原始告警等级（导入字段）</p><strong>{riskLabels[alert?.severity || ''] || '未提供'}</strong><p className="text-slate-400 mt-1">不代表当前已形成告警；不是 Windows 事件 Level。</p></div>
      <div className="border rounded p-3"><p className="text-slate-500">分析后风险</p><strong>{analyzedRisk}</strong></div>
      <div className="border rounded p-3"><p className="text-slate-500">分析方式</p><strong>{correlation ? '本地联合规则（无模型置信度）' : pending ? '尚未完成' : '单条日志研判'}</strong>{!correlation && !!incident.confidence && <p>模型置信度：{Math.round(incident.confidence * 100)}%（不等于真实概率）</p>}</div>
    </div>
    <section className="border rounded p-3 space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-2">
        <label>时间窗口 <select aria-label="联合分析时间窗口" className="border rounded px-2 py-1" value={windowMinutes} disabled={disabled} onChange={e => setWindowMinutes(Number(e.target.value))}>{[5,15,30,60].map(n=><option key={n} value={n}>前后各 {n} 分钟</option>)}</select></label>
        <button disabled={disabled} onClick={correlate} className="bg-primary-600 text-white rounded px-3 py-2 disabled:opacity-50 flex gap-1 items-center">{correlating && <Loader2 size={12} className="animate-spin"/>}运行本地联合分析</button>
        <button disabled={disabled} onClick={async () => {setAnalysisError(''); try {await onAnalyze(incident.id);} catch(e) {setAnalysisError(e instanceof Error ? e.message : '分析失败');}}} className="border rounded px-3 py-2 disabled:opacity-50 flex gap-1 items-center"><Zap size={12}/>单条模型分析</button>
      </div>
      <p className="text-slate-500">联合分析只使用已导入的同主机日志，不调用外部模型。账户、来源 IP 分组统计；演示数据与真实记录分开。保存后更新当前事件的结论，其他事件保持原状。</p>
      <p className="text-slate-500">单条模型分析会使用当前配置的模型服务；两种分析均保留历史结果，页面展示最近一轮。</p>
    </section>
    {analysisError && <p role="alert" className="text-sm text-red-600">{analysisError}</p>}
    {incident.status === 'interrupted' && <p className="text-xs text-amber-800">上次分析中断，原始记录已保留，可重新分析。</p>}
    {!correlation && !!assessment?.findings.length && <section className="text-xs space-y-2"><h3 className="font-semibold">单条判断的原文依据</h3>{assessment.findings.map((f,i)=><div className="border-l-2 border-amber-300 pl-2" key={i}><p>{f.reason}</p><p className="text-slate-500">来源：日志 #{incident.alert_id}</p><pre className="whitespace-pre-wrap break-words mt-1">{f.quote}</pre></div>)}</section>}
    {!!assessment?.missing_evidence.length && <section className="text-xs border rounded p-3"><h3 className="font-semibold mb-2">待补充或核对</h3><ul className="list-disc pl-4 space-y-1">{assessment.missing_evidence.map(m=><li key={m}>{m}</li>)}</ul></section>}
    <EvidenceTimeline records={records} result={correlation}/>
    {!records.length && <details className="text-xs"><summary>原始日志</summary><pre className="whitespace-pre-wrap break-all">{alert?.raw_content || '无内容'}</pre></details>}
  </div>;
}
