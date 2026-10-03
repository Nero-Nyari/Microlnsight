import { ArrowRight, Loader2, Zap } from 'lucide-react';
import { useState } from 'react';
import { useAppStore } from '../stores/appStore';
import { statusLabels, riskLabels } from '../services/assessment';
import { api } from '../services/api';

export default function AlertDetail({ onAnalyze, onShowEvidence }: { onAnalyze: (id: number) => Promise<void>; onShowEvidence: () => void }) {
  const [analysisError, setAnalysisError] = useState('');
  const [correlating, setCorrelating] = useState(false);
  const [windowMinutes, setWindowMinutes] = useState(15);
  const { selectedIncident: incident, loading } = useAppStore();
  if (!incident) return null;
  const alert = incident.alert;
  const assessment = incident.assessment;
  const correlation = incident.correlation;
  const records = correlation?.records || (incident.source_record ? [incident.source_record] : []);
  const pending = ['pending', 'analyzing', 'failed', 'interrupted'].includes(incident.status);
  const analyzedRisk = pending ? '待分析' : assessment?.classification === 'unknown' ? '待定' : assessment?.classification === 'benign' ? '未见明确异常' : riskLabels[incident.risk_level || ''] || '待定';
  const recommendations = correlation?.recommendations || (assessment?.classification === 'benign'
    ? ['保留日志并核对操作授权；当前不建议封禁、隔离或删除。']
    : ['核对证据与缺失项，确认操作账户和执行结果。']);
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
  return <div className="space-y-5">
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0"><p className="mb-2 text-xs text-slate-500">事件 #{incident.id} · {statusLabels[incident.status] || '待核实'}</p><h2 className="break-words text-xl font-semibold leading-8 text-slate-900">{alert?.title || '未命名记录'}</h2></div>
      <span className={`rounded-full px-3 py-1 text-xs ${incident.queue === 'alerts' ? 'bg-amber-100 text-amber-900' : 'bg-slate-200/70 text-slate-600'}`}>{assessment?.label || '待分析'}</span>
    </header>
    <section aria-label="运行分析" className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <label className="text-xs text-slate-500">关联时间窗口<select aria-label="联合分析时间窗口" className="mt-1 block rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700" value={windowMinutes} disabled={disabled} onChange={e => setWindowMinutes(Number(e.target.value))}>{[5,15,30,60].map(n => <option key={n} value={n}>前后各 {n} 分钟</option>)}</select></label>
        <button disabled={disabled} onClick={correlate} className="flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50">{correlating && <Loader2 size={16} className="animate-spin"/>}{correlating ? '正在分析…' : '运行本地联合分析'}</button>
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-500">使用已导入的同主机日志，无需模型。分析后更新当前事件，其他记录保持原状。</p>
      <details className="mt-3 border-t border-slate-100 pt-3 text-xs">
        <summary className="cursor-pointer text-slate-500">使用模型分析单条日志</summary>
        <p className="my-3 leading-5 text-slate-500">输入会发送至当前配置的模型服务。两种分析保留历史结果，页面展示最近一轮。</p>
        <button disabled={disabled} onClick={async () => {setAnalysisError(''); try {await onAnalyze(incident.id);} catch(e) {setAnalysisError(e instanceof Error ? e.message : '分析失败');}}} className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2 text-slate-700 hover:bg-slate-50 disabled:opacity-50"><Zap size={14}/>单条模型分析</button>
      </details>
    </section>
    {analysisError && <p role="alert" className="rounded-lg bg-red-50 p-3 text-sm text-red-600">{analysisError}</p>}
    {incident.status === 'interrupted' && <p className="text-sm text-amber-800">上次分析中断，原始记录已保留，可重新分析。</p>}
    <section aria-label="分析摘要" className="rounded-xl border border-slate-200 bg-white p-5">
      <div className="flex items-center justify-between gap-3"><h3 className="text-sm font-semibold text-slate-800">发现了什么</h3><span className="text-xs text-slate-500">分析风险：{analyzedRisk}</span></div>
      <p className="mt-3 text-sm leading-7 text-slate-700">{pending ? '选择时间窗口并运行分析，结果会显示在这里。' : incident.summary || '证据不足，待核实。'}</p>
      {!pending && <p className="mt-2 text-xs leading-5 text-slate-500">{incident.queue === 'alerts' ? '异常线索待复核，未确认入侵成功。' : '当前结论仅限本次输入，不代表整机安全。'}</p>}
      <button onClick={onShowEvidence} className="mt-4 flex items-center gap-2 text-sm font-medium text-primary-700 hover:underline">{correlation ? `查看 ${records.length} 条证据与原文` : '查看日志原文'}<ArrowRight size={14}/></button>
      {correlation && <p className="mt-1 text-xs text-slate-500">去重后 {records.length} 条记录 · {correlation.findings.length} 项规则线索</p>}
    </section>
    {!pending && <section className="rounded-xl border border-slate-200 bg-white p-5">
      <h3 className="text-sm font-semibold text-slate-800">下一步核查</h3><ul className="mt-3 list-disc space-y-2 pl-4 text-sm leading-6 text-slate-600">{recommendations.map(r => <li key={r}>{r}</li>)}</ul>
      {!!assessment?.missing_evidence.length && <details className="mt-4 border-t border-slate-100 pt-3"><summary className="cursor-pointer text-xs text-slate-500">待补充或核对（{assessment.missing_evidence.length} 项）</summary><ul className="mt-3 list-disc space-y-2 pl-4 text-xs leading-6 text-slate-600">{assessment.missing_evidence.map(m => <li key={m}>{m}</li>)}</ul></details>}
    </section>}
    <details className="px-1 text-xs text-slate-500"><summary className="cursor-pointer">记录信息与分析范围</summary><dl className="mt-3 grid gap-3 leading-6 sm:grid-cols-2"><div><dt>原始等级（导入字段）</dt><dd>{riskLabels[alert?.severity || ''] || '未提供'}；不代表已形成告警，也不是 Windows 事件 Level。</dd></div><div><dt>分析方式</dt><dd>{correlation ? '本地联合规则' : pending ? '尚未完成' : '单条日志研判'}{!correlation && !!incident.confidence && ` · 模型置信度 ${Math.round(incident.confidence * 100)}%（非真实概率）`}</dd></div></dl><p className="mt-2 leading-6">仅覆盖已导入记录。未读通道不在结论范围内；演示与真实日志分开，账户和来源 IP 分组统计。</p></details>
  </div>;
}
