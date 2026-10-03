import { useRef, useState } from 'react';
import { Search, Download, Loader2, Monitor } from 'lucide-react';
import { api } from '../services/api';
import { useAppStore } from '../stores/appStore';
import type { LogReadResult } from '../types';

export default function LogReader({ onImported }: { onImported?: () => void }) {
  const [result, setResult] = useState<LogReadResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [importing, setImporting] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [filter, setFilter] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const created = useRef(new Map<string, {alertId: number; incidentId?: number}>());
  const read = async () => {
    setBusy(true); setError(''); setMessage(''); setResult(null); setSelected(new Set());
    try {
      setResult(await api.logs.read(undefined, false, 200));
      setSelected(new Set());
    } catch (e) { setError(e instanceof Error ? e.message : '读取失败'); }
    finally { setBusy(false); }
  };
  const importSelected = async () => {
    if (!result || !selected.size) return;
    setImporting(true); setError(''); setMessage('');
    let lastId: number | undefined;
    try {
      for (const index of selected) {
        const event = result.events[index];
        const key = `${event.Channel}:${event.RecordId}:${event.TimeCreated}`;
        let saved = created.current.get(key);
        if (!saved) {
          const alert = await api.alerts.create({ title: `Windows ${event.EventID} · ${event.Computer || event.Channel}`,
            raw_content: JSON.stringify({...event, Platform: 'Windows', IsDemo: result.is_mock}, null, 2),
            source_type: result.is_mock ? 'windows_demo' : 'windows_log', severity: 'medium', status: 'pending' });
          saved = {alertId: alert.id}; created.current.set(key, saved);
        }
        if (!saved.incidentId) saved.incidentId = (await api.incidents.create({alert_id: saved.alertId, status:'pending'})).id;
        lastId = saved.incidentId;
      }
      const store = useAppStore.getState();
      await Promise.all([store.refreshAlerts(), store.refreshIncidents()]);
      if (lastId) await store.selectIncident(lastId);
      setMessage(`已将 ${selected.size} 条选中日志加入日志列表，可在事件详情中开始分析。`);
      setSelected(new Set());
      onImported?.();
    } catch (e) { setError(e instanceof Error ? e.message : '导入失败'); }
    finally { setImporting(false); }
  };
  const deniedChannels = result?.channel_results?.filter(c => c.error_kind === 'access_denied') || [];
  const visibleEvents = result?.events.map((event, index) => ({event, index})).filter(({event}) =>
    !filter || `${event.EventID} ${event.Message}`.toLowerCase().includes(filter.toLowerCase())) || [];
  return <div className="flex flex-col h-full min-h-0">
    <div className="p-3 border-b space-y-2 max-h-[65%] overflow-auto shrink-0">
      <h3 className="flex items-center gap-2 text-sm font-semibold"><Monitor size={16}/>Windows 本机日志</h3>
      <p className="text-xs text-slate-500">读取服务所在电脑的日志，预览后选择需要分析的记录。</p>
      <div className="flex flex-wrap gap-2">
        <button onClick={read} disabled={busy || importing} className="flex items-center gap-1 text-xs bg-primary-600 text-white px-3 py-2 rounded disabled:opacity-50">{busy ? <Loader2 size={12} className="animate-spin"/> : <Search size={12}/>}读取日志</button>
        <button onClick={importSelected} disabled={busy || importing || !selected.size} className="flex items-center gap-1 text-xs bg-emerald-700 text-white px-3 py-2 rounded disabled:opacity-50"><Download size={12}/>{importing ? '正在导入' : `加入日志列表 (${selected.size})`}</button>
      </div>
      {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
      {message && <p role="status" className="text-xs text-emerald-700">{message}</p>}
      {result && <>
        <p className="text-xs text-slate-600">已读 {result.total_raw} 条 · 预览记录 {result.total_filtered} 条{result.is_mock && <strong className="text-amber-700"> · 演示数据</strong>}</p>
        {result.read_status === 'partial' && <p role="status" className="text-xs text-amber-800 bg-amber-50 p-2 rounded">部分通道读取成功，已读取的记录仍可预览和导入。未完整读取的通道见下方。</p>}
        {result.read_status === 'failed' && <p role="alert" className="text-xs text-red-700 bg-red-50 p-2 rounded">本次所有请求通道均未成功读取，请检查下方原因后重试。</p>}
        {!!result.channel_results?.length && <div className="space-y-1 text-xs" aria-label="通道读取状态">
          {result.channel_results.map(channel => <div key={channel.channel} className="break-words">
            <p className={channel.status === 'success' ? 'text-slate-600' : 'text-amber-800'}>
              {channel.channel} · {channel.status === 'success' ? `已读取 ${channel.events_read} 条` : `${channel.message} 已读取 ${channel.events_read} 条`}
            </p>
            {channel.detail && <details className="text-slate-500 ml-2"><summary className="cursor-pointer">错误详情{channel.error_code != null ? `（${channel.error_code}）` : ''}</summary><p className="whitespace-pre-wrap break-all">{channel.detail}</p></details>}
          </div>)}
        </div>}
        {!result.channel_results?.length && result.warnings?.map(w => <p key={w} role="alert" className="text-xs text-amber-800 bg-amber-50 p-2 rounded">{w}</p>)}
        {!!deniedChannels.length && <details className="text-xs bg-amber-50 text-amber-900 p-2 rounded">
          <summary className="cursor-pointer">如何处理日志读取权限不足</summary>
          <div className="space-y-2 mt-2 leading-5">
            <p className="break-all">后端运行账户：{result.reader_context?.account || '未能获取'}；进程权限：{result.reader_context?.elevated == null ? '未知' : result.reader_context.elevated ? '已提升' : '未提升'}。</p>
            <p>读取权限取决于后端服务的 Windows 账户。以管理员身份打开浏览器不会改变后端权限。</p>
            <p>请由本机管理员核实上述账户对 {deniedChannels.map(c => c.channel).join('、')} 的读取权限。可在停止现有后端后，以管理员身份启动后端验证；长期运行应为专用采集账户配置所需的日志读取权限。</p>
            <p>权限调整或后端重启后，再点击“读取日志”验证。应用不会自动提权或修改用户组、审计策略及通道访问权限。</p>
          </div>
        </details>}
        <input aria-label="筛选本机日志" value={filter} onChange={e=>setFilter(e.target.value)} placeholder="按事件 ID 或关键词筛选" className="w-full text-xs border rounded p-2" />
      </>}
    </div>
    <div className="flex-1 overflow-auto">
      {!result && <p className="p-4 text-xs text-slate-400">点击“读取日志”开始预览。演示请使用 Windows 演示案例。</p>}
      {result && !result.events.length && <p className="p-4 text-xs text-slate-500">当前读取范围内没有预览记录。未读通道与历史记录不包含在此结论中。</p>}
      {!!result?.events.length && !visibleEvents.length && <p role="status" className="p-4 text-xs text-slate-500">没有匹配的预览记录，请调整筛选条件。</p>}
      {visibleEvents.map(({event,index}) => {
        return <label key={`${event.Channel}-${event.RecordId}-${index}`} className="flex items-start gap-2 border-b p-3 text-xs hover:bg-slate-50">
          <input type="checkbox" aria-label={`选择事件 ${event.EventID} 记录 ${event.RecordId}`} disabled={importing || busy} checked={selected.has(index)} onChange={e=>setSelected(prev=>{const next=new Set(prev); if(e.target.checked)next.add(index);else next.delete(index);return next;})}/>
          <span className="min-w-0"><strong>事件 {event.EventID}</strong><span className="block text-slate-500 break-all">{event.Channel} · {event.Computer || '主机未知'}</span><span className="block text-slate-400">{event.TimeCreated}</span><span className="block whitespace-pre-wrap break-words mt-1">{event.Message}</span></span>
        </label>;
      })}
    </div>
  </div>;
}
