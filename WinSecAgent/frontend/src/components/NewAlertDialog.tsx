import { useState } from 'react';
import { X, Monitor, FileText, Loader2 } from 'lucide-react';
import { api } from '../services/api';
import { useAppStore } from '../stores/appStore';

export default function NewAlertDialog({ onClose, onReadLocal }: { onClose: () => void; onReadLocal: () => void }) {
  const [mode, setMode] = useState<'local' | 'paste'>('local');
  const [title, setTitle] = useState('');
  const [raw, setRaw] = useState('');
  const [eventId, setEventId] = useState('');
  const [channel, setChannel] = useState('');
  const [computer, setComputer] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [createdAlertId, setCreatedAlertId] = useState<number | null>(null);

  const create = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!raw.trim() || busy) return;
    setBusy(true);
    setError('');
    try {
      const alertId = createdAlertId ?? (await api.alerts.create({
        title: title.trim() || `Windows ${eventId ? `事件 ${eventId}` : '手动日志'}`,
        raw_content: raw.trim(), source_type: 'windows_manual', severity: 'medium', status: 'pending',
        windows_context: { event_id: eventId ? Number(eventId) : undefined, channel: channel.trim() || undefined, computer: computer.trim() || undefined },
      })).id;
      setCreatedAlertId(alertId);
      const incident = await api.incidents.create({ alert_id: alertId, status: 'pending' });
      const store = useAppStore.getState();
      await Promise.all([store.refreshAlerts(), store.refreshIncidents()]);
      await store.selectIncident(incident.id);
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : '创建失败，请重试');
    } finally {
      setBusy(false);
    }
  };
  const inputClass = 'w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-primary-500';
  return <div className="fixed inset-0 bg-slate-900/40 flex items-center justify-center z-50 p-4">
    <section role="dialog" aria-modal="true" aria-labelledby="new-alert-heading" className="bg-white rounded-xl shadow-xl w-full max-w-2xl max-h-[90vh] overflow-auto">
      <div className="flex items-center justify-between px-5 py-4 border-b">
        <div><h2 id="new-alert-heading" className="font-semibold">导入 Windows 日志</h2><p className="text-xs text-slate-500 mt-1">选择日志来源，保留原始记录后再开始分析。</p></div>
        <button aria-label="关闭导入日志" onClick={onClose} disabled={busy} className="p-2 rounded hover:bg-slate-100"><X size={18} /></button>
      </div>
      <div className="grid grid-cols-2 gap-2 p-4">
        <button onClick={() => setMode('local')} disabled={busy} className={`border rounded-lg p-3 text-left ${mode === 'local' ? 'border-primary-500 bg-primary-50' : 'border-slate-200'}`}><Monitor size={18} /><span className="block text-sm font-medium mt-2">读取本机日志</span><span className="text-xs text-slate-500">此服务所在 Windows 电脑</span></button>
        <button onClick={() => setMode('paste')} disabled={busy} className={`border rounded-lg p-3 text-left ${mode === 'paste' ? 'border-primary-500 bg-primary-50' : 'border-slate-200'}`}><FileText size={18} /><span className="block text-sm font-medium mt-2">粘贴 Windows 日志</span><span className="text-xs text-slate-500">事件查看器文本、JSON 或 XML</span></button>
      </div>
      {mode === 'local' ? <div className="px-5 pb-5 space-y-4">
        <p className="text-sm text-slate-600 leading-6">读取 Security、System、Defender 与 PowerShell 等日志。先预览，再将选中的记录加入日志列表；不会在此步骤执行系统处置。</p>
        <p className="text-xs text-slate-500">部分通道需要额外读取权限。无法读取时会显示具体通道与原因。</p>
        <button onClick={onReadLocal} className="px-4 py-2 rounded-md bg-primary-600 text-white text-sm">前往本机日志</button>
      </div> : <form onSubmit={create} className="px-5 pb-5 space-y-3">
        <fieldset disabled={busy || createdAlertId !== null} className="space-y-3">
          <label className="block text-xs text-slate-600">日志标题（可选）<input className={`${inputClass} mt-1`} value={title} onChange={e => setTitle(e.target.value)} maxLength={200} placeholder="例如：研发电脑连续登录失败" /></label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <label className="text-xs text-slate-600">事件 ID（可选）<input type="number" min="1" max="65535" className={`${inputClass} mt-1`} value={eventId} onChange={e => setEventId(e.target.value)} placeholder="4625" /></label>
            <label className="text-xs text-slate-600">日志通道（可选）<input className={`${inputClass} mt-1`} value={channel} onChange={e => setChannel(e.target.value)} placeholder="Security" maxLength={200} /></label>
            <label className="text-xs text-slate-600">主机名（可选）<input className={`${inputClass} mt-1`} value={computer} onChange={e => setComputer(e.target.value)} placeholder="WIN-PC-01" maxLength={255} /></label>
          </div>
          <label className="block text-xs text-slate-600">日志原文 <span className="text-red-600">*</span><textarea required className={`${inputClass} mt-1 h-44 font-mono`} value={raw} onChange={e => setRaw(e.target.value)} placeholder="粘贴 Windows 事件的常规文本、JSON 或 XML。请保留事件 ID、时间、通道、主机和事件数据。" /></label>
          <p className="text-xs text-slate-500">缺失字段可在上方补充；未提供的信息会标为未知。此版本面向 Windows 日志。</p>
        </fieldset>
        {error && <p role="alert" className="text-sm text-red-600">{error}</p>}
        <div className="flex justify-end gap-2 pt-2"><button type="button" onClick={onClose} disabled={busy} className="px-4 py-2 text-sm rounded hover:bg-slate-100">取消</button><button type="submit" disabled={busy || !raw.trim()} className="flex items-center gap-2 px-4 py-2 text-sm rounded bg-primary-600 text-white disabled:opacity-50">{busy && <Loader2 size={16} className="animate-spin" />}{createdAlertId ? '继续导入' : '导入日志'}</button></div>
      </form>}
    </section>
  </div>;
}
