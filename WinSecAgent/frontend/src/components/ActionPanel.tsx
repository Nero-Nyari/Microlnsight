import { useState } from 'react';
import { Check, X, Play, ShieldAlert, ShieldCheck, Zap, Loader2 } from 'lucide-react';
import { useAppStore } from '../stores/appStore';
import { api } from '../services/api';

const riskClass: Record<string, string> = {
  high: 'bg-red-50 border-red-200 text-red-700',
  medium: 'bg-orange-50 border-orange-200 text-orange-700',
  low: 'bg-green-50 border-green-200 text-green-700',
};

export default function ActionPanel() {
  const { selectedIncident, actions, refreshIncidentDetail } = useAppStore();
  const [executing, setExecuting] = useState<number | null>(null);
  const [executorStatus, setExecutorStatus] = useState<{ dry_run: boolean; is_windows: boolean } | null>(null);

  if (selectedIncident?.correlation) {
    return <div className="text-xs space-y-2">{selectedIncident.correlation.recommendations.map(r=><p key={r}>{r}</p>)}<p className="text-slate-500">本地联合分析仅提供核查建议，不生成可执行处置。</p></div>;
  }

  if (selectedIncident?.queue !== 'alerts') {
    return <div className="text-xs bg-slate-50 border rounded p-3 space-y-2"><p>{selectedIncident?.assessment?.classification === 'benign' ? '当前为正常活动，不建议封禁、隔离或删除。' : '先完成分析并补充证据，暂不提供系统处置。'}</p><p>保留原始日志，核对执行账户、操作时间与授权。历史处置不会用于当前记录。</p></div>;
  }
  if (!actions.length) {
    return <div className="text-xs text-slate-400 text-center py-4">暂无处置建议，请先复核原文证据。</div>;
  }

  const handleApprove = async (actionId: number) => {
    if (!selectedIncident) return;
    await api.actions.approve(selectedIncident.id, actionId, 'operator');
    await refreshIncidentDetail();
  };

  const handleReject = async (actionId: number) => {
    if (!selectedIncident) return;
    await api.actions.reject(selectedIncident.id, actionId, 'operator');
    await refreshIncidentDetail();
  };

  const handleSimulate = async (actionId: number) => {
    if (!selectedIncident) return;
    await api.actions.simulate(selectedIncident.id, actionId);
    await refreshIncidentDetail();
  };

  const handleExecute = async (actionId: number) => {
    if (!selectedIncident) return;
    setExecuting(actionId);
    try {
      await api.actions.execute(selectedIncident.id, actionId);
      await refreshIncidentDetail();
    } catch (e: any) {
      alert('执行失败: ' + e.message);
    }
    setExecuting(null);
  };

  const handleLoadStatus = async () => {
    try {
      const status = await api.actions.executorStatus();
      setExecutorStatus(status);
    } catch { /* ignore */ }
  };

  return (
    <div className="space-y-2">
      {/* Executor status bar */}
      <div className="flex items-center gap-2 text-[10px] text-slate-500 border-b border-slate-200 pb-2">
        <button onClick={handleLoadStatus}
          className="flex items-center gap-1 text-primary-600 hover:text-primary-700 transition">
          <Zap className="w-3 h-3" /> Check Executor
        </button>
        {executorStatus && (
          <>
            <span className={executorStatus.dry_run ? 'text-amber-600' : 'text-green-600'}>
              {executorStatus.dry_run ? 'DRY RUN' : 'LIVE'}
            </span>
            <span>{executorStatus.is_windows ? 'Windows' : 'Non-Windows'}</span>
          </>
        )}
      </div>

      {actions.map((action) => (
        <div key={action.id} className={`border rounded-md p-2.5 ${riskClass[action.risk] || 'bg-slate-50 border-slate-200'}`}>
          <div className="flex items-start justify-between mb-1">
            <div className="flex items-center gap-1.5">
              {action.approval_required ? (
                <ShieldAlert className="w-3.5 h-3.5" />
              ) : (
                <ShieldCheck className="w-3.5 h-3.5" />
              )}
              <span className="text-xs font-semibold">{action.action_type}</span>
            </div>
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-white/80 border border-black/5">
              {action.status}
            </span>
          </div>
          <div className="text-[11px] opacity-90 leading-relaxed">{action.description}</div>
          {action.result && (
            <div className="mt-1.5 text-[10px] bg-white/60 rounded p-1.5 border border-black/5">
              <span className="font-medium">执行结果:</span> {action.result.message || JSON.stringify(action.result)}
            </div>
          )}
          {action.risk === 'high' && (
            <div className="text-[10px] mt-1 opacity-75">高风险操作 - 需要审批</div>
          )}
          <div className="flex gap-1 mt-2 flex-wrap">
            {action.status === 'pending' && (
              <>
                <button onClick={() => handleApprove(action.id)}
                  className="flex items-center gap-1 text-[10px] bg-green-600 hover:bg-green-700 text-white px-2 py-1 rounded">
                  <Check className="w-3 h-3" /> 批准
                </button>
                <button onClick={() => handleReject(action.id)}
                  className="flex items-center gap-1 text-[10px] bg-slate-500 hover:bg-slate-600 text-white px-2 py-1 rounded">
                  <X className="w-3 h-3" /> 驳回
                </button>
                <button onClick={() => handleSimulate(action.id)}
                  className="flex items-center gap-1 text-[10px] bg-primary-600 hover:bg-primary-700 text-white px-2 py-1 rounded">
                  <Play className="w-3 h-3" /> 模拟
                </button>
              </>
            )}
            {action.status === 'approved' && (
              <button onClick={() => handleExecute(action.id)} disabled={executing === action.id}
                className="flex items-center gap-1 text-[10px] bg-red-600 hover:bg-red-700 text-white px-2 py-1 rounded disabled:opacity-50 transition">
                {executing === action.id ? (
                  <Loader2 className="w-3 h-3 animate-spin" />
                ) : (
                  <Zap className="w-3 h-3" />
                )}
                执行
              </button>
            )}
            {action.status !== 'pending' && action.status !== 'approved' && (
              <span className="text-[10px] text-slate-500">
                {action.status} {action.approved_by ? `by ${action.approved_by}` : ''}
              </span>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
