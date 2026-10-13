import { CheckCircle2, XCircle, Loader2, Clock } from 'lucide-react';
import { useAppStore } from '../stores/appStore';

const statusIcon: Record<string, React.ReactNode> = {
  success: <CheckCircle2 className="w-4 h-4 text-green-500" />,
  failed: <XCircle className="w-4 h-4 text-red-500" />,
  running: <Loader2 className="w-4 h-4 text-primary-600 animate-spin" />,
  pending: <Clock className="w-4 h-4 text-slate-400" />,
};

export default function AgentFlow() {
  const { agentRuns } = useAppStore();

  if (!agentRuns.length) {
    return <div className="text-xs text-slate-400 text-center py-4">暂无 Agent 执行记录</div>;
  }

  return (
    <div className="space-y-2">
      <p className="text-[11px] text-slate-500">展示最近一轮分析的一致性结果。历史原始输出仍保留，不混入当前结论。</p>
      {agentRuns.map((run) => (
        <div key={run.id} className="border border-slate-200 rounded-md p-2.5 bg-white">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              {statusIcon[run.status] || statusIcon.pending}
              <span className="text-xs font-semibold text-slate-700">{({'Parser':'日志解析', 'Triage':'风险研判', 'Evidence':'证据整理', 'Attack Chain':'攻击链核查', 'Response':'处置建议', 'Correlation':'本地联合分析'} as Record<string,string>)[run.agent_name] || run.agent_name}</span>
            </div>
            <span className="text-[10px] text-slate-400">
              {run.finished_at
                ? `${Math.round((new Date(run.finished_at).getTime() - new Date(run.started_at).getTime()) / 1000)}s`
                : '运行中'}
            </span>
          </div>
          {run.error_message && (
            <div className="text-[11px] text-red-600 bg-red-50 rounded px-2 py-1 mt-1">{run.error_message}</div>
          )}
          {run.output_data && !run.error_message && (
            <div className="text-[11px] text-slate-600 bg-slate-50 rounded px-2 py-1 mt-1 max-h-32 overflow-auto">
              {run.agent_name === 'Correlation' ? `已核对 ${run.output_data.records?.length || 0} 条去重记录，发现 ${run.output_data.findings?.length || 0} 项线索。详情及原文见结果页。` : typeof run.output_data === 'string' ? run.output_data : JSON.stringify(run.output_data, null, 2)}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
