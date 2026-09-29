import { ArrowRight, Target } from 'lucide-react';
import { useAppStore } from '../stores/appStore';

export default function AttackChain() {
  const { selectedIncident, agentRuns } = useAppStore();

  const chainRun = [...agentRuns].reverse().find((r) => r.agent_name === 'Attack Chain');
  const stages = chainRun?.output_data?.stages || [];
  const path = chainRun?.output_data?.attack_path || selectedIncident?.attack_stage || '未知';
  const suspicious = chainRun?.output_data?.suspicious_success || '未知';

  if (selectedIncident?.correlation) {
    return <div className="text-xs space-y-2"><p className="font-semibold">本地事件时间关联</p>{selectedIncident.correlation.findings.map((f,i)=><p key={i}>{f.title}</p>)}<p className="text-slate-500">时间相邻不等于因果关系，尚未确认攻击成功。请在结果页查看对应记录与待补证项。</p></div>;
  }

  if (!chainRun) {
    return <div className="text-xs text-slate-400 text-center py-4">攻击链尚未分析</div>;
  }
  if (selectedIncident?.queue !== 'alerts') {
    return <div className="text-xs bg-slate-50 border rounded p-3 space-y-2"><p className="font-semibold">{selectedIncident?.assessment?.classification === 'benign' ? '正常活动：不建立攻击链' : '证据不足：暂不建立攻击链'}</p><p>{path}</p><p className="text-slate-500">仅覆盖已提供日志，不代表整台主机安全。旧分析中的攻击推断不作为当前结论。</p></div>;
  }

  return (
    <div className="space-y-3">
      <div className="bg-slate-50 border border-slate-200 rounded-md p-3">
        <div className="text-[10px] text-slate-400 uppercase mb-1">可能的攻击路径（待核实）</div>
        <div className="text-xs font-medium text-slate-700 flex items-center flex-wrap gap-1">
          {path.split(' -> ').map((stage: string, i: number, arr: string[]) => (
            <span key={i} className="flex items-center gap-1">
              {stage}
              {i < arr.length - 1 && <ArrowRight className="w-3 h-3 text-slate-400" />}
            </span>
          ))}
        </div>
      </div>

      <div className="bg-orange-50 border border-orange-200 rounded-md p-3 flex gap-2">
        <Target className="w-4 h-4 text-orange-500 shrink-0 mt-0.5" />
        <div>
          <div className="text-[10px] text-orange-600 font-semibold uppercase">证据边界</div>
          <div className="text-xs text-orange-800 mt-0.5">{suspicious}</div>
        </div>
      </div>

      <div className="space-y-2">
        {stages.map((stage: any, idx: number) => (
          <div key={idx} className="flex gap-2">
            <div className="flex flex-col items-center">
              <div className="w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-[10px] font-bold">
                {idx + 1}
              </div>
              {idx < stages.length - 1 && <div className="w-0.5 flex-1 bg-slate-200 my-1" />}
            </div>
            <div className="flex-1 border border-slate-200 rounded-md p-2 mb-2 bg-white">
              <div className="text-xs font-semibold text-slate-700">{stage.stage}</div>
              <div className="text-[11px] text-slate-500 mt-0.5">{stage.evidence}</div>
              <div className="mt-1 text-[10px] text-slate-400">置信度: {(stage.confidence * 100).toFixed(0)}%</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
