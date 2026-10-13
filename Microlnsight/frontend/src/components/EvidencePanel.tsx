import { FileText, Shield, Server, Search, Wrench } from 'lucide-react';
import { useAppStore } from '../stores/appStore';

const typeIcon: Record<string, React.ReactNode> = {
  log: <FileText className="w-3.5 h-3.5 text-blue-500" />,
  ioc: <Shield className="w-3.5 h-3.5 text-red-500" />,
  asset: <Server className="w-3.5 h-3.5 text-green-500" />,
  vuln: <Search className="w-3.5 h-3.5 text-orange-500" />,
  tool: <Wrench className="w-3.5 h-3.5 text-slate-500" />,
};

export default function EvidencePanel() {
  const { evidence, selectedIncident } = useAppStore();
  const localCorrelation = !!selectedIncident?.correlation;

  if (!evidence.length) {
    return <div className="text-xs text-slate-400 text-center py-4">暂无证据</div>;
  }

  return (
    <div className="space-y-2">
      {localCorrelation && <p className="text-xs text-slate-500">以下为本轮关联的原始记录快照，不表示攻击置信度。</p>}
      {evidence.map((item) => (
        <div key={item.id} className="border border-slate-200 rounded-md p-2.5 bg-white">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-1.5">
              {typeIcon[item.type] || <FileText className="w-3.5 h-3.5" />}
              <span className="text-xs font-semibold text-slate-700">{item.title}</span>
            </div>
            <span className="text-[10px] text-slate-400">{item.source}</span>
          </div>
          <div className="text-[11px] text-slate-600 whitespace-pre-wrap break-words leading-relaxed">{item.content}</div>
          {localCorrelation ? <p className="mt-1 text-[10px] text-slate-500">已保存原文快照</p> : <div className="mt-1 flex items-center gap-2">
            <div className="flex-1 h-1.5 bg-slate-100 rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-500 rounded-full"
                style={{ width: `${(item.confidence || 0) * 100}%` }}
              />
            </div>
            <span className="text-[10px] text-slate-500">模型证据评分：{((item.confidence || 0) * 100).toFixed(0)}%（非攻击概率）</span>
          </div>}
        </div>
      ))}
    </div>
  );
}
