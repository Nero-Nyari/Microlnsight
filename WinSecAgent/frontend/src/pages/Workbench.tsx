import { useEffect, useState } from 'react';
import { Shield, Plus, Loader2, Settings } from 'lucide-react';
import { useAppStore } from '../stores/appStore';
import AlertList from '../components/AlertList';
import AlertDetail from '../components/AlertDetail';
import AgentFlow from '../components/AgentFlow';
import EvidencePanel from '../components/EvidencePanel';
import AttackChain from '../components/AttackChain';
import ActionPanel from '../components/ActionPanel';
import ReportView from '../components/ReportView';
import LogReader from '../components/LogReader';
import KnowledgePanel from '../components/KnowledgePanel';
import MemoryPanel from '../components/MemoryPanel';
import SystemInfoPanel from '../components/SystemInfoPanel';
import SchedulerPanel from '../components/SchedulerPanel';
import ModelManager from '../components/ModelManager';
import NewAlertDialog from '../components/NewAlertDialog';

const RIGHT_TABS = [
  { key: 'agents', label: '智能体执行' },
  { key: 'evidence', label: '证据列表' },
  { key: 'chain', label: '攻击链' },
  { key: 'actions', label: '处置建议' },
  { key: 'report', label: '事件报告' },
] as const;

const LEFT_TABS = [
  { key: 'logs', label: '日志读取' },
  { key: 'knowledge', label: '知识库' },
  { key: 'memory', label: '记忆库' },
  { key: 'system', label: '系统信息' },
  { key: 'scheduler', label: '定时调度' },
] as const;

type RightTabKey = typeof RIGHT_TABS[number]['key'];
type LeftTabKey = typeof LEFT_TABS[number]['key'];

export default function Workbench() {
  const [activeRightTab, setActiveRightTab] = useState<RightTabKey>('agents');
  const [activeLeftTab, setActiveLeftTab] = useState<LeftTabKey>('logs');
  const [showNewAlert, setShowNewAlert] = useState(false);
  const [showModelManager, setShowModelManager] = useState(false);

  const {
    selectedIncident,
    loading,
    refreshAlerts,
    refreshIncidents,
    runAnalysis,
  } = useAppStore();

  useEffect(() => {
    refreshAlerts();
    refreshIncidents();
  }, [refreshAlerts, refreshIncidents]);

  return (
    <div className="h-screen flex flex-col bg-slate-50">
      <header className="min-h-14 py-2 gap-2 flex-wrap bg-white border-b border-slate-200 flex items-center justify-between px-4 shrink-0">
        <div className="flex items-center gap-2">
          <Shield className="w-6 h-6 text-primary-600" />
          <h1 className="font-bold text-lg text-slate-800">WinSecAgent</h1>
          <span className="hidden sm:inline text-xs text-slate-400 ml-2">Windows 安全事件工作台</span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowModelManager(true)}
            className="flex items-center gap-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 text-sm px-3 py-1.5 rounded-md transition border border-slate-200"
          >
            <Settings className="w-4 h-4" />
            模型管理
          </button>
          <button
            onClick={() => setShowNewAlert(true)}
            className="flex items-center gap-1 bg-primary-600 hover:bg-primary-700 text-white text-sm px-3 py-1.5 rounded-md transition"
          >
            <Plus className="w-4 h-4" />
            导入日志
          </button>
        </div>
      </header>

      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-2 2xl:grid-cols-[280px_260px_minmax(320px,1fr)_400px] overflow-auto">
        {/* Left panel - WinSecAgent features */}
        <aside id="local-log-panel" className="h-96 2xl:h-auto min-h-0 bg-white border-r border-slate-200 flex flex-col shrink-0">
          <div className="flex border-b border-slate-200 overflow-x-auto">
            {LEFT_TABS.map((t) => (
              <button key={t.key} onClick={() => setActiveLeftTab(t.key)}
                className={`px-2.5 py-2 text-[10px] font-medium whitespace-nowrap border-b-2 transition ${
                  activeLeftTab === t.key
                    ? 'border-primary-600 text-primary-700'
                    : 'border-transparent text-slate-500 hover:text-slate-700'
                }`}>
                {t.label}
              </button>
            ))}
          </div>
          <div className="flex-1 overflow-hidden">
            {activeLeftTab === 'logs' && <LogReader />}
            {activeLeftTab === 'knowledge' && <KnowledgePanel />}
            {activeLeftTab === 'memory' && <MemoryPanel />}
            {activeLeftTab === 'system' && <SystemInfoPanel />}
            {activeLeftTab === 'scheduler' && <SchedulerPanel />}
          </div>
        </aside>

        {/* Center - Alert queue + detail */}
        <div className="h-96 2xl:h-auto min-h-0 bg-white border-r border-slate-200 flex flex-col shrink-0">
          <AlertList />
        </div>

        <main className="h-[34rem] 2xl:h-auto min-h-0 flex flex-col min-w-0 bg-white">
          <AlertDetail onAnalyze={(id) => runAnalysis(id)} />
        </main>

        {/* Right panel - SecAgentX features */}
        <aside className="h-[34rem] 2xl:h-auto min-h-0 bg-white border-l border-slate-200 flex flex-col shrink-0">
          <div className="flex border-b border-slate-200 overflow-x-auto">
            {RIGHT_TABS.map((t) => (
              <button key={t.key} onClick={() => setActiveRightTab(t.key)}
                className={`px-3 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition ${
                  activeRightTab === t.key
                    ? 'border-primary-600 text-primary-700'
                    : 'border-transparent text-slate-500 hover:text-slate-700'
                }`}>
                {t.label}
              </button>
            ))}
          </div>
          <div className="flex-1 overflow-auto p-3">
            {loading && (
              <div className="flex items-center justify-center py-8 text-slate-400">
                <Loader2 className="w-5 h-5 animate-spin mr-2" />
                处理中...
              </div>
            )}
            {!selectedIncident && !loading && (
              <div className="text-sm text-slate-400 text-center py-8">请从左侧选择一个事件</div>
            )}
            {selectedIncident && (
              <>
                {activeRightTab === 'agents' && <AgentFlow />}
                {activeRightTab === 'evidence' && <EvidencePanel />}
                {activeRightTab === 'chain' && <AttackChain />}
                {activeRightTab === 'actions' && <ActionPanel />}
                {activeRightTab === 'report' && <ReportView />}
              </>
            )}
          </div>
        </aside>
      </div>

      {showNewAlert && <NewAlertDialog onClose={() => setShowNewAlert(false)} onReadLocal={() => {
        setShowNewAlert(false);
        setActiveLeftTab('logs');
        document.getElementById('local-log-panel')?.scrollIntoView({ behavior: 'smooth' });
      }} />}

      <ModelManager open={showModelManager} onClose={() => setShowModelManager(false)} />
    </div>
  );
}
