import { useEffect, useRef, useState } from 'react';
import { ArrowLeft, FileSearch, Plus, Settings, Shield, X } from 'lucide-react';
import { useAppStore } from '../stores/appStore';
import AlertList from '../components/AlertList';
import AlertDetail from '../components/AlertDetail';
import AgentFlow from '../components/AgentFlow';
import EvidencePanel from '../components/EvidencePanel';
import EvidenceTimeline from '../components/EvidenceTimeline';
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
import { sourceLabelFor } from '../services/logSource';

const RESULT_TABS = [
  { key: 'overview', label: '分析概览' },
  { key: 'evidence', label: '证据与原文' },
  { key: 'report', label: '分析报告' },
  { key: 'details', label: '更多详情' },
] as const;
const TOOL_TABS = [
  { key: 'logs', label: '本机日志' },
  { key: 'knowledge', label: '知识库' },
  { key: 'memory', label: '记忆库' },
  { key: 'system', label: '系统信息' },
  { key: 'scheduler', label: '定时调度' },
  { key: 'models', label: '模型管理' },
] as const;
type ResultTab = typeof RESULT_TABS[number]['key'];
type ToolTab = typeof TOOL_TABS[number]['key'];

export default function Workbench() {
  const [resultTab, setResultTab] = useState<ResultTab>('overview');
  const [toolTab, setToolTab] = useState<ToolTab>('logs');
  const [showTools, setShowTools] = useState(false);
  const [showNewAlert, setShowNewAlert] = useState(false);
  const [showRecords, setShowRecords] = useState(false);
  const [showDemos, setShowDemos] = useState(false);
  const [loadError, setLoadError] = useState('');
  const toolsDialog = useRef<HTMLDialogElement>(null);
  const { selectedIncident, selectedIncidentId, loading, refreshAlerts, refreshIncidents, runAnalysis, sourceScope, setSourceScope } = useAppStore();
  const toggleDemos = (open: boolean) => {
    setShowDemos(open);
    if (open) setSourceScope('demo');
  };

  useEffect(() => {
    Promise.all([refreshAlerts(), refreshIncidents()]).catch(e => setLoadError(e instanceof Error ? e.message : '日志加载失败'));
  }, [refreshAlerts, refreshIncidents]);
  useEffect(() => { setResultTab('overview'); setShowRecords(false); }, [selectedIncidentId]);
  useEffect(() => {
    if (showTools && !toolsDialog.current?.open) toolsDialog.current?.showModal();
    if (!showTools && toolsDialog.current?.open) toolsDialog.current?.close();
  }, [showTools]);
  const records = selectedIncident?.correlation?.records || (selectedIncident?.source_record ? [selectedIncident.source_record] : []);
  const selecting = loading && selectedIncident?.id !== selectedIncidentId;

  return <div className="h-dvh flex flex-col bg-slate-50">
    <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-white px-4 py-3 sm:px-6 shrink-0">
      <div className="flex items-center gap-3">
        <span className="rounded-xl bg-primary-50 p-2 text-primary-600"><Shield size={22}/></span>
        <div><h1 className="text-base font-semibold text-slate-900">WinSecAgent</h1><p className="text-xs text-slate-500">Windows 日志研判</p></div>
      </div>
      <div className="flex items-center gap-2">
        <button onClick={() => setShowTools(true)} className="flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-slate-600 hover:bg-slate-100"><Settings size={16}/><span>工具与设置</span></button>
        <button onClick={() => setShowNewAlert(true)} className="flex items-center gap-2 rounded-lg bg-primary-600 px-3 py-2 text-sm font-medium text-white hover:bg-primary-700"><Plus size={16}/>导入日志</button>
      </div>
    </header>
    {loadError && <p role="alert" className="bg-red-50 px-4 py-2 text-sm text-red-700">加载失败：{loadError}。请确认后端已启动后刷新。</p>}
    <div className="min-h-0 flex-1 md:grid md:grid-cols-[280px_minmax(0,1fr)] xl:grid-cols-[320px_minmax(0,1fr)]">
      <aside aria-label="日志与告警列表" className={`${selectedIncidentId && !showRecords ? 'hidden md:flex' : 'flex'} h-full min-h-0 flex-col border-r border-slate-200 bg-white`}>
        <AlertList showDemos={showDemos} onToggleDemos={toggleDemos} onSelect={() => {setShowRecords(false); setResultTab('overview');}}/>
      </aside>
      <main aria-label="日志分析工作区" className={`${!selectedIncidentId || showRecords ? 'hidden md:flex' : 'flex'} h-full min-h-0 min-w-0 flex-col`}>
        {selectedIncidentId ? <>
          {!selecting && selectedIncident && <div aria-label="当前记录来源" className={`flex flex-wrap items-center gap-x-3 gap-y-1 border-b px-4 py-2 text-xs ${sourceScope === 'demo' ? 'border-amber-200 bg-amber-50 text-amber-900' : 'border-slate-200 bg-white text-slate-500'}`}><strong>{sourceScope === 'demo' ? '演示数据' : `实际日志 · ${sourceLabelFor(selectedIncident.alert)}`}</strong>{sourceScope === 'demo' && <span>合成案例，用于体验流程，不代表本机真实安全事件。</span>}</div>}
          <div className="flex flex-wrap items-center gap-x-4 border-b border-slate-200 bg-white px-4 shrink-0">
            <button onClick={() => setShowRecords(true)} className="flex items-center gap-1 py-3 text-sm text-slate-600 md:hidden"><ArrowLeft size={16}/>日志列表</button>
            <nav aria-label="分析内容" className="flex flex-wrap gap-x-5">
              {RESULT_TABS.map(tab => <button key={tab.key} aria-current={resultTab === tab.key ? 'page' : undefined} onClick={() => setResultTab(tab.key)} className={`border-b-2 py-3 text-sm transition ${resultTab === tab.key ? 'border-primary-600 font-semibold text-primary-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}>{tab.label}</button>)}
            </nav>
          </div>
          <div className="min-h-0 flex-1 overflow-auto p-4 sm:p-6" aria-busy={loading}>
            {selecting ? <p role="status" className="py-12 text-center text-sm text-slate-500">正在加载记录…</p> : selectedIncident ? <div className="mx-auto max-w-5xl">
              <div hidden={resultTab !== 'overview'}><AlertDetail key={selectedIncident.id} onAnalyze={runAnalysis} onShowEvidence={() => setResultTab('evidence')}/></div>
              {resultTab === 'evidence' && <div className="rounded-xl border border-slate-200 bg-white p-5"><EvidenceTimeline records={records} result={selectedIncident.correlation}/>{!records.length && <pre className="mt-3 whitespace-pre-wrap break-all text-xs">{selectedIncident.alert?.raw_content || '无原文'}</pre>}{!selectedIncident.correlation && <>
                {!!selectedIncident.assessment?.findings.length && <section className="mt-5 space-y-3 text-sm"><h3 className="font-semibold">单条判断的原文依据</h3>{selectedIncident.assessment.findings.map((finding, index) => <article key={index} className="border-l-2 border-amber-300 pl-3"><p>{finding.reason}</p><pre className="mt-2 whitespace-pre-wrap break-words text-xs text-slate-500">{finding.quote}</pre></article>)}</section>}
                <details className="mt-6 border-t pt-4"><summary className="cursor-pointer text-sm text-slate-600">模型提取的证据</summary><div className="mt-3"><EvidencePanel/></div></details>
              </>}</div>}
              {resultTab === 'report' && <div className="rounded-xl border border-slate-200 bg-white p-5"><ReportView/></div>}
              {resultTab === 'details' && <div className="space-y-3">{[
                {title: '分析执行记录', content: <AgentFlow/>},
                {title: '攻击链核查', content: <AttackChain/>},
                {title: '处置建议与审批', content: <ActionPanel/>},
              ].map(item => <details key={item.title} className="rounded-xl border border-slate-200 bg-white p-4"><summary className="cursor-pointer text-sm font-medium text-slate-700">{item.title}</summary><div className="mt-4">{item.content}</div></details>)}</div>}
            </div> : <p className="py-12 text-center text-sm text-slate-500">记录尚未加载，请重新选择。</p>}
          </div>
        </> : <div className="flex flex-1 items-center justify-center p-8">
          <div className="max-w-md text-center"><FileSearch size={40} className="mx-auto mb-5 text-slate-300"/><h2 className="text-xl font-semibold text-slate-800">{sourceScope === 'demo' ? '选择一个演示案例' : '从一条实际日志开始'}</h2><p className="mt-3 text-sm leading-7 text-slate-500">{sourceScope === 'demo' ? '这里仅展示合成数据。载入案例后，可体验分析、证据核对和报告下载。' : '选择左侧记录或导入日志。演示案例在“演示数据”视图中单独显示。'}</p><div className="mt-6 flex flex-wrap justify-center gap-3"><button onClick={() => setShowNewAlert(true)} className="rounded-lg bg-primary-600 px-4 py-2 text-sm text-white hover:bg-primary-700">导入日志</button><button onClick={() => toggleDemos(true)} className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm text-slate-600 hover:bg-slate-50">选择演示案例</button></div></div>
        </div>}
      </main>
    </div>
    <dialog ref={toolsDialog} onClose={() => setShowTools(false)} aria-labelledby="tools-heading" className="m-auto h-[85dvh] max-h-[900px] w-[calc(100%_-_2rem)] max-w-4xl overflow-hidden rounded-2xl border border-slate-200 bg-white p-0 shadow-xl backdrop:bg-slate-900/40">
      {showTools && <div className="flex h-full min-h-0 flex-col">
        <header className="flex items-center justify-between border-b px-5 py-4"><h2 id="tools-heading" className="font-semibold">工具与设置</h2><button autoFocus aria-label="关闭工具与设置" onClick={() => setShowTools(false)} className="rounded-lg p-2 hover:bg-slate-100"><X size={18}/></button></header>
        <div className="flex flex-wrap gap-1 border-b px-4 py-2">{TOOL_TABS.map(tab => <button key={tab.key} onClick={() => setToolTab(tab.key)} aria-pressed={toolTab === tab.key} className={`rounded-lg px-3 py-2 text-sm ${toolTab === tab.key ? 'bg-primary-50 font-medium text-primary-700' : 'text-slate-500 hover:bg-slate-50'}`}>{tab.label}</button>)}</div>
        <div className="min-h-0 flex-1 overflow-auto">
          {toolTab === 'logs' && <LogReader onImported={() => {setShowTools(false); setShowRecords(false); setResultTab('overview');}}/>}{toolTab === 'knowledge' && <KnowledgePanel/>}{toolTab === 'memory' && <MemoryPanel/>}{toolTab === 'system' && <SystemInfoPanel/>}{toolTab === 'scheduler' && <SchedulerPanel/>}
          {toolTab === 'models' && <ModelManager/>}
        </div>
      </div>}
    </dialog>
    {showNewAlert && <NewAlertDialog onClose={() => setShowNewAlert(false)} onReadLocal={() => {setShowNewAlert(false); setToolTab('logs'); setShowTools(true);}}/>}
  </div>;
}
