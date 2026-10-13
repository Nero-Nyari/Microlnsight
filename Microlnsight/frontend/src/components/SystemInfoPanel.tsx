import { useState } from 'react';
import { Cpu, Loader2, RefreshCw, Wifi, HardDrive, Calendar, Layers } from 'lucide-react';
import { api } from '../services/api';
import type { SystemInfo } from '../types';

type Tab = 'processes' | 'network' | 'services' | 'tasks' | 'registry';

const TABS: { key: Tab; label: string; icon: any }[] = [
  { key: 'processes', label: '进程', icon: Cpu },
  { key: 'network', label: '网络', icon: Wifi },
  { key: 'services', label: '服务', icon: HardDrive },
  { key: 'tasks', label: '计划任务', icon: Calendar },
  { key: 'registry', label: '注册表', icon: Layers },
];

export default function SystemInfoPanel() {
  const [data, setData] = useState<SystemInfo | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('processes');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleRefresh = async () => {
    setLoading(true);
    setError('');
    try {
      const info = await api.system.all();
      setData(info);
    } catch (e) { setError(e instanceof Error ? e.message : '系统信息读取失败'); }
    setLoading(false);
  };

  const items = data
    ? activeTab === 'network' ? data.network_connections
      : activeTab === 'services' ? data.services
      : activeTab === 'tasks' ? data.scheduled_tasks
      : activeTab === 'registry' ? data.registry
      : data.processes
    : [];
  const sourceKey = { processes: 'processes', network: 'network_connections', services: 'services', tasks: 'scheduled_tasks', registry: 'registry' }[activeTab];
  const collectionFailed = !!data?.collection_errors?.[sourceKey];

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-slate-200">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-sm font-semibold text-slate-700 flex items-center gap-1.5">
            <Cpu className="w-4 h-4" />
            系统信息
          </h3>
          <button onClick={handleRefresh} disabled={loading}
            className="flex items-center gap-1 text-xs bg-primary-600 text-white px-2 py-1 rounded hover:bg-primary-700 disabled:opacity-50 transition">
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <RefreshCw className="w-3 h-3" />}
            采集
          </button>
        </div>

        {data && (
          <div className="text-[10px] text-slate-400 mb-2">
            平台：{data.platform} {data.is_mock && '（演示数据）'}
          </div>
        )}

        {error && <p role="alert" className="text-xs text-red-600 mb-2">{error}</p>}
        {data?.warnings?.map(w => <p key={w} role="alert" className="text-xs text-amber-800 mb-2">{w}</p>)}
        {activeTab === 'processes' && data?.processes.some(item => item.path === '路径不可读') && <p className="mb-2 text-xs leading-5 text-slate-500">“路径不可读”表示本次未获取到该字段，不能仅据此判断后端是否以管理员身份运行。</p>}
        <div className="flex gap-1 overflow-x-auto">
          {TABS.map((t) => (
            <button key={t.key} onClick={() => setActiveTab(t.key)}
              className={`flex items-center gap-1 text-[10px] px-2 py-1 rounded whitespace-nowrap transition ${
                activeTab === t.key ? 'bg-primary-100 text-primary-700 font-medium' : 'text-slate-500 hover:bg-slate-100'
              }`}>
              <t.icon className="w-3 h-3" />
              {t.label}
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {!data && !loading && (
          <div className="text-xs text-slate-400 text-center py-8">
            点击"采集"获取系统信息
          </div>
        )}
        {items.map((item: any, i: number) => (
          <div key={i} className="px-3 py-1.5 border-b border-slate-100 text-[11px] font-mono text-slate-600 hover:bg-slate-50">
            {activeTab === 'processes' && (
              <span>PID {item.pid} | {item.name} | <span className="text-slate-400">{item.path}</span></span>
            )}
            {activeTab === 'network' && (
              <span>{item.protocol} {item.local} → {item.remote} | {item.state} | PID {item.pid}</span>
            )}
            {activeTab === 'services' && (
              <span>{item.name} ({item.state}) | <span className="text-slate-400">{item.path}</span></span>
            )}
            {activeTab === 'tasks' && (
              <span>{item.name} | {item.status} | Next: {item.next_run}</span>
            )}
            {activeTab === 'registry' && (
              <span className="break-all">{item.key} → {item.value}</span>
            )}
          </div>
        ))}
        {data && items.length === 0 && (
          <div role="status" className="text-xs text-slate-500 text-center py-4">{collectionFailed ? '本项采集失败，请查看上方原因后重试。' : '本次采集未返回记录。'}</div>
        )}
      </div>
    </div>
  );
}
