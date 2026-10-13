import { useState, useEffect } from 'react';
import { Clock, Play, Pause, Square, Loader2, Settings } from 'lucide-react';
import { api } from '../services/api';
import type { SchedulerStatus } from '../types';

export default function SchedulerPanel() {
  const [status, setStatus] = useState<SchedulerStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [interval, setInterval_] = useState(300);
  const [threshold, setThreshold] = useState(0.85);

  useEffect(() => { loadStatus(); }, []);

  const loadStatus = async () => {
    try {
      const s = await api.scheduler.status();
      setStatus(s);
      setInterval_(s.scan_interval);
      setThreshold(s.auto_threshold);
    } catch { /* ignore */ }
  };

  const handleAction = async (action: 'start' | 'stop' | 'pause' | 'resume') => {
    setLoading(true);
    try {
      if (action === 'start') await api.scheduler.start();
      else if (action === 'stop') await api.scheduler.stop();
      else if (action === 'pause') await api.scheduler.pause();
      else await api.scheduler.resume();
      await loadStatus();
    } catch (e: any) {
      alert(e.message);
    }
    setLoading(false);
  };

  const handleConfig = async () => {
    setLoading(true);
    try {
      await api.scheduler.config(interval, threshold);
      await loadStatus();
    } catch (e: any) {
      alert(e.message);
    }
    setLoading(false);
  };

  return (
    <div className="flex flex-col h-full p-3">
      <h3 className="text-sm font-semibold text-slate-700 flex items-center gap-1.5 mb-3">
        <Clock className="w-4 h-4" />
        自动扫描调度器
      </h3>

      {status && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-2 text-[10px]">
            <div className={`rounded px-2 py-1.5 ${status.running ? 'bg-green-50' : 'bg-slate-50'}`}>
              <div className="text-slate-500">Status</div>
              <div className={`font-bold ${status.running ? 'text-green-600' : 'text-slate-600'}`}>
                {status.running ? (status.paused ? 'Paused' : 'Running') : 'Stopped'}
              </div>
            </div>
            <div className="bg-blue-50 rounded px-2 py-1.5">
              <div className="text-blue-500">Scans Done</div>
              <div className="text-lg font-bold text-blue-700">{status.scan_count}</div>
            </div>
            <div className="bg-slate-50 rounded px-2 py-1.5">
              <div className="text-slate-500">Interval</div>
              <div className="font-bold text-slate-700">{status.scan_interval}s</div>
            </div>
            <div className="bg-slate-50 rounded px-2 py-1.5">
              <div className="text-slate-500">Auto Threshold</div>
              <div className="font-bold text-slate-700">{(status.auto_threshold * 100).toFixed(0)}%</div>
            </div>
          </div>

          <div className="text-[10px] text-slate-400">
            上次扫描: {status.last_scan ? new Date(status.last_scan).toLocaleString() : '从未扫描'}
          </div>

          <div className="flex gap-1.5">
            {!status.running ? (
              <button onClick={() => handleAction('start')} disabled={loading}
                className="flex items-center gap-1 text-xs bg-green-600 text-white px-3 py-1.5 rounded hover:bg-green-700 disabled:opacity-50 transition">
                <Play className="w-3 h-3" /> 启动
              </button>
            ) : (
              <>
                <button onClick={() => handleAction('pause')} disabled={loading}
                  className="flex items-center gap-1 text-xs bg-yellow-500 text-white px-3 py-1.5 rounded hover:bg-yellow-600 disabled:opacity-50 transition">
                  <Pause className="w-3 h-3" /> {status.paused ? '恢复' : '暂停'}
                </button>
                <button onClick={() => handleAction('stop')} disabled={loading}
                  className="flex items-center gap-1 text-xs bg-red-500 text-white px-3 py-1.5 rounded hover:bg-red-600 disabled:opacity-50 transition">
                  <Square className="w-3 h-3" /> 停止
                </button>
              </>
            )}
          </div>

          <div className="border-t border-slate-200 pt-3">
            <h4 className="text-xs font-medium text-slate-600 flex items-center gap-1 mb-2">
              <Settings className="w-3 h-3" /> 配置
            </h4>
            <div className="space-y-2">
              <label className="block text-[10px] text-slate-500">
                Scan Interval (seconds)
                <input type="number" min={30} value={interval} onChange={(e) => setInterval_(Number(e.target.value))}
                  className="block w-full mt-0.5 text-xs border border-slate-300 rounded px-2 py-1" />
              </label>
              <label className="block text-[10px] text-slate-500">
                自动执行阈值 (0-1)
                <input type="number" min={0} max={1} step={0.05} value={threshold}
                  onChange={(e) => setThreshold(Number(e.target.value))}
                  className="block w-full mt-0.5 text-xs border border-slate-300 rounded px-2 py-1" />
              </label>
              <button onClick={handleConfig} disabled={loading}
                className="text-xs bg-primary-600 text-white px-3 py-1.5 rounded hover:bg-primary-700 disabled:opacity-50 transition">
                保存配置
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
