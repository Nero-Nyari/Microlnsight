import { useState, useEffect } from 'react';
import { Brain, Loader2, Trash2, Search } from 'lucide-react';
import { api } from '../services/api';

export default function MemoryPanel() {
  const [stats, setStats] = useState<any>(null);
  const [recent, setRecent] = useState<any[]>([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const s = await api.memory.stats();
      setStats(s);
      const r = await api.memory.recent(5);
      setRecent(r.entries || []);
    } catch { /* ignore */ }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setLoading(true);
    try {
      const result = await api.memory.search(searchQuery, 5);
      setSearchResults(result.results || []);
    } catch { /* ignore */ }
    setLoading(false);
  };

  const handleClear = async (type: 'short' | 'long') => {
    if (!confirm(`清除${type === 'short' ? '短期' : '长期'}记忆？`)) return;
    if (type === 'short') await api.memory.clearShort();
    else await api.memory.clearLong();
    loadStats();
  };

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-slate-200">
        <h3 className="text-sm font-semibold text-slate-700 flex items-center gap-1.5 mb-2">
          <Brain className="w-4 h-4" />
          Agent 记忆库
        </h3>

        {stats && (
          <div className="grid grid-cols-2 gap-2 text-[10px] mb-2">
            <div className="bg-blue-50 rounded px-2 py-1.5">
              <div className="text-blue-500 font-medium">短期记忆</div>
              <div className="text-lg font-bold text-blue-700">{stats.short_term_count}</div>
            </div>
            <div className="bg-green-50 rounded px-2 py-1.5">
              <div className="text-green-500 font-medium">长期记忆</div>
              <div className="text-lg font-bold text-green-700">{stats.long_term_count}</div>
            </div>
          </div>
        )}

        <div className="flex gap-1.5 mb-2">
          <input
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="搜索记忆..."
            className="flex-1 text-xs border border-slate-300 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <button onClick={handleSearch} disabled={loading}
            className="flex items-center gap-1 text-xs bg-primary-600 text-white px-2 py-1 rounded hover:bg-primary-700 disabled:opacity-50 transition">
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
          </button>
        </div>

        <div className="flex gap-1">
          <button onClick={() => handleClear('short')}
            className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-red-500 transition">
            <Trash2 className="w-3 h-3" /> 清除短期
          </button>
          <button onClick={() => handleClear('long')}
            className="flex items-center gap-1 text-[10px] text-slate-500 hover:text-red-500 transition">
            <Trash2 className="w-3 h-3" /> 清除长期
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {searchResults.length > 0 && (
          <>
            <div className="px-3 py-1 text-[10px] font-semibold text-slate-500 uppercase bg-slate-50">
              Search Results
            </div>
            {searchResults.map((entry, i) => (
              <div key={i} className="px-3 py-2 border-b border-slate-100">
                <div className="text-[10px] text-slate-400 mb-0.5">
                  {new Date(entry.timestamp).toLocaleString()}
                  {entry.relevance_score && (
                    <span className="ml-2 text-primary-500">
                      {(entry.relevance_score * 100).toFixed(0)}% 匹配
                    </span>
                  )}
                </div>
                <div className="text-[11px] text-slate-600">
                  风险: <span className="font-medium">{entry.analysis_result?.risk_level || '无'}</span>
                  {' | '}类型: {entry.analysis_result?.event_type || '无'}
                </div>
              </div>
            ))}
          </>
        )}

        {recent.length > 0 && (
          <>
            <div className="px-3 py-1 text-[10px] font-semibold text-slate-500 uppercase bg-slate-50">
              最近事件
            </div>
            {recent.map((entry, i) => (
              <div key={i} className="px-3 py-2 border-b border-slate-100">
                <div className="text-[10px] text-slate-400 mb-0.5">
                  {new Date(entry.timestamp).toLocaleString()}
                </div>
                <div className="text-[11px] text-slate-600 truncate">
                  {entry.event_data?.Message?.slice(0, 100) || '事件数据'}
                </div>
              </div>
            ))}
          </>
        )}

        {!stats && !loading && (
          <div className="text-xs text-slate-400 text-center py-8">记忆库为空</div>
        )}
      </div>
    </div>
  );
}
