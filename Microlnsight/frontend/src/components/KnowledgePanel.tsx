import { useState } from 'react';
import { BookOpen, Search, Loader2 } from 'lucide-react';
import { api } from '../services/api';
import type { KnowledgeEntry } from '../types';

const categoryColors: Record<string, string> = {
  login: 'bg-blue-100 text-blue-700',
  account: 'bg-purple-100 text-purple-700',
  persistence: 'bg-red-100 text-red-700',
  malware: 'bg-orange-100 text-orange-700',
  playbook: 'bg-green-100 text-green-700',
  mitre: 'bg-indigo-100 text-indigo-700',
};

export default function KnowledgePanel() {
  const [entries, setEntries] = useState<KnowledgeEntry[]>([]);
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [loaded, setLoaded] = useState(false);

  const handleSearch = async () => {
    if (!query.trim()) return;
    setLoading(true);
    try {
      const results = await api.knowledge.search(query, 10);
      setEntries(results);
      setLoaded(true);
    } catch (e: any) {
      alert('Search failed: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadAll = async () => {
    setLoading(true);
    try {
      const all = await api.knowledge.entries();
      setEntries(all);
      setLoaded(true);
    } catch (e: any) {
      alert('加载失败: ' + e.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="p-3 border-b border-slate-200">
        <h3 className="text-sm font-semibold text-slate-700 flex items-center gap-1.5 mb-2">
          <BookOpen className="w-4 h-4" />
          Security Knowledge Base (RAG)
        </h3>
        <div className="flex gap-1.5">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            placeholder="搜索知识库..."
            className="flex-1 text-xs border border-slate-300 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary-500"
          />
          <button
            onClick={handleSearch}
            disabled={loading}
            className="flex items-center gap-1 text-xs bg-primary-600 text-white px-2 py-1 rounded hover:bg-primary-700 disabled:opacity-50 transition"
          >
            {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Search className="w-3 h-3" />}
          </button>
          <button
            onClick={handleLoadAll}
            disabled={loading}
            className="text-xs bg-slate-100 text-slate-600 px-2 py-1 rounded hover:bg-slate-200 transition"
          >
            全部
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        {!loaded && !loading && (
          <div className="text-xs text-slate-400 text-center py-8">
            Search or click "All" to browse the knowledge base
          </div>
        )}
        {entries.map((entry) => (
          <div key={entry.id} className="px-3 py-2 border-b border-slate-100">
            <div className="flex items-center gap-2 mb-1">
              <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${categoryColors[entry.category] || 'bg-slate-100 text-slate-600'}`}>
                {entry.category}
              </span>
              <span className="text-xs font-medium text-slate-700">{entry.title}</span>
              {entry.score !== undefined && (
                <span className="text-[10px] text-slate-400 ml-auto">
                  {(entry.score * 100).toFixed(0)}% 匹配
                </span>
              )}
            </div>
            <div className="text-[11px] text-slate-500 whitespace-pre-wrap">
              {entry.content}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
