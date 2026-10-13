import { useEffect, useState } from 'react';
import { Check, Cpu, Loader2, Plus, Trash2, X, Zap } from 'lucide-react';
import { api } from '../services/api';

interface ModelConfig {
  id: string;
  name: string;
  provider: string;
  model: string;
  base_url?: string;
  is_active: boolean;
}

const PROVIDERS = [
  { value: 'deepseek', label: 'DeepSeek', models: ['deepseek-chat', 'deepseek-reasoner', 'deepseek-v4-flash', 'deepseek-v4-pro'] },
  { value: 'openai', label: 'OpenAI', models: ['gpt-4o', 'gpt-4o-mini', 'gpt-4-turbo', 'gpt-3.5-turbo'] },
  { value: 'anthropic', label: 'Anthropic', models: ['claude-3-opus', 'claude-3-sonnet', 'claude-3-haiku'] },
  { value: 'ollama', label: 'Ollama (本地)', models: ['llama2', 'mistral', 'codellama', 'qwen2'] },
];
const inputClass = 'mt-1.5 w-full min-w-0 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-700 placeholder:text-slate-400 disabled:bg-slate-50';
const secondaryClass = 'inline-flex items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50';
const errorMessage = (error: unknown) => error instanceof Error ? error.message : '请求失败，请重试';

export default function ModelManager() {
  const [models, setModels] = useState<ModelConfig[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [fetching, setFetching] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [mode, setMode] = useState<'provider' | 'custom'>('provider');
  const [provider, setProvider] = useState('');
  const [format, setFormat] = useState('openai');
  const [modelId, setModelId] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [testResult, setTestResult] = useState<{id: string; ok: boolean; message: string} | null>(null);
  const disabled = !!busy || fetching || !loaded;
  const suggestedModels = PROVIDERS.find(item => item.value === provider)?.models || [];

  const loadModels = async () => {
    setFetching(true);
    try {
      setModels(await api.models.list());
      setLoaded(true);
    } catch (e) {
      setLoaded(false);
      throw e;
    } finally { setFetching(false); }
  };
  useEffect(() => { loadModels().catch(e => setError(`模型列表加载失败：${errorMessage(e)}`)); }, []);

  const resetForm = () => {
    setProvider(''); setModelId(''); setApiKey(''); setBaseUrl(''); setDisplayName('');
    setShowForm(false);
  };
  const refreshRuntime = async () => {
    const result = await api.models.refresh();
    if (!result.ok) throw new Error(result.message || '配置刷新失败');
  };
  const addModel = async (event: React.FormEvent) => {
    event.preventDefault();
    if (disabled) return;
    setBusy('add'); setError(''); setMessage('');
    let saved = false;
    try {
      const selectedProvider = mode === 'provider' ? provider : format;
      const label = PROVIDERS.find(item => item.value === selectedProvider)?.label || selectedProvider;
      const created = await api.models.create({
        name: displayName.trim() || `${label} ${modelId.trim()}`,
        provider: selectedProvider, model: modelId.trim(), api_key: apiKey.trim(),
        base_url: mode === 'custom' ? baseUrl.trim() : '', is_active: models.length === 0,
      });
      saved = true;
      resetForm();
      await loadModels();
      if (created.is_active) await refreshRuntime();
      setMessage(created.is_active ? '模型已添加，并设为当前使用。' : '模型已添加，可测试连接或设为当前使用。');
    } catch (e) {
      setError(`${saved ? '模型已保存，但列表或配置刷新失败，请刷新页面，不要重复添加' : '添加失败'}：${errorMessage(e)}`);
    } finally { setBusy(null); }
  };
  const activateModel = async (model: ModelConfig) => {
    if (disabled) return;
    setBusy(model.id); setError(''); setMessage('');
    let saved = false;
    try {
      await api.models.setActive(model.id);
      saved = true;
      await loadModels();
      await refreshRuntime();
      setMessage(`已切换为 ${model.name}。`);
    } catch (e) { setError(`${saved ? '选择已保存，但列表或配置刷新失败' : '切换失败'}：${errorMessage(e)}`); }
    finally { setBusy(null); }
  };
  const deleteModel = async (id: string) => {
    if (disabled) return;
    setBusy(id); setError(''); setMessage('');
    let deleted = false;
    try {
      await api.models.delete(id);
      deleted = true;
      setDeleteId(null);
      await loadModels();
      await refreshRuntime();
      setMessage('模型配置已删除。');
    } catch (e) { setError(`${deleted ? '模型已删除，但列表或配置刷新失败' : '删除失败'}：${errorMessage(e)}`); }
    finally { setBusy(null); }
  };
  const testModel = async (id: string) => {
    if (disabled) return;
    setBusy(id); setTestResult(null); setError(''); setMessage('');
    try {
      const result = await api.models.test(id);
      setTestResult({id, ok: result.ok, message: result.message});
    } catch (e) { setTestResult({id, ok: false, message: errorMessage(e)}); }
    finally { setBusy(null); }
  };

  return <section aria-labelledby="model-manager-heading" className="min-h-full space-y-5 bg-slate-50 p-4 sm:p-6">
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div><h3 id="model-manager-heading" className="text-base font-semibold text-slate-800">模型管理</h3><p className="mt-1 text-xs leading-6 text-slate-500">配置单条日志分析使用的模型，本地联合分析无需模型。</p></div>
      {!showForm && <button onClick={() => {setShowForm(true); setError(''); setMessage(''); setDeleteId(null);}} disabled={disabled} className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-3 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50"><Plus size={16}/>添加模型</button>}
    </header>
    {error && <div role="alert" className="rounded-lg border border-red-100 bg-red-50 p-3 text-sm text-red-700"><p className="break-words">{error}</p>{!loaded && <button disabled={fetching} onClick={() => {setError(''); loadModels().catch(e => setError(`模型列表加载失败：${errorMessage(e)}`));}} className="mt-2 underline disabled:opacity-50">重新加载</button>}</div>}
    {message && <p role="status" className="rounded-lg bg-emerald-50 p-3 text-sm text-emerald-800">{message}</p>}
    {showForm && <form onSubmit={addModel} aria-labelledby="add-model-heading" className="rounded-xl border border-slate-200 bg-white p-4 sm:p-5">
      <div className="mb-4 flex items-center justify-between"><h4 id="add-model-heading" className="text-sm font-semibold text-slate-800">添加模型</h4><button type="button" aria-label="取消添加模型" onClick={resetForm} disabled={!!busy} className="rounded-lg p-2 text-slate-400 hover:bg-slate-100 disabled:opacity-50"><X size={16}/></button></div>
      <fieldset disabled={disabled} className="space-y-4">
        <div role="group" aria-label="配置方式" className="inline-flex rounded-lg bg-slate-100 p-1">{(['provider', 'custom'] as const).map(value => <button key={value} type="button" aria-pressed={mode === value} onClick={() => setMode(value)} className={`rounded-md px-3 py-2 text-xs font-medium ${mode === value ? 'bg-white text-primary-700 shadow-sm' : 'text-slate-500'}`}>{value === 'provider' ? '模型服务商' : '自定义接口'}</button>)}</div>
        <div className="grid gap-4 sm:grid-cols-2">
          {mode === 'provider' ? <label className="text-xs font-medium text-slate-600">服务商<select required value={provider} onChange={e => {setProvider(e.target.value); setModelId('');}} className={inputClass}><option value="">选择服务商</option>{PROVIDERS.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}</select></label> : <label className="text-xs font-medium text-slate-600">接口格式<select value={format} onChange={e => setFormat(e.target.value)} className={inputClass}><option value="openai">OpenAI 兼容格式</option><option value="anthropic">Anthropic Messages 格式</option></select></label>}
          <label className="text-xs font-medium text-slate-600">模型 ID<input required value={modelId} onChange={e => setModelId(e.target.value)} list={mode === 'provider' ? 'model-id-suggestions' : undefined} placeholder="输入服务商提供的模型 ID" className={inputClass}/>{mode === 'provider' && <datalist id="model-id-suggestions">{suggestedModels.map(id => <option key={id} value={id}/>)}</datalist>}</label>
          {mode === 'custom' && <label className="text-xs font-medium text-slate-600 sm:col-span-2">服务基础地址<input required type="url" value={baseUrl} onChange={e => setBaseUrl(e.target.value)} placeholder="https://your-service.example/v1" className={inputClass}/><span className="mt-1.5 block font-normal leading-5 text-slate-500">填写 SDK 使用的基础地址，不包含 /chat/completions 或 /messages。</span></label>}
          <label className="text-xs font-medium text-slate-600">API 密钥<input required type="password" autoComplete="new-password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="输入 API 密钥" className={inputClass}/></label>
          <label className="text-xs font-medium text-slate-600">显示名称 <span className="font-normal text-slate-400">（可选）</span><input value={displayName} onChange={e => setDisplayName(e.target.value)} placeholder="便于识别的名称" className={inputClass}/></label>
        </div>
      </fieldset>
      <footer className="mt-5 flex justify-end gap-2 border-t border-slate-100 pt-4"><button type="button" onClick={resetForm} disabled={!!busy} className={secondaryClass}>取消</button><button type="submit" disabled={disabled || !modelId.trim() || !apiKey.trim() || (mode === 'provider' ? !provider : !baseUrl.trim())} className="inline-flex items-center gap-2 rounded-lg bg-primary-600 px-4 py-2 text-sm font-medium text-white hover:bg-primary-700 disabled:opacity-50">{busy === 'add' && <Loader2 size={14} className="animate-spin"/>}{busy === 'add' ? '保存中…' : '保存模型'}</button></footer>
    </form>}
    <div className="space-y-3" aria-busy={fetching}>
      <div className="flex items-center justify-between"><h4 className="text-sm font-semibold text-slate-700">已配置模型</h4><span className="text-xs text-slate-400">{loaded ? `${models.length} 个` : '正在加载'}</span></div>
      {fetching && <p role="status" className="flex items-center gap-2 py-4 text-sm text-slate-500"><Loader2 size={16} className="animate-spin"/>正在加载配置…</p>}
      {loaded && !fetching && !models.length && <div className="rounded-xl border border-dashed border-slate-300 bg-white px-5 py-8 text-center"><Cpu size={28} className="mx-auto mb-3 text-slate-300"/><p className="text-sm font-medium text-slate-700">尚未添加模型</p><p className="mt-2 text-xs leading-6 text-slate-500">需要单条模型分析时再添加配置。你仍可以使用本地联合分析。</p></div>}
      {models.map(model => <article key={model.id} className={`rounded-xl border bg-white p-4 ${model.is_active ? 'border-primary-200' : 'border-slate-200'}`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h5 className="break-words text-sm font-semibold text-slate-800">{model.name}</h5>{model.is_active && <span className="inline-flex items-center gap-1 rounded-full bg-primary-50 px-2 py-0.5 text-xs font-medium text-primary-700"><Check size={12}/>当前使用</span>}</div><p className="mt-1 break-all text-xs leading-6 text-slate-500">{PROVIDERS.find(item => item.value === model.provider)?.label || model.provider} · {model.model}</p></div>
          {busy === model.id && <span role="status" aria-label="正在处理模型" className="text-primary-600"><Loader2 size={16} className="animate-spin"/></span>}
        </div>
        {testResult?.id === model.id && <p role="status" className={`mt-3 break-words rounded-lg p-2.5 text-xs leading-5 ${testResult.ok ? 'bg-emerald-50 text-emerald-800' : 'bg-red-50 text-red-700'}`}>{testResult.message}</p>}
        <div className="mt-3 flex flex-wrap gap-2"><button disabled={disabled} onClick={() => testModel(model.id)} className={secondaryClass}><Zap size={13}/>测试连接</button>{!model.is_active && <button disabled={disabled} onClick={() => activateModel(model)} className={secondaryClass}><Check size={13}/>设为当前</button>}<button disabled={disabled} onClick={() => setDeleteId(model.id)} className="inline-flex items-center gap-1.5 rounded-lg px-3 py-2 text-xs text-slate-500 hover:bg-red-50 hover:text-red-600 disabled:opacity-50"><Trash2 size={13}/>删除</button></div>
        {deleteId === model.id && <div className="mt-3 rounded-lg border border-red-100 bg-red-50 p-3"><p className="text-xs leading-5 text-red-800">确定删除“{model.name}”的配置？{model.is_active && '删除后将切换到剩余配置（如有）。'}</p><div className="mt-3 flex gap-2"><button disabled={disabled} onClick={() => setDeleteId(null)} className={secondaryClass}>保留</button><button disabled={disabled} onClick={() => deleteModel(model.id)} className="rounded-lg bg-red-600 px-3 py-2 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50">确认删除</button></div></div>}
      </article>)}
      {!!models.length && <p className="text-xs leading-5 text-slate-500">“测试连接”会向所选模型服务发送一条简短测试请求。</p>}
    </div>
  </section>;
}
