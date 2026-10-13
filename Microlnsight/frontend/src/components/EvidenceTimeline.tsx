import type { CorrelationResult, EvidenceRecord } from '../types';

export default function EvidenceTimeline({records, result}: {records: EvidenceRecord[]; result?: CorrelationResult | null}) {
  return <section className="space-y-3 text-xs" aria-label="结构化证据与时间线">
    <h3 className="font-semibold text-slate-700">依据与相关记录</h3>
    {result && <>
      <p className="text-slate-500">本地规则版本 {result.rule_version} · 分析时间 {result.analyzed_at} · 当前记录前后各 {result.window_minutes} 分钟 · 去重后 {records.length} 条</p>
      {result.warnings.map(w => <p key={w} className="text-amber-800 bg-amber-50 p-2 rounded">{w}</p>)}
      {result.findings.map((finding, index) => <article key={`${finding.rule_id}-${index}`} className="border border-amber-200 rounded p-3 space-y-2">
        <h4 className="font-semibold text-amber-900">{finding.title}</h4>
        <p>{finding.reason}</p>
        <dl className="grid sm:grid-cols-2 gap-2 text-slate-600">
          <div><dt>时间范围</dt><dd>{finding.start || '未知'} — {finding.end || '未知'}</dd></div>
          {finding.failure_count != null && <div><dt>实际失败记录数</dt><dd>{finding.failure_count} 次（去重后）</dd></div>}
          {finding.source_ip && <div><dt>来源 IP</dt><dd>{finding.source_ip}</dd></div>}
          {finding.account && <div><dt>账户</dt><dd>{finding.account}</dd></div>}
        </dl>
        <p className="flex flex-wrap gap-2">对应证据：{finding.record_refs.map(id => <a className="text-primary-700 underline" key={id} href={`#evidence-record-${id}`}>日志 #{id}</a>)}</p>
        <p className="text-slate-500">待核对：{finding.missing_evidence.join('；')}</p>
      </article>)}
    </>}
    <ol className="space-y-2">
      {records.map(r => <li key={r.alert_id} id={`evidence-record-${r.alert_id}`} className="border-l-2 border-slate-300 pl-3 py-2 scroll-mt-3">
        <p className="font-semibold">{r.timestamp || '时间未知'} · 事件 {r.event_id || '未知'} · 日志 #{r.alert_id}{r.is_demo && <span className="text-amber-700"> · 演示数据</span>}</p>
        <p className="text-slate-600 break-words">{r.computer || '主机未知'} · {r.channel || '通道未知'} · 记录号 {r.record_id ?? '未提供'}</p>
        <p className="text-slate-600">账户：{[r.account_domain, r.username].filter(Boolean).join('\\') || '未提供'} · 来源 IP：{r.source_ip || '未提供'}</p>
        {r.service_path && <p className="break-all">服务路径：{r.service_path}</p>}
        <details className="mt-1"><summary className="cursor-pointer text-primary-700">查看原始证据</summary><p className="text-slate-400 break-all my-1">原文 SHA-256：{r.raw_sha256}</p><pre className="whitespace-pre-wrap break-all bg-slate-900 text-slate-100 p-2 rounded max-h-60 overflow-auto">{r.raw_content}</pre></details>
      </li>)}
    </ol>
  </section>;
}
