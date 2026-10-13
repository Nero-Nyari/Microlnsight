import type { Alert } from '../types';

export type SourceScope = 'actual' | 'demo';

export function sourceScopeFor(alert?: Pick<Alert, 'is_demo' | 'source_type'>): SourceScope {
  return alert?.is_demo || alert?.source_type.includes('demo') ? 'demo' : 'actual';
}

export function sourceLabelFor(alert?: Pick<Alert, 'is_demo' | 'source_type'>): string {
  if (sourceScopeFor(alert) === 'demo') return '演示数据';
  return alert?.source_type === 'windows_log' ? '本机采集' : '手动 / 外部导入';
}
