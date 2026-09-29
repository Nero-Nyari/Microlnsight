export const statusLabels: Record<string, string> = {
  pending: '待分析', analyzing: '分析中', benign: '正常活动', false_positive: '正常活动',
  needs_review: '待核实', review: '异常待复核', failed: '分析失败', interrupted: '分析中断',
  approved: '已批准', closed: '已关闭', rejected: '已驳回',
};
export const riskLabels: Record<string, string> = { critical: '严重', high: '高', medium: '中', low: '低', info: '信息' };
