import type {
  AuditAssessment,
  AuditMode,
  AuditStatus,
  CheckState,
  EvalMetric,
  EvalPrediction,
  EvalRunStatus,
  EvalSampleStatus,
  EvalSampleType,
  Source,
} from './types'

/**
 * Shown wherever the backend reported nothing. The UI never guesses a value or
 * fills the gap with a placeholder of its own.
 */
export const NO_DATA = '没有数据'

/** For any optional string that came off the wire. */
export function orNoData(value: string | null | undefined): string {
  return value === null || value === undefined || value === '' ? NO_DATA : value
}

function parseAuditAssessment(value: string | AuditAssessment | null | undefined): AuditAssessment | null {
  if (!value)
    return null

  try {
    const parsed: unknown = typeof value === 'string' ? JSON.parse(value) : value
    if (!parsed || typeof parsed !== 'object')
      return null

    const assessment = parsed as Partial<AuditAssessment>
    if (assessment.verdict !== 0 && assessment.verdict !== 1)
      return null
    if (assessment.verdict === 0 && assessment.reproduction_report !== null)
      return null
    if (assessment.verdict === 1 && (!assessment.reproduction_report || typeof assessment.reproduction_report !== 'object'))
      return null
    return assessment as AuditAssessment
  }
  catch {
    return null
  }
}

/** Compact label for the audit task list; preserves the first line of old results. */
export function auditResultPreview(value: string | AuditAssessment | null | undefined): string {
  const assessment = parseAuditAssessment(value)
  if (assessment)
    return assessment.verdict === 1 ? '1 · 有漏洞' : '0 · 无漏洞'
  return typeof value === 'string' ? value.split(/\r?\n/, 1)[0] || NO_DATA : NO_DATA
}

/** Readable JSON for the audit detail panel; old free-form results pass through. */
export function formatAuditResult(value: string | AuditAssessment | null | undefined): string {
  const assessment = parseAuditAssessment(value)
  if (assessment)
    return JSON.stringify(assessment, null, 2)
  return orNoData(typeof value === 'string' ? value : value ? JSON.stringify(value, null, 2) : null)
}

/** Expanded report for vulnerable evaluation samples; null for all other results. */
export function formatReproductionReport(value: string | AuditAssessment | null | undefined): string | null {
  const assessment = parseAuditAssessment(value)
  return assessment?.verdict === 1 && assessment.reproduction_report
    ? JSON.stringify(assessment.reproduction_report, null, 2)
    : null
}

export function formatLatency(ms: number | null): string {
  if (ms === null)
    return NO_DATA
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`
}

export function formatClock(iso: string): string {
  return new Date(iso).toLocaleTimeString('zh-CN', { hour12: false })
}

/** `HH:MM` — short enough for a chart axis tick. */
export function formatTimeShort(iso: string): string {
  return formatClock(iso).slice(0, 5)
}

/** Durations that can run into minutes, for traces and spans. */
export function formatDuration(ms: number | null): string {
  if (ms === null)
    return NO_DATA
  if (ms < 1000)
    return `${Math.round(ms)} ms`
  if (ms < 60_000)
    return `${(ms / 1000).toFixed(1)} s`
  const minutes = Math.floor(ms / 60_000)
  const seconds = Math.round((ms % 60_000) / 1000)
  return `${minutes} 分 ${seconds} 秒`
}

export function formatTokens(value: number | null | undefined): string {
  // 0 is a measurement, not a missing value — only null means "no data".
  if (value === null || value === undefined)
    return NO_DATA
  if (value < 1000)
    return String(value)
  if (value < 1_000_000)
    return `${(value / 1000).toFixed(1)}k`
  return `${(value / 1_000_000).toFixed(1)}M`
}

/** Payload sizes, which run from bytes to megabytes. */
export function formatBytes(value: number | null | undefined): string {
  if (value === null || value === undefined)
    return NO_DATA
  if (value < 1024)
    return `${value} B`
  if (value < 1024 * 1024)
    return `${(value / 1024).toFixed(1)} KB`
  return `${(value / 1024 / 1024).toFixed(1)} MB`
}

export function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

/** Relative phrasing for the "last run" line, e.g. `3 分钟前`. */
export function formatRelative(iso: string): string {
  const seconds = Math.round((Date.now() - new Date(iso).getTime()) / 1000)
  if (seconds < 60)
    return '刚刚'
  if (seconds < 3600)
    return `${Math.floor(seconds / 60)} 分钟前`
  if (seconds < 86400)
    return `${Math.floor(seconds / 3600)} 小时前`
  return `${Math.floor(seconds / 86400)} 天前`
}

export const STATE_LABELS: Record<CheckState, string> = {
  pass: '通过',
  fail: '失败',
  running: '检测中',
  idle: '未检测',
}

/** Vocabulary for where the data came from. */
export const SOURCE_LABELS: Record<Source, string> = {
  live: '实时数据',
  unavailable: '未连接',
}

/** Full digits with thousands separators — for the one headline figure. */
export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined)
    return NO_DATA
  return value.toLocaleString('en-US')
}

/** 万 / 亿, for the compact figures beside the headline. */
export function formatCompact(value: number | null | undefined): string {
  if (value === null || value === undefined)
    return NO_DATA
  if (value < 10_000)
    return value.toLocaleString('en-US')
  if (value < 100_000_000)
    return `${(value / 10_000).toFixed(1)} 万`
  return `${(value / 100_000_000).toFixed(2)} 亿`
}

/** Vocabulary for the audit task lifecycle. */
export const AUDIT_STATUS_LABELS: Record<AuditStatus, string> = {
  queued: '排队中',
  cloning: '拉取中',
  running: '审查中',
  done: '已完成',
  failed: '失败',
  cancelled: '已停止',
}

/** Vocabulary for what an audit covers. */
export const AUDIT_MODE_LABELS: Record<AuditMode, string> = {
  project: '项目检测',
  function: '函数检测',
}

/**
 * Elapsed time from `from` to `to`, or to now when `to` is null — so a task
 * still in flight shows a clock that keeps moving rather than a blank.
 */
export function elapsedLabel(from: string | null, to: string | null): string {
  if (!from)
    return NO_DATA
  return formatDuration(Date.parse(to ?? new Date().toISOString()) - Date.parse(from))
}

/* -------------------------------------------------------------------------- */
/* Benchmark evaluation                                                        */
/* -------------------------------------------------------------------------- */

/** Vocabulary for the evaluation run lifecycle. `interrupted` remains for
 * older bridge responses; current restarts restore unfinished runs as paused. */
export const EVAL_RUN_STATUS_LABELS: Record<EvalRunStatus, string> = {
  queued: '排队中',
  running: '测评中',
  paused: '已暂停',
  done: '已完成',
  interrupted: '已中断',
}

/** Same lifecycle, one sample down. */
export const EVAL_SAMPLE_STATUS_LABELS: Record<EvalSampleStatus, string> = {
  queued: '排队中',
  cloning: '拉取中',
  running: '测评中',
  done: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

/** Which side of a pair a sample audits. */
export const EVAL_SAMPLE_TYPE_LABELS: Record<EvalSampleType, string> = {
  vul: '漏洞版本',
  sec: '修复版本',
}

/** What the dataset labels a sample, and what the agent said about it. */
export const EVAL_LABEL_TEXT: Record<EvalPrediction, string> = {
  vulnerable: '有漏洞',
  'non-vulnerable': '无漏洞',
}

/**
 * The headline metrics. Keys come from the bridge, which computes the numbers;
 * the wording is interface vocabulary, so it lives here with the other labels.
 */
export const EVAL_METRIC_LABELS: Record<string, string> = {
  recall: '召回率',
  fpr: '误报率',
  precision: '精确率',
  f1: 'F1',
  accuracy: '准确率',
  pairCorrectness: 'Pair-Correctness',
  youdenJ: "Youden's J",
}

/** Metrics where a bigger number is better, for colouring them. */
export const EVAL_METRIC_HIGHER_IS_BETTER: Record<string, boolean> = {
  fpr: false,
}

/** `50.00%` — or 「没有数据」 when the ratio is over an empty denominator. */
export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined)
    return NO_DATA
  return `${(value * 100).toFixed(2)}%`
}

/** `50.00% (2/4)`, so the counts behind a ratio are never hidden by it. */
export function formatMetric(metric: EvalMetric | undefined): string {
  if (!metric || metric.value === null)
    return NO_DATA
  if (metric.numerator === null || metric.denominator === null)
    return formatPercent(metric.value)
  return `${formatPercent(metric.value)} (${metric.numerator}/${metric.denominator})`
}
