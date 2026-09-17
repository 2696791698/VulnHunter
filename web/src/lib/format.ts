import type { AuditStatus, CheckState, Source } from './types'

/**
 * Shown wherever the backend reported nothing. The UI never guesses a value or
 * fills the gap with a placeholder of its own.
 */
export const NO_DATA = '没有数据'

/** For any optional string that came off the wire. */
export function orNoData(value: string | null | undefined): string {
  return value === null || value === undefined || value === '' ? NO_DATA : value
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
