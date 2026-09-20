import type { Component } from 'vue'
import {
  BotIcon,
  FileSearchIcon,
  LayoutDashboardIcon,
  ListChecksIcon,
} from '@lucide/vue'

export interface NavSection {
  id: string
  /** Route path — each section is its own page. */
  path: string
  title: string
  description: string
  icon: Component
}

export const NAV_SECTIONS: NavSection[] = [
  {
    id: 'overview',
    path: '/overview',
    title: '概览',
    description: 'Token 使用情况',
    icon: LayoutDashboardIcon,
  },
  {
    id: 'env-check',
    path: '/env-check',
    title: '环境检查',
    description: '各依赖项的连通情况',
    icon: ListChecksIcon,
  },
  {
    id: 'audit',
    path: '/audit',
    title: '漏洞审查',
    description: '发起审查任务',
    icon: FileSearchIcon,
  },
  {
    id: 'agent',
    path: '/agent',
    title: 'Agent 监控',
    description: '追踪 Agent 运行情况',
    icon: BotIcon,
  },
]

export function sectionByPath(path: string): NavSection | undefined {
  return NAV_SECTIONS.find(section => section.path === path)
}
