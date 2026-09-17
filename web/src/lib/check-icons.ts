import type { Component } from 'vue'
import {
  BrainIcon,
  BugIcon,
  ContainerIcon,
  DatabaseIcon,
  PlugIcon,
  ScanSearchIcon,
} from '@lucide/vue'

/**
 * The backend names an icon; only the component reference itself cannot cross
 * the wire, so this name → component table lives here. It is keyed by generic
 * icon names rather than by check id, so adding or renaming a check stays a
 * backend-only change and the frontend keeps working.
 */
const ICONS: Record<string, Component> = {
  bug: BugIcon,
  brain: BrainIcon,
  container: ContainerIcon,
  database: DatabaseIcon,
  'scan-search': ScanSearchIcon,
}

/** Used when the backend names an icon this build does not know. */
export const FALLBACK_ICON: Component = PlugIcon

export function checkIcon(name: string | null | undefined): Component {
  return (name && ICONS[name]) || FALLBACK_ICON
}
