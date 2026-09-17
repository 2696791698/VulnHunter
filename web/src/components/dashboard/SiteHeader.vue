<script setup lang="ts">
import { computed } from 'vue'
import { RouterLink, useRoute } from 'vue-router'
import { Badge } from '@/components/ui/badge'
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from '@/components/ui/breadcrumb'
import { Separator } from '@/components/ui/separator'
import { SidebarTrigger } from '@/components/ui/sidebar'
import { SOURCE_LABELS } from '@/lib/format'
import { sectionByPath } from '@/lib/navigation'
import type { Source } from '@/lib/types'

defineProps<{
  source: Source
  detail: string
}>()

const route = useRoute()

const title = computed(() => (route.meta.title as string | undefined) ?? '概览')
const section = computed(() => sectionByPath(route.path))
</script>

<template>
  <header class="flex h-(--header-height) shrink-0 items-center gap-2 border-b transition-[width,height] ease-linear group-has-data-[collapsible=icon]/sidebar-wrapper:h-(--header-height)">
    <div class="flex w-full items-center gap-1 px-4 lg:gap-2 lg:px-6">
      <SidebarTrigger class="-ml-1" />
      <Separator orientation="vertical" class="mx-2 data-[orientation=vertical]:h-4" />

      <Breadcrumb>
        <BreadcrumbList>
          <BreadcrumbItem class="hidden md:block">
            <BreadcrumbLink as-child>
              <RouterLink to="/overview">
                VulnHunter
              </RouterLink>
            </BreadcrumbLink>
          </BreadcrumbItem>
          <BreadcrumbSeparator class="hidden md:block" />
          <BreadcrumbItem>
            <BreadcrumbPage>{{ title }}</BreadcrumbPage>
          </BreadcrumbItem>
        </BreadcrumbList>
      </Breadcrumb>

      <p v-if="section" class="text-muted-foreground ml-2 hidden truncate text-sm lg:block">
        {{ section.description }}
      </p>

      <div class="ml-auto flex items-center gap-2">
        <span class="text-muted-foreground hidden text-xs sm:block">{{ detail }}</span>
        <Badge :variant="source === 'live' ? 'secondary' : 'outline'">
          {{ SOURCE_LABELS[source] }}
        </Badge>
      </div>
    </div>
  </header>
</template>
