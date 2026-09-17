<script setup lang="ts">
import TokenTrendChart from '@/components/dashboard/TokenTrendChart.vue'
import TokenUsageCard from '@/components/dashboard/TokenUsageCard.vue'
import { Skeleton } from '@/components/ui/skeleton'
import { useTokenUsage } from '@/composables/useTokenUsage'

const { totals, buckets, interval, intervals, loading } = useTokenUsage()
</script>

<template>
  <section class="flex flex-col gap-4 px-4 md:gap-6 lg:px-6">
    <template v-if="loading">
      <Skeleton class="h-56 rounded-xl" />
      <Skeleton class="h-[400px] rounded-xl" />
    </template>

    <template v-else>
      <TokenUsageCard :totals="totals" />
      <TokenTrendChart
        v-model:interval="interval"
        :buckets="buckets"
        :intervals="intervals"
      />
    </template>
  </section>
</template>
