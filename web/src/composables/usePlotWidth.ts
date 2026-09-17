import { nextTick, onMounted, onUnmounted, ref } from 'vue'

/**
 * Width of a plot container, measured before the chart is allowed to mount.
 *
 * Unovis sizes itself against the container while initialising, so it must not
 * be created against a box the browser has not laid out yet. Two details make
 * this less obvious than it looks:
 *
 * - The measurement is taken synchronously, because `getBoundingClientRect`
 *   forces layout, whereas a ResizeObserver callback is delivered from the
 *   rendering step — which a hidden tab suspends entirely.
 * - If even that first measurement reads zero (a pane with no size yet), a
 *   timer keeps re-measuring, so the gate can never stay shut forever. A timer
 *   still fires when the tab is hidden; an animation frame does not.
 */
export function usePlotWidth() {
  const plotRef = ref<HTMLElement | null>(null)
  const plotWidth = ref(0)

  let observer: ResizeObserver | null = null
  let retry: ReturnType<typeof setInterval> | null = null

  function measure() {
    const width = Math.round(plotRef.value?.getBoundingClientRect().width ?? 0)
    if (width > 0 && width !== plotWidth.value)
      plotWidth.value = width
  }

  onMounted(async () => {
    await nextTick()
    measure()

    observer = new ResizeObserver(measure)
    if (plotRef.value)
      observer.observe(plotRef.value)

    retry = setInterval(() => {
      measure()
      if (plotWidth.value > 0 && retry) {
        clearInterval(retry)
        retry = null
      }
    }, 400)
  })

  onUnmounted(() => {
    observer?.disconnect()
    if (retry)
      clearInterval(retry)
  })

  return { plotRef, plotWidth }
}
