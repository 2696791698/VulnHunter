import { createRouter, createWebHistory } from 'vue-router'

/* Every section is its own route and its own lazily-loaded chunk, so the first
 * paint only ships the overview. */
const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    { path: '/', redirect: '/overview' },
    {
      path: '/overview',
      name: 'overview',
      component: () => import('@/pages/OverviewPage.vue'),
      meta: { title: '概览' },
    },
    {
      path: '/env-check',
      name: 'env-check',
      component: () => import('@/pages/ChecksPage.vue'),
      meta: { title: '环境检查' },
    },
    {
      path: '/audit',
      name: 'audit',
      component: () => import('@/pages/AuditPage.vue'),
      meta: { title: '漏洞审查' },
    },
    {
      path: '/agent',
      name: 'agent',
      component: () => import('@/pages/AgentPage.vue'),
      meta: { title: 'Agent 监控' },
    },
    { path: '/:pathMatch(.*)*', redirect: '/overview' },
  ],
  scrollBehavior(to, _from, saved) {
    if (saved)
      return saved
    // Deep links like /env-check#check-codeql land on the right card.
    if (to.hash)
      return { el: to.hash, behavior: 'smooth' }
    return { top: 0 }
  },
})

export default router
