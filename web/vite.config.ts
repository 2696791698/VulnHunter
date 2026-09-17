import { fileURLToPath, URL } from 'node:url'
import tailwindcss from '@tailwindcss/vite'
import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [vue(), tailwindcss()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    // Honour an assigned PORT so several preview sessions can run side by side.
    port: Number(process.env.PORT) || 5173,
    proxy: {
      // The Python bridge in `server/` is optional — when it is not listening the
      // app falls back to its built-in demo data. Keep BRIDGE_PORT in sync with
      // `server/main.py` and `agent_tracing.py`.
      '/api': {
        target: `http://127.0.0.1:${process.env.BRIDGE_PORT ?? '8901'}`,
        changeOrigin: true,
      },
    },
  },
})
