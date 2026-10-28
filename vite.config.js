import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

// https://vite.dev/config/
export default defineConfig(({ command }) => ({
  base: './', // Relative paths: the build works in a domain root, a subdomain or a subfolder
  plugins: [
    vue({
      template: { compilerOptions: { isCustomElement: (tag) => tag.startsWith('altcha-') } },
    }),
    command === 'serve' && vueDevTools(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  build: {
    // No inline data: URIs for scripts/workers, so the strict CSP (script-src 'self') holds.
    assetsInlineLimit: 0,
  },
  worker: { format: 'es' },
  server: {
    // Development: PHP backend on `php -S localhost:8000 -t public` (see README).
    proxy: Object.fromEntries(['/internal', '/go.php', '/static', '/api.php'].map((p) => [p, {
      target: 'http://localhost:8000',
      changeOrigin: false,
    }])),
  },
}))
