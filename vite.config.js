import { fileURLToPath, URL } from 'node:url'

import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import vueDevTools from 'vite-plugin-vue-devtools'

// https://vite.dev/config/
export default defineConfig({
  base: './', // Relative paths for assets
  plugins: [
    vue(),
    vueDevTools(),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    },
  },
  server: {
    proxy: {
      // Proxy API requests to PHP server during development
      '/api.php': 'http://localhost:8000',
      // Proxy short codes (if needed for testing redirects in dev)
      // Note: This might conflict with Vite's history fallback if not careful
      // For now, we focus on API.
    }
  }
})
