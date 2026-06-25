import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The built app is served behind the fastscan-ui Go server under its own path,
// so assets are referenced relatively (base "./"). The dev server proxies the
// API + SSE stream to the running engine on :8888.
export default defineConfig({
  base: './',
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8888',
        changeOrigin: true,
      },
    },
  },
})
