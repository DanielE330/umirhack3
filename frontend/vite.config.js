import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Центр (FastAPI) отдаёт собранный фронтенд под /static, а API — под /api.
// В dev-режиме запросы к /api (включая WebSocket) проксируются на центр.
const API_TARGET = process.env.VITE_API_TARGET || 'http://localhost:4000'

// https://vite.dev/config/
export default defineConfig(({ command }) => ({
  plugins: [react()],
  base: command === 'build' ? '/static/' : '/',
  server: {
    proxy: {
      '/api': { target: API_TARGET, changeOrigin: true, ws: true },
    },
  },
}))
