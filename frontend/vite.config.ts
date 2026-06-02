import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: [
      'test-lws.tkt-market.ru',
    ],
    proxy: {
      '/api': {
        target: 'http://localhost:3099',
        changeOrigin: true,
      },
      '/ws': {
        target: 'ws://localhost:3099',
        ws: true,
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});