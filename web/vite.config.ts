import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false, target: 'es2022', assetsInlineLimit: 0 },
  server: {
    port: 5173,
    proxy: { '/v1': { target: 'http://localhost:8080', ws: true } },
  },
});
