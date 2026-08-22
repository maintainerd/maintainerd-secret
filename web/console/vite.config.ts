import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [
    react(),
    /** Tailwind/Shadcn */
    tailwindcss(),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  /** Production build configuration */
  build: {
    // Never emit source maps: this console handles credential material, and a
    // source map would publish its original TypeScript alongside the bundle.
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'data-vendor': ['@tanstack/react-query', 'axios'],
          'form-vendor': ['react-hook-form', '@hookform/resolvers', 'zod'],
          'ui-vendor': [
            '@radix-ui/react-checkbox', '@radix-ui/react-dialog',
            '@radix-ui/react-dropdown-menu', '@radix-ui/react-label',
            '@radix-ui/react-popover', '@radix-ui/react-select',
            '@radix-ui/react-separator', '@radix-ui/react-slot',
            '@radix-ui/react-switch', '@radix-ui/react-tabs',
            '@radix-ui/react-tooltip', 'lucide-react',
          ],
          'util-vendor': ['date-fns', 'clsx', 'tailwind-merge', 'class-variance-authority'],
        },
      },
    },
  },
  /** Development server configuration */
  server: {
    allowedHosts: ['.maintainerd.local'],
    watch: {
      ignored: ['**/coverage/**'],
    },
    proxy: {
      // Proxy REST calls to secret's own API through the maintainerd-dev nginx
      // edge, which routes console-api.secret.maintainerd.local to m9d-secret:8092.
      // Same-origin `/api/v1` in the browser keeps the bearer token off any
      // cross-origin preflight.
      '/api': {
        target: 'https://console-api.secret.maintainerd.local',
        changeOrigin: true,
        secure: false,
        configure: (proxy) => {
          proxy.on('error', (err) => {
            console.log('Proxy error:', err)
          })
        },
      },
    },
  },
  test: {
    globals: true,
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    testTimeout: 15000,
  },
})
