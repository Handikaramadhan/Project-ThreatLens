import { defineConfig } from "vite";

const apiTarget = process.env.THREATLENS_API_TARGET;

export default defineConfig({
  server: {
    proxy: apiTarget ? { "/api": { target: apiTarget, changeOrigin: true } } : undefined,
  },
});
