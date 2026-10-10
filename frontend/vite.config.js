import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The dev server proxies /api and /health to the FastAPI backend so `npm run dev`
// works against a locally running backend without CORS friction.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/health": "http://127.0.0.1:8000",
    },
  },
});
