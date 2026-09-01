import { defineConfig } from "vite";

export default defineConfig({
  root: ".",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      input: "index.html",
    },
  },
  server: {
    proxy: {
      "/api": "http://localhost:3000",
      "/oauth2": "http://localhost:4180",
    },
  },
});
