import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The Go server embeds dist/app. In dev, API calls go to a local lookout-server.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: { outDir: "dist/app", emptyOutDir: true },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
