import { defineConfig } from "vite";
import { resolve } from "path";

export default defineConfig({
  build: {
    outDir: "dist",
    emptyOutDir: true,
    target: "es2020",
    rollupOptions: {
      input: {
        popup: resolve(__dirname, "src/ui/popup/index.html"),
        options: resolve(__dirname, "src/ui/options/index.html"),
        service_worker: resolve(__dirname, "src/background/service_worker.ts")
      },
      output: {
        entryFileNames: "[name].js",
        chunkFileNames: "chunks/[name].js",
        assetFileNames: "assets/[name][extname]"
      }
    }
  }
});
