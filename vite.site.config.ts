import { defineConfig } from "vite"
import { resolve } from "node:path"

export default defineConfig({
  resolve: {
    alias: [{ find: /^@automerge\/automerge$/, replacement: "@automerge/automerge/slim" }],
  },
  build: {
    emptyOutDir: false,
    outDir: resolve(import.meta.dirname, "../meta-uber-engineer/assets/mesh"),
    lib: {
      entry: resolve(import.meta.dirname, "apps/meta-site/launcher.ts"),
      formats: ["es"],
      fileName: () => "app.js",
    },
    rollupOptions: {
      output: { assetFileNames: "[name][extname]", chunkFileNames: "mesh-runtime-[hash].js" },
    },
  },
})
