import { defineConfig } from "vite"
import { resolve } from "node:path"

export default defineConfig({
  resolve: {
    alias: [{ find: /^@automerge\/automerge$/, replacement: "@automerge/automerge/slim" }],
  },
  build: {
    // Keep the Vite 7 browser floor when upgrading the bundler.
    target: ["chrome107", "edge107", "firefox104", "safari16"],
    emptyOutDir: false,
    outDir: resolve(import.meta.dirname, "../meta-uber-engineer/assets/mesh"),
    lib: {
      entry: resolve(import.meta.dirname, "apps/meta-site/launcher.ts"),
      formats: ["es"],
      fileName: () => "app.js",
    },
    rolldownOptions: {
      output: { assetFileNames: "[name][extname]", chunkFileNames: "mesh-runtime-[hash].js" },
    },
  },
})
