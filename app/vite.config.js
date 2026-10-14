import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// The ewe-sync shape: plain Vite (no SvelteKit). Tailwind and the design
// system's component classes come with the screens; the plumbing only needs
// the token layer (src/tokens.css).
export default defineConfig({
  plugins: [svelte()],
  resolve: {
    alias: {
      $lib: fileURLToPath(new URL("./src/lib", import.meta.url))
    }
  },
  clearScreen: false,
  server: {
    port: 5176,
    strictPort: true,
    watch: { ignored: ["**/src-tauri/**"] }
  },
  envPrefix: ["VITE_", "TAURI_ENV_"],
  build: {
    target: "chrome105",
    minify: true,
    sourcemap: false
  }
});
