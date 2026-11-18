import { fileURLToPath, URL } from "node:url"
import tailwindcss from "@tailwindcss/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

export default defineConfig({
  base: "./",
  plugins: [
    react(),
    tailwindcss(),
    {
      name: "desktop-content-policy",
      apply: "build",
      transformIndexHtml: {
        order: "pre",
        handler: () => [{
          tag: "meta",
          attrs: {
            "http-equiv": "Content-Security-Policy",
            content: "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'",
          },
          injectTo: "head-prepend",
        }],
      },
    },
  ],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  build: {
    target: "chrome110",
  },
})
