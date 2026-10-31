import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

const r = (p: string) => resolve(import.meta.dirname, p);

export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    // Sem source maps em produção: não expõe o código-fonte original.
    sourcemap: false,
    target: "es2020",
    cssCodeSplit: true,
    // Nada embutido como data: URL. Mantém a CSP restrita (font-src 'self').
    assetsInlineLimit: 0,
    rollupOptions: {
      input: {
        main: r("index.html"),
        privacidade: r("privacidade/index.html"),
        termos: r("termos/index.html"),
        notfound: r("404.html"),
      },
    },
  },
  server: { host: true },
});
