import { defineConfig } from "vite";
import solid from "vite-plugin-solid";
export default defineConfig({ plugins: [solid()], resolve: { dedupe: ["solid-js"] }, build: { target: "es2022", sourcemap: false }, server: { port: 4173 } });
