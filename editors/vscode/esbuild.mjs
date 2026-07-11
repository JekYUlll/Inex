import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/extension.ts"],
  bundle: true,
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node22",
  outfile: "dist/extension.js",
  sourcemap: true,
  sourcesContent: false,
  logLevel: "info",
});
