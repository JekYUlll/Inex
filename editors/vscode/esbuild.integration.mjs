import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["src/integration/suite.ts"],
  bundle: true,
  external: ["vscode"],
  format: "cjs",
  platform: "node",
  target: "node22",
  outfile: "dist/test/suite/index.js",
  sourcemap: false,
  logLevel: "info",
});
