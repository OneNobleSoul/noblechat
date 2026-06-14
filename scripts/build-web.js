import * as esbuild from "esbuild";

await esbuild.build({
  entryPoints: ["apps/web/src/main.js"],
  bundle: true,
  format: "iife",
  target: ["es2020"],
  outfile: "apps/web/public/app.bundle.js",
  legalComments: "none",
  logLevel: "info",
});
console.log("web client bundled → apps/web/public/app.bundle.js");
