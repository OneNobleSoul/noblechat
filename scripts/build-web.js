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

// The nym transport ships as its own bundle: it embeds a multi-megabyte WASM
// SDK, so it must not weigh down the main client. main.js loads it lazily, only
// when the nym transport is active.
await esbuild.build({
  entryPoints: ["apps/web/src/nym-transport.js"],
  bundle: true,
  format: "iife",
  target: ["es2020"],
  outfile: "apps/web/public/nym-transport.bundle.js",
  legalComments: "none",
  logLevel: "info",
});
console.log("nym transport bundled → apps/web/public/nym-transport.bundle.js");
