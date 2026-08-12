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

// The landing page is a single static file with no client code of its own, so
// the coming-soon curtain gets its own tiny bundle instead of pulling in the
// whole chat client.
await esbuild.build({
  entryPoints: ["apps/web/src/landing-gate.js"],
  bundle: true,
  format: "iife",
  target: ["es2020"],
  outfile: "apps/web/public/landing-gate.js",
  legalComments: "none",
  logLevel: "info",
});
console.log("landing gate bundled → apps/web/public/landing-gate.js");

// The admin panel is bundled too, so it can share the auth secret derivation
// with the chat client rather than keeping a second copy of the KDF in sync.
await esbuild.build({
  entryPoints: ["apps/web/src/admin.js"],
  bundle: true,
  format: "iife",
  target: ["es2020"],
  outfile: "apps/web/public/admin.js",
  legalComments: "none",
  logLevel: "info",
});
console.log("admin panel bundled → apps/web/public/admin.js");

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
