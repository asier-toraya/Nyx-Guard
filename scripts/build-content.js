const esbuild = require("esbuild");
const path = require("path");

const entry = path.resolve(__dirname, "..", "src", "content", "content_script.ts");
const outfile = path.resolve(__dirname, "..", "dist", "content_script.js");

esbuild
  .build({
    entryPoints: [entry],
    bundle: true,
    outfile,
    format: "iife",
    target: "es2020",
    platform: "browser",
    sourcemap: false,
    legalComments: "none",
    logLevel: "info"
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
