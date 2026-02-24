const fs = require("fs");
const path = require("path");

const filesToCopy = [
  { src: "src/manifest.json", dest: "dist/manifest.json" },
  { src: "src/dnr/rules.json", dest: "dist/dnr/rules.json" },
  { src: "src/icons/nyx-alert-128.png", dest: "dist/icons/nyx-alert-128.png" },
  { src: "src/icons/nyx-main-16.png", dest: "dist/icons/nyx-main-16.png" },
  { src: "src/icons/nyx-main-32.png", dest: "dist/icons/nyx-main-32.png" },
  { src: "src/icons/nyx-main-48.png", dest: "dist/icons/nyx-main-48.png" },
  { src: "src/icons/nyx-main-128.png", dest: "dist/icons/nyx-main-128.png" },
  { src: "dist/src/ui/popup/index.html", dest: "dist/popup.html" },
  { src: "dist/src/ui/options/index.html", dest: "dist/options.html" }
];

for (const file of filesToCopy) {
  const from = path.resolve(process.cwd(), file.src);
  const to = path.resolve(process.cwd(), file.dest);
  if (!fs.existsSync(from)) {
    throw new Error(`Missing build artifact: ${from}`);
  }
  fs.mkdirSync(path.dirname(to), { recursive: true });
  fs.copyFileSync(from, to);
}

console.log("Static files copied.");
