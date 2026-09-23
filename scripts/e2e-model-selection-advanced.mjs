#!/usr/bin/env node
/** Real mounted model picker interactions in isolated Electron fixtures. */
import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { mkdtemp, mkdir, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { resolveElectronBinary } from "./e2e/boot.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(root, "packages/agent-runtime/package.json"));
const { build } = require("esbuild");
const { electronBinary } = resolveElectronBinary(root);
const screenshots = join(root, ".cache", "model-advanced-selection");
await mkdir(screenshots, { recursive: true });
const source = join(root, "apps/desktop/src/components/settings/ModelSelectionPanes.tsx");
const baselineRef = process.env.PI_MODEL_BASELINE_REF;
const previous = baselineRef && execFileSync("git", ["show", `${baselineRef}:apps/desktop/src/components/settings/ModelSelectionPanes.tsx`], {
  cwd: root, encoding: "utf8",
});

for (const [version, before] of baselineRef ? [["before", true], ["after", false]] : [["after", false]]) {
  const temp = await mkdtemp(join(tmpdir(), `pi-model-selection-${version}-`));
  try {
    await build({
      entryPoints: [join(root, "scripts/e2e/model-selection-advanced.tsx")],
      outfile: join(temp, "renderer.js"), bundle: true, platform: "browser", format: "iife", jsx: "automatic",
      define: { "process.env.NODE_ENV": '"production"' },
      loader: { ".woff": "file", ".woff2": "file", ".ttf": "file" },
      alias: {
        "@pi-desktop/i18n": join(root, "packages/i18n/src/index.ts"),
        react: join(root, "apps/desktop/node_modules/react"),
        "react-dom": join(root, "apps/desktop/node_modules/react-dom"),
      },
      nodePaths: [join(root, "apps/desktop/node_modules")],
      ...(before ? { plugins: [{ name: "baseline-picker", setup(plugin) {
        plugin.onLoad({ filter: /ModelSelectionPanes\.tsx$/ }, (args) =>
          args.path === source ? { contents: previous, loader: "tsx", resolveDir: dirname(source) } : null);
      } }] } : {}),
    });
    await writeFile(join(temp, "index.html"),
      '<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src \'self\'; style-src \'self\' \'unsafe-inline\'"><link rel="stylesheet" href="renderer.css"><title>Model Advanced selection fixture</title></head><body><script src="renderer.js"></script></body></html>');
    await writeFile(join(temp, "main.cjs"), `
const { app, BrowserWindow } = require("electron");
const { writeFile } = require("node:fs/promises");
const path = require("node:path");
app.commandLine.appendSwitch("disable-gpu");
app.disableHardwareAcceleration();
app.setPath("userData", path.join(__dirname, "profile"));
app.whenReady().then(async () => {
  const window = new BrowserWindow({ show: false, title: "Model Advanced ${version} fixture", width: 1280, height: 780,
    webPreferences: { offscreen: true, sandbox: true, contextIsolation: true, nodeIntegration: false } });
  try {
    await window.loadFile(path.join(__dirname, "index.html"));
    const selected = await window.webContents.executeJavaScript('globalThis.modelSelectionProbe("select")');
    await window.webContents.executeJavaScript("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)))");
    await writeFile(${JSON.stringify(join(screenshots, `${version}.png`))}, await window.webContents.capturePage().then(image => image.toPNG()));
    const remaining = await window.webContents.executeJavaScript('globalThis.modelSelectionProbe("finish")');
    console.log("MODEL_SELECTION_PROBE " + JSON.stringify({ selected, remaining }));
    app.quit();
  } catch (error) {
    console.error("MODEL_SELECTION_PROBE " + JSON.stringify({ error: String(error) }));
    app.exit(1);
  }
});
`);
    const env = { ...process.env };
    delete env.ELECTRON_RUN_AS_NODE;
    const child = spawn(electronBinary, [join(temp, "main.cjs")], { env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    for (const stream of [child.stdout, child.stderr]) stream.on("data", (chunk) => { output += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 45_000);
    let code;
    try { code = await new Promise((resolve, reject) => { child.once("error", reject); child.once("close", resolve); }); }
    finally { clearTimeout(timer); }
    const line = output.split(/\r?\n/).find((entry) => entry.startsWith("MODEL_SELECTION_PROBE "));
    assert(line, `${version} fixture did not report (exit ${code}): ${output.slice(-1800)}`);
    const result = JSON.parse(line.slice("MODEL_SELECTION_PROBE ".length));
    assert.equal(code, 0, output.slice(-1800));
    assert(!result.error, result.error);
    const expected = before ? { "fixture-a": "true", "fixture-b": "false" } : { "fixture-a": "false", "fixture-b": "true" };
    assert.deepEqual(result.selected.afterSelection, expected);
    assert.equal(result.remaining.manuallyClosed, !before);
    assert.equal(result.remaining.manuallyReopened, !before);
    assert.equal(result.remaining.afterLastSelection["fixture-e"], "true");
    if (!before) assert.equal(result.remaining.lastHeadingVisible, true);
    assert.equal(result.remaining.afterBulk["fixture-e"], "true");
    assert.equal(result.remaining.afterDeepSelection["fixture-p"], before ? "false" : "true");
    if (!before) {
      assert(result.remaining.deepScrollTop > 0, JSON.stringify(result.remaining));
      assert.equal(result.remaining.deepHeadingVisible, true);
    }
    assert.equal(result.remaining.unchangedLimits, true);
    assert.deepEqual(result.remaining.modelIds, ["fixture-a", "fixture-b", "fixture-e", ..."cdfghijklmnop".split("").map((letter) => `fixture-${letter}`), "custom-fixture"]);
    assert.equal(result.remaining.allRowsRemain, true, JSON.stringify(result));
    assert.equal(result.remaining.afterCustom["custom-fixture"], "true");
    console.log(`PASS ${version}: ${JSON.stringify(result)}; screenshot=${join(screenshots, `${version}.png`)}`);
  } finally {
    const tempRoot = await realpath(tmpdir());
    const tempActual = await realpath(temp);
    if (!tempActual.startsWith(tempRoot + sep)) throw Error("fixture path escaped the temporary directory");
    await rm(tempActual, { recursive: true, force: true });
  }
}
