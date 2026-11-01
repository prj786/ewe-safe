// The window's guards that need no browser (node --test, no packages):
// - every <button> says its type: a button inside a form without one
//   submits it (the generator's Words/Close/dice once saved the item);
// - the sync state uses ewe Sync's words, one table for the whole window;
// - the display name is "ewe Safe" where people see it, and the launcher
//   still finds it by "passwords" — the binaries and ids stay `ewe-safe`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { SYNC_WORDS, syncLine, syncState, syncWhere } from "../src/lib/format.js";

const app = join(dirname(fileURLToPath(import.meta.url)), "..");
const read = (p) => readFileSync(join(app, p), "utf8");

function svelteFiles(dir) {
  return readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? svelteFiles(p) : p.endsWith(".svelte") ? [p] : [];
  });
}

test("every button declares its type", () => {
  const missing = [];
  for (const f of svelteFiles(join(app, "src"))) {
    const src = readFileSync(f, "utf8");
    for (const tag of src.match(/<button\b[^>]*?>/gs) ?? []) {
      if (!/\btype=/.test(tag)) missing.push(`${f.slice(app.length + 1)}: ${tag.replace(/\s+/g, " ").slice(0, 80)}`);
    }
  }
  assert.deepEqual(missing, []);
});

test("the generator never submits the editor's form", () => {
  const src = read("src/lib/components/Generator.svelte");
  const tags = src.match(/<button\b[^>]*?>/gs) ?? [];
  assert.ok(tags.length >= 5, "the generator has its buttons");
  for (const tag of tags) assert.match(tag, /type="button"/);
});

test("the sync words are ewe Sync's", () => {
  const word = (sync) => syncState(sync)?.word;
  assert.equal(word({ state: "in-sync" }), "Up to date");
  assert.equal(word({ state: "pending" }), "Waiting to upload");
  assert.equal(word({ state: "offline" }), "Offline");
  assert.equal(word({ state: "error" }), "Couldn’t sync");
  assert.equal(word({ state: "local" }), "On this computer only");
  assert.equal(word({ state: "in-sync", warning: "rollback" }), "Needs attention");
  assert.equal(word({ state: "in-sync", warning: "single-writer" }), "Needs attention");
  assert.equal(syncState(null), null);
  assert.equal(syncState({ state: "unknown" }), null);
  // one table: every state has a word, a tone and an icon
  for (const s of Object.values(SYNC_WORDS)) assert.ok(s.word && s.tone && s.icon);
});

test("the rail and an item's foot say the same thing", () => {
  const now = new Date("2026-11-01T12:00:00Z");
  const last = new Date(now - 2 * 60000).toISOString();
  assert.equal(syncLine({ state: "in-sync", last }, now).text, "Up to date · 2 min ago");
  assert.equal(syncLine({ state: "pending", last }, now).text, "Waiting to upload");
  assert.equal(syncWhere({ state: "in-sync" }, { kind: "nextcloud" }), "Up to date in your ewe account");
  assert.equal(syncWhere({ state: "local" }, { kind: "local" }), "On this computer only");
});

test("the display name is ewe Safe; search still finds passwords", () => {
  assert.match(read("index.html"), /<title>ewe Safe<\/title>/);
  assert.equal(JSON.parse(read("src-tauri/tauri.conf.json")).productName, "ewe Safe");
  const desktop = read("../packaging/ewe-safe.desktop");
  assert.match(desktop, /^Name=ewe Safe$/m);
  assert.match(desktop, /^Exec=ewe-safe-app$/m);
  assert.match(desktop, /^Keywords=.*\bpasswords\b/m);
  const lib = read("src-tauri/src/lib.rs");
  assert.match(lib, /\.title\("ewe Safe"\)/);
  assert.match(lib, /\.title\("Unlock ewe Safe"\)/);
});
