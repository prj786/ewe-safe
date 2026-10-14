// The dev mock: a plain browser with ?mock=1 gets a fake Safe built from
// docs/PROTOCOL.md's shapes, for UI work and screenshots — no daemon, no
// real secrets. Switches:
//   ?mock=1&locked=0      start unlocked (default: locked)
//   ?mock=1&setup=0       no safe on this machine yet
//   ?mock=1&daemon=0      the service isn't there (daemon-unavailable)
//   ?mock=1&empty=1       a safe with no items
// The master password is "mock"; every revealed value is "mock-<field>".

import fixture from "../../.dev-mock/items.json";

export function install(params) {
  const flag = (k, dflt) => (params.has(k) ? params.get(k) === "1" : dflt);
  const s = {
    daemon: flag("daemon", true),
    setUp: flag("setup", true),
    locked: flag("locked", true),
    items: flag("empty", false) ? [] : structuredClone(fixture),
    deleted: []
  };
  const listeners = { "safe-event": new Set(), "safe-daemon": new Set() };
  const emit = (name, payload) => listeners[name]?.forEach((fn) => fn(payload));
  const fail = (error, message, hint) => ({ ok: false, error, message, ...(hint ? { hint } : {}) });
  const sync = {
    state: "in-sync",
    last: "2026-10-14T16:02:12Z",
    by_machine: "mock-machine",
    pending: false,
    warning: null
  };
  const place = { kind: "nextcloud", location: "ewe/safe/passwords.kdbx", guarded: true };
  const find = (id) => s.items.find((i) => i.id === id);
  const unavailable = () =>
    fail("daemon-unavailable", "Safe's service isn't running (mock).", "systemctl --user start ewe-safe.socket");

  const verbs = {
    daemon_state: () =>
      s.daemon ? { available: true } : { available: false, ...unavailable(), ok: undefined },
    ping: () => ({ ok: true, pong: true }),
    version: () => ({ ok: true, version: "0.1.0-alpha", protocol: 1 }),
    status: () => ({
      ok: true,
      set_up: s.setUp,
      locked: s.locked,
      read_only: false,
      place: s.setUp ? place : null,
      unlock_methods: ["password"],
      items: s.locked ? null : s.items.length,
      sync: s.setUp ? sync : null,
      version: "0.1.0-alpha"
    }),
    summary: () => ({ ok: true, locked: s.locked, items: s.locked ? null : s.items.length, sync_state: sync.state }),
    init: ({ place: p, password }) => {
      if (!password) return fail("bad-request", "A master password is needed.");
      s.setUp = true;
      s.locked = false;
      s.items = [];
      emit("safe-event", { event: "unlocked" });
      return { ok: true, place: { ...place, kind: p?.place ?? "local" } };
    },
    open: ({ password }) => verbs.unlock({ password }),
    unlock: ({ password }) => {
      if (!s.setUp) return fail("not-set-up", "There's no safe on this computer yet.", "ewe-safe init");
      if (password !== "mock") return fail("wrong-key", "That password doesn't open the safe.");
      s.locked = false;
      emit("safe-event", { event: "unlocked" });
      return { ok: true, items: s.items.length };
    },
    lock: () => {
      s.locked = true;
      emit("safe-event", { event: "locked", reason: "user" });
      return { ok: true, locked: true };
    },
    list: ({ kind, tag, deleted }) => {
      const from = deleted ? s.deleted : s.items;
      const items = from
        .filter((i) => !kind || i.kind === kind)
        .filter((i) => !tag || i.tags.includes(tag))
        .sort((a, b) => a.title.localeCompare(b.title));
      return { ok: true, items };
    },
    search: ({ text }) => {
      const q = (text ?? "").toLowerCase();
      return { ok: true, items: s.items.filter((i) => (i.title + " " + i.username + " " + i.urls.join(" ")).toLowerCase().includes(q)) };
    },
    match_items: ({ query }) => ({
      ok: true,
      items: verbs.search({ text: query ?? "" }).items.filter((i) => i.kind === "login").map((i) => ({ ...i, score: 1, reason: "mock" }))
    }),
    show: ({ id }) => {
      const i = find(id);
      return i ? { ok: true, item: { ...i, notes: "" } } : fail("not-found", `No item ${id}.`);
    },
    reveal: ({ id, field }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      return { ok: true, value: `mock-${field}`, ...(field === "otp" ? { expires_in: 17 } : {}) };
    },
    copy: ({ id }) => (find(id) ? { ok: true, cleared_after: 30 } : fail("not-found", `No item ${id}.`)),
    add: ({ item }) => {
      const id = crypto.randomUUID();
      s.items.push({
        id,
        kind: item?.kind ?? "login",
        title: item?.title ?? "Untitled",
        username: item?.username ?? "",
        urls: item?.url ?? [],
        apps: item?.app ?? [],
        tags: item?.tag ?? [],
        folder: item?.folder ?? "",
        has_password: !!(item?.password_value || item?.generate),
        has_otp: false,
        modified: new Date().toISOString().replace(/\.\d+Z$/, "Z")
      });
      emit("safe-event", { event: "changed" });
      return { ok: true, id, sync };
    },
    edit: ({ id, item }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      if (item?.title) i.title = item.title;
      if (item?.username !== undefined) i.username = item.username;
      emit("safe-event", { event: "changed" });
      return { ok: true, sync };
    },
    rm: ({ id }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      s.items = s.items.filter((x) => x !== i);
      s.deleted.push(i);
      emit("safe-event", { event: "changed" });
      return { ok: true, sync };
    },
    restore: ({ id }) => {
      const i = s.deleted.find((x) => x.id === id);
      if (!i) return fail("not-found", `No item ${id}.`);
      s.deleted = s.deleted.filter((x) => x !== i);
      s.items.push(i);
      emit("safe-event", { event: "changed" });
      return { ok: true, sync };
    },
    generate: ({ words }) => (words ? { ok: true, value: "mock-mock-mock-mock-mock", bits: 64 } : { ok: true, value: "mock-generated-Pw-20!", bits: 128 }),
    sync: () => ({ ok: true, sync }),
    place: () => ({ ok: true, place, sync, probe: { guarded: true, checked_at: sync.last } }),
    passwd: ({ newPassword }) => (newPassword ? { ok: true, sync } : fail("bad-request", "A new password is needed."))
  };
  const needsDaemon = (cmd) => cmd !== "daemon_state";
  const needsUnlock = new Set(["list", "search", "match_items", "show", "reveal", "copy", "add", "edit", "rm", "restore"]);

  window.__SAFE_MOCK__ = {
    async invoke(cmd, args) {
      await new Promise((r) => setTimeout(r, 60));
      if (needsDaemon(cmd) && !s.daemon) return unavailable();
      if (needsUnlock.has(cmd) && !s.setUp) return fail("not-set-up", "There's no safe on this computer yet.", "ewe-safe init");
      if (needsUnlock.has(cmd) && s.locked) return fail("locked", "Safe is locked.", "ewe-safe unlock");
      const f = verbs[cmd];
      return f ? f(args ?? {}) : fail("bad-request", `There is no verb "${cmd}".`);
    },
    listen(name, fn) {
      listeners[name]?.add(fn);
      return () => listeners[name]?.delete(fn);
    },
    // for the console: __SAFE_MOCK__.daemonGone() / .daemonBack()
    daemonGone() {
      s.daemon = false;
      emit("safe-daemon", { available: false, ...unavailable(), ok: undefined });
    },
    daemonBack() {
      s.daemon = true;
      emit("safe-daemon", { available: true });
    }
  };
}
