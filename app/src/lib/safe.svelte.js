// The page's state of Safe, in Svelte 5 runes, kept in step by the
// daemon's events. Screens read `safe.*` and call its methods; nothing else
// talks to the backend.
//
// - `daemon`: {available, message?, hint?} — when Safe's service can't be
//   reached the page says so with the hint, never spins.
// - `status`: the last `status` reply (PROTOCOL.md), or null.
// - `items`: the item summaries — never a secret.
// - `error`: the last failed reply ({error, message, hint?}), cleared by the
//   next success.
// - `busy`: the verb in flight, or "" — every call ends (the window's
//   commands all have the protocol's wait).
//
// A revealed value is returned to the caller and never kept here.

import { api, listen } from "./api.js";

class Safe {
  daemon = $state({ available: true });
  status = $state(null);
  items = $state([]);
  deleted = $state([]);
  error = $state(null);
  busy = $state("");
  // `[safe]` from ewe.conf (through ewe-conf): lock and clipboard settings,
  // and where a safe lives when this machine has none yet
  settings = $state({});
  // the copy in the place has a new master key (changed elsewhere)
  keyChanged = $state(false);
  // a counter the screens watch to reload what they show (an item's notes)
  changes = $state(0);

  #unlisten = [];

  get locked() {
    return this.status?.locked ?? true;
  }

  get setUp() {
    return this.status?.set_up ?? false;
  }

  /** Call once, when the page mounts. */
  async start() {
    this.#unlisten.push(
      await listen("safe-daemon", (d) => {
        this.daemon = d ?? { available: false };
        if (d?.available) this.refresh();
      }),
      await listen("safe-event", (e) => this.#onEvent(e))
    );
    const d = await api.daemonState();
    if (d && typeof d.available === "boolean") this.daemon = d;
    await this.refresh();
  }

  stop() {
    this.#unlisten.forEach((u) => u?.());
    this.#unlisten = [];
  }

  #onEvent(e) {
    switch (e?.event) {
      case "unlocked":
        this.keyChanged = false;
        this.refresh();
        break;
      case "changed":
        this.changes += 1;
        this.refresh();
        break;
      case "locked":
        this.items = [];
        this.deleted = [];
        this.refresh();
        break;
      case "sync":
        if (this.status) this.status = { ...this.status, sync: e.sync };
        break;
    }
  }

  /** One reply: note an error, note the daemon's absence, return it. */
  #take(r) {
    if (r?.ok) {
      this.error = null;
    } else {
      this.error = r ? { error: r.error, message: r.message, hint: r.hint } : null;
      if (r?.error === "key-changed") this.keyChanged = true;
      if (r?.error === "daemon-unavailable") {
        this.daemon = { available: false, message: r.message, hint: r.hint };
      }
    }
    return r;
  }

  async #run(verb, f) {
    this.busy = verb;
    try {
      return this.#take(await f());
    } finally {
      this.busy = "";
    }
  }

  async refresh() {
    const r = this.#take(await api.status());
    if (!r?.ok) return r;
    this.daemon = { available: true };
    this.status = r;
    if (r.set_up && !r.locked) await this.loadItems();
    else this.items = [];
    return r;
  }

  async loadItems(filter = {}) {
    const r = this.#take(await api.list(filter));
    if (r?.ok) this.items = r.items ?? [];
    const d = await api.list({ deleted: true });
    if (d?.ok) this.deleted = d.items ?? [];
    return r;
  }

  get readOnly() {
    return this.status?.read_only ?? false;
  }

  async loadSettings() {
    const r = await api.settingsGet();
    if (r?.ok) this.settings = r.settings ?? {};
    return this.settings;
  }

  /** One `[safe]` setting through ewe-conf; the daemon reads it again. */
  async setSetting(key, value) {
    const before = this.settings[key];
    this.settings = { ...this.settings, [key]: value };
    const r = await api.settingsSet(key, value);
    if (!r?.ok) this.settings = { ...this.settings, [key]: before };
    return r;
  }

  /** A new safe: place = {place, location?}; the password is passed on. */
  async create(place, password) {
    const r = await this.#run("init", () => api.init(place, password));
    if (r?.ok) await this.refresh();
    return r;
  }

  /** An existing safe file or the account's safe. */
  async openSafe(place, password) {
    const r = await this.#run("open", () => api.open(place, password));
    if (r?.ok) await this.refresh();
    return r;
  }

  async show(id) {
    return this.#take(await api.show(id));
  }

  async passwd(newPassword, current) {
    return this.#run("passwd", () => api.passwd(current, newPassword));
  }

  async importItems(opts) {
    const r = await this.#run(opts.dryRun ? "import-check" : "import", () => api.importItems(opts));
    if (r?.ok && !opts.dryRun) await this.refresh();
    return r;
  }

  /** The password is passed straight through; the page clears its field. */
  async unlock(password) {
    const r = await this.#run("unlock", () => api.unlock(password));
    if (r?.ok) {
      this.keyChanged = false;
      await this.refresh();
    }
    return r;
  }

  async lock() {
    const r = await this.#run("lock", () => api.lock());
    if (r?.ok) await this.refresh();
    return r;
  }

  async search(text) {
    const r = this.#take(await api.search(text));
    return r?.ok ? r.items : [];
  }

  /** One field of one item, for the caller to show briefly and drop. */
  async reveal(id, field) {
    const r = this.#take(await api.reveal(id, field));
    return r?.ok ? r.value : null;
  }

  /** `clearAfter` 0 keeps it on the clipboard (a public key). */
  copy(id, field, clearAfter) {
    return this.#run("copy", () => api.copy(id, field, clearAfter));
  }

  add(item) {
    return this.#run("add", () => api.add(item));
  }

  edit(id, item) {
    return this.#run("edit", () => api.edit(id, item));
  }

  remove(id) {
    return this.#run("rm", () => api.rm(id));
  }

  restore(id) {
    return this.#run("restore", () => api.restore(id));
  }

  generate(opts) {
    return api.generate(opts);
  }

  /** A key file in (its passphrase is passed straight through). */
  async sshAdd(opts) {
    const r = await this.#run("ssh-add", () => api.sshAdd(opts));
    if (r?.ok) await this.loadItems();
    return r;
  }

  async sshNew(opts) {
    const r = await this.#run("ssh-new", () => api.sshNew(opts));
    if (r?.ok) await this.loadItems();
    return r;
  }

  sshStatus() {
    return api.sshStatus();
  }

  sshEnable(confirm) {
    return this.#run("ssh-enable", () => api.sshEnable(confirm));
  }

  sync() {
    return this.#run("sync", () => api.sync());
  }
}

export const safe = new Safe();
