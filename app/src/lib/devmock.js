// The dev mock: a plain browser with ?mock=1 gets a fake Safe built from
// docs/PROTOCOL.md's shapes and the mockup's sample data ("Sam"), for UI
// work and screenshots — no daemon, no real secrets. Switches:
//   ?mock=1&locked=0      start unlocked (default: locked)
//   &setup=0              no safe on this machine yet; &known=nextcloud: ewe.conf
//                         already names one (a restored machine); &signedin=0
//   &step=place|password|kit   where setup starts
//   &daemon=0             the service isn't there (daemon-unavailable)
//   &empty=1              a safe with no items     &readonly=1  read-only
//   &sync=pending|offline|error|local|rollback|single-writer
//   &keychanged=1         unlocking says the master password changed elsewhere
//   &wrong=1              the first unlock is a wrong password
//   &login=1              login unlock is on (the login password is "login")
//   &mode=unlock          the compact `--unlock` window
//   &mode=approve         the SSH agent's question (`--approve`); &system=0 a
//                         program outside /usr and /opt
//   &mode=confirm         a card fill's confirm (`--confirm`); &reason=…
//   &view=ssh             the SSH keys      &agent=1   the SSH agent on
//   &view=settings|import|trash   &edit=github|new   &gen=1 (generator open)
//   &import=old           the daemon has no `import` verb yet
//   &light=1              Ewe Light (the real token map, .dev-mock/theme-light.json)
// The master password is "mock".

import fixture from "../../.dev-mock/items.json";
import light from "../../.dev-mock/theme-light.json";

export function install(params) {
  const flag = (k, dflt) => (params.has(k) ? params.get(k) === "1" : dflt);
  const clone = (x) => structuredClone(x);
  const s = {
    daemon: flag("daemon", true),
    setUp: flag("setup", true),
    locked: flag("locked", true),
    readOnly: flag("readonly", false),
    keyChanged: flag("keychanged", false),
    wrong: flag("wrong", false),
    loginEnabled: flag("login", false),
    superP: params.get("superp") || "1password",
    items: flag("empty", false) ? [] : clone(fixture.items),
    deleted: flag("empty", false) ? [] : clone(fixture.deleted),
    settings: {
      lock_after_minutes: 30,
      lock_on_screen_lock: true,
      lock_on_sleep: true,
      clipboard_clear_seconds: 30,
      generator_length: 20,
      generator_words: 5,
      unlock_at_login: true,
      ...(params.get("known") ? { place: params.get("known"), location: "ewe/safe/passwords.kdbx" } : {})
    },
    agent: flag("agent", false)
  };
  // an SSH key (TRIO.md S2): the fixture has none
  const sshKey = (title, type, n) => ({
    id: crypto.randomUUID(),
    kind: "ssh-key",
    title,
    username: "",
    urls: [],
    apps: [],
    tags: [],
    folder: "",
    has_password: false,
    has_otp: false,
    modified: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    ssh: {
      public_key: `${type === "rsa" ? "ssh-rsa" : "ssh-ed25519"} AAAAC3NzaC1lZDI1NTE5AAAAIMock${n}KeyForTheWindowOnlyXXXXXXXXXXXXXXXX ${title}`,
      fingerprint: `SHA256:mock${n}Kp3zQ9xVt1bW7uYc2nRj8eLh5aGfD0sT4oM6iN`,
      key_type: type,
      agent: true
    },
    passkey: null,
    _notes: ""
  });
  if (!flag("empty", false)) s.items.push(sshKey("GitHub key", "ed25519", 1));
  const listeners = { "safe-event": new Set(), "safe-daemon": new Set(), "safe-args": new Set() };
  const emit = (name, payload) => listeners[name]?.forEach((fn) => fn(payload));
  const fail = (error, message, hint) => ({ ok: false, error, message, ...(hint ? { hint } : {}) });
  const minsAgo = (m) => new Date(Date.now() - m * 60000).toISOString().replace(/\.\d+Z$/, "Z");
  const syncKind = params.get("sync") ?? "in-sync";
  const sync = {
    state: ["rollback", "single-writer"].includes(syncKind) ? "in-sync" : syncKind,
    last: minsAgo(2),
    by_machine: "laptop",
    pending: syncKind === "pending",
    warning: ["rollback", "single-writer"].includes(syncKind) ? syncKind : null
  };
  const place = { kind: syncKind === "local" ? "local" : "nextcloud", location: "ewe/safe/passwords.kdbx", guarded: syncKind !== "single-writer" };
  const find = (id) => s.items.find((i) => i.id === id) ?? s.deleted.find((i) => i.id === id);
  const pub = ({ _notes, _password, ...rest }) => rest;
  const unavailable = () =>
    fail("daemon-unavailable", "Safe's service isn't running (mock).", "systemctl --user start ewe-safe.socket");
  const changed = () => emit("safe-event", { event: "changed" });
  const otpCode = () => String(100000 + ((Math.floor(Date.now() / 30000) * 7919) % 900000));

  const verbs = {
    daemon_state: () => (s.daemon ? { available: true } : { available: false, ...unavailable(), ok: undefined }),
    ping: () => ({ ok: true, pong: true }),
    version: () => ({ ok: true, version: "0.1.0-alpha", protocol: 1 }),
    status: () => ({
      ok: true,
      set_up: s.setUp,
      locked: s.locked,
      read_only: s.readOnly,
      ...(s.readOnly ? { reasons: ["2 items have a field Safe can't keep (from KeePassXC's browser add-on)."] } : {}),
      place: s.setUp ? place : null,
      unlock_methods: s.loginEnabled ? ["password", "login"] : ["password"],
      login: { enabled: s.loginEnabled, session_open: s.loginEnabled },
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
      s.deleted = [];
      place.kind = p?.place ?? "local";
      emit("safe-event", { event: "unlocked" });
      return { ok: true, place };
    },
    open: ({ password }) => {
      if (password !== "mock") return fail("wrong-key", "That password doesn't open the safe.");
      s.setUp = true;
      s.locked = false;
      emit("safe-event", { event: "unlocked" });
      return { ok: true, place, items: s.items.length };
    },
    unlock: ({ password }) => {
      if (!s.setUp) return fail("not-set-up", "There's no safe on this computer yet.", "ewe-safe init");
      if (s.wrong) {
        s.wrong = false;
        return fail("wrong-key", "That password doesn't open the safe.");
      }
      if (s.keyChanged) {
        s.keyChanged = false;
        return fail("key-changed", "The master password was changed on another machine.", "Unlock with the new password");
      }
      if (password !== "mock") return fail("wrong-key", "That password doesn't open the safe.");
      s.locked = false;
      emit("safe-event", { event: "unlocked" });
      return { ok: true, items: s.items.length };
    },
    // login unlock (docs/SYSTEM.md §2): the mock login password is "login"
    unlock_login: ({ loginPassword }) => {
      if (!s.setUp) return fail("not-set-up", "There's no safe on this computer yet.", "ewe-safe init");
      if (!s.loginEnabled) return fail("not-enabled", "Login unlock isn't set up on this computer.");
      if (loginPassword !== "login") return fail("wrong-key", "That login password doesn't open Safe.");
      s.locked = false;
      emit("safe-event", { event: "unlocked" });
      return { ok: true, items: s.items.length };
    },
    login_status: () => ({ ok: true, enabled: s.loginEnabled, session_open: s.loginEnabled }),
    login_enable: ({ loginPassword, password }) => {
      if (loginPassword !== "login") return fail("wrong-key", "That isn't your login password.");
      if (s.locked && password !== "mock") return fail("wrong-key", "That password doesn't open the safe.");
      s.loginEnabled = true;
      return { ok: true, enabled: true };
    },
    login_disable: () => {
      s.loginEnabled = false;
      return { ok: true, enabled: false };
    },
    // the window runs unix_chkpwd itself; the mock just checks the fake pw
    check_login_password: ({ loginPassword }) =>
      loginPassword === "login" ? { ok: true } : fail("wrong-key", "That isn't your login password."),
    confirm: ({ password, loginPassword }) => {
      const ok = loginPassword ? loginPassword === "login" : password === "mock";
      return ok ? { ok: true, confirmed_for: 300 } : fail("wrong-key", "That password is wrong.");
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
        .sort((a, b) => a.title.localeCompare(b.title))
        .map(pub);
      return { ok: true, items };
    },
    search: ({ text }) => {
      const q = (text ?? "").toLowerCase();
      return { ok: true, items: s.items.filter((i) => (i.title + " " + i.username + " " + i.urls.join(" ")).toLowerCase().includes(q)).map(pub) };
    },
    match_items: ({ query }) => ({
      ok: true,
      items: verbs.search({ text: query ?? "" }).items.filter((i) => i.kind === "login").map((i) => ({ ...i, score: 1, reason: "mock" }))
    }),
    show: ({ id, revealNotes }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      return { ok: true, item: { ...pub(i), ...(i.kind === "login" || revealNotes ? { notes: i._notes ?? "" } : {}) } };
    },
    reveal: ({ id, field }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      if (field === "otp") return { ok: true, value: otpCode(), expires_in: 30 - (Math.floor(Date.now() / 1000) % 30) };
      if (field === "password") return { ok: true, value: i._password ?? "" };
      if (field === "username") return { ok: true, value: i.username };
      if (field === "notes") return { ok: true, value: i._notes ?? "" };
      if (field === "public_key" && i.ssh) return { ok: true, value: i.ssh.public_key };
      return fail("not-found", `No field ${field}.`);
    },
    copy: ({ id }) => (find(id) ? { ok: true, copied: true, cleared_after: s.settings.clipboard_clear_seconds } : fail("not-found", `No item ${id}.`)),
    add: ({ item }) => {
      if (s.readOnly) return fail("read-only", "Safe can't save this file.");
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
        modified: minsAgo(0),
        passkey: null,
        ssh: null,
        _notes: item?.notes ?? "",
        _password: item?.password_value ?? ""
      });
      changed();
      return { ok: true, id, sync: { ...sync, state: "pending", pending: true } };
    },
    edit: ({ id, item }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      if (item?.title) i.title = item.title;
      if (item?.username !== undefined) i.username = item.username;
      if (item?.password_value) i._password = item.password_value;
      if (item?.notes !== undefined) i._notes = item.notes;
      if (item?.clear_url) i.urls = [];
      for (const u of item?.url ?? []) if (!i.urls.includes(u)) i.urls.push(u);
      for (const a of item?.app ?? []) if (!i.apps.includes(a)) i.apps.push(a);
      i.apps = i.apps.filter((a) => !(item?.remove_app ?? []).includes(a));
      for (const t of item?.tag ?? []) if (!i.tags.includes(t)) i.tags.push(t);
      i.tags = i.tags.filter((t) => !(item?.remove_tag ?? []).includes(t));
      if (item?.remove_passkey && i.passkey) {
        i.passkey = null;
        i.tags = i.tags.filter((t) => t !== "Passkey");
      }
      i.modified = minsAgo(0);
      changed();
      return { ok: true, sync };
    },
    rm: ({ id }) => {
      const i = s.items.find((x) => x.id === id);
      if (!i) return fail("not-found", `No item ${id}.`);
      s.items = s.items.filter((x) => x !== i);
      s.deleted.push(i);
      changed();
      return { ok: true, sync };
    },
    restore: ({ id }) => {
      const i = s.deleted.find((x) => x.id === id);
      if (!i) return fail("not-found", `No item ${id}.`);
      s.deleted = s.deleted.filter((x) => x !== i);
      s.items.push(i);
      changed();
      return { ok: true, sync };
    },
    generate: ({ words, length, noDigits, noSymbols }) => {
      if (words) {
        const list = ["amble", "crisp", "lantern", "oyster", "velvet", "harbor", "tundra", "quill", "mosaic", "ember"];
        return { ok: true, value: Array.from({ length: words }, (_, n) => list[(n * 3 + Date.now()) % list.length]).join("-"), bits: Math.round(words * 12.9) };
      }
      const pool = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ" + (noDigits ? "" : "23456789") + (noSymbols ? "" : "!#@$%&*");
      const n = length ?? 20;
      const a = crypto.getRandomValues(new Uint32Array(n));
      return { ok: true, value: Array.from(a, (x) => pool[x % pool.length]).join(""), bits: Math.round(n * Math.log2(pool.length)) };
    },
    sync: () => ({ ok: true, sync }),
    place: () => ({ ok: true, place, sync, probe: { guarded: place.guarded, checked_at: sync.last } }),
    passwd: ({ newPassword }) => (newPassword ? { ok: true, sync } : fail("bad-request", "A new password is needed.")),
    import_items: ({ format, file, dryRun, skipDuplicates }) => {
      if (params.get("import") === "old") return fail("bad-request", 'There is no verb "import".');
      if (format !== "op" && !file) return fail("bad-request", "Choose the export file first.");
      const report = {
        logins: 142,
        notes: 9,
        attachments: 3,
        otps: 18,
        duplicates: skipDuplicates ? 4 : 4,
        skipped: [
          { title: "Old laptop (archived)", reason: "In 1Password's trash" },
          { title: "Passport scan", reason: "A document with no fields: its file is kept as an attachment of a note" }
        ],
        folders: ["From 1Password"]
      };
      if (dryRun) return { ok: true, report, dry_run: true };
      return {
        ok: true,
        report,
        sync,
        ...(format === "op" ? {} : { hint: "This export holds every password in plain text. Delete it now." })
      };
    },

    ssh_new: ({ title, keyType }) => {
      if (!title) return fail("bad-request", "ssh new needs --title");
      const k = sshKey(title, keyType ?? "ed25519", s.items.length);
      s.items.push(k);
      changed();
      return { ok: true, item_id: k.id, ssh: k.ssh, sync };
    },
    ssh_add: ({ file, title }) => {
      if (!file) return fail("bad-request", "ssh add needs the private key's file");
      const k = sshKey(title || file.split("/").pop(), "ed25519", s.items.length);
      s.items.push(k);
      changed();
      return { ok: true, item_id: k.id, ssh: k.ssh, sync };
    },
    ssh_adopt: ({ dryRun }) => ({ ok: true, adopted: [], skipped: [], ...(dryRun ? { dry_run: true } : { sync }) }),
    ssh_enable: () => {
      s.agent = true;
      return { ok: true, enabled: true, recorded: true, socket: "/run/user/1000/ewe-safe-ssh.sock", identity_agent: "IdentityAgent /run/user/1000/ewe-safe-ssh.sock" };
    },
    ssh_disable: () => {
      s.agent = false;
      return { ok: true, enabled: false, recorded: true, env_file_removed: true };
    },
    ssh_status: () => ({
      ok: true,
      enabled: s.agent,
      confirm: "first-use",
      socket: "/run/user/1000/ewe-safe-ssh.sock",
      listening: true,
      keys: s.items.filter((i) => i.kind === "ssh-key").length,
      locked: s.locked,
      ssh_auth_sock: s.agent ? "/run/user/1000/ewe-safe-ssh.sock" : null,
      points_here: s.agent,
      env_file: null,
      identity_agent: "IdentityAgent /run/user/1000/ewe-safe-ssh.sock",
      ssh_config_agents: []
    }),

    // the window's own commands
    launch_args: () => ({
      mode: ["unlock", "approve", "confirm"].includes(params.get("mode")) ? params.get("mode") : "main",
      reason: params.get("mode") === "confirm" ? params.get("reason") || "Type your password to fill Visa •• 4242 on shop.com" : null,
      approve:
        params.get("mode") === "approve"
          ? {
              app: "ssh (from git)",
              key: "GitHub key",
              path: params.get("system") === "0" ? "/home/sam/.local/bin/ssh (not a system program), started by /usr/bin/git" : "/usr/bin/ssh, started by /usr/bin/git",
              system: params.get("system") !== "0"
            }
          : null,
      show: null,
      new: params.get("edit") === "new",
      import: params.get("view") === "import"
    }),
    theme_tokens: () => (flag("light", false) ? light : null),
    theme_key: () => "mock",
    settings_get: () => ({ ok: true, settings: s.settings }),
    settings_set: ({ key, value }) => {
      s.settings[key] = value;
      return { ok: true };
    },
    // &superp=ewe|auto|… (default 1password): what Super+P fills from
    passwords_provider: () => ({ ok: true, provider: s.superP }),
    use_safe_for_passwords: () => {
      s.superP = "ewe";
      return { ok: true, provider: "ewe" };
    },
    cloud_status: () =>
      flag("signedin", true)
        ? { ok: true, signed_in: true, server: "https://cloud.example.org", user: "sam", display_name: "Sam" }
        : { ok: true, signed_in: false },
    window_classes: () => ({ ok: true, classes: ["code", "discord", "firefox", "kitty", "slack", "steam"] }),
    open_url: () => ({ ok: true }),
    open_ewe_sync: () => ({ ok: true }),
    pick_file: ({ kind }) =>
      kind === "ssh-key"
        ? { ok: true, path: "/home/sam/.ssh/id_ed25519" }
        : { ok: true, path: `/home/sam/Downloads/1PasswordExport.${kind === "csv" ? "csv" : kind}` },
    print_page: () => ({ ok: true }),
    quit_app: () => ({ ok: true })
  };
  const local = new Set(["daemon_state", "launch_args", "theme_tokens", "theme_key", "settings_get", "settings_set", "passwords_provider", "use_safe_for_passwords", "cloud_status", "window_classes", "open_url", "open_ewe_sync", "pick_file", "print_page", "quit_app", "check_login_password"]);
  const needsUnlock = new Set(["list", "search", "match_items", "show", "reveal", "copy", "add", "edit", "rm", "restore", "import_items", "ssh_new", "ssh_add", "ssh_adopt", "confirm"]);

  window.__SAFE_MOCK__ = {
    async invoke(cmd, args) {
      await new Promise((r) => setTimeout(r, 40));
      if (!local.has(cmd) && !s.daemon) return unavailable();
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

/** After the page mounted: the view switches that need the UI store. */
export async function arrange(params, ui) {
  const view = params.get("view");
  if (view === "settings" || view === "import") ui.go(view);
  if (view === "trash") ui.pick({ trash: true });
  if (view === "ssh") ui.pick({ kind: "ssh-key" });
  const edit = params.get("edit");
  if (edit && edit !== "new") {
    ui.selected = fixture.items.find((i) => i.title.toLowerCase() === edit)?.id ?? null;
    ui.editing = { mode: "edit", id: ui.selected, kind: "login" };
  }
  const sel = params.get("select");
  if (sel) ui.selected = fixture.items.find((i) => i.title.toLowerCase() === sel)?.id ?? null;
  if (params.get("step")) ui.setupStep = params.get("step");
  if (params.get("kit") === "1") ui.kit = true;
  if (params.get("gen") === "1") ui.genOpen = true;
}
