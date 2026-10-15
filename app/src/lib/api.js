// The page's only way to Safe: the window's Tauri commands (one per
// docs/PROTOCOL.md verb) and its two events. In a plain browser with ?mock=1
// the dev mock (devmock.js) answers instead. Every command resolves to the
// daemon's JSON reply — `{ok: true, …}` or `{ok: false, error, message,
// hint}` — and never throws.

const inTauri = () => typeof window !== "undefined" && !!window.__TAURI_INTERNALS__;

function notHere() {
  return {
    ok: false,
    error: "daemon-unavailable",
    message: "This page talks to Safe only inside the Safe window.",
    hint: "Open it with ?mock=1 for the dev mock"
  };
}

async function invoke(cmd, args = {}) {
  try {
    if (inTauri()) {
      const core = await import("@tauri-apps/api/core");
      return await core.invoke(cmd, args);
    }
    if (window.__SAFE_MOCK__) return await window.__SAFE_MOCK__.invoke(cmd, args);
    return notHere();
  } catch (e) {
    return { ok: false, error: "internal", message: String(e?.message ?? e) };
  }
}

/** `safe-event` (the daemon's events) and `safe-daemon` (reachable or not). */
export async function listen(name, fn) {
  if (inTauri()) {
    const ev = await import("@tauri-apps/api/event");
    return ev.listen(name, (e) => fn(e.payload));
  }
  if (window.__SAFE_MOCK__) return window.__SAFE_MOCK__.listen(name, fn);
  return () => {};
}

export const api = {
  status: () => invoke("status"),
  summary: () => invoke("summary"),
  ping: () => invoke("ping"),
  version: () => invoke("version"),
  daemonState: () => invoke("daemon_state"),
  // place: {place, location?, url?, user?}
  init: (place, password) => invoke("init", { place, password }),
  open: (place, password) => invoke("open", { place, password }),
  unlock: (password) => invoke("unlock", { password }),
  lock: () => invoke("lock"),
  list: ({ kind, tag, deleted } = {}) => invoke("list", { kind, tag, deleted }),
  search: (text) => invoke("search", { text }),
  match: ({ cls, title, url, query, limit } = {}) =>
    invoke("match_items", { class: cls, title, url, query, limit }),
  show: (id, revealNotes = false) => invoke("show", { id, revealNotes }),
  // the one call that returns a secret: one field, on demand
  reveal: (id, field) => invoke("reveal", { id, field }),
  copy: (id, field, clearAfter) => invoke("copy", { id, field, clearAfter }),
  // item: PROTOCOL.md add/edit keys (title, username, url[], app[], tag[],
  // folder, generate, length, words, password_value, notes, …)
  add: (item) => invoke("add", { item }),
  edit: (id, item) => invoke("edit", { id, item }),
  rm: (id) => invoke("rm", { id }),
  restore: (id) => invoke("restore", { id }),
  generate: ({ length, words, noSymbols, noDigits } = {}) =>
    invoke("generate", { length, words, noSymbols, noDigits }),
  sync: () => invoke("sync"),
  place: () => invoke("place"),
  passwd: (password, newPassword) => invoke("passwd", { password, newPassword }),
  // format: "1pux" | "1password-csv" | "op"; file: a path (none for op)
  importItems: ({ format, file, dryRun, folder, skipDuplicates, vault }) =>
    invoke("import_items", { format, file, dryRun, folder, skipDuplicates, vault }),
  // SSH keys and the agent (PROTOCOL.md "SSH keys"): a key file by its path
  // (the daemon reads it); its passphrase, if any, is a secret
  sshAdd: ({ file, title, folder, passphrase }) => invoke("ssh_add", { file, title, folder, passphrase }),
  // keyType: "ed25519" | "ecdsa" | "rsa"
  sshNew: ({ title, keyType, bits, folder }) => invoke("ssh_new", { title, keyType, bits, folder }),
  sshAdopt: (dryRun = false) => invoke("ssh_adopt", { dryRun }),
  sshEnable: (confirm) => invoke("ssh_enable", { confirm }),
  sshDisable: () => invoke("ssh_disable"),
  sshStatus: () => invoke("ssh_status"),

  // the window and the desktop around it (not the daemon)
  launchArgs: () => invoke("launch_args"),
  themeTokens: () => invoke("theme_tokens"),
  themeKey: () => invoke("theme_key"),
  settingsGet: () => invoke("settings_get"),
  settingsSet: (key, value) => invoke("settings_set", { key, value }),
  // Super+P: the Passwords plugin's provider, and switching it to Safe
  passwordsProvider: () => invoke("passwords_provider"),
  useSafeForPasswords: () => invoke("use_safe_for_passwords"),
  cloudStatus: () => invoke("cloud_status"),
  windowClasses: () => invoke("window_classes"),
  openUrl: (url) => invoke("open_url", { url }),
  openEweSync: () => invoke("open_ewe_sync"),
  pickFile: (kind) => invoke("pick_file", { kind }),
  print: () => {
    if (inTauri()) return invoke("print_page");
    window.print();
    return Promise.resolve({ ok: true });
  },
  quit: (code = 0) => invoke("quit_app", { code })
};
