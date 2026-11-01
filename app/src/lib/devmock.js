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
//   &view=ssh             the SSH page (docs/GATE.md S28)   &view=sshkeys  the SSH key list
//   &gate=off|old|1password|good   the SSH gate: the agent off (default; &agent=1
//                         = good); on but ssh still asks 1Password (no gate
//                         lines yet); the gate on but 1Password still named
//                         by the hosts work and work-proxy, one key only in
//                         1Password, two key files not in Safe (one with the
//                         passphrase "mock"); all good
//   &hosts=0              no hosts (default: github.com, work, work-proxy,
//                         dev-vm in ewe.conf; emoh and nas in your own lines)
//   &test=fail|changed    every Check fails (GitHub doesn't know the key) / the
//                         server's key changed (default: works; work-proxy
//                         can't be reached)
//   &remote=0|offline|empty   no ewe-remote / all your ewe computers offline /
//                         none (default: one online, one offline, one not paired)
//   &signing=1            Git commits are signed with the GitHub key
//   &email=0              git has no user.email: signing asks for it
//   &connect=github|…|pick   the connect sheet open on that service (pick: the
//                         list)       &takeover=1   the "Move SSH to Safe" sheet
//   &select=key           show the GitHub key (in the SSH key list)
//   &view=settings|import|trash   &edit=github|new   &gen=1 (generator open)
//   &import=old           the daemon has no `import` verb yet
//   &view=cards|addresses the cards, the addresses (sample data, fake numbers)
//   &edit=card|address    edit the sample Visa / Home     &new=card|address  a new one
//   &select=card|address  show the sample Visa / Home
//   &convert=1            Settings' "Cards from an earlier import" finds two notes
//   &light=1              Ewe Light (the real token map, .dev-mock/theme-light.json)
//   &keyring=broken|locked|none|safe   the keyring: `default` names a second
//                         keyring (the prompt at every start; locked: it is
//                         locked too), no keyring runs, or Safe keeps them
//                         (default: fine, gnome-keyring with `default` = login)
// The master password is "mock".

import fixture from "../../.dev-mock/items.json";
import light from "../../.dev-mock/theme-light.json";
import { brandOf, digits } from "./cards.js";

// cards and addresses (docs/SYSTEM.md §4): fake numbers only, the card
// networks' published test numbers
export const MOCK_CARD = "0b6d2a1c-cccc-4c3d-8e9f-0a1b2c3d4e01";
export const MOCK_ADDRESS = "0b6d2a1c-aaaa-4c3d-8e9f-0a1b2c3d4e01";
export const MOCK_SSH = "0b6d2a1c-5555-4c3d-8e9f-0a1b2c3d4e01";

export function install(params) {
  const flag = (k, dflt) => (params.has(k) ? params.get(k) === "1" : dflt);
  const clone = (x) => structuredClone(x);
  const minsAgo = (m) => new Date(Date.now() - m * 60000).toISOString().replace(/\.\d+Z$/, "Z");
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
      confirm_cards: true,
      ...(params.get("known") ? { place: params.get("known"), location: "ewe/safe/passwords.kdbx" } : {})
    },
    keyring: params.get("keyring") ?? "fine"
  };
  // the keyring's app secrets (names and dates only, as `keyring list`)
  const krItems = () =>
    s.keyring === "none"
      ? []
      : [
          { id: "/org/freedesktop/secrets/collection/login/1", label: "ewe cloud", collection: "login", app: "ewe-cloud", created: minsAgo(60 * 24 * 40), modified: minsAgo(60 * 24 * 3) },
          { id: "/org/freedesktop/secrets/collection/login/2", label: "Chrome Safe Storage", collection: "login", app: "chrome", created: minsAgo(60 * 24 * 90), modified: minsAgo(60 * 24 * 90) },
          ...(s.keyring === "locked"
            ? []
            : [
                { id: "/org/freedesktop/secrets/collection/Default_5fkeyring/1", label: "ewe mail (sam@example.org)", collection: s.keyring === "broken" ? "Default_keyring" : "login", app: "ewe-mail", created: minsAgo(60 * 24 * 30), modified: minsAgo(60 * 24 * 30) },
                { id: "/org/freedesktop/secrets/collection/Default_5fkeyring/2", label: "ewe companion: anthropic API key", collection: s.keyring === "broken" ? "Default_keyring" : "login", app: "ewe-companion", created: minsAgo(60 * 24 * 8), modified: minsAgo(60 * 24 * 8) }
              ])
        ];
  // an SSH key (TRIO.md S2; GATE.md S22: its public file, last use): the
  // fixture has none
  const sshKey = (title, type, n, extra = {}) => ({
    id: extra.id ?? crypto.randomUUID(),
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
      agent: true,
      file: `~/.ssh/ewe-safe/key-mock${n}Kp3zQ9xVt1b.pub`,
      last_used: extra.last_used ?? null
    },
    passkey: null,
    _notes: ""
  });
  // the SSH gate (GATE.md S21–S28): keys, hosts, 1Password's agent, key files
  const gateFlag = params.get("gate") ?? (flag("agent", false) ? "good" : "off");
  const good = gateFlag === "good";
  const g = {
    enabled: gateFlag !== "off",
    on: gateFlag === "1password" || good,
    confirm: "first-use",
    // 1Password's agent: its keys, and the ones Safe doesn't have
    op: good ? null : { keys: 4, missing: [{ agent: "1Password", comment: "Staging deploy key", fingerprint: "SHA256:op9Qm2Lx7RkVt3eN1bW8uYc5", key_type: "ed25519" }] },
    // private key files in ~/.ssh
    files: [
      { path: "/home/sam/.ssh/id_ed25519", fingerprint: "SHA256:file1Hk2QpX9mVt7cR4bN", comment: "sam@laptop", passphrase: "", in_safe: good, item_id: null },
      { path: "/home/sam/.ssh/id_rsa_work", fingerprint: "SHA256:file2Lm8WqT3zYc6dK1eP", comment: "", passphrase: "mock", in_safe: good, item_id: null }
    ],
    signing: null,
    gitEmail: flag("email", true),
    test: params.get("test") ?? "ok",
    remote: params.get("remote") ?? "1"
  };
  const OP_SOCK = "~/.1password/agent.sock";
  const NEVER = "ssh_confirm is never: any program running as you can use your SSH keys while Safe is unlocked, without a question.";
  const sshKeys = {};
  if (!flag("empty", false)) {
    sshKeys.github = sshKey("GitHub key", "ed25519", 1, { id: MOCK_SSH, last_used: { at: minsAgo(2), program: "ssh (from git)" } });
    sshKeys.work = sshKey("Work laptop", "ed25519", 2, { last_used: { at: minsAgo(60 * 26), program: "ssh" } });
    sshKeys.azure = sshKey("Azure DevOps", "rsa", 3);
    s.items.push(sshKeys.github, sshKeys.work, sshKeys.azure);
    if (good) {
      // the key files, already in Safe
      g.files.forEach((f, n) => {
        const k = sshKey(f.comment || f.path.split("/").pop(), n ? "rsa" : "ed25519", 4 + n, { last_used: n ? null : { at: minsAgo(60 * 24 * 3), program: "ssh" } });
        f.item_id = k.id;
        s.items.push(k);
      });
    }
    if (flag("signing", false)) g.signing = MOCK_SSH;
  }
  const keyRef = (k) => (k ? { item_id: k.id, title: k.title, fingerprint: k.ssh.fingerprint } : null);
  // ewe.conf's hosts (`source: "ewe"`) and the user's own lines (`yours`);
  // `_agent`: the host's own IdentityAgent
  const host = (alias, o) => ({ alias, host_name: null, user: null, port: null, source: "ewe", key: null, file: null, service: null, _agent: null, ...o });
  const emohKey = s.items.find((i) => i.ssh && i.title === "sam@laptop");
  s.hosts = !flag("hosts", true)
    ? []
    : [
        host("github.com", { user: "git", key: keyRef(sshKeys.github), file: sshKeys.github?.ssh.file ?? null, service: "github" }),
        host("work", { host_name: "work.example.com", user: "sam", _agent: good ? null : OP_SOCK }),
        host("work-proxy", { host_name: "proxy.example.com", user: "sam", port: 2222, _agent: good ? null : OP_SOCK }),
        host("dev-vm", { host_name: "20.61.14.2", user: "azureuser", key: keyRef(sshKeys.work), file: sshKeys.work?.ssh.file ?? null }),
        host("emoh", { host_name: "emoh.lan", user: "sam", source: "yours", file: "~/.ssh/id_ed25519", key: keyRef(emohKey) }),
        host("nas", { host_name: "nas.lan", user: "admin", source: "yours", _agent: OP_SOCK })
      ];
  const hostsReply = () =>
    s.hosts.map(({ _agent, ...h }) => ({ ...h, agent: g.on ? "safe" : _agent }));
  const gateReply = () => ({
    on: g.on,
    include: g.on,
    config_file: "/home/sam/.ssh/ewe-safe/config",
    overridden: s.hosts.filter((h) => h._agent).map((h) => ({ host: h.alias, agent: h._agent })),
    key_files: g.files.map((f) => ({ path: f.path, fingerprint: f.fingerprint, in_safe: f.in_safe })),
    other_agents: g.op ? [{ socket: "/home/sam/.1password/agent.sock", name: "1Password", keys: g.op.keys, missing_from_safe: g.op.missing.length }] : []
  });
  // the catalogue (GATE.md S24); the daemon's steps win, these are samples
  const COPIED = "Safe copied your public key.";
  const BACK = "Come back and press Check.";
  const LATER = "Then add the address here and press Check.";
  const SERVICES = [
    { service: "github", name: "GitHub", group: "git", host: "github.com", user: "git", key_type: "ed25519", page: "https://github.com/settings/ssh/new", needs: [], signing: true, steps: [COPIED, "On the GitHub page, paste it into Key, give it a name and press Add SSH key.", BACK] },
    { service: "gitlab", name: "GitLab", group: "git", host: "gitlab.com", user: "git", key_type: "ed25519", page: "https://gitlab.com/-/user_settings/ssh_keys", needs: [], signing: true, steps: [COPIED, "On the GitLab page, press Add new key. Paste it into Key and press Add key.", BACK] },
    { service: "azure-devops", name: "Azure DevOps", group: "git", host: "ssh.dev.azure.com", user: "git", key_type: "rsa", page: "https://dev.azure.com/", needs: ["org"], signing: false, steps: [COPIED, "In Azure DevOps, open User settings (top right) → SSH public keys → New Key. Paste it into Public Key Data, give it a name and press Add.", BACK] },
    { service: "bitbucket", name: "Bitbucket", group: "git", host: "bitbucket.org", user: "git", key_type: "ed25519", page: "https://bitbucket.org/account/settings/ssh-keys/", needs: [], signing: false, steps: [COPIED, "On the Bitbucket page, press Add key. Paste it into Key and press Add key.", BACK] },
    { service: "codeberg", name: "Codeberg", group: "git", host: "codeberg.org", user: "git", key_type: "ed25519", page: "https://codeberg.org/user/settings/keys", needs: [], signing: false, steps: [COPIED, "On the Codeberg page, press Add key. Paste it into Content, give it a name and press Add key.", BACK] },
    { service: "gitea", name: "Gitea or Forgejo", group: "git", host: null, user: "git", key_type: "ed25519", page: null, needs: ["host"], signing: false, steps: [COPIED, "On your server's page, press Add key. Paste it into Content, give it a name and press Add key.", BACK] },
    { service: "azure-vm", name: "Azure virtual machine", group: "cloud", host: null, user: "azureuser", key_type: "ed25519", page: "https://portal.azure.com/#browse/Microsoft.Compute%2FVirtualMachines", needs: [], signing: false, steps: [COPIED, "Paste it as the SSH public key when you create the VM. For a VM you have: Help → Reset password → Reset SSH public key.", LATER] },
    { service: "aws", name: "AWS EC2", group: "cloud", host: null, user: "ec2-user", key_type: "ed25519", page: "https://console.aws.amazon.com/ec2/home#ImportKeyPair:", needs: [], signing: false, steps: [COPIED, "On the AWS page, give the key a name, paste it and press Import key pair. Pick it when you start an instance.", LATER] },
    { service: "gcloud", name: "Google Cloud VM", group: "cloud", host: null, user: "your name", key_type: "ed25519", page: "https://console.cloud.google.com/compute/metadata?tab=sshkeys", needs: [], signing: false, steps: [COPIED, "On the Google Cloud page, press Edit, then Add item. Paste it and press Save.", LATER] },
    { service: "digitalocean", name: "DigitalOcean", group: "cloud", host: null, user: "root", key_type: "ed25519", page: "https://cloud.digitalocean.com/account/security", needs: [], signing: false, steps: [COPIED, "On the DigitalOcean page, press Add SSH Key. Paste it, give it a name and press Add SSH Key.", LATER] },
    { service: "hetzner", name: "Hetzner Cloud", group: "cloud", host: null, user: "root", key_type: "ed25519", page: "https://console.hetzner.cloud/", needs: [], signing: false, steps: [COPIED, "Open your project → Security → SSH keys → Add SSH key. Paste it and press Add SSH key.", LATER] },
    { service: "server", name: "A server you can log in to", group: "server", host: null, user: null, key_type: "ed25519", page: null, needs: ["host", "user"], signing: false, steps: ["Safe opens a terminal that puts your key on the server.", "Type your password for the server there, once.", BACK] }
  ];
  const svcOf = (id) => SERVICES.find((x) => x.service === id);
  const svcName = (alias) => {
    const h = s.hosts.find((x) => x.alias === alias);
    const id = h?.service ?? SERVICES.find((x) => x.host && (x.host === alias || x.host === h?.host_name))?.service ?? (svcOf(alias) ? alias : null);
    return svcOf(id)?.name ?? alias;
  };
  const base = (id, kind, title) => ({
    id,
    kind,
    title,
    username: "",
    urls: [],
    apps: [],
    tags: [],
    folder: "",
    has_password: false,
    has_otp: false,
    modified: new Date().toISOString().replace(/\.\d+Z$/, "Z"),
    passkey: null,
    ssh: null,
    card: null,
    address: null,
    _notes: ""
  });
  const cardInfo = (c) => {
    const d = digits(c.number);
    return {
      brand: c.brand || (d ? brandOf(d) : "other"),
      last4: d.length >= 10 ? d.slice(-4) : "",
      expiry: c.expiry ?? "",
      holder: c.holder ?? "",
      has_number: !!d,
      has_security_code: !!c.security_code,
      has_pin: !!c.pin
    };
  };
  const mockCard = (id, title, c, extra = {}) => ({ ...base(id, "card", title), card: cardInfo(c), _card: { ...c }, ...extra });
  const addrInfo = (a) => ({ name: a.full_name ?? "", line1: a.line1 ?? "", city: a.city ?? "", country: a.country ?? "" });
  const mockAddress = (id, title, a, extra = {}) => ({ ...base(id, "address", title), address: addrInfo(a), _address: { ...a }, ...extra });
  if (!flag("empty", false)) {
    s.items.push(
      mockCard(MOCK_CARD, "Visa •• 4242", { holder: "Sam Shepherd", number: "4242424242424242", expiry: "08/2029", security_code: "123", pin: "4321" }, { tags: ["money"], _notes: "Daily card. Bank: Ewe Bank." }),
      mockCard(crypto.randomUUID(), "Work Amex", { holder: "Sam Shepherd", number: "378282246310005", expiry: "03/2027", security_code: "1234" }, { folder: "Work" }),
      mockCard(crypto.randomUUID(), "Old Mastercard", { holder: "S Shepherd", number: "5555555555554444", expiry: "11/2024", security_code: "321" }),
      mockAddress(MOCK_ADDRESS, "Home", { full_name: "Sam Shepherd", line1: "12 Rustaveli Ave", line2: "Flat 4", city: "Tbilisi", postal_code: "0108", country: "GE", phone: "+995 555 12 34 56", email: "sam@example.org" }),
      mockAddress(crypto.randomUUID(), "Work", { full_name: "Sam Shepherd", organization: "Flock Ltd", line1: "1 Hill Rd", city: "Ewetown", region: "Canterbury", postal_code: "9012", country: "NZ", phone: "+64 21 000 001" }, { folder: "Work" })
    );
  }
  // "8/29", "08/29" → "08/2029"
  const longExpiry = (e) => {
    const d = digits(e);
    return d.length === 4 ? `${d.slice(0, 2)}/20${d.slice(2)}` : d.length === 6 ? `${d.slice(0, 2)}/${d.slice(2)}` : "";
  };
  const CARD_FIELDS = { number: "number", Number: "number", security_code: "security_code", "Security code": "security_code", pin: "pin", PIN: "pin", holder: "holder", Cardholder: "holder", expiry: "expiry", Expiry: "expiry" };
  const listeners = { "safe-event": new Set(), "safe-daemon": new Set(), "safe-args": new Set() };
  const emit = (name, payload) => listeners[name]?.forEach((fn) => fn(payload));
  const fail = (error, message, hint) => ({ ok: false, error, message, ...(hint ? { hint } : {}) });
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
  const pub = ({ _notes, _password, _card, _address, ...rest }) => rest;
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
      const full = i.kind === "address" ? { address: { ...i.address, ...i._address } } : {};
      return { ok: true, item: { ...pub(i), ...full, ...(i.kind === "login" || revealNotes ? { notes: i._notes ?? "" } : {}) } };
    },
    reveal: ({ id, field }) => {
      const i = find(id);
      if (!i) return fail("not-found", `No item ${id}.`);
      if (field === "otp") return { ok: true, value: otpCode(), expires_in: 30 - (Math.floor(Date.now() / 1000) % 30) };
      if (field === "password") return { ok: true, value: i._password ?? "" };
      if (field === "username") return { ok: true, value: i.username };
      if (field === "notes") return { ok: true, value: i._notes ?? "" };
      if (field === "public_key" && i.ssh) return { ok: true, value: i.ssh.public_key };
      if (i.kind === "card" && CARD_FIELDS[field]) {
        const v = i._card?.[CARD_FIELDS[field]] ?? "";
        return v ? { ok: true, value: v } : fail("not-found", `${id}: no such field.`);
      }
      if (i.kind === "address" && i._address?.[field] !== undefined) return { ok: true, value: i._address[field] };
      return fail("not-found", `No field ${field}.`);
    },
    copy: ({ id }) => (find(id) ? { ok: true, copied: true, cleared_after: s.settings.clipboard_clear_seconds } : fail("not-found", `No item ${id}.`)),
    add: ({ item }) => {
      if (s.readOnly) return fail("read-only", "Safe can't save this file.");
      const id = crypto.randomUUID();
      if (item?.kind === "card") {
        const c = { ...(item.card ?? {}) };
        c.number = digits(c.number);
        c.expiry = c.expiry ? longExpiry(c.expiry) : "";
        const info = cardInfo(c);
        const title = item.title || `${{ visa: "Visa", mastercard: "Mastercard", amex: "Amex" }[info.brand] ?? "Card"}${info.last4 ? ` •• ${info.last4}` : ""}`;
        s.items.push(mockCard(id, title, c, { tags: item.tag ?? [], _notes: item.notes ?? "" }));
        changed();
        return { ok: true, item_id: id, sync: { ...sync, state: "pending", pending: true } };
      }
      if (item?.kind === "address") {
        s.items.push(mockAddress(id, item.title || "Home", item.address ?? {}, { tags: item.tag ?? [], _notes: item.notes ?? "" }));
        changed();
        return { ok: true, item_id: id, sync: { ...sync, state: "pending", pending: true } };
      }
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
      if (item?.card && i.kind === "card") {
        const c = { ...item.card };
        if (c.number !== undefined) c.number = digits(c.number);
        if (c.expiry !== undefined) c.expiry = c.expiry ? longExpiry(c.expiry) : "";
        i._card = { ...i._card, ...c };
        if (c.number !== undefined && c.brand === undefined) i._card.brand = "";
        i.card = cardInfo(i._card);
      }
      if (item?.address && i.kind === "address") {
        i._address = { ...i._address, ...item.address };
        i.address = addrInfo(i._address);
      }
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
    convert: ({ dryRun }) => {
      const found =
        params.get("convert") === "1"
          ? [
              { item_id: crypto.randomUUID(), title: "Visa (1Password)", kind: "card" },
              { item_id: crypto.randomUUID(), title: "Sam Shepherd", kind: "address" }
            ]
          : [];
      const skipped = params.get("convert") === "1" ? [{ title: "Store card", reason: "Safe found no card number in it" }] : [];
      return { ok: true, converted: found, skipped, ...(dryRun ? { dry_run: true } : { sync }) };
    },
    // `ssh enable` turns the gate on too (GATE.md S21)
    ssh_enable: ({ confirm }) => {
      g.enabled = true;
      g.on = true;
      if (confirm) g.confirm = confirm;
      return { ok: true, enabled: true, recorded: true, socket: "/run/user/1000/ewe-safe-ssh.sock", env_file: "/home/sam/.config/environment.d/90-ewe-safe-ssh.conf", identity_agent: "IdentityAgent /run/user/1000/ewe-safe-ssh.sock", ...(g.confirm === "never" ? { warning: NEVER } : {}), gate: gateReply() };
    },
    ssh_disable: () => {
      g.enabled = false;
      g.on = false;
      return { ok: true, enabled: false, recorded: true, env_file_removed: true };
    },
    ssh_status: () => ({
      ok: true,
      enabled: g.enabled,
      confirm: g.confirm,
      socket: "/run/user/1000/ewe-safe-ssh.sock",
      listening: true,
      keys: s.items.filter((i) => i.kind === "ssh-key").length,
      locked: s.locked,
      ssh_auth_sock: g.enabled ? "/run/user/1000/ewe-safe-ssh.sock" : null,
      points_here: g.on,
      env_file: g.enabled ? "/home/sam/.config/environment.d/90-ewe-safe-ssh.conf" : null,
      identity_agent: "IdentityAgent /run/user/1000/ewe-safe-ssh.sock",
      ssh_config_agents: [...new Set(s.hosts.map((h) => h._agent).filter(Boolean))],
      ...(g.confirm === "never" ? { warning: NEVER } : {}),
      gate: gateReply(),
      signing: keyRef(find(g.signing))
    }),
    // GATE.md S23: a dry run lists, a real run moves; files are never changed
    ssh_takeover: ({ dryRun, passphrases }) => {
      const imported = [];
      const already = [];
      const needs = [];
      const skipped = [];
      for (const f of g.files) {
        const title = f.comment || f.path.split("/").pop();
        if (f.in_safe) {
          already.push({ item_id: f.item_id, title, file: f.path });
          continue;
        }
        if (f.passphrase) {
          const p = passphrases?.[f.path];
          if (!p) {
            needs.push(f.path);
            continue;
          }
          if (p !== f.passphrase) {
            skipped.push({ file: f.path, reason: "That passphrase is wrong." });
            continue;
          }
        }
        let id = null;
        if (!dryRun) {
          const k = sshKey(title, f.path.includes("rsa") ? "rsa" : "ed25519", s.items.length);
          s.items.push(k);
          f.in_safe = true;
          f.item_id = id = k.id;
        }
        imported.push({ item_id: id, title, file: f.path });
      }
      const fixed = s.hosts.filter((h) => h.source === "ewe" && h._agent);
      const reply = {
        ok: true,
        enabled: true,
        imported,
        already,
        needs_passphrase: needs,
        skipped,
        hosts_fixed: fixed.map((h) => h.alias),
        overridden: s.hosts.filter((h) => h.source === "yours" && h._agent).map((h) => ({ host: h.alias, agent: h._agent })),
        missing_from_safe: g.op?.missing ?? [],
        files_left: [...imported, ...already].map((x) => x.file),
        hint: g.op?.missing?.length
          ? "Import them from 1Password first: Safe → Import (or `ewe-safe import op`), then `ewe-safe ssh adopt`."
          : "Safe signs for these keys now. Delete the files when you are ready."
      };
      if (dryRun) return { ...reply, gate: gateReply(), dry_run: true };
      g.enabled = true;
      g.on = true;
      fixed.forEach((h) => (h._agent = null));
      changed();
      return { ...reply, gate: gateReply(), sync };
    },
    ssh_services: () => ({ ok: true, services: clone(SERVICES) }),
    ssh_connect: ({ service, key, title, host: h, user, port, alias, org, replace, sign, noOpen }) => {
      const sv = svcOf(service);
      if (!sv) return fail("bad-request", `Safe doesn't know the service ${service}.`);
      if (service === "server" && (!h || !user)) return fail("bad-request", "A server needs its address and your user name on it.");
      if (service === "gitea" && !h) return fail("bad-request", "Gitea needs its address: --host.");
      let k = key ? find(key) : null;
      if (key && !k?.ssh) return fail("not-found", `No SSH key ${key}.`);
      const target = h || sv.host;
      const a = target ? alias || target : null;
      const there = a ? s.hosts.find((x) => x.alias === a) : null;
      if (there?.source === "yours") return { ...fail("conflict", `You set up ${a} yourself in ~/.ssh/config. Change it there, or use --alias.`), alias: a };
      if (there?.key && there.key.item_id !== k?.id && !replace)
        return { ...fail("conflict", `${a} already uses the key ${there.key.title}. Use --replace, or --alias ${service}-2 for a second account.`), alias: a };
      if (!k) {
        k = sshKey(title || sv.name, sv.key_type === "rsa" ? "rsa" : "ed25519", s.items.length);
        s.items.push(k);
      }
      if (a) {
        const def = host(a, { host_name: a === target ? null : target, user: user || sv.user, port: port && Number(port) !== 22 ? Number(port) : null, key: keyRef(k), file: k.ssh.file, service: sv.service });
        s.hosts = [...s.hosts.filter((x) => x.alias !== a), def];
      }
      if (sign) g.signing = k.id;
      changed();
      const page =
        service === "gitlab" && h ? `https://${h}/-/user_settings/ssh_keys` : service === "gitea" ? `https://${h}/user/settings/keys` : service === "azure-devops" && org ? `https://dev.azure.com/${org}/_usersSettings/keys` : sv.page;
      const hint = sv.group !== "git" || !a ? null : service === "azure-devops" ? `git@${a}:v3/${org || "<org>"}/<project>/<repo>` : `git@${a}:<owner>/<repo>.git`;
      return { ok: true, item_id: k.id, ssh: k.ssh, service, alias: a, page, copied: true, opened: !noOpen, steps: sv.steps, remote_hint: hint, sync };
    },
    // GATE.md S24: the answer read the way a user would
    ssh_test: ({ target }) => {
      const name = svcName(target);
      const known = s.hosts.find((x) => x.alias === target);
      const line = (d) => d.slice(0, 400);
      if (g.test === "changed")
        return { ok: true, connected: false, account: null, host_key: "changed", message: "The server's key changed. Safe stopped. Check with the server's owner.", detail: line("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nHost key verification failed.") };
      if (target === "work-proxy" && g.test !== "fail")
        return { ok: true, connected: false, account: null, host_key: "known", message: "Safe couldn't reach proxy.example.com. Check the address, and that you are online.", detail: "ssh: connect to host proxy.example.com port 2222: Connection timed out" };
      if (g.test === "fail")
        return { ok: true, connected: false, account: null, host_key: "known", message: `${name} doesn't know this key yet. Add it on the page, then check again.`, detail: `git@${known?.host_name ?? target}: Permission denied (publickey).` };
      const git = ["github", "gitlab", "bitbucket", "codeberg", "gitea", "azure-devops"].includes(known?.service ?? target);
      return { ok: true, connected: true, account: git ? "sam" : null, host_key: known ? "known" : "added", message: git ? `Connected to ${name} as sam.` : `Connected to ${name}.`, detail: git ? "Hi sam! You've successfully authenticated, but GitHub does not provide shell access." : "" };
    },
    ssh_hosts: () => ({ ok: true, hosts: hostsReply() }),
    ssh_host_set: ({ alias, host: h, user, port, key, noKey }) => {
      if (!alias || /[\s*?!]/.test(alias)) return fail("bad-request", "A host name can't be empty or have a space, *, ? or !.");
      const there = s.hosts.find((x) => x.alias === alias);
      if (there?.source === "yours") return { ...fail("conflict", `You set up ${alias} yourself in ~/.ssh/config. Change it there.`), alias };
      const k = key ? find(key) : null;
      if (key && !k?.ssh) return fail("not-found", `No SSH key ${key}.`);
      const def = there ?? host(alias, {});
      if (h !== undefined) def.host_name = h && h !== alias ? h : null;
      if (user !== undefined) def.user = user || null;
      if (port !== undefined) def.port = port && Number(port) !== 22 ? Number(port) : null;
      if (k) Object.assign(def, { key: keyRef(k), file: k.ssh.file });
      if (noKey) Object.assign(def, { key: null, file: null });
      s.hosts = [...s.hosts.filter((x) => x.alias !== alias), def];
      return { ok: true, alias, sync };
    },
    ssh_host_remove: ({ alias }) => {
      const there = s.hosts.find((x) => x.alias === alias);
      if (!there) return fail("not-found", `There is no host ${alias}.`);
      if (there.source === "yours") return { ...fail("conflict", `You set up ${alias} yourself in ~/.ssh/config. Change it there.`), alias };
      s.hosts = s.hosts.filter((x) => x !== there);
      return { ok: true, alias, sync };
    },
    // GATE.md S25
    ssh_sign: ({ itemId, email, off }) => {
      if (off) {
        g.signing = null;
        return { ok: true, signing: null, sync };
      }
      const k = find(itemId);
      if (!k?.ssh) return fail("not-found", `No SSH key ${itemId}.`);
      if (!g.gitEmail && !email) return fail("bad-request", "Tell Safe your Git email: --email");
      if (email) g.gitEmail = true;
      g.signing = k.id;
      return { ok: true, signing: keyRef(k), email: email || "sam@example.org", sync };
    },

    keyring_status: () => {
      const broken = s.keyring === "broken" || s.keyring === "locked";
      return {
        ok: true,
        adopted: s.keyring === "safe",
        serving: s.keyring === "safe",
        open: s.keyring === "safe",
        items: s.keyring === "safe" ? krItems().length : 0,
        owner: { none: "none", safe: "ewe-safe" }[s.keyring] ?? "gnome-keyring",
        pam: false,
        default: s.keyring === "none" ? null : broken ? "Default_keyring" : "login",
        collections: s.keyring === "none" ? [] : broken ? ["Default_keyring", "login", "session"] : ["login", "session"],
        needs_repair: broken
      };
    },
    keyring_list: () => ({
      ok: true,
      items: krItems().sort((a, b) => a.label.localeCompare(b.label)),
      locked: s.keyring === "locked" ? [{ collection: "Default_keyring", label: "Default keyring", items: 2 }] : [],
      source: { none: "none", safe: "ewe-safe" }[s.keyring] ?? "gnome-keyring"
    }),
    keyring_repair: ({ dryRun }) => {
      if (s.keyring === "none") return fail("source-error", "No keyring runs now.");
      if (s.keyring === "fine") return { ok: true, already: true, fixed: true, default_was: "login", moved: 0, duplicates: 0, conflicts: 0, replaced: 0, skipped: 0, locked: [], sources: [], message: "The keyring is fine: “default” already is your login keyring." };
      const report = { default_was: "Default_keyring", already: false, moved: 2, duplicates: 1, conflicts: 0, replaced: 0, skipped: 0, locked: [], sources: ["Default_keyring"] };
      if (!dryRun) s.keyring = "fine";
      return { ok: true, ...report, fixed: !dryRun, ...(dryRun ? { dry_run: true } : { hint: "The old keyring (Default_keyring) stays as a backup. To delete it later: Passwords and Keys (seahorse) → right-click it → Delete, or remove ~/.local/share/keyrings/Default_keyring.keyring and log out and back in." }) };
    },

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
      import: params.get("view") === "import",
      ssh: params.get("view") === "ssh"
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
    open_page: () => ({ ok: true }),
    open_ewe_sync: () => ({ ok: true }),
    // your ewe computers (RFC-009), as the window passes `ewe-remote status --offline` on
    remote_status: () => {
      if (g.remote === "0") return { ok: false, code: "missing", error: "missing", message: "ewe-remote is not installed." };
      const all = [
        { id: "a1b2c3d4e5f60718", name: "desk", user: "sam", online: g.remote !== "offline", paired: true, allowed: true, sharing: true, last_seen: Math.floor(Date.now() / 1000) - 60 },
        { id: "0f1e2d3c4b5a6978", name: "travel laptop", user: "sam", online: false, paired: true, allowed: true, sharing: true, last_seen: Math.floor(Date.now() / 1000) - 86400 * 4 },
        { id: "99aa88bb77cc66dd", name: "living-room", user: "sam", online: g.remote !== "offline", paired: false, allowed: false, sharing: true, last_seen: Math.floor(Date.now() / 1000) - 300 }
      ];
      return { ok: true, this: { name: "laptop", sharing: true }, computers: g.remote === "empty" ? [] : all };
    },
    remote_terminal: ({ id }) => (g.remote === "offline" ? fail("unreachable", "travel laptop can't be reached right now") : { ok: true, id }),
    ssh_terminal: () => ({ ok: true }),
    pick_file: ({ kind }) =>
      kind === "ssh-key"
        ? { ok: true, path: "/home/sam/.ssh/id_ed25519" }
        : { ok: true, path: `/home/sam/Downloads/1PasswordExport.${kind === "csv" ? "csv" : kind}` },
    print_page: () => ({ ok: true }),
    quit_app: () => ({ ok: true })
  };
  const local = new Set(["daemon_state", "launch_args", "theme_tokens", "theme_key", "settings_get", "settings_set", "passwords_provider", "use_safe_for_passwords", "cloud_status", "window_classes", "open_url", "open_page", "open_ewe_sync", "remote_status", "remote_terminal", "ssh_terminal", "pick_file", "print_page", "quit_app", "check_login_password"]);
  const needsUnlock = new Set(["list", "search", "match_items", "show", "reveal", "copy", "add", "edit", "rm", "restore", "import_items", "ssh_new", "ssh_add", "ssh_adopt", "confirm", "convert", "ssh_takeover", "ssh_connect", "ssh_test", "ssh_sign"]);

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
  if (view === "ssh") ui.go("ssh");
  if (view === "sshkeys") ui.pick({ kind: "ssh-key" });
  // the SSH page's sheets
  const connect = params.get("connect");
  if (connect) {
    ui.go("ssh");
    ui.connect = connect === "pick" ? {} : { service: connect };
  }
  if (params.get("takeover") === "1") {
    ui.go("ssh");
    ui.takeover = true;
  }
  if (view === "cards") ui.pick({ kind: "card" });
  if (view === "addresses") ui.pick({ kind: "address" });
  const edit = params.get("edit");
  if (edit === "card" || edit === "address") {
    ui.pick({ kind: edit });
    ui.selected = edit === "card" ? MOCK_CARD : MOCK_ADDRESS;
    ui.editing = { mode: "edit", id: ui.selected, kind: edit };
  } else if (edit && edit !== "new") {
    ui.selected = fixture.items.find((i) => i.title.toLowerCase() === edit)?.id ?? null;
    ui.editing = { mode: "edit", id: ui.selected, kind: "login" };
  }
  const sel = params.get("select");
  if (sel) ui.selected = fixture.items.find((i) => i.title.toLowerCase() === sel)?.id ?? null;
  // &select=card|address: the sample Visa, the sample Home
  if (sel === "card") ui.selected = MOCK_CARD;
  if (sel === "address") ui.selected = MOCK_ADDRESS;
  if (sel === "key") {
    ui.pick({ kind: "ssh-key" });
    ui.selected = MOCK_SSH;
  }
  const fresh = params.get("new");
  if (fresh === "card" || fresh === "address") {
    ui.pick({ kind: fresh });
    ui.editing = { mode: "new", kind: fresh };
  }
  if (params.get("step")) ui.setupStep = params.get("step");
  if (params.get("kit") === "1") ui.kit = true;
  if (params.get("gen") === "1") ui.genOpen = true;
}
