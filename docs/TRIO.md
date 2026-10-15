# Safe, the browser and the companion — working together

**Status:** plan, 2026-10-15. Asked by the owner on 2026-10-15. Amends RFC-008
(Safe): **passkeys** and the **SSH agent** leave the parked list (§18), and S8
(the companion) gets the actions below. Work started the same day.

This file is the contract between three repos: `ewe-safe`, `ewe-browser`
and `ewe-companion` (+ `ewe-plugin-passwords`, `ewe-plugin-companion`). Every
agent reads it first. When code and this file disagree, fix one of them in
the same change.

## What the owner asked (2026-10-15, in short)

1. **Safe is a real safe.** It works like 1Password does today:
   - suggestions **in** the login fields of the browser;
   - **passkeys**: create and sign in with them ("in 1Password I used passkeys
     and could log in with no problem");
   - **SSH keys**: stored in Safe and used by `ssh` and `git` (the owner pushes
     with 1Password's SSH agent today). A standalone `ewe-ssh` comes later;
   - a **CLI** that needs no 1Password CLI. Today `Super+P` still shows
     "make sure 1Password CLI is installed" (cause: the Passwords plugin is
     still set to `provider = "1password"`).
2. **ewe browser**: real syncing, real history management, Safe built in like
   an extension.
3. **The companion**: can use Safe and the browser. "Search something" opens
   the browser. It finds files and folders. New commands.
4. **Well-known, well-documented formats** wherever one exists, so other
   apps (KeePassXC, KeePassDX, Strongbox, ssh, git) understand our data.

A note on "no GitHub login": the live safe on this machine has the login
(`GitHub` in *Personal*, three `github.com` in *Remedium*; `match --url
https://github.com/login` finds all four). What the owner saw is the picker
still asking 1Password (provider `1password`) and the released browser
(0.1.0-beta) having no Safe yet (`feat/safe` is not merged). Both are fixed
below (S3, B1).

## The rules this keeps

- **Values never cross** (RFC-007 C3, RFC-008 S8). The companion asks Safe to
  *copy* a value; Safe runs `wl-copy` itself. No reply to the companion, and no
  model context, ever holds a password, a code, a key or a note.
- **Names stay local.** Titles and usernames may be shown on the island. They
  never go to a model provider and never into `companion.db`.
- **Fill is a click.** Nothing fills on page load. A passkey is used only after
  a click in the browser's own UI.
- **The browser decides the origin.** Safe never trusts an origin or an RP ID
  that a page sent. The browser's main process takes it from the frame.
- **Public API is additive** (rule 4). New verbs and fields; nothing renamed.
- **Every CLI prints JSON and exits 0** (rule 5), except the documented
  exceptions (`reveal`, `read`, `run`, the git helper — they follow the tool
  they copy).
- **Tests run in sandboxes only:** XDG sandboxes, fake keyring, mock WebDAV,
  `EWE_SAFE_NO_LOGIND`, low KDF, `EWE_SAFE_OP` fake. Never the live safe, the
  live `ewe.conf`, the live `~/.ssh` or the live browser profile.

---

## S1. Passkeys in Safe (ewe-safe)

### Storage: the KeePassXC format

A passkey is stored the way **KeePassXC 2.7.7+** stores it. KeePassDX (4.1+)
and Strongbox read the same fields, so a passkey made in ewe works on the
phone too. Custom fields on a login entry:

| field | value | protected |
|---|---|---|
| `KPEX_PASSKEY_CREDENTIAL_ID` | credential id, base64url, no padding | **yes** (KeePassXC and KeePassDX protect it; checked 2026-10-15) |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | the private key, PKCS#8 PEM | **yes** |
| `KPEX_PASSKEY_RELYING_PARTY` | the RP ID (`github.com`) | no |
| `KPEX_PASSKEY_USERNAME` | `user.name` from the site | no |
| `KPEX_PASSKEY_USER_HANDLE` | `user.id`, base64url | **yes** |

Check every name, encoding and the protected flags against KeePassXC's source
(`src/browser/BrowserPasskeys*.cpp`, `PasskeyUtils`, `BrowserService`) before
writing code, and keep a KeePassXC-made fixture in the test corpus. When
KeePassXC also sets the title, URL, username or a tag, do the same.

- **Where it goes:** if the browser names a login (`item_id`), the fields go
  on that entry (1Password keeps the passkey in the login too). Otherwise a
  new login: title = RP name (or RP ID), username = `user.name`, URL =
  `https://<rp_id>`.
- **One passkey per entry.** A second passkey for another account on the same
  site is a second entry.
- **Algorithms:** ES256 (`-7`) must work; EdDSA (`-8`) should; RS256 (`-257`)
  only if it is cheap. The first algorithm in the site's list that we support
  wins.
- **Sign count:** always 0 (synced passkeys can't keep a counter; Apple,
  Google and KeePassXC send 0).
- **Flags:** UP always; UV when the browser says the user was verified (the
  safe is unlocked and the user clicked = UV, as 1Password treats it); **BE
  and BS set** (the passkey is backed up and synced: it lives in the file).
  AT on create.
- **AAGUID:** Safe's own, fixed: `452b824e-42d3-4324-bc6c-581888ca2851`.
- **Attestation:** `none` only (`{"fmt":"none","attStmt":{},"authData":…}`).
- **Import:** 1Password's export leaves passkeys out (`docs/IMPORT.md`). The
  owner signs in once with the password (or 1Password) and adds a Safe
  passkey on each site. The window says this in one line on the Import screen.

### Item summary (added field)

`"passkey": {"rp_id": "github.com", "username": "sam"}` on an item that has
one, `null` otherwise. Never the key or the user handle.

### Verbs (socket; CLI where it makes sense)

Bytes travel as base64url without padding.

| verb | args | reply (besides `ok`) |
|---|---|---|
| `passkey-list` | `rp_id`, optional `allow` (list of credential ids) | `passkeys: [{item_id, title, username, rp_id, credential_id}]`, best first (last used, then title). CLI: `ewe-safe passkey list [--rp R]` |
| `passkey-create` | `rp_id`, `rp_name`, `user_id`, `user_name`, `user_display_name`, `client_data_hash` (32 bytes), `algorithms` (COSE ids, the site's order), `exclude` (credential ids), optional `item_id`, `origin` (for the URL), `user_verified` | `item_id`, `credential_id`, `attestation_object`, `authenticator_data`, `public_key` (SPKI DER), `public_key_algorithm`, `sync` |
| `passkey-get` | `rp_id`, `credential_id` (the one the user picked), `client_data_hash`, `user_verified` | `item_id`, `credential_id`, `authenticator_data`, `signature` (DER for ES256), `user_handle` |

New error codes (additive): `excluded` (a credential in `exclude` is already
in the safe: the browser answers `InvalidStateError`), `unsupported` (no
algorithm we support: `NotSupportedError`). `not-found` when the credential
isn't in the safe for that RP. `locked` as everywhere.

The daemon checks that `rp_id` is a syntactically valid host name and that
`client_data_hash` is 32 bytes. It does **not** check origins: the browser did.
`edit <id> --remove-passkey` removes the five fields.

The window shows a passkey row on the item ("Passkey · github.com · sam",
Remove), and a key badge in the list.

## S2. SSH keys in Safe (ewe-safe)

### Storage: the KeeAgent format

KeePassXC's SSH agent reads **KeeAgent** entries. We use the same, so the file
stays portable:

- the private key as an **attachment** (OpenSSH format, e.g. `id_ed25519`);
- a `KeeAgent.settings` attachment (XML) that names it, with
  `AllowUseOfSshKey=true`; KeePassXC's own defaults for the rest;
- the key's passphrase (if any) in the entry's **password**;
- unprotected custom fields `public_key` (the OpenSSH public line) and
  `fingerprint` (`SHA256:…`), so lists don't decrypt the key.

Check the XML shape and names against KeePassXC's `src/sshagent/` before
writing code; keep a KeePassXC-made fixture.

The summary's `kind` gets a third value, `"ssh-key"`, plus
`"ssh": {"public_key": "…", "fingerprint": "SHA256:…", "key_type": "ed25519",
"agent": true}` (null for other kinds; `agent`: an agent may use it, as
built). `match` keeps answering logins only.

### Getting keys in

- `ewe-safe ssh add <file> [--title T]` (and the window's *Add SSH key*):
  imports an existing private key file. `ewe-safe ssh new [--type ed25519]
  --title T` makes a new one.
- **1Password import:** the *SSH Key* category becomes an `ssh-key` item (it
  was a note until now). For safes already imported (the owner's):
  `ewe-safe ssh adopt [--dry-run]` turns those notes into `ssh-key` items in
  place (same UUID, nothing lost; the note text stays in notes).

### The agent

`ewe-safed` also speaks the **ssh-agent protocol**
(draft-miller-ssh-agent) on `$XDG_RUNTIME_DIR/ewe-safe-ssh.sock` (0600,
`SO_PEERCRED` same uid, socket-activated like the main socket).

- `REQUEST_IDENTITIES`: every `ssh-key` item that allows agent use. Works
  **while locked** from a public-key cache in
  `$XDG_STATE_HOME/ewe/safe/ssh-public.json` (public keys only).
- `SIGN_REQUEST`: ed25519, ecdsa-sha2-nistp256/384, rsa-sha2-256/512. Locked →
  the daemon opens the unlock prompt and waits (60 s), as 1Password does.
- **Approval:** the first use of a key by an app in each unlock asks "Allow
  *ssh (from git)* to use *GitHub key*?" (Allow / Deny), like 1Password. The
  app is found through `SO_PEERCRED` → `/proc/<pid>` (and its parent). Setting
  `[safe] ssh_confirm = "first-use" | "every-time" | "never"`, default
  `first-use`. No answer in 60 s = deny.
- Adding or removing keys through the agent (`ssh-add`) is refused; keys come
  from Safe.
- **Turning it on:** `ewe-safe ssh enable` records `[safe] ssh_agent = true`
  (through `ewe-conf`) and sets `SSH_AUTH_SOCK` for new sessions
  (environment.d); it prints the one `IdentityAgent` line for `~/.ssh/config`
  but never edits that file. `ewe-safe ssh status` answers `enabled`,
  `socket`, `keys`, and whether `SSH_AUTH_SOCK` points at us.

`ewe-plugin-ssh` stays as it is; the standalone `ewe-ssh` comes later and
builds on this.

## S3. The CLI that replaces `op` (ewe-safe)

Copy the shapes people already know from 1Password's CLI:

| command | does | like |
|---|---|---|
| `ewe-safe read "safe://<folder>/<title>/<field>"` (or `safe://<item-id>/<field>`) | prints the bare value, exits 0; nothing found → nothing printed, exit 1 (same as `reveal`) | `op read` |
| `ewe-safe run [--env-file F] -- <cmd>…` | env values that are `safe://…` references are resolved for the child only; exits with the child's code | `op run` |
| `ewe-safe inject -i <template> [-o <file>]` | replaces `{{ safe://… }}`; the output file is written 0600 | `op inject` |
| `ewe-safe git-credential get\|store\|erase` | git's credential-helper protocol; strict host match; `store` asks before saving a new login | `git-credential-*` |

Fields: `password`, `username`, `otp`, `notes`, `url`, `public_key`,
`private_key`, or a custom field's name. A title with `/` is written `%2F`.
Two items with the same path → error `ambiguous` (exit 1 for `read`), never a
guess.

**`Super+P` without 1Password:** `ewe-plugin-passwords` uses provider `ewe`
when Safe is set up and the configured provider can't answer (the picker's
error row gets a *Use Safe* button that records the change through the
plugin-settings path); a 1Password import that finishes offers *Use Safe for
Super+P*. On this machine the setting is changed once, with the owner's OK.

---

## B1. Safe in ewe browser, like 1Password (ewe-browser, `feat/safe`)

The staged `feat/safe` work stays the base (owner review pending). On top:

### Inline suggestions

- When a username, email, password or one-time-code field gets focus **from
  the user** (click or Tab), a small menu drops under the field: the logins
  (and passkeys) for **that frame's own origin** — favicon, title, username.
  The footer: *Open Safe*, *Use a strong password* (new-password fields),
  *Unlock Safe* when locked.
- **Focus stays in the field.** Typing filters the list; ↑ ↓ move; Enter
  fills; Esc closes. The page's preload catches only those keys, only while
  the menu is open.
- The menu is drawn by the browser (the overlay view, placed by main at the
  field's rectangle, following scroll and resize), never inside the page's
  DOM: the page can't read it or restyle it (1Password uses an extension
  iframe for the same reason).
- A setting: *Show suggestions when a field gets focus* (on) — off means the
  key icon only, as today.

### Passkeys (WebAuthn)

- The preload replaces `navigator.credentials.create/get` **for
  `publicKey` requests only**; anything else goes to the original.
  `PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()` and
  `isConditionalMediationAvailable()` answer `true` when Safe is set up;
  `getClientCapabilities()` says so too.
- Main takes the origin from the frame (`senderFrame.origin`), checks the RP
  ID (https only, `localhost` excepted; the RP ID is the host or a registrable
  suffix of it, never a public suffix: tldts), builds `clientDataJSON`
  (`type`, `challenge`, `origin`, `crossOrigin: false`), hashes it, and calls
  `passkey-create` / `passkey-get`. Cross-origin frames get
  `NotAllowedError` in this version.
- UI in the overlay: *Save a passkey for github.com in Safe?* (account name;
  *Save* / *Use a security key instead* / *Cancel*) and *Sign in to github.com
  with a passkey* (the passkeys, `allowCredentials` applied). The safe locked
  → *Unlock Safe* first.
- **Conditional mediation** (`mediation: "conditional"`): the passkeys appear
  at the top of the inline suggestions on the username field; picking one
  resolves the waiting promise. `AbortSignal` is honoured.
- The returned object looks like a real `PublicKeyCredential`
  (`rawId`, `response.clientDataJSON`, `attestationObject`,
  `getTransports()` → `["internal","hybrid"]`, `getAuthenticatorData()`,
  `getPublicKey()`, `getPublicKeyAlgorithm()`, `authenticatorAttachment:
  "platform"`, `getClientExtensionResults()` with `credProps.rk = true`,
  `toJSON()`). Study how Bitwarden's browser extension does this
  (`fido2` page script) and test against a local test RP in e2e.
- Errors map to the WebAuthn `DOMException` names (`NotAllowedError`,
  `InvalidStateError`, `NotSupportedError`, `AbortError`, `SecurityError`).

## B2. History and real sync (ewe-browser, `feat/history`)

- **`app://history`**: all of it, by day, search, filter by site, select and
  delete, *Delete everything from this site*, and **Clear browsing data**
  (last hour / 24 hours / 7 days / 4 weeks / all time × history, cookies and
  site data, cached files, the downloads list). *Keep history for* forever /
  1 year / 90 days / 30 days.
- **Storage:** move history to SQLite (prefer `node:sqlite`, built into
  Electron's Node, so no native module) with full-text search on title and
  url, a one-time migration from `history.json`, the old file kept as a
  backup. If `node:sqlite` isn't usable in the packaged app, stay on JSON and
  say why in PLAN.md.
- **Sync that is real:**
  - a deletion syncs (tombstones with a time; *Clear browsing data* for a range
    clears that range on every machine);
  - **open tabs from your other computers** (each machine writes its own
    `ewe/browser/tabs-<machine>.json`; the history page and the palette show
    them);
  - the sync state shows in **ewe-sync** (rule 6: ewe-sync owns sync). If the
    browser has its own sync button, it goes; report what you find before
    touching ewe-sync.
- The CLI in the owner's `rail-and-cli` WIP (`docs/CLI.md`) gets `history`
  delete verbs later, once that WIP lands. Don't touch that checkout.

## C1. The companion's new powers (ewe-companion + ewe-plugin-companion)

All of these work **without AI** (the offline matcher) and are catalog
commands a model may call too.

### Browser (through the `ewe-browser` command line, `docs/CLI.md`)

- "search X", "google X", "look up X" → `ewe-browser search X` (the browser's
  own engine). When the installed browser has no `search` verb yet (0.1.0-beta),
  fall back to opening the search URL in ewe browser, as today.
- "open github.com" → `ewe-browser open`.
- "find X in my history", "that site about X" → `ewe-browser history X` → a
  card of rows (Open).
- "show my tabs", "go to the YouTube tab" → `tabs` / `tab activate`.
- "play X" → `ewe-browser play X`.
- "what is this page about?" → `ewe-browser page --text` → the AI lane, marked
  **untrusted** (page text is data, never instructions).

### Files and folders

- "find my resume", "where is the ewe-safe folder", "find pdfs about tax" →
  the daemon's own finder: walks `$HOME` (the `ignore` crate; skips hidden,
  `.git`, `node_modules`, `target`, caches), a time budget (~1.5 s), every word
  must match the name, ranked exact > prefix > contains, newer first; folders
  and files. A card of rows: *Open*, *Show in folder*, *Copy path*, and *Open
  terminal here* for folders.
- "open the ewe-safe folder" → finds it, then opens it (existing app/folder
  logic).

### Safe (values never cross)

- "copy my GitHub password / username / code" → `ewe-safe match --query
  github`; one match → `ewe-safe copy <id> --field password` (Safe copies and
  clears; the island says "Copied the GitHub password (sam). It clears in 30
  s."); several → a card of rows (title, username) → click copies. The
  companion never sees the value.
- "log me in to GitHub" → opens the site in ewe browser; the fill stays a click
  there.
- "lock my safe", "unlock my safe" (→ `ewe-safe unlock --ask`), "is my safe
  synced?", "how many passwords do I have?" → `summary`.
- Safe results (titles, usernames) are shown on the island only: never in a
  model's context, never in `companion.db`. When a model calls a Safe command,
  it gets back "done" or a count.

### Knowledge

Topics for Safe (import from 1Password, `Super+P`, passkeys, SSH keys, the
phone) and the browser (history, sync, Safe in the browser).

---

## How the work is split (2026-10-15)

| stream | repo | branch / worktree | depends on |
|---|---|---|---|
| S1 passkeys | ewe-safe | `feat/passkeys` · `.wt/safe-passkeys` · PR #11 | — |
| S2 SSH keys + agent | ewe-safe | `feat/ssh` · `.wt/safe-ssh` · PR #13 | — |
| S3 CLI + `Super+P` fix | ewe-safe, ewe-plugin-passwords | `feat/cli-power` · `.wt/safe-cli`, `.wt/passwords-safe` · PR #10 | — |
| B1 inline + passkeys | ewe-browser | `feat/safe` · `.wt/ewe-browser-safe` | S1's contract (a fake daemon in tests) |
| B2 history + sync | ewe-browser | `feat/history` · `.wt/ewe-browser-history` | — |
| C1 companion powers | ewe-companion, ewe-plugin-companion | `feat/powers` · `.wt/companion-powers` | the CLI contracts above |

S1, S2 and S3 meet in ewe-safe: `integrate/trio` (`.wt/safe-integrate`)
merges the three and the window's edit hotfix (PR #12) and tests them
together, as one PR; merging it lands all four.

Then: an independent review pass (DeepSeek reviewers through `opencode`, plus
the security reviewer on S1, S2 and B1's WebAuthn code), merge, the owner's
real test, releases through the `ewe-release` skill (each with the owner's OK).

## Owner's answers (2026-10-15)

- **`Super+P`:** switched to provider `ewe` on this machine
  (`ewe-plugin set ewe.passwords provider ewe`; `press_enter` kept).
  Gotcha found on the way: `ewe-conf set` with a quoted dotted id
  (`plugins.settings."ewe.passwords".provider`) silently writes a bogus
  `[plugins.settings."\"ewe"]` table — use `ewe-plugin set`.
- **`rail-and-cli`** (the browser's CLI + rail WIP): taken over — reviewed,
  tested, committed on its branch, PR opened, no merge without the owner.
- **Commits:** each stream is committed on its branch and opened as a PR once
  tested. No merge and no release without the owner's OK. `feat/safe` still
  waits for the owner's review of its diff (ewe-browser's AGENTS.md).
- The companion's uncommitted guides (`AGENTS.md`, `docs/EXTENDING.md`,
  `docs/TESTING.md`) ride along on `feat/powers`.
