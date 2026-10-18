# Safe and the system — login unlock, the keyring, cards and addresses

*Owner's ask, 2026-10-18 (they were heading out: "choose any recommended
option"):*

1. *"When I register somewhere it should ask me if I want to save the data as
   a new login."* (ewe browser)
2. *"I want to unlock Safe with my sudo password."* (= the login password)
3. *"Get rid of this keyring thing: it asks me to enter the keyring password
   every time I turn the laptop on."*
4. *"Safe for addresses and cards — without ruining users' safety. Even
   Nextcloud maybe isn't safe, so encrypt it there."*
5. *"Full Safe control, good integration with the system."*

This file is the contract for the streams that build it. It amends RFC-008
(PLAN.md §1: cards and identities were "out"; §8: "unlock with my login" kept
the key in the keyring). Rule 4 holds: protocol fields and verbs are only
**added**.

## 0. What we found on the owner's machine (2026-10-18)

- `~/.local/share/keyrings/default` says **`Default_keyring`**: a second
  keyring with its own password, made on 2026-09-03 by the bug in ewe's
  TROUBLESHOOTING ("Choose password for new keyring … Default keyring").
  PAM unlocks `login.keyring` with the login password, but apps read and write
  the *default* collection → `Default_keyring` is locked → a prompt at every
  boot. The 2026-09-03 fix stopped new installs from making it; it never moved
  this machine's items back.
- At this boot two apps asked to unlock at once; gnome-keyring hit
  `gkd-secret-unlock.c:244 perform_next_unlock: assertion failed` and dumped
  core. The replacement daemon was started by D-Bus **without** the password,
  so even `login` was locked after that.

So the prompt is gnome-keyring's own state plus a gnome-keyring crash. The
answer the owner asked for is to stop depending on it: **Safe becomes the
keyring** (§3), unlocked by the login password at the greeter (§2).

## 1. Decisions (recommended options, taken)

| # | decision | why |
|---|---|---|
| D1 | **Login password unlock = a wrapped key, not polkit.** The safe's master password is sealed on this computer under a key that only the login password opens. Typing the login password (greeter, Safe's unlock window) opens it. | Works from a user service (polkit's subject problem, PLAN §8, disappears); needs no keyring; it is real crypto, not only "a person is present". No polkit policy file. |
| D2 | **The greeter hands the password over through Safe's own PAM module**, `pam_ewe_safe.so` (as `pam_gnome_keyring` does). | The only way to unlock at login without a second prompt. |
| D3 | **Safe serves the Secret Service** (`org.freedesktop.secrets`) when the user adopts it, per machine. App secrets live in a **separate, local, never-synced** keyring file, open for the whole login session. gnome-keyring's files are left untouched as a backup. | "Get rid of the keyring" + "full Safe control". Local because app secrets are per machine (an Electron or Chromium storage key from another machine would clash). Open all session because background tools (ewe-sync, mail) must keep working while the screen is locked, like gnome-keyring's login keyring. |
| D4 | **Cards and addresses are items in the same safe file.** Nextcloud only ever holds the encrypted KDBX (AES-256 + Argon2id, made on this computer). Card number, security code and PIN are protected fields. | The owner's worry ("encrypt it there") is already how Safe works; we say so in the UI. |
| D5 | **Filling a card asks for the login (or master) password again** — once per 5 minutes (`[safe] confirm_cards`, default on). Never into `http://` pages. | Like Chrome's card autofill. "Don't ruin users' safety." |
| D6 | **Sign-up forms always get a "Save to Safe?" prompt**, even when Safe is locked ("Unlock and save"). | The owner's first point; today a locked Safe drops the capture silently. |
| D7 | The login unlock is **per machine** and **off for Nextcloud**: the copy in the place is still opened only by the master password. | A weak login password must not weaken the cloud copy. |

Honest limits (go into the UI and the docs, plain words): with login unlock
on, *the safe on this computer* is as strong as the login password. The copy
in Nextcloud is not affected. Malware running as you can still read what an
unlocked Safe holds (same as every desktop password manager).

## 2. Login unlock (stream **L**)

> **As built (2026-10-18).** This release ships login unlock without the PAM
> module: the owner wanted to review a module that takes the login password at
> the greeter before it goes near their machine. So:
>
> - **Shipped:** `login.key` / `master.wrap` and the crypto; the verbs
>   `unlock {login_password}`, `login-status` / `login-enable` / `login-disable`,
>   `confirm`; the 5-try limit (`too-many-tries`); `key-changed` (a stale
>   `master.wrap` is deleted); `master.wrap` re-sealed on every master unlock;
>   `[safe] unlock_at_login`; the Settings toggle and the window's login and
>   confirm modes.
> - **How W reaches the daemon at login:** not the greeter's PAM handoff below,
>   but gnome-keyring's `login` collection (`pam_gnome_keyring` already unlocks
>   it silently at login). Stream **K** owns that gnome-keyring client
>   (`carrier_store` / `fetch` / `delete`) and, at daemon start, puts W into
>   `daemon.session` and calls **`login::unlock_from_session(&Daemon)`** (W +
>   `master.wrap` → the normal unlock, no password; the caller honours
>   `unlock_at_login`). `login-enable` / `login-disable` carry W in and out
>   through the hooks **`login::ON_ENABLE` / `login::ON_DISABLE`** (`OnceLock`s K
>   sets at start).
> - **Parked for the owner's review** (`.wt/parked-pam/`, unchanged, not in the
>   build): `pam_ewe_safe.so`, `ewe-safe-pam-helper`, the greetd `pam.d` lines,
>   the `login-handoff` verb, the stale-candidate re-seal, and the screen-locker
>   stretch. The `unlock_at_login` background-unlock note and the honest limits
>   below still hold.

### Files (this computer only, `$XDG_STATE_HOME/ewe/safe/`, `0600`, never synced)

| file | what | sealed by |
|---|---|---|
| `login.key` | **W**, a random 32-byte session key | `KEK = Argon2id(login password, salt; 64 MiB, t=3, p=2)` |
| `master.wrap` | the safe's master password (UTF-8) | W |
| `keyring.safe` | the app secrets (§3) | W |

- Format of each: JSON `{"v":1, "kind":"ewe-safe-login-key"|"ewe-safe-master"|"ewe-safe-keyring", "kdf":{"alg":"argon2id","m_kib":65536,"t":3,"p":2,"salt":b64} (login.key only), "nonce":b64, "ct":b64}`, AEAD = **XChaCha20-Poly1305** (RustCrypto `chacha20poly1305`), the `kind` string as associated data. Writes: temp + fsync + rename. A new crate **`crates/login`** (`safe-login`) owns the format; L writes it first, K uses it.
- **W lives in the daemon's memory for the login session** once the login password opened `login.key` once (zeroized, `mlock` if possible). Locking the *safe* (idle, screen lock, sleep, `ewe-safe lock`) does **not** drop W; the daemon stopping (logout) does.
- Typing the login password always re-derives the KEK and opens `login.key` — W in memory is never a reason to skip the password.

### The flows

- **Enable** (Settings → Security → *Unlock with my login password*; CLI
  `ewe-safe login enable`): the caller asks for the login password, checks it
  with `/usr/bin/unix_chkpwd "$USER" nullok` (password on stdin; exit 0 = right;
  the daemon can't, `NoNewPrivileges` blocks the setuid helper), then calls
  the daemon with it (and the master password if the safe is locked). The
  daemon makes W (or opens the existing `login.key`), seals `master.wrap`.
- **Disable**: delete `master.wrap` (keep `login.key` while the keyring uses it).
- **Unlock with it**: socket `unlock {login_password}` → KEK → W → `master.wrap` → the master password → the normal unlock. 5 failed login-password tries in a row → `too-many-tries` until the master password is used once.
- **At login** (greetd, §2 PAM): the handoff opens `login.key` → W in memory → the keyring opens → if `master.wrap` exists and `[safe] unlock_at_login` (default on), the safe unlocks too (in the background; the network part must not hold anything up).
- **Login password changed** with `passwd` (Arch's `/etc/pam.d/passwd` doesn't include our module): the next login's handoff can't open `login.key`. The daemon keeps that password (it came from a *session* handoff, so PAM accepted it) in memory as the **candidate** (≤ 15 min, zeroized), status says `login.stale: true`, and the next time the user types the **old** login password (the window's "Your login password changed" mode) or the master password (master path: re-seal `master.wrap` with a fresh W, and the keyring through K's escrow, §3) the daemon re-seals under the candidate.
- **The master password changed** (here or on another machine): the next master unlock re-seals `master.wrap`. A login unlock whose master no longer opens the safe → `key-changed`, `master.wrap` is deleted, the window asks for the master password.

### `pam_ewe_safe.so` (Rust `cdylib`, crate `crates/pam`; `/usr/lib/security/`) — PARKED

> Parked for the owner's review (`.wt/parked-pam/`); not built or installed in
> this release. The daemon's `login-handoff` verb and the stale-candidate
> re-seal that this section needs were removed with it. The rest of §2 (the
> files, the verbs, `confirm`) ships; W reaches the daemon through
> gnome-keyring instead (see the "As built" note above).

- `pam_sm_authenticate`: copy `PAM_AUTHTOK` into PAM data (`pam_set_data`, a zeroizing cleanup). If the process already runs as the target user (a screen locker: Quickshell's `PamContext` calls only `pam_authenticate`), hand off now with `source: "lock"`. Always returns `PAM_IGNORE`.
- `pam_sm_setcred`: `PAM_IGNORE`.
- `pam_sm_open_session` (greetd, as root): if a stashed password exists, `fork`; the child drops to the user (`initgroups`, `setgid`, `setuid`), double-forks so login never waits, and execs **`/usr/lib/ewe-safe/ewe-safe-pam-helper handoff --source session`** with the password on a pipe. Return value: **`PAM_SUCCESS` iff the user adopted Safe as the keyring** (marker `~user/.local/state/ewe/safe/keyring.on`: opened `O_NOFOLLOW`, regular, owned by the user), else `PAM_IGNORE`. That lets ewe's greetd file skip gnome-keyring for exactly those users (below).
- `pam_sm_chauthtok` (`PAM_UPDATE_AUTHTOK`, only where a stack includes us): helper `rewrap` with old + new on the pipe (re-seals `login.key` directly, then tells the daemon if it runs).
- `pam_sm_close_session`: `PAM_IGNORE`.
- Never panics across FFI (`catch_unwind`), never logs a secret, never blocks login more than a fork. Every failure → `PAM_IGNORE`.
- **The helper** (`ewe-safe-pam-helper`, cli crate or its own bin): `handoff` connects to `$XDG_RUNTIME_DIR/ewe-safe.sock` (`/run/user/<uid>` when unset), retrying up to 5 s (the user manager may still be starting `sockets.target`), sends socket verb **`login-handoff {password, source}`**, exits.
- **Daemon `login-handoff`**: `source` = `session` | `lock` | `passwd`. Failures from `lock` are ignored silently (the locker sends every attempt, right or wrong); they never count against the 5 tries. `session` failures become the candidate (above).
- **ewe's `system/pam.d/greetd`** gets, after the existing lines of each type:
  ```
  -auth      optional                    pam_ewe_safe.so
  -session   [success=1 default=ignore]  pam_ewe_safe.so
  -session   optional                    pam_gnome_keyring.so auto_start
  ```
  (our session line goes directly **before** gnome-keyring's, replacing its old position). `success=1` skips gnome-keyring only for users with the marker. Missing module (Safe not installed) → nothing changes. **Prove both with a `pam_start_confdir` harness** (Linux-PAM ≥ 1.4, no root: a temp confdir with `pam_permit.so` + the module by absolute path + a second module standing in for gnome-keyring), including that a missing `-session [success=1 …]` module still runs the next line, and that our `ok` can't turn a failed stack into success.
- **The screen locker** (stretch, only if fully tested in the nested harness): ewe's `Lock.qml` uses `PamContext { config: "hyprlock" }`. If `/usr/share/ewe-safe/pam/ewe-lock` exists, use `configDirectory: "/usr/share/ewe-safe/pam"`, `config: "ewe-lock"` (`auth include /etc/pam.d/hyprlock` by absolute path — check that `include` accepts one inside a confdir — then `-auth optional pam_ewe_safe.so`). If anything is unsure, leave the locker alone: the safe then asks for the login password in its own window after a screen lock, which already meets the owner's ask.

## 3. Safe as the keyring (stream **K**)

- **Crate `crates/secrets`**: the Secret Service API on the **session bus** with zbus 5 (already a daemon dependency): `org.freedesktop.Secret.Service` (`OpenSession` with `plain` **and** `dh-ietf1024-sha256-aes128-cbc-pkcs7`, `CreateCollection`, `SearchItems`, `Unlock`, `Lock`, `GetSecrets`, `ReadAlias`, `SetAlias`, property `Collections`, signals), `Collection` (`CreateItem` with `replace`, `SearchItems`, `Delete`, `Label`, `Locked`, `Created`, `Modified`, `Items`, signals `ItemCreated/Deleted/Changed`), `Item` (`GetSecret`, `SetSecret`, `Delete`, `Label`, `Attributes`, `Locked`, `Created`, `Modified`), `Session.Close`, `Prompt` (`Prompt`, `Dismiss`, `Completed`). One collection `login` with alias `default`; `CreateCollection` makes named ones in the same file. Objects at the usual paths (`/org/freedesktop/secrets/collection/login/<n>`).
- The crate takes a trait from the daemon (`KeySource`: "W if open", "ask the user", "W arrived" events), so it builds and tests without the rest. The daemon glue is small.
- **Store**: `keyring.safe` (§2 table): `{items: [{id, collection, label, attributes, secret (b64), content_type, created, modified}]}`, sealed by W, written atomically on every change.
- **Locked keyring** (W not in memory: autologin, fingerprint login, a stale `login.key`): `Unlock` returns a prompt; `Prompt.Prompt` first waits up to 5 s if the daemon started in the last 30 s (the greeter's handoff may be on its way), then opens the Safe window in login mode (`ewe-safe-app --unlock --login`, or the stale mode). `Dismiss`/closing → `Completed(true, …)`.
- **`ewe-safe keyring` verbs** (CLI + socket, rule 5 JSON):
  - `status` → `adopted`, `serving` (we own the bus name), `open` (W in memory), `items` (count), `owner` (who owns `org.freedesktop.secrets` now: `ewe-safe` | `gnome-keyring` | `kwallet` | other | none), `pam` (greetd's PAM file names `pam_ewe_safe.so` with the skip).
  - `import [--dry-run]`: copy every item of every collection from the *current* owner (gnome-keyring) through its own Secret Service API: it unlocks each collection (gnome-keyring shows its own prompt — the last time the owner sees it), reads label, attributes, secret, content type, times. Same attributes in two collections → keep the newest. Report: `{collections, items, duplicates, skipped}`; labels never logged.
  - `adopt`: needs the login password (checked with `unix_chkpwd`; it makes or opens `login.key`), refuses with a hint when greetd's PAM file lacks the module (the hint is the exact command: the ewe update, or `sudo install -m644 <payload>/system/pam.d/greetd /etc/pam.d/greetd`). Then: import, write `keyring.on`, write the **user D-Bus service override** `$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service` (`Name=org.freedesktop.secrets`, `Exec=/usr/bin/ewe-safed`, `SystemdService=ewe-safe.service`; user dirs win over `/usr/share`), stop the running gnome-keyring **only if** the name's owner's `/proc/<pid>/exe` is `gnome-keyring-daemon` (SIGTERM), take the name. Answers what happened and `restart_apps` (apps that held the old keyring may need a restart).
  - `release`: the way back: drop the name, delete the override and the marker; `keyring.safe` stays (a later adopt reuses it). gnome-keyring's own files were never touched.
  - `list`: `{items: [{id, label, collection, app, created, modified}]}` (`app` from `application`/`xdg:schema` attributes); never a secret. `rm <id>`.
- **Escrow (should):** while the safe is unlocked and the keyring is adopted, keep W in the safe as a protected entry `ewe.kind = keyring-key` in a group `Safe/This computer keys`, title `Keyring key — <machine>` (custom data `ewe.machine` = machine id). The master password can then re-seal a stale `login.key` without the old login password. Skipped by every list, never offered by the picker or the browser.
- **The daemon at start**, adopted: request the name (`DO_NOT_QUEUE`); if gnome-keyring holds it (the PAM file not updated yet), log it, set `status.keyring.owner`, and don't fight.
- **Tests**: `dbus-run-session` sandboxes only (never the live session bus): `secret-tool store/lookup/search/clear` (libsecret: dh **and** plain), a zbus client, and `import` from a real `gnome-keyring-daemon --unlock --components=secrets` started inside the sandbox bus with sandbox `XDG_DATA_HOME`, then serving the same items. Check ewe's callers' code paths (`ewe-cloud` / `ewe-auth` via `secret-tool`, `ewe-companion` `keyring.rs`, `ewe-sync` `accounts.rs`) against the sandbox.

## 4. Cards and addresses (stream **C**)

### In the file (docs/FORMAT.md; every KeePass app shows plain fields)

| Safe | KDBX field | protected |
|---|---|---|
| kind | custom data `ewe.kind = card` / `address` | — |
| card: name of the card | `Title` (default "Visa •• 4242") | no |
| cardholder | `Cardholder` | no |
| number | `Number` | **yes** |
| expiry | `Expiry` (`MM/YYYY`) | no |
| security code | `Security code` | **yes** |
| PIN | `PIN` | **yes** |
| brand | `Brand` (`visa` `mastercard` `amex` `discover` `jcb` `unionpay` `diners` `maestro` `mir` `other`; from the number when not given) | no |
| address: name of it | `Title` (default "Home") | no |
| | `Full name`, `Organization`, `Address line 1`, `Address line 2`, `City`, `Region`, `Postal code`, `Country` (ISO 3166-1 alpha-2 when known), `Phone`, `Email` | no |
| both | `Notes` (protected, as for notes) | yes |

### The protocol (docs/PROTOCOL.md, added only)

- `kind`: `card` | `address` join `login` | `note` | `ssh-key`. `list --kind card|address`. Callers that don't know a kind skip it (already the rule).
- Summary gains `card` and `address` (null for other kinds):
  - `"card": {"brand": "visa", "last4": "4242", "expiry": "08/2029", "holder": "Sam Moe"}`
  - `"address": {"name": "Sam Moe", "line1": "12 Main St", "city": "Tbilisi", "country": "GE"}`
- `add` / `edit`, socket: `card: {holder, number, expiry, security_code, pin, brand}` and `address: {full_name, organization, line1, line2, city, region, postal_code, country, phone, email}`; in `edit` only the keys sent change, `""` clears. CLI: `--holder`, `--expiry`, `--brand`, `--card-stdin` (lines: number, security code, PIN; empty line = none), address flags `--full-name --organization --line1 --line2 --city --region --postal-code --country --phone --email`.
- `reveal --field number|security_code|pin` (cards; also the KDBX names).
- **`fields {item_id}`**, socket only, for the browser: a card → `fields: {holder, number, expiry_month: "08", expiry_year: "2029", security_code, brand}` (never the PIN); an address → `fields: {full_name, given_name, family_name, organization, line1, line2, city, region, postal_code, country, phone, email}`. A card needs a **fresh confirm** when `[safe] confirm_cards` is on → error **`confirm-needed`** (new code) otherwise.
- **`confirm {password | login_password}`**, socket; CLI `ewe-safe confirm [--ask] [--reason TEXT]` (`--ask` opens `ewe-safe-app --confirm --reason TEXT`, waits, like `unlock --ask`) → `confirmed_for` (seconds, 300). The safe must be unlocked. L adds `login_password` to it; C builds it with the master password first.
- New error codes: `confirm-needed`, `too-many-tries`, `login-stale` (L), `not-enabled` (L).
- **Import**: 1Password Credit Card → `card`, Identity → `address` (today both become notes). An existing safe's notes that came from those (the importer kept their fields) can be turned into items: `ewe-safe convert --from-1password [--dry-run]` (should).
- `[safe] confirm_cards` (bool, default true) in ewe's `[safe]` domain (ewe repo).

### The window (app/)

Sidebar: Cards, Addresses. New item: Card, Address. Detail: a card face (brand,
•••• last 4, expiry, holder; number/code/PIN hidden with reveal and copy), an
address block. Edit forms (number formatted in groups, brand detected,
expiry `MM/YY` input). A one-line note on the Card form and in Settings:
"Encrypted on this computer before it leaves it. Nextcloud only sees a locked
file." Design system v3 tokens only, the existing components' patterns.

### As built (stream C, 2026-10-18)

What differs from the plan above, or adds to it (all additions; rule 4):

- **Summary `card`** also has `has_number`, `has_security_code`, `has_pin`
  (the window and the browser know which rows exist without a reveal);
  `last4` is `""` for a number under ten digits. **`show`** gives an
  address's every part. `add`/`edit` replies carry **`warning`** when the
  number fails Luhn or isn't 12–19 digits (kept anyway).
- **`fields`** also answers `kind` and, for a card, `confirmed_for`. It takes
  `item_id` (also `id`). Items in the recycle bin: `not-found`.
- **`edit --card-stdin`:** an empty line keeps that value and `-` clears it
  (an empty line meaning "none" would wipe a number when only the code
  changes). In `add` an empty line is none, as planned.
- A new number sent without a brand takes its own brand; a card still titled
  as Safe titles a new one follows its new number. Empty values leave no
  KDBX field. `reveal`/`copy` also take `holder`, `expiry`, `brand` and an
  address's protocol names.
- **`convert`** moves the number, code and PIN out of their old protected
  custom fields (no duplicate secrets) and takes the lines that became
  fields out of the note's text (the window shows a card's notes in plain
  view); the rest of the text stays, the history keeps the note. The marker
  is the importer's own category line plus, for a card, exactly one
  protected 12–19-digit field. Identity lines are found by 1Password's
  English labels: a non-English export's identity stays a note
  ("Safe found no name or address in it").
- **Not built here:** the `confirm` verb and its window (stream L; tests call
  `Session::confirm` from a unit test), and `[safe] confirm_cards` in ewe's
  `ewe-conf` schema (the ewe branch). The window's switch writes
  `safe.confirm_cards` through ewe-conf; a schema that refuses the key makes
  the switch flip back with a toast.
- **The window** adds Settings → *Cards and addresses* (the encryption
  line, the `confirm_cards` switch, *Cards from an earlier import* =
  `convert` with a dry run first) and a New menu (Login, Note, Card,
  Address, SSH key) where the list shows more than one kind.

## 5. The ewe browser (stream **B**, branch off `origin/main`, staged only)

- **Sign-up save (D6):** a capture is never dropped because Safe is locked —
  the prompt says "Unlock and save" (`ewe-safe unlock --ask`, then save).
  A form whose password field is `new-password` (sign-up, or a confirm field)
  saves a **new login** unless a login for the same host *and* username exists
  (then update); never "update the only login on the site" when the username
  is unknown on a sign-up. Username: `autocomplete=username|email`, an email
  field, the text field before the first password, else one typed on an
  earlier step of the same site in the same tab (≤ 5 min). Submits that are
  not `<form>` submits: Enter in the password field, a submit-like button
  (exists), the password field leaving the DOM or an in-page navigation within
  10 s after typing. A password made with *Use a strong password* is offered
  for saving even when no submit is seen (on the tab's next navigation or
  when the tab closes).
- **Cards and addresses:** detect `cc-*` and address `autocomplete` tokens
  (and common name/label patterns); the inline list on those fields shows
  cards (brand, •••• last 4, expiry) or addresses (title, name, line 1); a
  pick fills the related fields of that form section in that frame. Cards:
  `https` frames only (or `localhost`); `fields` → `confirm-needed` →
  `ewe-safe confirm --ask --reason "Fill <card> on <host>"` → retry. Payment
  iframes (Stripe, Adyen…) are their own frames: fill what is in the focused
  frame. Never put a card number or code in a log, a toast or the CLI.
- **Coordination:** the wave-2 session (`.wt/b2-input`) is changing
  `main/safe/window.ts` (armGenerate/takeGenerate, openForKey, keyedAt),
  `preload/safe/content.ts` (inputIn, firstField, safeKindOf, openSafeAt),
  deleting `main/passwords.ts`, and adding `pageAction` to `ipc-contract.ts`.
  Keep your changes in those files small and separate; wave 2 lands first,
  then this branch is rebased.

## 6. Shared rules for every stream

- Sandboxes only: XDG sandboxes with a short `XDG_RUNTIME_DIR` symlink,
  `EWE_SAFE_NO_LOGIND`, low KDF (`EWE_SAFE_KDF_ITERATIONS`), `dbus-run-session`
  for anything on D-Bus, the nested Hyprland with your own `HS_WORK` for the
  desktop. **Never** the live session bus, keyring, `ewe.conf`, `ewe.service`,
  `/etc`, or the owner's safe. No `sudo`. Don't `pkill -f`.
- `cargo build --workspace` before `cargo test` (the CLI tests run the built daemon).
- No commits, no pushes, no vault edits: the main session reviews and lands.
- Plain short sentences in user-facing text; the name is **Safe**.
- Each stream finishes with: what it built, how it was tested (commands), what
  is unverified, and the exact list of changed files.

## 7. The base every ewe-safe stream starts from (branch `feat/system-base`)

Already written and tested, so L and K don't wait on each other:

- **`crates/login` (`safe_login`)**: `SessionKey` (W; `generate`,
  `from_bytes`, `as_bytes`, constant-time `==`), `Kdf` (`STANDARD` 64 MiB/3/2,
  `CHEAP` for tests, `from_env()` reads `EWE_SAFE_LOGIN_KDF=m_kib,t,p`),
  `create_key` / `seal_key` / `open_key` / `rewrap_key` for `login.key`,
  `seal` / `open` for any blob under W (with `KIND_*`), `seal_master` /
  `open_master`, `write_atomic`, `remove`; `Error::{Missing, WrongKey,
  Corrupt, Io}`.
- **`crates/daemon/src/session.rs`**: `Daemon.session` — `key()`, `is_open()`,
  `set(w)` (wakes waiters), `wait(timeout)`; the confirm: `confirm()`,
  `is_confirmed()`, `confirmed_for()`, `clear_confirm()` (already called by
  `Daemon::lock`); `CONFIRM_FOR` = 300 s; and
  `open_or_create(path, login_password, create)`.
- **`Paths`**: `login_key()`, `master_wrap()`, `keyring()`, `keyring_marker()`.

Who owns what, so the three ewe-safe branches merge cleanly:

| piece | owner |
|---|---|
| verbs `unlock {login_password}`, `login-handoff`, `login status/enable/disable`, `confirm`; `status.login`; `[safe] unlock_at_login`; the PAM module and helper; the app's Unlock (login, stale, confirm modes) and Settings → Security | **L** |
| `crates/secrets`, `daemon/src/keyring.rs`, verbs `keyring *`, `status.keyring`, escrow, the app's Settings → Keyring | **K** |
| kinds `card`/`address`, `fields`, the card gate (`session.is_confirmed()` + `[safe] confirm_cards`), import + convert, the app's items, FORMAT.md | **C** |
| ewe repo: greetd PAM, phase 30, `[safe] unlock_at_login` + `confirm_cards`, TROUBLESHOOTING, Lock.qml (stretch) | **L** (one ewe branch) |

Shared files (`verbs.rs` dispatch, `cli/src/main.rs` usage, `PROTOCOL.md`,
`status`, `app/src/lib/api.js`, `Settings.svelte`): add your lines in your own
block, don't reorder or reformat others'. CI runs `cargo clippy --all-targets
--locked -- -D warnings` and `cargo fmt --check`: both must be clean on your
branch (base's unused-yet items become used by L and K).

## 8. As built: §3, stream K (2026-10-18)

The main session's decision during the wave: **no PAM module in this
release** (L's module waits for the owner's review). Without it Safe can't
hold W after a restart, so taking over the keyring would bring back the
prompt it is meant to remove. So K shipped, in this order:

- **`ewe-safe keyring repair [--dry-run]`** (new, not in §3): fixes §0's
  bug in the keyring that runs. Through gnome-keyring's own API it copies
  every item of every other collection into `login` (duplicates — the same
  attributes and secret — skipped; the same attributes with another secret:
  the newer by `Modified` wins, reported as `conflicts`/`replaced`), then
  `SetAlias("default", login)`. Source items and collections are never
  changed or deleted. A collection that stays locked leaves everything as it
  was (`default` too), so nothing is stranded behind a prompt. Tested
  against a real gnome-keyring-daemon shaped like the owner's machine.
- **`keyring status`** answers `default`, `collections`, `needs_repair`
  from the running keyring; **`keyring list`** lists the running keyring's
  items (names and dates, no secret, no prompt; locked collections by
  count). Neither starts a keyring.
- **The carrier** (new, not in §3): `safe_secrets::carrier_store / fetch /
  delete` keep W as one item in gnome-keyring's `login` (label "Safe —
  unlock key for this computer", attributes `application=ewe-safe`,
  `ewe-safe=session-key`, `machine=<id>`), never prompting. The main session
  wires it to L's login verbs.
- **Safe as the keyring** (§3 itself) is built and tested but **parked**:
  `adopt` refuses with `needs-login-module` while
  `/usr/lib/security/pam_ewe_safe.so` is missing (`EWE_SAFE_PAM_MODULE` in
  tests), and the server starts only when `keyring.on` exists, which only
  `adopt` writes.

Where the build differs from §3:

- `keyring.safe`'s JSON also holds `collections` (name, label, times, the
  next item number) and `aliases`; each item has `n`, its stable path
  number. A new, unsealed file **`keyring.index`** holds the collections,
  the aliases and, per item, its collection, number and salted SHA-256
  hashes of its attributes (never a label, an attribute's value or a
  secret): a locked keyring can then answer `SearchItems` with the right
  locked paths, so libsecret's `Unlock` → prompt flow works (gnome-keyring
  keeps hashed attributes for the same reason).
- The login password for `adopt` is checked with `unix_chkpwd` by the
  caller (`safe_client::chkpwd`, `EWE_SAFE_CHKPWD`), as §2 says for
  `login enable`: the daemon can't (`NoNewPrivileges`).
- `status.keyring.pam` = the module is installed **and** greetd's file has
  the skip line. `open` = W is in memory; `items` = Safe's own keyring's
  count.
- Added verbs: `keyring unlock` (W from `login.key`, opening Safe's
  keyring; the prompt window's fallback) and the error codes
  `keyring-locked`, `not-adopted`, `pam-missing`, `needs-login-module`,
  `no-login-keyring`.
- `Lock` is a mark only while W is known (no prompt to unlock again).
- The D-Bus file's `Exec` is the daemon's own path (`/usr/bin/ewe-safed`
  when installed). `adopt` and `release` call `ReloadConfig` (dbus-broker
  doesn't watch its folders).
- **Escrow** (W in the safe as a hidden entry) was **not built**: it only
  matters once Safe serves the keyring, and the carrier covers the login
  path in this release.
