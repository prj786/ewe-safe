# ewe-safe protocol — the CLI and the socket (v1)

The public API of Safe (house rule 4: renaming a verb or a field breaks
installed callers). Callers: the Passwords plugin's `ewe-pass`, the Safe
app, ewe-sync, the ewe browser, ewe-companion, scripts.

**Stability:** fields may be **added** at any time; callers ignore fields
they don't know. Renaming or removing a verb or a field means `"v": 2`.

## The CLI

`ewe-safe <verb> [args]` prints **one JSON object** on stdout and **exits 0**
(house rule 5). Three documented exceptions (`watch` streams lines, below):

- **`reveal` without `--json`** prints the bare value and a newline, and exits 0.
  If there's no value (locked, not found, …) it prints nothing and exits 1,
  as `ewe-cloud token` does. Programs use `reveal --json`.
- **`unlock`, `init`, `passwd` read secrets from the terminal or stdin**,
  never from argv. With a terminal they prompt (no echo); without one they
  read one line per secret from stdin.
- **`read`, `run`, `inject` and `git-credential` follow the tools they
  copy** (1Password's `op`, git's credential helpers), below in
  [References](#references-safe): `read` prints the bare value (exit 1 and
  nothing on stdout when there is none, the reason on stderr; `--json` is
  the rule-5 answer); `run` exits with its command's code; `inject` prints
  the filled template (with `-o` it writes the file and answers JSON);
  `git-credential` speaks git's `key=value` lines and always exits 0.

Every reply has `"ok"`. A failure is:

```json
{"ok": false, "error": "locked", "message": "Safe is locked.", "hint": "ewe-safe unlock"}
```

`message` is a sentence a UI may show as is; `hint` is optional.

### Error codes

| code | meaning |
|---|---|
| `daemon-unavailable` | the CLI could not reach `ewe-safed` (the socket unit isn't installed or failed) |
| `not-set-up` | no safe on this machine (`init` or `open` first) |
| `locked` | the verb needs the safe unlocked |
| `wrong-key` | the password or key file doesn't open the safe |
| `not-found` | no item with that id |
| `read-only` | the safe can't be written without losing content (`reasons` lists what) |
| `offline` | the place can't be reached and there's no cached copy |
| `place-error` | the place answered with an error (`message` says which) |
| `key-changed` | the copy in the place has a different master key (changed on another machine): unlock with the new password |
| `bad-request` | unknown verb, missing or invalid argument |
| `cancelled` | the user dismissed a prompt (`unlock --ask`, `confirm --ask`) |
| `not-enabled` | login unlock isn't set up on this computer (docs/SYSTEM.md §2) |
| `too-many-tries` | five wrong login passwords in a row; the master password clears it |
| `ambiguous` | a `safe://` reference fits more than one item (or field): `hint` lists the items' ids. Never a guess |
| `source-error` | an import's source can't be read: not a 1PUX/CSV export, unreadable, or `op` failed (`message` has op's own words) |
| `excluded` | `passkey-create`: a credential in `exclude` is already in the safe (the browser answers `InvalidStateError`) |
| `unsupported` | `passkey-create`: no algorithm in the site's list is one Safe makes; `passkey-get`: the stored key is a type Safe can't sign with (RSA). The browser answers `NotSupportedError` |
| `confirm-needed` | `fields` on a card while `[safe] confirm_cards` is on and no password was typed in the last 5 minutes: `hint` is `ewe-safe confirm --ask`; confirm, then ask again (below, "Cards and addresses") |
| `internal` | a bug; `message` has the detail |

### Shapes

**Item summary** — never contains a secret. `username` isn't treated as one
(the picker shows it); a note's text and every password, one-time code and
protected custom field are.

```json
{
  "id": "4f9c0d1e-…",
  "kind": "login",
  "title": "Discord",
  "username": "sam",
  "urls": ["https://discord.com/login"],
  "apps": ["discord"],
  "tags": ["work"],
  "folder": "Internet",
  "has_password": true,
  "has_otp": false,
  "modified": "2026-10-14T16:02:11Z",
  "passkey": {"rp_id": "discord.com", "username": "sam"},
  "ssh": null,
  "card": null,
  "address": null
}
```

- `id`: the KDBX entry UUID, lowercase and hyphenated.
- `kind`: `login`, `note`, `ssh-key`, `card` or `address`; a note's, a
  card's and an address's `username` is `""` (and `has_password` false). A
  caller that knows only logins and notes skips other kinds.
- `ssh`: an SSH key's public part, `null` for the other kinds:
  `{"public_key": "ssh-ed25519 AAAA… comment", "fingerprint": "SHA256:…",
  "key_type": "ed25519", "agent": true}` — `key_type` is `ed25519`,
  `ecdsa`, `rsa`, `dsa` or the algorithm's own name; `agent` = an SSH agent
  may use it (its `KeeAgent.settings`). Never the private key.
- `apps`: window classes, from the entry's `app:<class>` tags; `tags` are the
  other tags (`app:*` excluded).
- `folder`: the group path below the root, `""` at the root.
- `passkey`: the item's passkey, `{"rp_id", "username"}` (the site's
  `user.name`), or `null`. Never the key, the credential id or the user
  handle.
- `card`: a card's `{"brand": "visa", "last4": "4242", "expiry": "08/2029",
  "holder": "Sam Moe", "has_number": true, "has_security_code": true,
  "has_pin": false}`, `null` for the other kinds. `brand` is one of
  `visa` `mastercard` `amex` `discover` `jcb` `unionpay` `diners` `maestro`
  `mir` `other`; `last4` is `""` when the number has fewer than ten digits;
  `expiry` is `MM/YYYY` or `""`. **Never** the number, the security code or
  the PIN (docs/FORMAT.md, "Cards and addresses").
- `address`: an address's `{"name": "Sam Moe", "line1": "12 Main St",
  "city": "Tbilisi", "country": "GE"}`, `null` for the other kinds
  (`show` gives every part, below).

**Place** — never contains a secret.

```json
{"kind": "nextcloud", "location": "ewe/safe/passwords.kdbx", "guarded": true}
```

`kind` is `local` | `nextcloud` | `webdav` | `folder` | `sftp` | `dropbox` |
`gdrive`; `guarded` = the place refuses a stale save (PLAN.md §6).

**Sync**

```json
{
  "state": "in-sync",
  "last": "2026-10-14T16:02:12Z",
  "by_machine": "emoh",
  "pending": false,
  "warning": null
}
```

- `state`: `in-sync` | `pending` | `offline` | `error` | `local` (a
  This-computer safe has nothing to sync with).
- `last`: the last successful exchange with the place, or `null`.
- `by_machine`: the machine that wrote the copy in the place, if known.
- `pending`: local changes are not yet in the place.
- `warning`: `null` | `"rollback"` (the place served an older copy than one
  already seen) | `"single-writer"` (the place can't refuse a stale save).
- `message`: present when `state` is `offline` or `error` — the last
  failure as a sentence a UI may show (e.g. "not signed in to your ewe
  account: sign in with ewe-sync").

### Verbs

| verb | args | reply (besides `"ok": true`) |
|---|---|---|
| `status` | | `set_up`, `locked`, `read_only`, `reasons` (when read-only), `place` (or null), `unlock_methods` (`["password"]`, plus `"login"` when unlock-with-login is on), `login` (`{enabled, session_open}`, docs/SYSTEM.md §2), `items` (count, null while locked), `sync` (null until set up), `version`, and `upgrade_from` (e.g. `"KDBX 3.1"`) when the file becomes KDBX 4.1 at its next save |
| `summary` | | `locked`, `items`, `sync_state` — counts and states only, for the companion (PLAN.md S8) |
| `init` | `--place P [--location L] [--url U --user N]` + password twice on tty/stdin | `place` |
| `open` | `--place P [--location L] [--url U --user N]` + password on tty/stdin | `place`, `items` |
| `unlock` | `[--ask] [--login]` (+ password on tty/stdin unless `--ask`) | `items`. `--ask` is the CLI's: it opens a prompt and waits until the safe is unlocked or the prompt is gone (`cancelled`). Phase 1's prompt is a small kitty window running `ewe-safe unlock` (`EWE_SAFE_ASK_CMD` replaces it); later the Safe window. `--login` reads the **login** password (docs/SYSTEM.md §2) instead of the master. Over the socket, `unlock` takes `password`, or `login_password` for login unlock |
| `confirm` | `[--ask] [--login] [--reason TEXT]` (+ password on tty/stdin unless `--ask`) | `confirmed_for` (seconds, 300): a fresh presence check for a sensitive fill, e.g. a card (docs/SYSTEM.md §4). The safe must be unlocked. The master password, or the login password with `--login`. `--ask` opens the Safe window in confirm mode (`ewe-safe-app --confirm --reason TEXT`, `EWE_SAFE_ASK_CMD` replaces it) and waits for it, like `unlock --ask`. Over the socket, `confirm` takes `password` or `login_password` |
| `login status` | `login-status` | `enabled` (login unlock is on: `master.wrap` is present), `session_open` (W is in memory for this login session) |
| `login enable` | `login-enable`: `login_password`, and `password` (the master) when the safe is locked | `enabled`. Seals the safe's master password on this computer under W, and W under the login password. The CLI and the window check the login password with `/usr/bin/unix_chkpwd` first — the daemon can't (`NoNewPrivileges` blocks the setuid helper). `EWE_SAFE_CHKPWD` replaces the helper for tests |
| `login disable` | `login-disable` | `enabled: false`. Deletes `master.wrap`; the login password no longer opens Safe |
| `lock` | | `locked: true` |
| `list` | `[--kind login\|note\|ssh-key\|card\|address] [--tag T] [--deleted]` | `items: [summary…]` (by title) |
| `search` | `<text>` | `items: [summary…]` (best first) |
| `match` | `[--class C] [--title T] [--url U] [--query Q] [--limit N]` | `items: [summary + "score", "reason"]` best first; nothing matched → every login by title (so the picker's search still finds it) |
| `show` | `<id>` | `item: summary + "notes"` for a login (a note's, an SSH key's, a card's and an address's notes only with `--reveal-notes`). An address's `address` has every part: `name`, `full_name`, `organization`, `line1`, `line2`, `city`, `region`, `postal_code`, `country`, `phone`, `email`. A card's number, code and PIN never: `reveal` them |
| `reveal` | `<id> --field password\|username\|otp\|notes\|<custom name> [--json]` | bare value; with `--json`: `value` (and `expires_in` seconds for `otp`). On an SSH key, `private_key` is the key (OpenSSH form) and `public_key` its public line |
| `copy` | `<id> --field … [--clear-after S]` | `copied`, `cleared_after` (seconds; default `[safe] clipboard_clear_seconds`, 0 = keep). The daemon runs `wl-copy` (value on stdin) after dropping the clipboard plugin's `$XDG_RUNTIME_DIR/ewe-clip-skip` marker, so the history skips it — `wl-copy` can't offer the `x-kde-passwordManagerHint` type next to the text. It clears the clipboard later, and on lock, only if it still holds this value (it keeps a hash, not the value). The CLI sends its `WAYLAND_DISPLAY` as `wayland_display` |
| `add` | `--kind login\|note --title T [--username U] [--url U]… [--app CLASS]… [--tag T]… [--folder F] [--generate [--length N \| --words N]] [--password-stdin] [--notes-stdin]` | `item_id` (the new item's id — not `id`, which is the socket's own request id), `sync`. `--folder Work/Mail` makes the folders that are missing. The item is in the cache (verified) when the answer comes; the place gets it moments later, so `sync.state` is usually `pending` here |
| `edit` | `<id>` + the same fields (`--clear-url`, `--remove-app C`, `--remove-tag T` to remove) | `sync`. `--title`, `--username`, a password and notes replace; `--url`, `--app` and `--tag` add what isn't there yet (apps and tags compare without case); `--clear-url` empties the websites first; `--folder` moves the item (`""` = the top). An edit that changes nothing saves nothing |
| `rm` | `<id>` | `sync` (the item goes to the recycle bin) |
| `restore` | `<id>` | `sync` |
| `generate` | `[--length N \| --words N] [--no-symbols] [--no-digits]` | `value`, `bits` (estimated entropy). Needs no safe |
| `sync` | | `sync` — a nudge; never fails because the place is offline (that's a state) |
| `place` | | `place`, `sync`, `probe` (`{guarded, checked_at}`) |
| `passwd` | new password twice on tty/stdin (current one first if locked) | `sync`. Needs the place: the other machines' changes come in under the old password first (`place-error` while offline) |
| `import` | `<format> [<file>] [--dry-run] [--folder F] [--skip-duplicates] [--vault V]… [--account A]` — formats: `1pux` (1Password's export), `1password-csv` (1Password 8's CSV: logins and passwords only), `op` (live from the 1Password app through its `op` CLI: no file; `--vault` (repeatable, a name or an id) picks vaults, default all; `--account` when `op` knows several accounts); more formats later (Bitwarden, browsers, KeePass, pass). docs/IMPORT.md has the mapping | `report`: `{logins, notes, ssh_keys, cards, addresses, attachments, otps, duplicates, skipped: [{title, reason}], folders}`; with `--dry-run` also `dry_run: true` and nothing changes, without it `sync`. One save for the whole import (one merge, one upload); an import that adds nothing saves nothing. Duplicate = a website host (without `www.`) and a username an item already in the safe has; kept unless `--skip-duplicates`, which lists them under `skipped`. 1Password's SSH Keys become **SSH key** items (below, "SSH keys"). 1Password's Credit Cards become **cards** and its Identities **addresses** (docs/IMPORT.md); items it calls Bank Account, Server, … become **Notes** whose text lists their fields; their secret fields are also kept as protected custom fields. Vaults become folders (below `--folder`); 1Password's trash is skipped, its archive goes to the folder `Archive`. `skipped` also names attachments left out (`"<title> — <file>"`: missing, or bigger than 25 MB), and SSH keys kept as notes (`"<title> — SSH key"`, `"kept as a note: <why>"`). The file is a plaintext export: for `1pux` and `1password-csv` the reply's `hint` says to delete it. The daemon reads the file itself (same uid; the CLI sends the full path); `op` runs as argv from the daemon (`vault list`, `item list --include-archive`, `item get`, `read` for attachments, `document get`), and its first call may wait for the user to approve Safe in 1Password. Needs the safe unlocked, a dry run too (duplicates are counted against it) |
| `edit` | `<id> --remove-passkey` | `sync`. Removes the item's passkey: every `KPEX_PASSKEY_*` field and the tag `Passkey` (docs/FORMAT.md). The login and its password stay; the item's history keeps the old version. An item without one saves nothing |
| `add` | `--kind card [--title T] [--holder H] [--expiry MM/YY] [--brand B] [--card-stdin] [--tag T]… [--folder F] [--notes-stdin]`; `--kind address [--title T] [--full-name N] [--organization O] [--line1 L] [--line2 L] [--city C] [--region R] [--postal-code P] [--country C] [--phone P] [--email E]` | `item_id`, `sync`, and `warning` (a sentence) when the number looks mistyped (Luhn, or not 12–19 digits): Safe keeps it anyway. Over the socket the fields travel in one object: `card: {holder, number, expiry, security_code, pin, brand}` (its secrets are `number`, `security_code`, `pin`), `address: {full_name, organization, line1, line2, city, region, postal_code, country, phone, email}`. The title defaults to "Visa •• 4242" (brand and last four digits) or "Home"; the brand to the number's; the expiry is read as `MM/YY`, `MM/YYYY`, `M/YY` (anything else is `bad-request`); a two-letter country becomes its upper-case code. `--card-stdin` reads three lines: the number, the security code, the PIN (no echo on a terminal; an empty line is none); with `--notes-stdin` too, the notes follow them. A `card` object on another kind (or `address`) is `bad-request` |
| `edit` | `<id>` + the card or address flags above | `sync`, `warning` as for `add`. Only the keys sent change; `""` clears one (`--holder ""`). In `edit`, a `--card-stdin` line left empty keeps that value and `-` clears it. A new number sent without a brand takes the number's brand; a card still titled as Safe titles a new one ("Visa •• 4242") follows its new number unless a title is sent. An edit that changes nothing saves nothing |
| `reveal` | `<id> --field number\|security_code\|pin\|holder\|expiry\|brand` (a card), `--field full_name\|line1\|…` (an address) | as above; the KDBX names work too (`--field "Security code"`). `copy` takes the same names |
| `convert` | `--from-1password [--dry-run]` | `converted: [{item_id, title, kind}]`, `skipped: [{title, reason}]`, and `dry_run: true` or `sync`. Turns the Notes an earlier 1Password import made from Credit Cards and Identities into cards and addresses, in place (same id; docs/FORMAT.md, "Cards and addresses"). A run that finds nothing saves nothing |
| `fields` | **socket only**, for the browser. `item_id` | a card: `kind: "card"`, `fields: {holder, number, expiry_month: "08", expiry_year: "2029", security_code, brand}` (**never the PIN**) and `confirmed_for` (seconds the last confirm still lasts); an address: `kind: "address"`, `fields: {full_name, given_name, family_name, organization, line1, line2, city, region, postal_code, country, phone, email}` (`given_name` / `family_name`: the full name split before its last word). A card needs a fresh confirm while `[safe] confirm_cards` is on: else `confirm-needed`. Another kind is `bad-request`; an item in the recycle bin `not-found`. Like `reveal`, its reply carries values; nothing is logged |
| `passkey list` | `[--rp R]` | the socket's `passkey-list` (below), every passkey without `--rp` |
| `passkey-list` | **socket only.** `rp_id` (absent: every passkey), optional `allow` (credential ids) | `passkeys: [{item_id, title, username, rp_id, credential_id}]`, best first (last used, then title); only those `allow` names when it names any. From memory, like `match`. `username` is the site's `user.name` (the item's username when that is empty) |
| `passkey-create` | **socket only.** `rp_id`, `rp_name`, `user_id`, `user_name`, `user_display_name`, `client_data_hash`, `algorithms` (COSE ids, the site's order; empty = ES256), `exclude` (credential ids), optional `item_id`, `origin`, `user_verified` | `item_id`, `credential_id`, `attestation_object`, `authenticator_data`, `public_key` (SPKI DER), `public_key_algorithm` (`-7` or `-8`), `sync`. One save, like `add`. `user_display_name` is taken but not stored (KeePassXC keeps none either); `rp_name` and `user_name` longer than 64 UTF-8 bytes are cut on a character boundary, not refused |
| `passkey-get` | **socket only.** `rp_id`, `credential_id`, `client_data_hash`, `user_verified` | `item_id`, `credential_id`, `authenticator_data`, `signature`, `user_handle` (`null` when the passkey has none). Saves nothing |
| `watch` | | **CLI only, a stream** for shells and scripts that can't hold a socket (the desktop plugin's bridge). The first line is `{"v": 1, "event": "status", "status": {…}}` — the `status` verb's reply object, as the `sync` event carries `"sync": {…}`; then every socket event as-is, one per line (the `subscribe` stream below); the last line is `{"v": 1, "event": "daemon-gone"}` — also the only line when the daemon can't be reached — and `watch` exits 0. It runs until killed or the daemon goes away |
| `read` | `<safe://…> [--json] [-n\|--no-newline]` | **CLI**, like `op read`: the bare value and a newline; nothing (exit 1) when there is none. `--json`: `resolve`'s reply. A locked safe opens the unlock prompt once (`unlock --ask`), then tries again |
| `run` | `[--env-file F]… [--] <command> [args…]` | **CLI**, like `op run`: every environment value that is a `safe://` reference, or holds `{{ safe://… }}`, is resolved — in the command's environment only — and ewe-safe becomes the command (exec), so the exit code is the command's. ewe-safe's own failures exit 125, a command that can't run 126 or 127 (as `env` does). It fails closed: a value that starts with `safe://` (or holds `{{ safe://… }}`) and doesn't resolve — a typo, an `ambiguous` name, a safe left locked — is never passed on as text; the command never runs and the exit is 125. ewe-safe itself is not dumpable and has no core limit; the command gets its own core limit back `--env-file` (repeatable) is a dotenv file and wins over the inherited environment. The output is **not** masked: the command can print what it got |
| `inject` | `[-i <template>] [-o <file>]` | **CLI**, like `op inject`: the template (stdin without `-i`) with each `{{ safe://… }}` replaced; any other `{{ … }}` stays. To stdout, or with `-o` into the file (written whole, `0600`), answering `file`, `references` (how many). One reference that fails: nothing is written |
| `git-credential` | `get\|store\|erase` | **CLI**, git's credential-helper protocol (`git help credential`); setup: `git config --global credential.helper '!ewe-safe git-credential'`. `get`: a login whose website has git's protocol and host exactly (`www.` and subdomains differ; a website without a scheme is https), with `credential.useHttpPath` also a path the repository's path starts with, and git's `username` when sent; the closest path, then the newest wins; nothing fits → nothing printed. Locked → the unlock prompt once. `store`: only after a yes — "Save the login …?" (title = the host) or "Update the password …?" when exactly one login with that host and username has another password; asked on git's terminal, else a prompt window (`EWE_SAFE_CONFIRM_CMD` replaces both: it writes `yes` into `$EWE_SAFE_ANSWER`; the question is `$EWE_SAFE_QUESTION`); never while locked, never for an OAuth token (`password_expiry_utc`, `oauth_refresh_token`) or an `ephemeral` credential. `erase` does nothing: Safe never deletes a login because a server refused it once |
| `resolve` | `ref` (a `safe://` reference) | **socket only** (the CLI's face is `read --json`): `value`, `item_id`, `field` (as asked), `expires_in` for `otp`. Like `reveal`, it carries a value |
| `ping` | | `pong: true` |
| `version` | | `version`, `protocol: 1` |

Ids are full UUIDs. A UI may shorten them for display, but always sends the full id.

### Passkeys (for the ewe browser)

The browser's main process calls the three passkey verbs on the socket.
The browser checks the origin and the RP ID against the page (Safe never
trusts a page); Safe checks only their shape: `rp_id` must be a lowercase
host name (`github.com`, no port, no IP address) and `client_data_hash` 32
bytes. Anything else is `bad-request`.

- **Bytes** travel as base64url without padding (`user_id`,
  `client_data_hash`, credential ids, and every byte field in a reply).
  Safe also reads padded or standard base64.
- **`passkey-create`:** the first algorithm in `algorithms` that Safe makes
  wins: ES256 (`-7`) or EdDSA (`-8`); none → `unsupported` (checked before
  `exclude`, WebAuthn's order). A credential in `exclude` that the safe has
  for `rp_id` → `excluded`. With `item_id` the passkey goes on that login,
  replacing one it had (a note or an SSH key, or an item in the recycle
  bin: `bad-request` / `not-found`); without, a new login: title `rp_name` (else
  the RP ID), username `user_name`, website the `origin` (else
  `https://<rp_id>`). Names longer than WebAuthn's 64 bytes are cut on a
  UTF-8 character boundary, as browsers and authenticators cut them
  (WebAuthn §6.4.1), never refused. The attestation is `none`; `authenticator_data` is the
  one inside `attestation_object` (with the credential), so the browser's
  `getAuthenticatorData()` returns it.
- **`passkey-get`:** a passkey that isn't in the safe for that RP (or is in
  the recycle bin) → `not-found`. The signature covers `authenticator_data
  || client_data_hash`: DER for ES256, 64 bytes for EdDSA.
- **Flags:** UP always; UV when `user_verified` is true; BE and BS set (the
  passkey is in the synced file; for `get`, as the entry's
  `KPEX_PASSKEY_FLAG_BE`/`_BS` say); AT on create. Sign count 0. AAGUID
  `452b824e-42d3-4324-bc6c-581888ca2851`.
- Errors as everywhere: `locked`, `not-set-up`, `read-only` (create). Nothing
  a passkey verb receives or answers is logged.

### Cards and addresses (for the ewe browser and the window)

Cards and addresses are items in the safe file (docs/FORMAT.md): the
summary shows what a list may show, `reveal` and `copy` give one field,
and the browser fills a form with `fields`.

- **The gate (`[safe] confirm_cards`, a boolean, default `true`):** a card's
  `fields` needs a password typed in the last 5 minutes (the `confirm` verb:
  docs/SYSTEM.md §4 and §7, built by the login stream). Without it the
  answer is `confirm-needed`, `"message": "Safe needs your password again
  before it fills a card."`, `"hint": "ewe-safe confirm --ask"`. The confirm
  ends when the safe locks. Addresses need none. Like `ssh_confirm` it cuts
  down on surprises; it is not a security boundary against a program running
  as you while Safe is unlocked (`reveal` reads a card's number too).
- The browser fills cards into `https` frames only (or `localhost`), and
  never puts a number or a code in a log, a toast or the CLI
  (docs/SYSTEM.md §5).
- `import` reports `cards` and `addresses` next to `logins` and `notes`
  (docs/IMPORT.md).

### SSH keys and the agent

SSH keys live in the safe as KeeAgent entries (docs/FORMAT.md, "SSH
keys"), and `ewe-safed` serves them to `ssh` and `git` as an SSH agent
(below, "The SSH agent"). The CLI is `ewe-safe ssh <sub>`; over the socket
each is the verb `ssh-<sub>`. A key's passphrase travels as `"passphrase"`,
a secret like `"password"` (from the terminal or a stdin line, never argv).

| CLI | socket verb, args | reply (besides `"ok": true`) |
|---|---|---|
| `ssh list` | `ssh-list` | `items: [summary…]`, the SSH keys (by title) |
| `ssh add <file> [--title T] [--folder F] [--passphrase-stdin]` | `ssh-add`: `private_key` (the file's text, a secret; the CLI and the window read the file, and refuse one over 1 MB unread) and `file_name` (for the title), or `file` (a full path the daemon reads itself); `title`, `folder`, `passphrase` | `item_id`, `ssh`, `sync`. OpenSSH or PEM (PKCS#8, PKCS#1, SEC1) keys; stored as OpenSSH. Ed25519, ECDSA P-256/P-384 and RSA only: DSA, P-521 and security-key (`sk-`) keys are `bad-request`, with the reason. A key with a passphrase keeps it (the CLI asks on a terminal); the title defaults to the key's comment, else the file name. A key Safe already has is `bad-request` |
| `ssh new --title T [--type ed25519\|ecdsa\|rsa] [--bits N] [--folder F]` | `ssh-new`: `title`, `type`, `bits`, `folder` | `item_id`, `ssh`, `sync`. Ed25519 by default; ECDSA 256 or 384 bits; RSA 2048, 3072 (default) or 4096. The comment is the title |
| `ssh adopt [--dry-run]` | `ssh-adopt`: `dry_run` | `adopted: [{item_id, title}]`, `skipped: [{title, reason}]`, `dry_run: true` or `sync`. Turns the notes an earlier 1Password import made from SSH keys into SSH key items, in place (same id, the note text and every field kept, the note as it was in history) |
| `ssh enable [--confirm first-use\|every-time\|never]` | `ssh-enable`: `confirm` | `enabled`, `recorded` (ewe-conf stored `[safe] ssh_agent = true`), `socket`, `env_file`, `identity_agent`, `hint`, and `warning` when `ssh_confirm` is `never`. Only once it is recorded, writes `$XDG_CONFIG_HOME/environment.d/90-ewe-safe-ssh.conf` (`SSH_AUTH_SOCK` for new sessions; `env_file` is null otherwise); prints the one `IdentityAgent` line for `~/.ssh/config` and never edits that file |
| `ssh disable` | `ssh-disable` | `enabled`, `recorded`, `env_file_removed` (only a file `enable` wrote). The public-key list goes too |
| `ssh status` | `ssh-status`: `ssh_auth_sock` (the caller's) | `enabled`, `confirm`, `socket`, `listening`, `keys` (how many the agent offers now; from the public-key list while locked), `locked`, `ssh_auth_sock`, `points_here` (it is our socket), `env_file` (or null), `identity_agent`, `ssh_config_agents` (`IdentityAgent` values `~/.ssh/config` names: one there wins over `SSH_AUTH_SOCK`), `warning` when `ssh_confirm` is `never` |

`[safe]` settings: `ssh_agent` (`false` until `enable`; off, the agent
lists no key and signs nothing) and `ssh_confirm` (`first-use`, the
default; `every-time`; `never`).

**`ssh_confirm` cuts down on surprises; it is not a security boundary.**
The master password is: while the safe is unlocked, any program running
as you can reach the agent, and it can imitate an app the user allowed or
wait for one. The question tells the user which program (by its full
path) wants a key, so an unexpected one stands out.

**Places in this version:** `local` and `nextcloud`. `init`/`open` with any
other kind PROTOCOL.md names answer `bad-request` ("not in this version").
`init --place local` defaults to `$XDG_DATA_HOME/ewe/safe/passwords.kdbx`
and needs a full path otherwise; `nextcloud` defaults to
`ewe/safe/passwords.kdbx` in the account. Both record the place in
ewe.conf `[safe]` through `ewe-conf` and in this machine's
`$XDG_STATE_HOME/ewe/safe/machine.json`.

## The socket

`$XDG_RUNTIME_DIR/ewe-safe.sock`, mode `0600`. Both ends check
`SO_PEERCRED`: a peer with another uid gets no answer. `ewe-safe.socket`
(a systemd user unit) starts `ewe-safed` on the first connection.

Newline-delimited JSON, one object per line, UTF-8.

**Request:**

```json
{"v": 1, "id": 7, "verb": "match", "args": {"class": "discord", "limit": 8}}
```

`args` keys are the CLI's long options without dashes, with `_` for `-`
(`clear_after` for `--clear-after`). Positional arguments are `"id"` or
`"text"`. Secrets travel as `"password"`, `"new_password"`,
`"password_value"` (for `add`/`edit`), `"notes"`, `"passphrase"` and
`"private_key"` (for `ssh-add`), and `"login_password"` (for `unlock`,
`login-enable`, `confirm`; docs/SYSTEM.md §2); every string in `add`/`edit`'s
`"card"` object is wiped like them. Booleans are JSON booleans.

**Reply:** the CLI's JSON object plus `"v": 1` and the request's `"id"`. So no reply field is ever called `id`: the envelope's would overwrite it (an item's id is `item_id` or sits inside `item`).
`reveal` over the socket always answers `{"ok": true, "value": "…"}`;
`resolve` answers the same way, plus `item_id` and `field`.

**Events:** after `{"v": 1, "id": n, "verb": "subscribe"}`, the connection
stays open and receives lines without an `"id"`:

```json
{"v": 1, "event": "unlocked"}
{"v": 1, "event": "locked", "reason": "screen"}
{"v": 1, "event": "changed"}
{"v": 1, "event": "sync", "sync": {"state": "in-sync", "pending": false}}
```

- `locked.reason`: `screen` | `sleep` | `idle` | `user` | `logout`.
- `changed`: items changed, here or merged in from another machine.
- `sync`: carries the sync object.

Events never carry a title, a username or a value.

## The SSH agent

`$XDG_RUNTIME_DIR/ewe-safe-ssh.sock`, mode `0600`, `SO_PEERCRED` checked
(another uid gets no answer). The second `ListenStream` of
`ewe-safe.socket`: a connection starts `ewe-safed` like the main socket
does (the daemon tells the two apart by their paths; without systemd it
binds both). The protocol is OpenSSH's (draft-miller-ssh-agent):

- `REQUEST_IDENTITIES` (11): every SSH key item whose `KeeAgent.settings`
  allows agent use and whose kind Safe signs with (Ed25519, ECDSA
  P-256/P-384, RSA; never DSA, P-521 or `sk-` keys), by title, the title as
  the comment. While the safe is locked the answer comes from
  `$XDG_STATE_HOME/ewe/safe/ssh-public.json` (public keys and their titles
  only, `0600`), written whenever the unlocked safe changes, and only while
  the agent is on (`disable` removes it; a daemon that starts with the
  agent off, or with no safe, removes a list left over). The list can't be
  checked while locked (the safe is encrypted): a key removed on another
  computer stays listed until the next unlock here, and signing with it
  fails then (a signature always checks the unlocked safe).
- `SIGN_REQUEST` (13): ed25519, ecdsa-sha2-nistp256/384, rsa-sha2-256/512
  (the flags 2 and 4). `ssh-rsa` (SHA-1) is refused. A locked safe opens
  the unlock prompt (`ewe-safe unlock --ask`) and the request waits up to
  60 s for it. A prompt closed or unanswered opens no new one for 30 s,
  then 60 s, … up to 10 min (until the safe is unlocked another way), so
  a loop of requests can't keep reopening it; the log names the program
  that asked.
- Approval: with `ssh_confirm = first-use` the first use of a key by an
  app in each unlock asks "Allow *ssh (from git)* to use *GitHub key*?"
  with the full paths ("/usr/bin/ssh, started by /usr/bin/git"); a
  program outside `/usr` and `/opt` is marked "not a system program". The
  app comes from `SO_PEERCRED`'s pid (its program and its parent's), and
  the answer is remembered for those programs' *files* (device and
  inode): the same file under another name is remembered, a copy or a
  replaced file is asked about again, and a program whose file can't be
  seen is asked every time. `every-time` asks each time; `never` never
  asks (logged with each signature). No answer in 60 s is a Deny. The
  prompt is `ewe-safe-app --approve` (exit 0 = Allow), else a notification
  with an Allow action (`notify-send --wait`); `EWE_SAFE_APPROVE_CMD`
  replaces both (tests; exit 0 = Allow). It gets `EWE_SAFE_APPROVE_APP`,
  `EWE_SAFE_APPROVE_KEY`, `EWE_SAFE_APPROVE_PATH` and
  `EWE_SAFE_APPROVE_SYSTEM` (`1` when both programs are system ones).
  Under systemd a prompt runs as its own transient user unit
  (`systemd-run --user --wait`), outside the service's sandbox.
- Everything else is refused (`FAILURE`): adding and removing keys
  (`ssh-add`, `ssh-add -d/-D`, constrained and SSH1 adds), locking the
  agent, smartcards, extensions. The keys come from Safe.
- Limits: 32 connections at once (more are closed at once); a connection
  waits at most 60 s for its next request, and a request must arrive
  whole within 10 s.

## Calls that must stay fast

`status`, `summary`, `match` and `list` answer from memory (or "locked")
without touching the place or the disk, so the picker opens instantly.
So does `passkey-list`; `passkey-get` reads the unlocked safe like `reveal`. Only
`unlock`, `open`, `init`, saves and `sync` talk to the place.

`show`, `reveal`, `copy` and `resolve` read the unlocked safe and never
wait for the place either (the daemon exchanges a copy of the safe with it). An edit
(`add`, `edit`, `rm`, `restore`) writes and verifies the encrypted cache
before it answers — a key derivation, about a second at the default cost —
and waits for an exchange already under way; the place gets the edit
moments later. `lock` never waits for the place.

## References (`safe://`)

A reference names one value in the safe, the way 1Password's `op://` does.
`read`, `run` and `inject` send it to the daemon's `resolve`, so every
caller follows the same rules (`safe_core::refs`).

| reference | names |
|---|---|
| `safe://Personal/GitHub/password` | the item titled GitHub in the folder Personal |
| `safe://Work/Mail/Gmail/username` | folders nest: Gmail in Work/Mail |
| `safe:///GitHub/password` | GitHub at the top (no folder) |
| `safe://GitHub/password` | GitHub in any folder |
| `safe://4f9c0d1e-…/password` | the item with that id (any spelling of the UUID) |

- **Fields:** `password`, `username`, `otp` (the current code; `expires_in`
  says how long it lasts), `notes`, `url` (the first website), or a custom
  field's name. These names compare without case. A custom field matches by
  its exact name first, then without case; several fields that differ only
  in case are `ambiguous`. A name that is no field but an attached file's
  (a text file) gives the file. `public_key` and `private_key` are an SSH
  key item's, the same as `reveal` gives them: the public line (the
  `public_key` field, else read from the key, as for a key KeePassXC
  stored) and the key file its `KeeAgent.settings` names (OpenSSH; still
  encrypted when the key has a passphrase).
- **Names:** a folder path and a title compare exactly first; when nothing
  fits exactly, without case and outer spaces. More than one item that fits
  is `ambiguous` (exit 1 for `read`), never a guess; name it by its id.
  Items in the recycle bin are never found.
- **Escapes:** each part is percent-decoded: a title with a `/` is written
  `%2F` (`safe://Music/AC%2FDC/password`), a `%` is `%25`, a space may be
  `%20`. A `%` that isn't followed by two hex digits stays a `%`. `?` and
  `#` are kept for later options: write them `%3F` and `%23`. A folder whose
  own name holds a `/` can't be told from two nested folders.
- **In `run` and `inject`:** a value that is a reference is replaced whole;
  `{{ safe://… }}` (spaces inside the braces allowed) is replaced inside
  any text. A reference on more than one line is not one.
- **Env files** (`run --env-file`): `KEY=value` lines, `export KEY=value`,
  `#` comments; `"double quotes"` take `\n` `\t` `\r` `\\` `\"` and may run over
  several lines, `'single quotes'` keep everything as is, a bare value ends
  at ` #`. `$VAR` is not expanded.
