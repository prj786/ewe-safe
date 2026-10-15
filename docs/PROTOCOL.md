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
| `cancelled` | the user dismissed a prompt (`unlock --ask`) |
| `source-error` | an import's source can't be read: not a 1PUX/CSV export, unreadable, or `op` failed (`message` has op's own words) |
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
  "modified": "2026-10-14T16:02:11Z"
}
```

- `id`: the KDBX entry UUID, lowercase and hyphenated.
- `kind`: `login`, `note` or `ssh-key`; a note's `username` is `""`. A
  caller that knows only logins and notes skips other kinds.
- `ssh`: an SSH key's public part, `null` for the other kinds:
  `{"public_key": "ssh-ed25519 AAAA… comment", "fingerprint": "SHA256:…",
  "key_type": "ed25519", "agent": true}` — `key_type` is `ed25519`,
  `ecdsa`, `rsa`, `dsa` or the algorithm's own name; `agent` = an SSH agent
  may use it (its `KeeAgent.settings`). Never the private key.
- `apps`: window classes, from the entry's `app:<class>` tags; `tags` are the
  other tags (`app:*` excluded).
- `folder`: the group path below the root, `""` at the root.

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
| `status` | | `set_up`, `locked`, `read_only`, `reasons` (when read-only), `place` (or null), `unlock_methods` (`["password"]`, plus `"login"` when unlock-with-login is on), `items` (count, null while locked), `sync` (null until set up), `version`, and `upgrade_from` (e.g. `"KDBX 3.1"`) when the file becomes KDBX 4.1 at its next save |
| `summary` | | `locked`, `items`, `sync_state` — counts and states only, for the companion (PLAN.md S8) |
| `init` | `--place P [--location L] [--url U --user N]` + password twice on tty/stdin | `place` |
| `open` | `--place P [--location L] [--url U --user N]` + password on tty/stdin | `place`, `items` |
| `unlock` | `[--ask]` (+ password on tty/stdin unless `--ask`) | `items`. `--ask` is the CLI's: it opens a prompt and waits until the safe is unlocked or the prompt is gone (`cancelled`). Phase 1's prompt is a small kitty window running `ewe-safe unlock` (`EWE_SAFE_ASK_CMD` replaces it); later the login unlock (polkit) or the Safe window. Over the socket, `unlock` takes `password` |
| `lock` | | `locked: true` |
| `list` | `[--kind login\|note\|ssh-key] [--tag T] [--deleted]` | `items: [summary…]` (by title) |
| `search` | `<text>` | `items: [summary…]` (best first) |
| `match` | `[--class C] [--title T] [--url U] [--query Q] [--limit N]` | `items: [summary + "score", "reason"]` best first; nothing matched → every login by title (so the picker's search still finds it) |
| `show` | `<id>` | `item: summary + "notes"` for a login (a note's text only with `--reveal-notes`) |
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
| `import` | `<format> [<file>] [--dry-run] [--folder F] [--skip-duplicates] [--vault V]… [--account A]` — formats: `1pux` (1Password's export), `1password-csv` (1Password 8's CSV: logins and passwords only), `op` (live from the 1Password app through its `op` CLI: no file; `--vault` (repeatable, a name or an id) picks vaults, default all; `--account` when `op` knows several accounts); more formats later (Bitwarden, browsers, KeePass, pass). docs/IMPORT.md has the mapping | `report`: `{logins, notes, ssh_keys, attachments, otps, duplicates, skipped: [{title, reason}], folders}`; with `--dry-run` also `dry_run: true` and nothing changes, without it `sync`. One save for the whole import (one merge, one upload); an import that adds nothing saves nothing. Duplicate = a website host (without `www.`) and a username an item already in the safe has; kept unless `--skip-duplicates`, which lists them under `skipped`. 1Password's SSH Keys become **SSH key** items (below, "SSH keys"). Items 1Password calls Credit Card, Identity, Bank Account, … become **Notes** whose text lists their fields; their secret fields are also kept as protected custom fields. Vaults become folders (below `--folder`); 1Password's trash is skipped, its archive goes to the folder `Archive`. `skipped` also names attachments left out (`"<title> — <file>"`: missing, or bigger than 25 MB). The file is a plaintext export: for `1pux` and `1password-csv` the reply's `hint` says to delete it. The daemon reads the file itself (same uid; the CLI sends the full path); `op` runs as argv from the daemon (`vault list`, `item list --include-archive`, `item get`, `read` for attachments, `document get`), and its first call may wait for the user to approve Safe in 1Password. Needs the safe unlocked, a dry run too (duplicates are counted against it) |
| `watch` | | **CLI only, a stream** for shells and scripts that can't hold a socket (the desktop plugin's bridge). The first line is `{"v": 1, "event": "status", "status": {…}}` — the `status` verb's reply object, as the `sync` event carries `"sync": {…}`; then every socket event as-is, one per line (the `subscribe` stream below); the last line is `{"v": 1, "event": "daemon-gone"}` — also the only line when the daemon can't be reached — and `watch` exits 0. It runs until killed or the daemon goes away |
| `ping` | | `pong: true` |
| `version` | | `version`, `protocol: 1` |

Ids are full UUIDs. A UI may shorten them for display, but always sends the full id.

### SSH keys and the agent

SSH keys live in the safe as KeeAgent entries (docs/FORMAT.md, "SSH
keys"), and `ewe-safed` serves them to `ssh` and `git` as an SSH agent
(below, "The SSH agent"). The CLI is `ewe-safe ssh <sub>`; over the socket
each is the verb `ssh-<sub>`. A key's passphrase travels as `"passphrase"`,
a secret like `"password"` (from the terminal or a stdin line, never argv).

| CLI | socket verb, args | reply (besides `"ok": true`) |
|---|---|---|
| `ssh list` | `ssh-list` | `items: [summary…]`, the SSH keys (by title) |
| `ssh add <file> [--title T] [--folder F] [--passphrase-stdin]` | `ssh-add`: `file` (full path; the daemon reads it), `title`, `folder`, `passphrase` | `item_id`, `ssh`, `sync`. OpenSSH or PEM (PKCS#8, PKCS#1, SEC1) keys; stored as OpenSSH. A key with a passphrase keeps it (the CLI asks on a terminal); the title defaults to the key's comment, else the file name. A key Safe already has is `bad-request` |
| `ssh new --title T [--type ed25519\|ecdsa\|rsa] [--bits N] [--folder F]` | `ssh-new`: `title`, `type`, `bits`, `folder` | `item_id`, `ssh`, `sync`. Ed25519 by default; ECDSA 256 or 384 bits; RSA 2048, 3072 (default) or 4096. The comment is the title |
| `ssh adopt [--dry-run]` | `ssh-adopt`: `dry_run` | `adopted: [{item_id, title}]`, `skipped: [{title, reason}]`, `dry_run: true` or `sync`. Turns the notes an earlier 1Password import made from SSH keys into SSH key items, in place (same id, the note text and every field kept, the note as it was in history) |
| `ssh enable [--confirm first-use\|every-time\|never]` | `ssh-enable`: `confirm` | `enabled`, `recorded` (ewe-conf stored `[safe] ssh_agent = true`), `socket`, `env_file`, `identity_agent`, `hint`. Writes `$XDG_CONFIG_HOME/environment.d/90-ewe-safe-ssh.conf` (`SSH_AUTH_SOCK` for new sessions); prints the one `IdentityAgent` line for `~/.ssh/config` and never edits that file |
| `ssh disable` | `ssh-disable` | `enabled`, `recorded`, `env_file_removed` (only a file `enable` wrote) |
| `ssh status` | `ssh-status`: `ssh_auth_sock` (the caller's) | `enabled`, `confirm`, `socket`, `listening`, `keys` (how many the agent offers now; from the public-key list while locked), `locked`, `ssh_auth_sock`, `points_here` (it is our socket), `env_file` (or null), `identity_agent`, `ssh_config_agents` (`IdentityAgent` values `~/.ssh/config` names: one there wins over `SSH_AUTH_SOCK`) |

`[safe]` settings: `ssh_agent` (`false` until `enable`; off, the agent
lists no key and signs nothing) and `ssh_confirm` (`first-use`, the
default; `every-time`; `never`).

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
`"password_value"` (for `add`/`edit`) and `"notes"`. Booleans are JSON
booleans.

**Reply:** the CLI's JSON object plus `"v": 1` and the request's `"id"`. So no reply field is ever called `id`: the envelope's would overwrite it (an item's id is `item_id` or sits inside `item`).
`reveal` over the socket always answers `{"ok": true, "value": "…"}`.

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
  allows agent use, by title, the title as the comment. While the safe is
  locked the answer comes from `$XDG_STATE_HOME/ewe/safe/ssh-public.json`
  (public keys and their titles only, `0600`), written whenever the
  unlocked safe changes.
- `SIGN_REQUEST` (13): ed25519, ecdsa-sha2-nistp256/384, rsa-sha2-256/512
  (the flags 2 and 4). `ssh-rsa` (SHA-1) is refused. A locked safe opens
  the unlock prompt (`ewe-safe unlock --ask`) and the request waits up to
  60 s for it.
- Approval: with `ssh_confirm = first-use` the first use of a key by an
  app in each unlock asks "Allow *ssh (from git)* to use *GitHub key*?"
  (the app from `SO_PEERCRED`'s pid: its program and its parent's);
  `every-time` asks each time; `never` never asks. No answer in 60 s is a
  Deny. The prompt is `ewe-safe-app --approve` (exit 0 = Allow), else a
  notification with an Allow action (`notify-send --wait`);
  `EWE_SAFE_APPROVE_CMD` replaces both (tests; exit 0 = Allow). Under
  systemd a prompt runs as its own transient user unit (`systemd-run
  --user --wait`), outside the service's sandbox.
- Everything else is refused (`FAILURE`): adding and removing keys
  (`ssh-add`, `ssh-add -d/-D`), locking the agent, smartcards,
  extensions. The keys come from Safe.

## Calls that must stay fast

`status`, `summary`, `match` and `list` answer from memory (or "locked")
without touching the place or the disk, so the picker opens instantly. Only
`unlock`, `open`, `init`, saves and `sync` talk to the place.

`show`, `reveal` and `copy` read the unlocked safe and never wait for the
place either (the daemon exchanges a copy of the safe with it). An edit
(`add`, `edit`, `rm`, `restore`) writes and verifies the encrypted cache
before it answers — a key derivation, about a second at the default cost —
and waits for an exchange already under way; the place gets the edit
moments later. `lock` never waits for the place.
