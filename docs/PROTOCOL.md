# ewe-safe protocol — the CLI and the socket (v1)

The public API of Safe (house rule 4: renaming a verb or a field breaks
installed callers). Callers: the Passwords plugin's `ewe-pass`, the Safe
app, ewe-sync, the ewe browser, ewe-companion, scripts.

**Stability:** fields may be **added** at any time; callers ignore fields
they don't know. Renaming or removing a verb or a field means `"v": 2`.

## The CLI

`ewe-safe <verb> [args]` prints **one JSON object** on stdout and **exits 0**
(house rule 5). Two documented exceptions:

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
- `kind`: `login` or `note`; a note's `username` is `""`.
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
| `list` | `[--kind login\|note] [--tag T] [--deleted]` | `items: [summary…]` (by title) |
| `search` | `<text>` | `items: [summary…]` (best first) |
| `match` | `[--class C] [--title T] [--url U] [--query Q] [--limit N]` | `items: [summary + "score", "reason"]` best first; nothing matched → every login by title (so the picker's search still finds it) |
| `show` | `<id>` | `item: summary + "notes"` for a login (a note's text only with `--reveal-notes`) |
| `reveal` | `<id> --field password\|username\|otp\|notes\|<custom name> [--json]` | bare value; with `--json`: `value` (and `expires_in` seconds for `otp`) |
| `copy` | `<id> --field … [--clear-after S]` | `copied`, `cleared_after` (seconds; default `[safe] clipboard_clear_seconds`, 0 = keep). The daemon runs `wl-copy` (value on stdin) after dropping the clipboard plugin's `$XDG_RUNTIME_DIR/ewe-clip-skip` marker, so the history skips it — `wl-copy` can't offer the `x-kde-passwordManagerHint` type next to the text. It clears the clipboard later, and on lock, only if it still holds this value (it keeps a hash, not the value). The CLI sends its `WAYLAND_DISPLAY` as `wayland_display` |
| `add` | `--kind login\|note --title T [--username U] [--url U]… [--app CLASS]… [--tag T]… [--folder F] [--generate [--length N \| --words N]] [--password-stdin] [--notes-stdin]` | `id`, `sync`. `--folder Work/Mail` makes the folders that are missing. The item is in the cache (verified) when the answer comes; the place gets it moments later, so `sync.state` is usually `pending` here |
| `edit` | `<id>` + the same fields (`--clear-url`, `--remove-app C`, `--remove-tag T` to remove) | `sync`. `--title`, `--username`, a password and notes replace; `--url`, `--app` and `--tag` add what isn't there yet (apps and tags compare without case); `--clear-url` empties the websites first; `--folder` moves the item (`""` = the top). An edit that changes nothing saves nothing |
| `rm` | `<id>` | `sync` (the item goes to the recycle bin) |
| `restore` | `<id>` | `sync` |
| `generate` | `[--length N \| --words N] [--no-symbols] [--no-digits]` | `value`, `bits` (estimated entropy). Needs no safe |
| `sync` | | `sync` — a nudge; never fails because the place is offline (that's a state) |
| `place` | | `place`, `sync`, `probe` (`{guarded, checked_at}`) |
| `passwd` | new password twice on tty/stdin (current one first if locked) | `sync`. Needs the place: the other machines' changes come in under the old password first (`place-error` while offline) |
| `ping` | | `pong: true` |
| `version` | | `version`, `protocol: 1` |

Ids are full UUIDs. A UI may shorten them for display, but always sends the full id.

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

**Reply:** the CLI's JSON object plus `"v": 1` and the request's `"id"`.
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
