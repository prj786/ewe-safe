# Places and the sync engine

Where the safe file lives, how each place refuses a stale save, and how
the sync engine moves the safe between this machine and its place. The
decisions are in PLAN.md §6 and §7; the shapes the daemon reports are in
[PROTOCOL.md](PROTOCOL.md). Code: `crates/store` (`safe_store`).

## A place

Every place does four things (`Place`):

| | what |
|---|---|
| `info()` | `{kind, location, guarded}`, never a secret |
| `fetch(known)` | the file's bytes and version, `Unchanged` if it is still `known`, or `Missing` |
| `store(bytes, expect)` | write only if the file is still the version `expect` names (`Absent` for a new file); otherwise `Stale` |
| `probe()` | check that the place really refuses a stale save |

A **version** (`Tag`) is `etag:<v>` when the server has ETags, else
`sha256:<hex>` of the bytes.

Errors are of two kinds, as PROTOCOL.md has them: **`offline`** (no
connection, DNS, refused, timed out) and **`place-error`** (the place
answered, but not with what Safe needs: a status, a refused sign-in, a
plain-http address).

### This computer (`Local`)

- The file at a path; its version is its SHA-256.
- `store` compares the current bytes with `expect` and then writes
  atomically (temp file, fsync, rename), under one lock in this process.
  A change made by something else (KeePassXC, a restore, a sync tool) is
  reported as `Stale`, never overwritten.
- *Limit:* a program writing at the very instant between the compare and
  the rename isn't excluded. Phase 3's synced folder builds on this place.

### WebDAV (`WebDav`): Nextcloud and any other server

- **Nextcloud (the ewe account):** `ewe-cloud webdav-url` gives the base,
  and `ewe-cloud token --json` gives the user and app password. Both are
  run as argv, never through a shell. Signed out → `place-error`, with
  "sign in with ewe-sync". The password is held in memory only, and
  forgotten and asked again after a 401.
- **Any WebDAV:** a base URL, a user, and a password the daemon reads
  from the keyring (`Fixed`).
- **https only.** Plain http only to this machine, and only when asked
  (`insecure_loopback`, or `EWE_SAFE_INSECURE_LOOPBACK=1`, for tests).
  Certificates are checked against the system's trust store, so a
  self-hosted server's own CA works once the system trusts it.
- **Fetch:** `GET` with `If-None-Match` → `304` unchanged, `404` missing.
- **Store:** `PUT` with `If-Match: "<etag>"`, or `If-None-Match: *` for a
  new file. `412` means stale. A missing folder (`409`/`404`) gets `MKCOL`
  for each folder above the file, then one retry. The new version is the
  reply's `ETag`/`OC-ETag`, else a `HEAD`'s, else the content hash.
- **A server without ETags:** the content hash is the version, and `store`
  compares it before an unconditional `PUT`. That leaves a short race, and
  the probe reports such a server as not guarded.
- **The guard probe:** `PUT .ewe-safe-probe` next to the safe, then
  `PUT` with a wrong `If-Match` and `PUT` with `If-None-Match: *`. Both must
  get `412`. Then `DELETE`. A server that writes anyway is a
  **single-writer** place, and the sync status says so.
- ETags are compared without `W/` and quotes.

## The sync engine (`Syncer`)

One per safe. It owns a **state directory**: `~/.local/state/ewe/safe`
(`$XDG_STATE_HOME`), or one injected for tests.

```
<state>/
  sync.json                 the record below (0600)
  cache/passwords.kdbx      this machine's copy, encrypted
  cache/incoming.kdbx       the place's newer copy, fetched while locked
  backups/passwords-<UTC>.kdbx   earlier copies of the cache, the last 20
```

`sync.json` holds:

- the place's version the cache was last exchanged at, and the hash of
  those bytes;
- the newest change seen in any copy exchanged;
- `pending` (the cache has changes the place doesn't);
- the last success, and the last error with its code;
- who wrote the place's copy;
- the rollback warning, the probe's answer, and the version of `incoming`.

If `sync.json` can't be read, it is kept as `sync.json.broken` and the
cache is treated as pending, so the next exchange merges rather than
replaces.

### The steps

- **Save:**
  1. Stamp `ewe.saved-by` (this machine's name, in Meta custom data).
  2. Write and verify the bytes (`Safe::to_bytes` reads them back with the
     key).
  3. Replace the cache, keeping the old one as a backup, and mark it
     pending.
  4. Store it in the place with the last-seen version.
     - **Stale:** fetch theirs, open it with the same key, merge, verify,
       and store again. Three tries, then pending with reason `busy`.
     - **Offline or a place error:** pending, with that reason.
     - **Their copy doesn't open:** pending with `key-changed` (the master
       password changed elsewhere). The place is never touched.
- **Load (unlock):** fetch the place's copy and open the cache.
  - **Unreachable:** the cache, merged *in memory* with `incoming`.
    Nothing is marked in sync.
  - **Unchanged:** the cache. Pending changes go up.
  - **Missing:** the place lost the file, so this machine's copy goes back
    up.
  - **A newer copy:** merge this machine's copy into it.
    - If this machine adds nothing, the place's bytes are taken as they
      are and nothing is uploaded.
    - Otherwise the merge is verified and uploaded.
  - If either copy is read-only (the write guard), nothing can be merged:
    the place's copy is taken when nothing is pending, and otherwise the
    read-only error stands.
- **Poll unlocked:** pending → push. Otherwise fetch: unchanged → nothing;
  a newer copy → merge, by the same rule as load.
- **Poll locked:** pending → store the cache's bytes as they are, if the
  place still has the last-seen version (a stale one waits for the key).
  Otherwise download a newer copy into `incoming`.

**"Adds nothing"** compares the two copies' content with what changes on
every exchange left out: `ewe.saved-by` and the last-selected-group hints.
That rule is what stops two machines trading uploads forever. Usage counts
and last-access times take the larger of the two in a merge, so they settle
after one round.

**Rollback:** a fetched copy whose newest change (items and folders,
changed or moved, and recorded deletions) is older than the newest change
already seen is never taken silently. It is merged with this machine's copy
(the merge keeps the newer data), uploaded, and flagged `rollback` until
`clear_warning`.

**Key changes:**

- The place's copy doesn't open, but the cache does → `key-changed`:
  unlock with the new password.
- The cache doesn't open, but the place's copy does, and the cache has
  pending changes → `CacheKey` (code `key-changed`): those changes are under
  the old password; unlock with it once to bring them in.
- Without pending changes, the place's copy is taken and the old cache goes
  to the backups.

**Who saved it** (`by_machine`): the `ewe.saved-by` of the place's copy,
read before any merge touches it.

### Status (PROTOCOL.md's sync object)

| `state` | when |
|---|---|
| `offline` | the last exchange couldn't reach the place |
| `error` | the last exchange failed otherwise (`place-error`, `key-changed`, `busy`) |
| `pending` | changes wait, and no error is recorded |
| `local` | a This-computer safe, nothing waiting |
| `in-sync` | otherwise |

`warning` is `rollback` (sticky), else `single-writer` when the probe found
the place unguarded.

## Error codes

`Error::code()` gives PROTOCOL.md's codes:

| error | code |
|---|---|
| `Offline` | `offline` |
| `Place`, `Exists` | `place-error` |
| `KeyChanged`, `CacheKey` | `key-changed` |
| `Missing` | `not-set-up` |
| the password doesn't open the safe | `wrong-key` |
| the write guard | `read-only` |

## Known limits

- **Times have one-second steps.** When two copies changed an item in the
  same second, the merge can't tell which is newer and picks by content
  hash. The other version goes into history, so nothing is lost, but an
  edit made in the same second as the version it replaced can end up in
  history instead of current. A three-way merge against the last synced
  copy would settle it; it isn't built.
- **A local place's compare-and-rename**, and a server without ETags, each
  leave a short race (see above).
- **A place error during load is treated like offline:** the cache opens,
  so a revoked app password still lets the user use their passwords, and
  the status says `error`.

## Tested (`crates/store/tests`)

All against a mock WebDAV server on 127.0.0.1 (`tests/common`). It
handles GET/HEAD/PUT/MKCOL/DELETE, ETags, conditional requests, basic auth,
and switches for no conditions, no ETags and failing requests. A machine
goes offline when its credentials point at a dead port. No real network,
and no live account.

- `sync.rs`:
  - the round trip;
  - a stale save merging both edits;
  - two machines editing offline;
  - a master key changed elsewhere;
  - rollback;
  - the probe;
  - 5xx and 401;
  - a lost file;
  - a server without ETags;
  - backups;
  - locked polls;
  - create over an existing safe;
  - wrong key;
  - a restart with pending changes.
- `interleave.rs`: seeded random runs with 2–3 machines adding, editing,
  going offline, locking and polling. At the end, every item and every
  username version is on every machine, the machines agree, and nothing is
  pending. Defaults to 25 seeds; set `SAFE_SYNC_SEEDS` and `SAFE_SYNC_SALT`
  for longer runs (3,000 passed while this was written).
- `local.rs`: stale detection, and two syncers sharing one file.
- `ewe_cloud.rs`: Nextcloud credentials from a fake `ewe-cloud` on PATH,
  and the signed-out error.

Not tested here: a real Nextcloud or any other real server.
