# ewe Safe

ewe's own password manager. It's much simpler than 1Password: one safe, one
master password, logins and notes, and a search box. The safe is one
encrypted file in the standard KeePass format (KDBX 4), so KeePassXC opens it
on any computer and KeePassDX, Strongbox or KeePassium on a phone. It lives
where you choose: this computer, your own Nextcloud (the ewe account), any
WebDAV server, a synced folder, or, if you want, Dropbox or Google Drive.
`Super+P` fills a login into any window.

**Status: phase 1, under construction. Nothing here is usable yet.** The
design is in [PLAN.md](PLAN.md) (the RFC-008 draft). Phase 0's go/no-go
spike is [docs/SPIKE-0.md](docs/SPIKE-0.md): GO, with five conditions.

## What exists

| crate | what |
|---|---|
| `crates/core` (`safe_core`) | the safe itself, with no network: open, edit and write a KDBX file (history-tracked edits, recycle bin, recorded deletions); the write guard that keeps files keepass-rs can't write back read-only; verify-by-reread; search; the password and passphrase generator (EFF long list); one-time codes; atomic writes; Argon2id calibration |
| `crates/store` (`safe_store`) | the places a safe can live: a stub |
| `crates/daemon` (`ewe-safed`) | holds the unlocked safe: a stub |
| `crates/cli` (`ewe-safe`) | JSON verbs over the daemon's socket: a stub |

## Develop

    cargo test                      # unit tests (the corpus test skips until fetched)
    tests/corpus/fetch.sh           # other apps' KDBX test files, pinned (needs pykeepass)
    tests/fidelity/run.sh           # the fidelity gate: nothing another app wrote is lost
    cargo run --release -p safe-core --example merge-spike
    cargo run --release -p safe-core --example kdf-timing

Never enable quick-xml's `overlapped-lists` feature anywhere in the tree: it
corrupts every password keepass-rs reads (SPIKE-0, F2). CI checks for it.

MIT licensed. The EFF wordlist is CC BY 3.0 US; see [NOTICE](NOTICE).
