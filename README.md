# ewe Safe

ewe's own password manager. It's much simpler than 1Password: one safe, one
master password, logins and notes, and a search box. The safe is one
encrypted file in the standard KeePass format (KDBX 4), so KeePassXC opens it
on any computer and KeePassDX, Strongbox or KeePassium on a phone. It lives
where you choose: this computer, your own Nextcloud (the ewe account), any
WebDAV server, a synced folder, or, if you want, Dropbox or Google Drive.
`Super+P` fills a login into any window.

**Status: phase 1 — usable from a terminal and `Super+P`, not packaged or
released yet; no Safe window yet.** The design is in [PLAN.md](PLAN.md)
(RFC-008). Phase 0's go/no-go spike is [docs/SPIKE-0.md](docs/SPIKE-0.md):
GO, with five conditions. This version opens two places: **This computer**
and **your ewe account's Nextcloud**.

## What exists

| crate | what |
|---|---|
| `crates/core` (`safe_core`) | the safe itself, with no network: open, edit and write a KDBX file (history-tracked edits, folders, recycle bin, recorded deletions); the write guard that keeps files keepass-rs can't write back read-only; verify-by-reread; Safe's own merge; search and the fill picker's ranking; the password and passphrase generator (EFF long list); one-time codes; SSH keys as KeeAgent entries and signing with them; atomic writes; Argon2id calibration |
| `crates/store` (`safe_store`) | the places — This computer and WebDAV (Nextcloud through `ewe-cloud`) — and the sync engine: cache, backups, save → stale → merge → retry, offline pending, rollback warning ([docs/PLACES.md](docs/PLACES.md)) |
| `crates/daemon` (`ewe-safed`) | holds the unlocked safe: the socket (systemd activation or its own, `0600`, `SO_PEERCRED`), the verbs, locking with the screen, before sleep and when unused, the clipboard, the periodic exchange; the SSH agent on its own socket |
| `crates/cli` (`ewe-safe`) | the verbs as JSON ([docs/PROTOCOL.md](docs/PROTOCOL.md)); secrets from a terminal or stdin, never argv |
| `crates/client` (`safe_client`) | the one client of the protocol: request/reply on the socket (`SO_PEERCRED` checked), the event stream, secrets wiped from a request once it's sent; used by the CLI and the window |
| `app/` | the Safe window (Tauri v2 + Svelte 5), phase 2: so far only its plumbing — one command per protocol verb, the daemon's events, a Svelte store and a dev mock; the screens wait for the mockup's sign-off. Its own Cargo project (`app/src-tauri`), outside this workspace, so `cargo test` here never needs webkit2gtk |
| `crates/testkit` | test support only: a mock WebDAV server and a switchable proxy |
| `packaging/` | `ewe-safe.socket` (the main socket and the SSH agent's) + `ewe-safe.service` (user units) |

## Use it (until it's packaged)

    cargo build --release
    install -Dm755 target/release/ewe-safe target/release/ewe-safed -t ~/.local/bin
    sed 's#/usr/bin/#%h/.local/bin/#' packaging/ewe-safe.service > ~/.config/systemd/user/ewe-safe.service
    cp packaging/ewe-safe.socket ~/.config/systemd/user/
    systemctl --user daemon-reload && systemctl --user enable --now ewe-safe.socket

    ewe-safe init --place nextcloud      # or --place local; asks for the master password twice
    ewe-safe add --title GitHub --username sam --url https://github.com --generate
    ewe-safe match --class firefox --title "GitHub"
    ewe-safe reveal <id> --field password

The Passwords plugin (`ewe.passwords` 1.2.0, provider `ewe`) fills from it
with `Super+P`; a locked safe opens a small unlock prompt.

**SSH keys** (TRIO.md S2): Safe keeps them the way KeePassXC does and is an
SSH agent for `ssh` and `git`, asking once per app before a key is used:

    ewe-safe ssh new --title "GitHub key"      # prints the public key to give GitHub
    ewe-safe ssh add ~/.ssh/id_ed25519         # an existing key (asks its passphrase)
    ewe-safe ssh adopt --dry-run               # keys an earlier 1Password import made notes
    ewe-safe ssh enable                        # SSH_AUTH_SOCK for new sessions, and the IdentityAgent line
    ssh-add -L                                 # the keys, through Safe

`enable` never edits `~/.ssh/config`: if it names another agent
(`IdentityAgent ~/.1password/agent.sock`), put the line it prints there.
The question names the program by its full path and marks one outside
`/usr` and `/opt`. It cuts down on surprises, nothing more: the master
password is what protects the keys, since any program running as you can
use the agent while Safe is unlocked (docs/PROTOCOL.md, "The SSH agent").

## Develop

    cargo test                      # everything, including the binaries end to end
    tests/corpus/fetch.sh           # other apps' KDBX test files, pinned (needs pykeepass)
    tests/fidelity/run.sh           # the fidelity gate: nothing another app wrote is lost
    cargo run --release -p safe-core --example merge-spike
    cargo run --release -p safe-core --example kdf-timing

The window (`app/`, needs webkit2gtk-4.1 and Node):

    cd app && npm install
    npm run dev                     # the page alone; open http://localhost:5176/?mock=1
    npm run tauri dev               # the window against the running ewe-safed
    npm run tauri build -- --debug --no-bundle

`?mock=1` serves a fake Safe built from PROTOCOL.md's shapes (master
password `mock`; `&locked=0`, `&setup=0`, `&daemon=0`, `&empty=1`). The
window honours `EWE_SAFE_SOCKET` too, so it can talk to a sandboxed daemon.

The end-to-end tests run the real `ewe-safe` and `ewe-safed` in sandboxes
(their own XDG directories, a fake `ewe-conf`, `ewe-cloud` and clipboard, a
mock WebDAV server); the logind test uses a private D-Bus with a stand-in
logind. Nothing touches the live keyring, ewe.conf or account. The daemon's
test switches: `EWE_SAFE_KDF_ITERATIONS` (cheap keys),
`EWE_SAFE_INSECURE_LOOPBACK=1` (plain http to 127.0.0.1),
`EWE_SAFE_NO_LOGIND`, `EWE_SAFE_LOGIND_BUS`, `EWE_SAFE_IDLE_SECONDS`,
`EWE_SAFE_SYNC_SECONDS`, `EWE_SAFE_APPROVE_CMD` (the SSH agent's
question; exit 0 = Allow), `EWE_SAFE_PROMPT_SECONDS` (how long the agent's
prompts wait); the CLI's: `EWE_SAFE_ASK_CMD` (the unlock prompt), `EWE_SAFE_SOCKET`
(another socket than `$XDG_RUNTIME_DIR/ewe-safe.sock`).

Never enable quick-xml's `overlapped-lists` feature anywhere in the tree: it
corrupts every password keepass-rs reads (SPIKE-0, F2). CI checks for it.

MIT licensed. The EFF wordlist is CC BY 3.0 US; see [NOTICE](NOTICE).
