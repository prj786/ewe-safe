# Safe and the keyring

The **keyring** (the Secret Service, `org.freedesktop.secrets` on the
session bus) is where apps keep their own passwords: ewe-sync's account
(`ewe-cloud`), mail (`ewe-mail`), Google (`ewe-auth`), the companion's API
keys, Chromium's and Electron's storage keys. On ewe it is gnome-keyring,
and PAM opens its `login` keyring with your login password when you log in.

This file is how Safe helps with it. The contract is docs/SYSTEM.md §3;
the verbs are docs/PROTOCOL.md, "The keyring".

## The password prompt at every start — `ewe-safe keyring repair`

**The problem** (docs/SYSTEM.md §0, found on the owner's machine on
2026-10-18). PAM unlocks the keyring called `login`. But on a machine that
met ewe's 2026-09-03 bug ("Choose password for new keyring"), apps save
into a **second** keyring, `Default keyring`, because the `default` alias
names it. That keyring has its own password, so it is locked at every
start, and the first app that needs a password makes gnome-keyring ask.
When two apps ask at once, gnome-keyring can crash
(`gkd-secret-unlock.c:244 perform_next_unlock`), and the restarted daemon
has no password at all.

**The fix:**

```sh
ewe-safe keyring status          # needs_repair: true, default: "Default_keyring"
ewe-safe keyring repair --dry-run   # what it would do; changes nothing
ewe-safe keyring repair
```

Or Settings → Keyring → **Fix the keyring password prompt** in the Safe
window.

What it does, through gnome-keyring's own API:

1. It finds the collection behind `default`. If that already is `login`,
   there is nothing to do (`already: true`).
2. It copies every item of every other collection (but gnome-keyring's
   temporary `session` one) into `login`: label, attributes, secret and
   content type.
   - An item `login` already has — the same attributes **and** the same
     secret — is a duplicate and is not copied again. So running the repair
     twice is safe.
   - The same attributes with **another** secret is a conflict: the newer
     copy (by its `Modified` time) is kept. The reply counts them
     (`conflicts`, and `replaced` when the other keyring's copy was newer).
3. It points `default` at `login`. New passwords now go to `login`, which
   opens when you log in: no more prompt.

What it never does: change or delete an item in the old keyring, or delete
a collection. **The old keyring stays as a backup.** To delete it later:
Passwords and Keys (seahorse) → right-click it → Delete, or remove
`~/.local/share/keyrings/Default_keyring.keyring` and log out and back in.

**The last prompt.** The old keyring is locked, so the repair asks
gnome-keyring to unlock it, and gnome-keyring shows its own window: type
that keyring's password one last time. If you close the window, nothing is
changed (`default` included) and the reply says to run it again. If you
don't know that password any more, ewe's TROUBLESHOOTING ("You already have
a Default keyring") shows how to start over.

**No `login` keyring at all** (`no-login-keyring`): log out and back in
once — the login screen makes it with your login password — then run the
repair again.

## What is in the keyring — `ewe-safe keyring list`

Names and dates only (label, app, collection, modified), never a secret,
never a prompt: locked collections are listed by name with their count. The
Safe window shows the same list under Settings → Keyring, with who keeps the
keyring ("Kept by GNOME Keyring").

## The carrier (for the login unlock)

`safe_secrets::carrier_store(w, machine)`, `carrier_fetch(machine)` and
`carrier_delete(machine)` keep W, this computer's session key
(docs/SYSTEM.md §2), as one item in gnome-keyring's `login` collection:

- label "Safe — unlock key for this computer";
- attributes `application = ewe-safe`, `ewe-safe = session-key`,
  `machine = <machine id>`; the secret is W's 32 bytes.

Since PAM already unlocks `login` at login, Safe can find W there with no
PAM code of its own. None of the three ever shows a prompt or starts a
keyring: `login` locked (or no keyring running) → `None` / an error, and no
`Unlock` call is made (checked with `dbus-monitor`). Storing again replaces
the item. The main session wires them to the login unlock's verbs.

The honest limit: W in the `login` keyring is as safe as that keyring —
encrypted at rest with the login password, readable by any app of yours
while you are logged in (as every keyring item is).

## Safe as the keyring (built, parked)

Safe can also **be** the keyring: serve `org.freedesktop.secrets` itself
from `keyring.safe`, sealed by W, and replace gnome-keyring per user. It is
built and tested (below), but **`ewe-safe keyring adopt` refuses** until
Safe's login module (`/usr/lib/security/pam_ewe_safe.so`, stream L) is
reviewed and installed: without it, W isn't in memory after a restart, and
Safe would ask for the login password at every start — the very prompt this
is about. The refusal says: "Safe can take over the keyring once its login
module is installed. For now, use `ewe-safe keyring repair`."

### How it works (when the module is there)

- **The server** (`crates/secrets`): Service, Collection, Item, Session
  (`plain` and `dh-ietf1024-sha256-aes128-cbc-pkcs7`), Prompt; the `login`
  collection and the `default` alias, `CreateCollection` for more;
  `CreateItem` with replace; `SearchItems` split into unlocked and locked;
  `Lock`/`Unlock`, `GetSecrets`, `ReadAlias`/`SetAlias`; signals and
  `PropertiesChanged`. A collection is also served at
  `/org/freedesktop/secrets/aliases/<alias>` (libsecret writes to
  `aliases/default`). Item paths `…/collection/login/<n>` stay the same
  across restarts.
- **The files** (`$XDG_STATE_HOME/ewe/safe/`, `0600`, never synced):
  `keyring.safe` (every item, sealed by W), `keyring.index` (which items
  exist and their attributes as salted SHA-256 hashes — never a label, an
  attribute's value or a secret — so a locked keyring can still answer a
  search with the right item paths, as gnome-keyring does), `keyring.on`
  (the marker PAM reads), `login.key` (W under the login password).
- **Locked** (W not in memory): searches answer from the index, as locked;
  `Unlock` returns a prompt. `Prompt` waits up to 5 s when the daemon
  started in the last 30 s (the greeter's handoff may be on its way), then
  opens `ewe-safe-app --unlock --login` (without the window, a kitty with
  `ewe-safe keyring unlock`). One window at a time: two apps asking at once
  share it. Dismissed → `Completed(true)`.
- **`Lock`** only marks a collection locked; while W is known, `Unlock`
  opens it again without a question (the login session already proved who
  is there). The keyring locks for real at logout.
- **`adopt`**: checks the login password (`unix_chkpwd`, in the CLI),
  makes or opens `login.key`, imports from the running keyring, writes
  `keyring.on` and `$XDG_DATA_HOME/dbus-1/services/org.freedesktop.secrets.service`
  (`Exec=/usr/bin/ewe-safed`, `SystemdService=ewe-safe.service`), asks the
  bus to reload its service files, stops this user's gnome-keyring-daemon
  (SIGTERM, only when `/proc/<pid>/exe` of the name's owner is it), takes
  the name. **`release`** undoes the D-Bus file and the marker, reloads,
  drops the name; `keyring.safe` and gnome-keyring's files are never
  deleted.
- **At start**, adopted, the daemon asks for the name without queueing; if
  another keyring holds it, that is logged and shown in `status.keyring.owner`,
  and Safe takes the name only once it is free.

### dbus-broker (the owner's session bus)

The live session bus is dbus-broker (`dbus-broker-launch --scope user`).
It keeps the **first** service file it finds for a name and logs
"Ignoring duplicate name … in service file …" for later ones, so the user
file in `$XDG_DATA_HOME/dbus-1/services/` wins over gnome-keyring's in
`/usr/share/dbus-1/services/`. It doesn't watch those folders, so `adopt`
and `release` call `org.freedesktop.DBus.ReloadConfig`. Under dbus-broker
every activation goes through systemd, hence `SystemdService=`. To check
after an adopt:

```sh
journalctl --user -u dbus-broker | grep -i duplicate
# expect gnome-keyring's /usr/share/dbus-1/services/org.freedesktop.secrets.service ignored
```

## How it was tested

Every D-Bus test runs on a private bus (`dbus-run-session`, or a
`dbus-daemon` with a temp config), with sandbox `HOME`/`XDG_*` and no
display: never the session bus, the live gnome-keyring or
`~/.local/share/keyrings`.

- `cargo test -p safe-secrets`: the server against zbus clients on a private
  `dbus-daemon` — plain and dh sessions both ways, `CreateItem` through
  `aliases/default` with replace, the locked keyring's search and its
  prompt (Dismiss, and W arriving), `CreateItem` while locked, another
  client's session refused, the importer, the repair (duplicates, a
  conflict with the newer copy kept, the old keyring untouched, a second
  run does nothing, no `login`), the carrier (store, replace, fetch,
  locked → nothing and no window, delete), objects added before serving.
- `crates/cli/tests/keyring.rs`: the real CLI and daemon; `adopt` refused
  without the module; the repair against a **real gnome-keyring-daemon**
  shaped like the owner's machine (`login` plus `Default keyring` as
  `default`), then `secret-tool lookup` and `default` → `login`. Skipped
  where gnome-keyring, secret-tool or python-gobject are missing (CI).
- By hand in sandboxes: libsecret's `secret-tool` (store, lookup, replace,
  `search --all`, clear; dh by default, plain when Safe refuses dh),
  Python `gi.repository.Secret`, ewe-cloud's exact `keyring_probe`; the
  repair with the old keyring locked (gnome-keyring's prompter couldn't
  open: nothing changed, no hang); the carrier on real gnome-keyring with
  `dbus-monitor` (no `Unlock` call); the parked takeover end to end with a
  stand-in module file — import, gnome-keyring stopped, `secret-tool`
  served by Safe, a restart through D-Bus activation of the user service
  file (dbus-daemon), the prompt, `release` back to gnome-keyring.

## Not verified yet

- The repair on the owner's real machine (gnome-keyring 51, the real gcr
  prompt for `Default_keyring`'s password).
- dbus-broker's choice of the user service file and `ReloadConfig`
  (checked only with dbus-daemon in the sandbox).
- The takeover with the real `pam_ewe_safe.so` and greetd (parked).
- KWallet's bridge and KeePassXC as the keyring that runs (only
  gnome-keyring and Safe were tested).
- Flatpak apps use the Secret portal (`org.freedesktop.impl.portal.Secret`),
  which gnome-keyring serves; Safe doesn't.
