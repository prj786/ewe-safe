# Safe is the SSH gate

**Status:** S21–S27 built (daemon and CLI, `feat/ssh-gate`, 2026-11-01);
S28 (the window) in progress. Where the build differs from the first plan,
this file says "As built" and why. Asked by the owner on 2026-11-01. Amends RFC-008
(decisions S21–S28) and TRIO.md S2 ("Safe never edits `~/.ssh/config`" ends
here: Safe now owns two lines at its top). Release: Safe 0.4.0-beta.

This file is the contract for the work. Every agent reads it first. When code
and this file disagree, fix one of them in the same change.

## What the owner asked (2026-11-01, in short)

> Safe should be the main gate for SSH connections. Today 1Password does it.
> One ecosystem: Safe, the browser and ewe's SSH work together. Nothing stays
> outside. Each thing is the single source of truth for its job. Attach it to
> the account. Connecting to GitHub, Azure and others must be easy.

What is on the owner's computer today (read 2026-11-01):

- Safe 0.3.1-beta, the safe in the Nextcloud account, the agent **on**, 6 keys.
- But `ssh` still goes to 1Password: the hosts `work` and `work-proxy` say
  `IdentityAgent ~/.1password/agent.sock`. They live in ewe.conf
  (`[[network.ssh.hosts]]`, the managed block), so every computer of the
  account gets that line.
- `emoh` uses the plain file `~/.ssh/id_ed25519`.
- `ssh-status` says `points_here: false` and names the two 1Password lines.

So Safe has the keys but is not the gate. This plan makes it the gate.

## One owner for each job

| job | the one owner | where it lives | how it follows the account |
|---|---|---|---|
| private SSH keys | **Safe** | the safe file (KeeAgent entries) | the safe's place (the account's Nextcloud) |
| signing with a key | **Safe's agent** | `$XDG_RUNTIME_DIR/ewe-safe-ssh.sock` | — |
| which agent `ssh` asks | **Safe** (the gate) | one `Include` line on top of `~/.ssh/config` → `~/.ssh/ewe-safe/config`; `SSH_AUTH_SOCK` (environment.d) | `[safe] ssh_agent` (ewe.conf, shared): every computer turns the gate on or off by itself |
| host definitions (name, address, user, port, which key) | **ewe-conf** `[[network.ssh.hosts]]` | ewe.conf → the managed block in `~/.ssh/config` | ewe.conf sync |
| a key's public file, for `IdentityFile` | **Safe** | `~/.ssh/ewe-safe/key-<tag>.pub` | written on every computer from the safe |
| the services' host keys (github.com, …) | **Safe** | `~/.ssh/ewe-safe/known_hosts` | shipped in the package |
| signing Git commits | **Safe** sets git | `git config --global` | `[safe] git_sign` (ewe.conf, shared) |
| your ewe computers (RFC-009) | **ewe-remote** | its own key per computer | the account record is discovery only |
| opening a service's web page | **ewe browser** | — | Safe fills the login there, as always |

Two lines matter most:

- **Safe never writes ewe.conf itself** (rule 1). It asks `ewe-conf`, the
  same way `[safe]` settings are stored today (`config::conf_store`).
- **ewe-remote keeps its own key per computer** (RFC-009). A lost laptop is
  locked out alone, without touching the others. Safe *shows* your ewe
  computers and opens a terminal to them, but it doesn't hold their keys.

## S21. The gate

`ewe-safe ssh enable` (the existing verb; new reply fields only) now also
makes `ssh` ask Safe, even where `~/.ssh/config` names another agent.

1. It writes `~/.ssh/ewe-safe/config` (folder 0700, file 0600; absolute
   paths, because the file is per computer):

   ```
   # Written by Safe (ewe-safe). Every ssh on this computer asks Safe for keys.
   # `ewe-safe ssh disable` removes this file and the Include line.
   Host *
       IdentityAgent /run/user/1000/ewe-safe-ssh.sock
       GlobalKnownHostsFile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2 /home/sam/.ssh/ewe-safe/known_hosts
   ```

2. It puts **two lines at the very top** of `~/.ssh/config` (creating `~/.ssh`
   0700 and the file 0600 when missing):

   ```
   # Safe (ewe): every ssh asks Safe for keys. `ewe-safe ssh disable` removes these two lines.
   Include ~/.ssh/ewe-safe/config
   ```

   `ssh` takes the **first** value it finds for each option, so this
   `IdentityAgent` wins over every later one (`~/.1password/agent.sock`
   included). Checked with OpenSSH 10.6: `ssh -G` shows Safe's socket for a
   host that names 1Password. An `Include` of a missing file is no error, so
   a removed Safe never breaks `ssh`.

   Before the first edit, Safe copies the file to
   `~/.ssh/config.before-safe` (only if that copy doesn't exist yet). It
   writes atomically (temp file in `~/.ssh`, rename) and keeps the mode
   (a `~/.ssh/config` that is a link stays a link: its target is written).
   It never changes any other line. It adds the two lines only once: if
   they are on top already, nothing is written; lines of Safe's found
   lower down (moved by hand) are moved back to the top, since only there
   do they win.

3. It writes `~/.ssh/ewe-safe/known_hosts` (S26) and the public key files
   (S22).

`ewe-safe ssh disable` removes the two lines (only those exact lines), the
`config` file, the `key-*.pub` files Safe wrote, `known_hosts` and
`allowed_signers`, as it removes the environment.d file today. It never
touches `config.before-safe`. It also turns commit signing off (S25):
signing needs the agent, and with `commit.gpgsign` still set every `git
commit` would fail (reply: `signing_off`).

**It follows the account.** `[safe] ssh_agent` is shared in ewe.conf. When
`ewe-safed` starts and whenever it re-reads its settings, it makes this
computer match:

- `ssh_agent = true` and the safe is set up → the environment.d file, the
  two lines, `config`, `known_hosts` and the public key files are there (the
  same writes as `enable`; nothing is written when all is in place);
- `ssh_agent = false` → Safe's two lines and files are gone (the same as
  `disable`), only when Safe wrote them.

Only a settings read that ewe-conf answered counts: when ewe-conf is
missing or broken, nothing is taken away. (As built: the re-read is every
minute; `EWE_SAFE_SETTINGS_SECONDS` is the test switch.)

Turn it on once on one computer, and every computer you sign in to follows.

`ssh-status` gets a `gate` object (additive):

```json
"gate": {
  "on": true,
  "include": true,
  "config_file": "/home/sam/.ssh/ewe-safe/config",
  "overridden": [{"host": "work", "agent": "~/.1password/agent.sock"}],
  "key_files": [{"path": "/home/sam/.ssh/id_ed25519", "fingerprint": "SHA256:…", "in_safe": true}],
  "other_agents": [{"socket": "/home/sam/.1password/agent.sock", "name": "1Password", "keys": 4, "missing_from_safe": 1}]
}
```

- `on`: the `Include` line is on top and Safe's config file is there;
  `include`: the `Include` line is the first line `~/.ssh/config` says.
- `overridden`: hosts whose own `IdentityAgent` names another agent (in
  ewe.conf or the user's own lines). With the gate on, Safe answers anyway.
- `key_files`: private key files in `~/.ssh` (see S23 for which files).
- `other_agents`: agent sockets named in `~/.ssh/config` (and the files it
  includes), in ewe.conf's hosts, known (`~/.1password/agent.sock`), or the
  caller's `SSH_AUTH_SOCK`, that exist and answer, with how many keys they
  hold and how many of those Safe doesn't have (`ssh-add -L` against that
  socket, 5 s timeout, public keys only). `name` is `1Password` for that
  path, else the socket's file name. `missing_from_safe` needs the public-key
  cache (works while locked).

## S22. Keys you can point at: public key files

For every key the agent offers, Safe writes `~/.ssh/ewe-safe/key-<tag>.pub`
(0644): the key's public line with its title as the comment, from the
public-key cache, so it works while the safe is locked. (The cache,
`ssh-public.json`, now also holds each key's item id and fingerprint, so
`ssh hosts` and the window can name a key while locked.) It is written whenever the cache is written, and files
for keys that are gone are removed (only `key-*.pub` files in that folder).

`<tag>` = the first 16 characters of the key's SHA256 fingerprint (the base64
part, without `SHA256:`), with `+` → `-` and `/` → `_`. The name never
changes when the key is renamed, and every computer with the same safe gets
the same name, so host definitions in ewe.conf work everywhere.

A host uses one key with:

```
Host github.com
    IdentityFile ~/.ssh/ewe-safe/key-p2QAMXNIC1TJYWeI.pub
    IdentitiesOnly yes
```

`ssh` asks the agent for that key only (no "Too many authentication
failures"). The private key never leaves Safe.

The item summary's `ssh` object gets (additive): `file` (the path above, `~`
form) and `last_used` (`{at, program}` or `null`: the agent's last signature
with this key on this computer; `program` is the shown name, e.g. `ssh (from
git)`). The agent keeps this in `$XDG_STATE_HOME/ewe/safe/ssh-used.json`
(fingerprints, times and program names; no titles).

## S23. Moving SSH to Safe (`ssh takeover`)

New verb **`ssh-takeover`**, CLI `ewe-safe ssh takeover [--dry-run]`. The
window's "Move SSH to Safe". Needs the safe unlocked (a dry run too).

1. Turns the gate on (S21) if it is off.
2. **Key files:** every regular file in `~/.ssh` (not in subfolders) whose
   text starts with a private key header (`-----BEGIN OPENSSH PRIVATE KEY-----`,
   `… RSA PRIVATE KEY-----`, `… EC PRIVATE KEY-----`, `… PRIVATE KEY-----`),
   plus every `IdentityFile` named in `~/.ssh/config` (and the files it
   includes, our own excepted) whose path is a private key. Size limit as
   `ssh add`. For each:
   - Safe has it already (same fingerprint) → `already`;
   - no passphrase → added like `ssh add` (title: the key's comment, else
     the file name) → `imported`;
   - a passphrase → `needs_passphrase`, unless the args carry
     `passphrases: {"<path>": "<passphrase>"}` (a secret, like `password`);
     a wrong one → `skipped` with the reason.
   **Files are never deleted or changed.** `files_left` lists the private key
   files that are now also in Safe, with a hint: Safe signs for them now;
   delete the files when you are ready.
3. **Hosts in ewe.conf:** for every `[[network.ssh.hosts]]` entry with an
   `IdentityAgent` option that is not Safe's socket, that option is removed
   (`ewe-conf get network.ssh.hosts` → change → `ewe-conf set
   network.ssh.hosts '<json>'`; one set for all). → `hosts_fixed: [alias]`.
   The user's own lines outside the managed block are never changed; the
   gate overrides them (`overridden` in the reply).
4. **Other agents:** for each other agent that answers (S21 `other_agents`),
   its public keys that Safe doesn't have → `missing_from_safe: [{agent,
   comment, fingerprint, key_type}]` and a `hint`: "Import them from
   1Password first: Safe → Import (or `ewe-safe import op`), then `ewe-safe
   ssh adopt`." Safe can't take a private key out of another agent.

The request may also carry `ssh_auth_sock` (the caller's, as `ssh status`
does). With a terminal, the CLI runs a dry run first and asks for each
`needs_passphrase` file (empty: leave it out).

Reply: `enabled`, `gate`, `imported: [{item_id, title, file}]`, `already:
[{item_id, title, file}]`, `needs_passphrase: [file]`, `skipped: [{file,
reason}]`, `hosts_fixed`, `overridden`, `missing_from_safe`, `files_left`,
`hint`, then `dry_run: true` (nothing changed) or `sync`. One save for all
imports.

## S24. Connect to a service

The easy way to GitHub, Azure and the others. The window has a **Connect**
button and a grid of services; the CLI has `ewe-safe ssh connect`.

### The catalogue (one list, in the daemon; the window and the CLI read it)

New verb **`ssh-services`**, CLI `ewe-safe ssh services` → `services: [...]`,
each:

```json
{"service": "github", "name": "GitHub", "group": "git", "host": "github.com", "user": "git",
 "key_type": "ed25519", "key_bits": null, "page": "https://github.com/settings/ssh/new",
 "needs": [], "optional": [], "signing": true, "steps": ["…", "…"],
 "signing_steps": ["…"]}
```

(The field is `service`, not `id`: `id` is the socket envelope's.) As
built: `needs` lists what `connect` must get (`gitea`: `host`; `server`:
`host`, `user`) and `optional` what it may take (`gitlab`: `host`;
`azure-devops`: `org`; the cloud services: `host`, `user`). `host`/`user`
are `null` when they come from the user; `page` is `null` when it needs
`host` (`gitea`). `key_bits` is set for Azure DevOps only. `signing_steps`
are the extra steps for commit signing (GitHub: add the key again as a
Signing Key; GitLab: keep Usage type on Authentication & Signing);
`connect --sign` adds them to its `steps`.

| service | name | group | host | user | key | page | needs |
|---|---|---|---|---|---|---|---|
| `github` | GitHub | git | github.com | git | ed25519 | `https://github.com/settings/ssh/new` | — |
| `gitlab` | GitLab | git | gitlab.com (or `host`) | git | ed25519 | `https://<host>/-/user_settings/ssh_keys` | optional `host` |
| `azure-devops` | Azure DevOps | git | ssh.dev.azure.com | git | **rsa 3072** (Azure Repos takes RSA only; rsa-sha2-256/512; 3072 bits as Microsoft's own steps make it — no Microsoft page names 4096) | `https://dev.azure.com/<org>/_usersSettings/keys` | `org` (without it: `https://dev.azure.com/`, the steps say where) |
| `bitbucket` | Bitbucket | git | bitbucket.org | git | ed25519 | `https://bitbucket.org/account/settings/ssh-keys/` | — |
| `codeberg` | Codeberg | git | codeberg.org | git | ed25519 | `https://codeberg.org/user/settings/keys` | — |
| `gitea` | Gitea or Forgejo | git | `host` | git | ed25519 | `https://<host>/user/settings/keys` | `host` |
| `azure-vm` | Azure virtual machine | cloud | `host` (later) | azureuser | ed25519 (GA since 2024-10) | `https://portal.azure.com/#browse/Microsoft.Compute%2FVirtualMachines` | — |
| `aws` | AWS EC2 | cloud | `host` (later) | ec2-user | ed25519 | `https://console.aws.amazon.com/ec2/` (the console AWS's docs give; the steps say Key Pairs → Import key pair) | — |
| `gcloud` | Google Cloud VM | cloud | `host` (later) | your name (`--user`, else this computer's login) | ed25519 | `https://console.cloud.google.com/compute/metadata/sshKeys` (as Google's docs give it) | — |
| `digitalocean` | DigitalOcean | cloud | `host` (later) | root | ed25519 | `https://cloud.digitalocean.com/account/security` | — |
| `hetzner` | Hetzner Cloud | cloud | `host` (later) | root | ed25519 | `https://console.hetzner.cloud/` | — |
| `server` | A server you can log in to | server | `host` | `user` | ed25519 | — (a terminal runs `ssh-copy-id`) | `host`, `user` |

`steps`: two or three short, plain sentences per service (the owner is not a
native English speaker: short words, no jargon). Every URL, menu path and
answer was checked against the service's own docs on 2026-11-01 (Hetzner's
console path against Hetzner's community tutorial: no official page has
it). Example for GitHub: "Safe
copied your public key.", "On the GitHub page, paste it into Key, give it a
name and press Add SSH key.", "Come back and press Check." Azure DevOps:
"…User settings (top right) → SSH public keys → New key…". Azure VM: "Paste
it as the SSH public key when you create the VM. For a VM you have:
Help → Reset password → Reset SSH public key." Check every URL and menu path
against the service's own docs when you write them.

### `ssh-connect`

CLI: `ewe-safe ssh connect <service> [--key ID | --title T] [--host H]
[--user U] [--port N] [--alias A] [--org O] [--replace] [--sign [--email E]]
[--no-open]`. Socket args: the long options (`key` is an item id), plus
`wayland_display` (the CLI sends its own). Needs the safe unlocked.

0. **The gate**: when Safe's agent is off, `connect` turns it on (as
   `enable`): a key Safe holds is no use to `ssh` without it. The reply's
   `enabled` says it did.

1. **The key:** `--key` an SSH key item, else a new one (`ssh new` with the
   service's type; title `--title`, default the service's name, e.g.
   `GitHub`). The new key is saved first (one save).
2. **The public file** (S22) is written.
3. **The host definition** (git services, and any service given `--host`),
   through `ewe-conf` into `[[network.ssh.hosts]]`:
   - alias = `--alias`, else the host (`github.com`);
   - options: `HostName <host>` (only when alias ≠ host), `User <user>`,
     `Port <n>` (only when given and ≠ 22), `IdentityFile
     ~/.ssh/ewe-safe/key-<tag>.pub`, `IdentitiesOnly yes`;
   - the alias exists in ewe.conf with **another** `IdentityFile` → error
     `conflict` (new code, additive) with `alias` and a message ("github.com
     already uses the key *Work GitHub*. Use --replace, or --alias github-2
     for a second account."); `--replace` overwrites;
   - the alias is defined in the user's own lines of `~/.ssh/config` →
     `conflict` ("You set up github.com yourself in ~/.ssh/config. Change it
     there, or use --alias."); never edited;
   - a second account on one service (`--alias github-work`): the reply's
     `remote_hint` says `git@github-work:<owner>/<repo>.git`.
4. **The public key goes to the clipboard** (`wl-copy`; a public key, so no
   clear timer) and **the page opens in ewe browser** (`ewe-browser open
   <url>`; without ewe browser, `xdg-open`), unless `--no-open`. The page is
   where the user signs in; Safe fills that login in the browser as always.
   For `server`: Safe opens a kitty terminal that runs `ssh-copy-id -f -i
   <public file> -o PreferredAuthentications=keyboard-interactive,password,publickey
   [-p N] <user>@<host>` (the user types the server's password once, there;
   the password is asked first because an agent with many keys would use
   up the server's tries before it). Google Cloud takes the key with the
   login name as its last word, so for `gcloud` the clipboard holds
   `<key> <user>`. Test switch: `EWE_SAFE_OPEN` = a program called with the URL
   (or the terminal's argv) instead.
5. `--sign` turns on commit signing with this key (S25).

Reply: `item_id`, `ssh`, `service`, `alias` (or `null` for a cloud service
without a host yet), `page`, `copied`, `opened`, `steps`, `remote_hint`
(git services; Azure DevOps: `git@<alias>:v3/<org>/<project>/<repo>`),
`enabled`, `sync`, and `signing` (as `ssh sign-commits`) with `--sign`.
`--sign` checks the Git email before anything changes. For a cloud
service, the host comes later with `ssh host set`.

### `ssh-test`

CLI: `ewe-safe ssh test <alias|service|user@host[:port]> [--key ID]`. Safe
checks that the connection works, the way a user would by hand.

- The daemon runs `ssh -T -o BatchMode=yes -o ConnectTimeout=10 -o
  StrictHostKeyChecking=accept-new -o IdentityAgent=<Safe's socket>
  <target>` (git services: no command; others: `true`), with `-i <public
  file> -o IdentitiesOnly=yes` when `--key` is given. Test switch:
  `EWE_SAFE_SSH` = the `ssh` program.
- The agent doesn't ask "Allow…?" for this one: the `ssh` is the daemon's
  own child (its parent pid is the daemon), started because the user pressed
  Check. Logged as such.
- It reads the answer: GitHub `Hi <name>! You've successfully authenticated`;
  GitLab `Welcome to GitLab, @<name>!`; Bitbucket `authenticated via ssh key`
  (and `logged in as <name>`); Codeberg/Gitea/Forgejo `Hi there, <name>!`;
  Azure DevOps `Shell access is not supported` (= signed in); others: exit 0.
- Reply: `connected` (bool), `account` (the name, or `null`), `host_key`
  (`known` | `added` | `changed`), `message` (one plain sentence: "Connected
  to GitHub as sam.", "GitHub doesn't know this key yet. Add it on the page,
  then check again.", "The server's key changed. Safe stopped. Check with the
  server's owner."), `detail` (ssh's last lines, at most 400 characters).
  `changed` is never `connected`. Needs the safe unlocked (`locked`).
  Exit 0 (rule 5). Also `service` (the catalogue's, or `null`).
- A service name tests ewe.conf's host for that service when there is one
  (its `IdentityFile` applies), else `git@<the service's host>`; a service
  without a host of its own (`gitea`, the cloud ones) and none in ewe.conf
  is `bad-request` with a hint (`ssh host set`).

### `ssh-hosts`, `ssh-host-set`, `ssh-host-remove`

- `ewe-safe ssh hosts` → `hosts: [{alias, host_name, user, port, source,
  key, file, service, agent}]`: every host of ewe.conf (`source: "ewe"`) and
  of the user's own lines (`source: "yours"`, wildcards and `Match` left
  out); `key`: `{item_id, title, fingerprint}` when the `IdentityFile` is a
  Safe key (by its `.pub` content, any path), else `null`; `file`: the
  `IdentityFile` (or `null`); `service`: the catalogue's `service` whose host
  matches `HostName` (or the alias); `agent`: `safe` when the gate is on,
  else the host's `IdentityAgent` (or `null`). Works while locked (titles
  from the public-key cache).
- `ewe-safe ssh host set <alias> [--host H] [--user U] [--port N] [--key ID
  | --no-key]`: adds or changes an ewe.conf host; other options it had stay.
  An alias with a space, `*`, `?` or `!` is `bad-request`; one in the user's
  own lines is `conflict`. Reply: `alias`, `created`, `entry` (as in `ssh
  hosts`).
- `ewe-safe ssh host remove <alias>`: removes it from ewe.conf (never the
  user's own lines: `conflict`; an unknown alias: `not-found`). Reply:
  `alias`, `removed`.

## S25. Sign Git commits with an SSH key

As 1Password does. CLI `ewe-safe ssh sign-commits <id> [--email E]` and
`ewe-safe ssh sign-commits --off`; verb **`ssh-sign`** (`item_id`, `email`,
`off`).

- On: `git config --global` sets `gpg.format ssh`, `user.signingkey
  <public file>` (the `~` path), `gpg.ssh.program ewe-safe-ssh-sign`,
  `commit.gpgsign true`, `tag.gpgsign true`, `gpg.ssh.allowedSignersFile
  ~/.ssh/ewe-safe/allowed_signers`. Safe writes `allowed_signers` (`<email>
  namespaces="git" <public key>`; email = `--email`, else `git config
  user.email`, else error `bad-request` "Tell Safe your Git email: --email").
  Records `[safe] git_sign = "SHA256:…"` (ewe.conf, shared).
- `ewe-safe-ssh-sign` (new, `/usr/bin`, a 3-line shell script in
  `packaging/`): `ssh-keygen` with `SSH_AUTH_SOCK` set to Safe's socket, so
  signing reaches Safe even from a terminal that started before the gate.
  `ssh-keygen -Y sign -f <public file>` signs through the agent; the agent
  asks "Allow ssh-keygen (from git) to use GitHub key?" as usual. (Git
  expands the `~` of `user.signingkey` and `allowedSignersFile` itself:
  checked with Git 2.56.)
- The email comes from Git's **global** `user.email` (`git config --global`):
  the daemon's working folder may be any repository.
- Reply: on: `signing: {item_id, title, fingerprint, email, file,
  allowed_signers, recorded}`; off: `signing: null`, `unset` (the keys it
  unset), `recorded`. The gate goes on when it is off (as `connect`).
- Off: unsets those git keys **only where they still hold Safe's values**,
  removes `allowed_signers`, records `git_sign = ""`.
- Follows the account: at start and on a settings re-read, a computer with
  `git_sign` set and that key in its safe sets the same git config (only the
  keys above, only when they differ). As built, also the other way: with
  `git_sign = ""`, or Safe's agent off, Safe's values go from Git here.
- `ssh-status` gets `signing: {item_id, title, fingerprint, active} | null`
  (`item_id` and `title` are `null` when that key isn't in this safe;
  `active`: Git here signs with Safe now).
- GitHub and GitLab show a signed commit as *Verified* only when the key is
  also added there as a **signing key**. The GitHub steps say so (GitHub:
  the same page, Key type → Signing Key).

## S26. The services' host keys

`~/.ssh/ewe-safe/known_hosts` holds the published host keys of github.com,
gitlab.com, bitbucket.org, ssh.dev.azure.com (and vs-ssh.visualstudio.com)
and codeberg.org. The gate's `GlobalKnownHostsFile` adds it, so the first
connection to these never asks "Are you sure…?" and a fake server is caught.

The lines are shipped in the daemon (`include_str!` of a file in the repo).
A unit test checks each key's fingerprint against the one the service
publishes (write the source URL beside each fingerprint in the test):

- GitHub: `api.github.com/meta` (`ssh_key_fingerprints`; ED25519
  `+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU`, checked 2026-11-01);
- GitLab.com: docs.gitlab.com, "SSH host keys fingerprints";
- Bitbucket: support.atlassian.com, "Configure SSH and two-step
  verification" / Bitbucket's published `known_hosts`;
- Azure DevOps: learn.microsoft.com, "Use SSH key authentication" (RSA);
- Codeberg: docs.codeberg.org, "SSH key fingerprints".

Get the full lines with `ssh-keyscan`, then check the fingerprints against
those pages before committing. A mismatch = stop and report; never guess.

## S27. The agent says where a key goes (session-bind)

OpenSSH 8.9+ tells the agent which server it is talking to
(`SSH_AGENTC_EXTENSION` 27, `session-bind@openssh.com`: the server's host
key, the session id, the server's signature over it, `is_forwarding`). Safe
answers it (SUCCESS once the signature checks out; a bad one is FAILURE and
the connection is closed) and remembers the host key for the rest of that
agent connection.

- The approval question names the host when Safe knows it: "Allow *ssh
  (from git)* to use *GitHub key* for *github.com*?" Known = the host key is
  in S26's `known_hosts`, or in an unhashed line of `~/.ssh/known_hosts`
  (the first name on that line). Otherwise the question stays as today.
- `is_forwarding` true (an agent forwarded to another machine) → the
  question says "…through a forwarded connection" and `first-use` approval
  is not remembered for it. As built: it is also asked every time (an
  approval remembered for the local `ssh` would otherwise skip it).
- The prompt gets two more variables: `EWE_SAFE_APPROVE_HOST` (the host,
  `""` when unknown) and `EWE_SAFE_APPROVE_FORWARDED` (`1` or `0`). The
  window's `--approve` shows them.
- Every other extension keeps its answer today (FAILURE).
- As built: the agent keeps up to 16 bindings per connection (as OpenSSH's
  own agent does) and names the last one; the daemon's own `ssh` (`ssh
  test`) is never asked about.

This is last in the order. Ship it only with tests (a real `ssh` against a
real `sshd` on loopback, or the extension bytes built in a unit test). If
it doesn't fit, leave it out and say so; it must not delay S21–S26.

## S28. The window: an SSH page

The side navigation's "SSH keys" becomes **SSH** (same icon). It opens a page,
not the item list. One scroll, in this order:

1. **The gate card.**
   - Off: "Make Safe your SSH agent" — one line why, **Turn on** (`ssh
     enable`), and the approval choice (first use / every time / never).
   - On, and another agent still has keys or hosts → warning card "1Password
     still answers ssh for work, work-proxy" (from `gate`) → **Move SSH to
     Safe** opens the takeover sheet: a dry run list first (keys to import,
     files that need a passphrase with a field each, hosts to fix, keys only
     1Password has → "Import from 1Password" opens the Import screen), then
     **Move** → the result.
   - On, all good → a quiet success line: "Safe is your SSH agent. Every
     ssh and git on this computer asks Safe." and the approval choice.
2. **Connect.** A grid of the catalogue's services (name + a simple glyph or
   letter tile; no brand logos we don't have the right to ship). A click
   opens the connect sheet, three steps on one sheet:
   1. *Key*: "A new key (recommended)" with the title prefilled, or pick one
      of yours. Azure DevOps says why it uses RSA.
   2. *Add it to GitHub*: the public key in a mono box with **Copy**, the
      steps, and **Open GitHub** (the page in ewe browser). `server`: host,
      user, port fields and **Open a terminal** (ssh-copy-id). Cloud: host
      and user are optional ("add the address when your VM is ready").
      GitHub and GitLab: a check box "Also sign my Git commits with this key".
   3. *Check*: **Check** runs `ssh test` → "Connected to GitHub as sam." or
      what to do next. **Done**.
3. **Keys.** Each key: title, type, short fingerprint, "Used by" chips (the
   hosts that point at it), "Last used 2 min ago by git" (S22). Actions:
   Copy public key, Connect…, a menu with Sign commits on/off, Show item.
   **Add a key** (file) and **New key** stay.
4. **Hosts.** From `ssh hosts`: alias, `user@host:port`, the key chip (or
   "any key"), a "yours" badge for the user's own lines. Actions: **Open
   terminal** (kitty `ssh <alias>`), **Check** (inline result), Edit and
   Remove (ewe.conf hosts only). **Add a host**.
5. **Your ewe computers** (only when `ewe-remote` exists): from `ewe-remote
   status --offline`: name, online dot, **Open terminal** (`ewe-remote
   terminal <id>`). One line under it: "Each computer has its own key. It
   stays on that computer, so you can lock out one computer alone."
6. A footer line: "Your keys, hosts and these settings follow your ewe
   account to every computer you sign in to." (When the safe's place is
   Nextcloud; for a local safe: "This safe is only on this computer.")

`ewe-safe-app --ssh` opens the window on this page (for the SSH plugin and
the shell). The item detail of an SSH key gets the same "Used by", "Last
used", Copy public key and Connect.

Everything uses the design system's tokens and components (`tokens.css`,
`components.css`, `Kit.svelte`); no raw colours or sizes. The dev mock
(`devmock.js`) answers every new verb, so each screen renders in `npm run
dev` (`?view=ssh&…` flags) for screenshots.

## The rules this keeps

- **Rule 1:** ewe.conf only through `ewe-conf` (`conf_store`, `ewe-conf
  set network.ssh.hosts`).
- **Rule 2:** no secret in ewe.conf. Fingerprints and host definitions are
  not secrets.
- **Rule 4:** new verbs, new fields, one new error code (`conflict`).
  Nothing renamed. No reply field is called `id`.
- **Rule 5:** every new CLI prints one JSON object and exits 0.
- **Safe's files only:** Safe changes only its two lines in `~/.ssh/config`,
  its own folder `~/.ssh/ewe-safe/`, its environment.d file, and the git
  keys listed in S25. It never deletes or rewrites a key file, and never
  edits the user's own host lines.
- **Values never cross:** passphrases travel as secrets (stdin, the socket),
  never argv, never a log.

## Tests (sandboxes only)

- `HOME`, `XDG_*` in a temp folder (a short `XDG_RUNTIME_DIR` symlink:
  SUN_LEN), a fake `ewe-conf` on `PATH` that stores into a JSON file, low KDF,
  `EWE_SAFE_NO_LOGIND`. Never the live `~/.ssh`, `~/.gitconfig`
  (`GIT_CONFIG_GLOBAL` into the sandbox), ewe.conf or agent.
- **OpenSSH takes `~` from the passwd entry, not `$HOME`**, for its default
  config, known_hosts and identity files (an `Include ~/…` follows `$HOME`).
  So every real `ssh` in a test runs with `-F <sandbox config>` and a
  sandbox `UserKnownHostsFile`, and a real connection names its key with
  `-i <absolute path>`; an alias whose `IdentityFile` is `~/…` is checked
  with `ssh -G` only. The test `sshd` gets `SetEnv HOME=<sandbox>` and
  `PermitUserRC no`, so the session's shell reads nothing of the real home.
- Test switches: `EWE_SAFE_SSH` (the `ssh` of `ssh test`), `EWE_SAFE_OPEN`
  (what opens a page or a terminal), `EWE_SAFE_SETTINGS_SECONDS` (the
  settings re-read).
- A real `ssh-agent` with a key loaded plays "1Password" for `takeover`.
- `ssh -G -F <sandbox config>` proves the gate wins over another
  `IdentityAgent`.
- `ssh test`: a fake `ssh` (`EWE_SAFE_SSH`) for each service's answer, and
  one real `sshd` on loopback (non-root works with OpenSSH 10.6; see
  ewe's `tests/ewe-remote-test.sh` for the recipe) for `connected: true`
  through the real agent.
- Commit signing: a real `git commit -S` in a sandbox repo, signed through
  the agent, then `git verify-commit`.
- `cargo build` the workspace before `cargo test -p ewe-safe` (else a stale
  daemon binary). `cargo fmt --check` and `cargo clippy --all-targets -- -D
  warnings` before pushing.

## How the work is split (2026-11-01)

| stream | where | branch / worktree |
|---|---|---|
| A: daemon + CLI (S21–S27), PROTOCOL.md, packaging | `crates/`, `docs/`, `packaging/` | `feat/ssh-gate` · `.wt/safe-gate` |
| B: the window (S28) | `app/` | `feat/ssh-gate-app` · `.wt/safe-gate-app` |
| C: ewe docs, the SSH plugin's link to Safe, the vault | ewe, ewe-plugin-ssh, project-map | done centrally |

B builds against this contract and the dev mock; A and B meet on
`feat/ssh-gate` (B merges into it). One PR, then the owner's OK for the
release (Safe 0.4.0-beta).
