# Import — bringing your passwords to Safe

`ewe-safe import` (and the Safe window's Import screen) brings another
password manager's items into the safe. This version reads **1Password**
three ways. More formats follow (Bitwarden, browsers, KeePass, `pass`;
PLAN.md phase 4). The contract is the `import` row of docs/PROTOCOL.md; the
code is `safe_core::import` (reading and mapping) and the daemon's
`import.rs` (the file, `op`, the one save).

## Three ways in

| format | what | how |
|---|---|---|
| `1pux` | 1Password's full export: every item type, attachments, password history | `ewe-safe import 1pux ~/Downloads/<account>.1pux` |
| `1password-csv` | 1Password 8's CSV export: Logins and Passwords only, no custom fields, no attachments, no history | `ewe-safe import 1password-csv ~/Downloads/export.csv` |
| `op` | straight from the 1Password app through its command-line tool — no file on disk at all | `ewe-safe import op` (`--vault Personal` to take one vault; `--account` when op knows several accounts) |

Every way takes `--dry-run` (shows what would come in, changes nothing),
`--folder F` (everything goes below the folder F) and `--skip-duplicates`.

### Getting the export out of 1Password

- **1PUX (best):** in the 1Password 8 app, open the account menu (the `…`
  at the top of the sidebar; **File** on a Mac), choose **Export**, pick
  the account, enter your password, choose **1PUX**, then **Export Data**.
- **CSV:** the same, choosing CSV. It holds less (see the table above).
- **op:** install 1Password's CLI (`1password-cli`), then in the 1Password
  app turn on **Settings → Developer → Integrate with 1Password CLI**. The
  first call shows 1Password's own prompt to let Safe in; approve it.

**An export is plain text.** Anyone who can read the file can read every
password in it. Delete it as soon as the import is done; the reply's `hint`
says so. The `op` way never writes one.

## What becomes what

| 1Password | Safe |
|---|---|
| **Login**, **Password** | a **Login**: username, password, every website (the first is `URL`, the rest `KP2A_URL_1…`), the first one-time code (`otp`, as an `otpauth://` URI — a bare secret is turned into one), tags, notes. Every other field becomes a **custom field**, named `Section: label`, protected when 1Password conceals it (a PIN, a security answer). Web-form fields the browser extension saved become `Web form: <name>`; check boxes stay out |
| **Secure Note** | a **Note**: its text, then any extra fields listed below it |
| **SSH Key** | an **SSH key** item, as KeePassXC stores one (docs/FORMAT.md, "SSH keys"): the key as an OpenSSH attachment (1Password exports PKCS#8, which Safe turns into OpenSSH; through `op`, op's own OpenSSH form when its value can't be read: `op read "op://<vault>/<item>/private key?ssh-format=openssh"`), `KeeAgent.settings`, `public_key` and `fingerprint`; its notes and other fields as a Note lists them. A key Safe can't read or use (DSA, P-521, `sk-`) stays a **Note** as below, so nothing is lost, and the report's `skipped` says why (`"<title> — SSH key"`) |
| **Credit Card** | a **Card** (docs/FORMAT.md, "Cards and addresses"): cardholder → `Cardholder`, number → `Number`, verification number → `Security code`, PIN → `PIN` (all three protected), expiry date → `Expiry` (`MM/YYYY`), type → `Brand` (else the number's brand); notes as notes. Every other field (valid from, issuing bank, phone, credit limit, …) becomes a **custom field** named `Section: label`, protected when 1Password conceals it. Fields are known by 1Password's field id (`cardholder`, `ccnum`, `cvv`, `pin`, `expiry`, `type`), else by the English label |
| **Identity** | an **Address**: first name, initial and last name → `Full name`; company → `Organization`; the address → `Address line 1` (and `2` when the street has more lines), `City`, `Region` (state), `Postal code` (zip), `Country` (its code, upper case); default phone (else cell, home or business) → `Phone`; email → `Email`. Every other field (birth date, job title, username, reminder question and answer, …) becomes a custom field as above. Ids `firstname`, `initial`, `lastname`, `company`, `address`, `defphone`, `email` |
| **every other category** (Bank Account, Server, Database, Software License, Document, …) | a **Note** whose text starts with the category and lists every field as `label: value`, by section. The **secret** fields (concealed, an SSH private key) are also kept as **protected custom fields**, so a script or `reveal --field` can still read them |
| vault | a **folder** with the vault's name (below `--folder`; below the account's name when one 1PUX holds several accounts) |
| archived item | the folder **Archive** |
| item in the trash | **skipped** (listed in the report) |
| password history | the item's **history**, oldest first, each dated when it stopped being the password (`op` gives no dates: they are spread after the item's creation, in order) |
| file attachments, Document items | **attachments** (each up to 25 MB; bigger ones are listed as skipped, because the whole safe travels to its place on every save) |
| favourite | the tag **Favorite** |
| created / updated | the item's own creation and modification times |
| a second one-time code, or one Safe can't read | kept as a protected custom field |
| an address | one field, `street` / `city, state zip` / `country` |
| a date, a month and year | `YYYY-MM-DD`, `YYYY-MM` |
| an SSH key in a Note (a key Safe can't read) | the private key (protected), the public key and the fingerprint |

**Imported before cards existed?** Safe 0.2 made 1Password's Credit
Cards and Identities into Notes (the category on the first line, every
field listed, the secret ones also protected fields). `ewe-safe convert
--from-1password --dry-run` lists them, `ewe-safe convert
--from-1password` (or Settings → Cards and addresses → *Cards from an
earlier import*) turns them into cards and addresses in place: same item;
the number, the code and the PIN move into the card's own fields; the
lines that became fields leave the text; the note as it was stays in the
item's history (docs/FORMAT.md, "Cards and addresses"). A note with no
card number, or more than one, stays a note and the reply says why.

**Imported before SSH keys existed?** The owner's safe got its SSH keys as
Notes. `ewe-safe ssh adopt --dry-run` lists them, `ewe-safe ssh adopt`
turns them into SSH key items in place: same item, the note text and
every field kept (docs/PROTOCOL.md, "SSH keys and the agent").

**Duplicates:** an item whose website host (without `www.`) and username an
item already in the safe has. They are counted in the report and imported
anyway, unless `--skip-duplicates`, which lists them under `skipped`.

## What doesn't come in

- items in 1Password's **trash**;
- **links between items** (`reference` fields): they point at 1Password's
  own item ids;
- **passkeys**: 1Password's desktop export leaves them out. Sign in to each
  site once with the password, then add a Safe passkey there (the ewe
  browser offers it; the Import screen says so too);
- vault and item **icons**, Watchtower data, 1Password's item ids;
- attachments over **25 MB**, or missing from the export (the report names
  each one, as `"<item> — <file>"`).

## How it stays safe

- The daemon reads the export itself (same user; the CLI sends the full
  path) into memory; **nothing is written to disk** but the safe. The
  bytes and the parsed JSON are wiped once the items are built.
- `op` runs as argv from the daemon and is asked **by id** (`vault list`,
  `item list --include-archive`, `item get`, `read op://<vault>/<item>/<file>`,
  `read op://<vault>/<item>/private key?ssh-format=openssh` for a key it
  printed in a form Safe can't read, `document get`); no value ever goes
  on a command line.
- The report holds counts, folder names and titles — never a value.
- **One save** for the whole import: one verified write, one upload, one
  merge if another machine saved meanwhile.
- The safe must be unlocked first (a dry run too: duplicates are counted
  against what it holds).

## Verified, and not

- **Tested** (`crates/core/tests/import.rs`, `crates/cli/tests/import.rs`):
  synthetic fixtures written from 1Password's published 1PUX format
  (support.1password.com/1pux-format), the 1Password 8 CSV header (`Title,
  Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes`) and the op
  CLI's documented item JSON; KeePassXC's and Bitwarden's 1PUX readers were
  read for the corners (file names `files/<documentId>__<name>` and `___`,
  e-mail and address objects). `tests/import/make_fixtures.py` makes them;
  no real data was ever used. pykeepass reads every imported field back.
- Cards and addresses (`crates/core/tests/import.rs`, `crates/core/tests/cards.rs`,
  `crates/cli/tests/import.rs`, `crates/cli/tests/cards.rs`): a 1PUX Credit
  Card and Identity with 1Password's template field ids, the same through
  `op`'s JSON, and `convert` of notes made the way 0.2's importer made them.
  Not yet verified against a real export: the labels a non-English
  1Password app writes (the ids are used first; `convert` only has the
  labels), and the exact value `op` prints for a card's type and an address.
- SSH keys (`crates/core/tests/ssh.rs`): PKCS#8 keys made by the tests,
  in a 1PUX and in `op`'s JSON (with and without `ssh_formats`, and through
  `op read …?ssh-format=openssh`); a key Safe can't read stays a Note.
- **Not yet verified:** a 1PUX or CSV from the current 1Password app, and
  the real `op` (attachments through `op read`, the approval prompt when op
  is run by a user service, the exact JSON op prints for an SSH key). The first real import should be a
  `--dry-run`, compared with what 1Password shows.
