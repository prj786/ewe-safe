# The safe file, as Safe reads, writes and merges it

The reference the daemon is built against. The decisions are in PLAN.md
§5 and §7; the evidence is in [SPIKE-0.md](SPIKE-0.md). Code:
`crates/core` (`safe_core`).

## The file

- **KDBX 4.1** is what Safe writes. keepass-rs writes nothing else: a 4.0
  file is saved as 4.1 with the same crypto, and a 3.1 file is upgraded
  (Argon2id, ChaCha20 inner stream; the outer cipher stays). The user is
  told before the first write (C5, `Safe::upgrade_from`).
- **A new safe:** AES-256, ChaCha20 inner stream, gzip, Argon2id at 64 MiB
  and 2 lanes, with as many iterations as take about a second on the
  machine that makes it, capped at 40 (`kdf`).
- **Every write is verified:** the bytes are read back with the same key
  and their content compared with memory (`digest`) before anything is
  handed out. Memory then takes the file's own reading.
- **The write guard (C1):** a file holding anything keepass-rs would drop
  on save (another app's extension) opens **read-only**, with the reason
  (`guard`).

## Items

| Safe | KDBX |
|---|---|
| title, username, password, notes | `Title`, `UserName`, `Password` (protected), `Notes` |
| websites | `URL`, then `KP2A_URL_1…n` |
| one-time code | `otp`: an `otpauth://` URI, protected; codes computed by Safe (F7) |
| apps (the `Super+P` pins) | tags `app:<window-class>` |
| kind Note | custom data `ewe.kind = note`; its notes are protected |
| passkey | KeePassXC's `KPEX_PASSKEY_*` fields and the tag `Passkey` (below) |

Everything else in an entry (custom fields, attachments, icons, colours,
auto-type) is left as it was.

**The file itself:** Meta custom data `ewe.saved-by` names the machine that
wrote the copy (set before every save by the sync engine, read for
ewe-sync's "last saved by"; the merge keeps the newer stamp). Read it with
`Safe::saved_by`, which survives F6. `Safe::newest_change` (items and
folders changed or moved, recorded deletions) is what the rollback check
compares (docs/PLACES.md).

## Passkeys

A passkey is stored exactly as **KeePassXC** stores it (checked in its
source, `develop` at `52e2743b3a77`, 2026-10-14: `BrowserService::
addPasskeyToEntry`, `BrowserPasskeys`, `PasskeyUtils`, `EntryAttributes`).
**KeePassDX** (`PasskeyEntryFields.kt`) and Strongbox read the same fields,
so a passkey made in Safe works in them, and theirs work in Safe.

| field | value | protected |
|---|---|---|
| `KPEX_PASSKEY_USERNAME` | the site's `user.name` | no |
| `KPEX_PASSKEY_CREDENTIAL_ID` | credential id, base64url, no padding (32 random bytes) | **yes** |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | the private key, PKCS#8 PEM | **yes** |
| `KPEX_PASSKEY_RELYING_PARTY` | the RP ID (`github.com`) | no |
| `KPEX_PASSKEY_USER_HANDLE` | the site's `user.id`, base64url, no padding | **yes** |
| `KPEX_PASSKEY_FLAG_BE`, `KPEX_PASSKEY_FLAG_BS` | `1` (backup eligible, backed up) | no |
| tag `Passkey` | on the entry | — |

- **The credential id is protected.** KeePassXC and KeePassDX both write it
  that way (TRIO.md's first table said "no"; the apps win).
- **Reading,** Safe does what KeePassXC does: Strongbox's
  `KPEX_PASSKEY_GENERATED_USER_ID` and `KPXC_PASSKEY_USERNAME` win when
  present; a flag reads `1` or `true` as set, and a missing flag as set.
  Ids are compared as base64url, so padded or standard base64 from another
  app still matches. A PEM without line breaks still reads (KeePassXC's
  own tests store keys that way). KeePassDX needs all five fields: Safe
  always writes all five.
- **Keys:** ES256 is a P-256 key in PKCS#8 v0 with the public point inside
  (`MIGHAgEAMBMG…`), EdDSA an Ed25519 seed in PKCS#8 v1 (48 bytes): the
  shapes Botan (KeePassXC's library) and OpenSSL write. No RS256: Safe makes
  none, and signing with one another app made answers `unsupported`.
- **One passkey per entry.** Putting one on an entry that has one replaces
  it; the old one goes with every `KPEX_PASSKEY_*` field and Strongbox's
  names. **Removing** takes every `KPEX_PASSKEY_*` field (KeePassXC's
  rule), `KPXC_PASSKEY_USERNAME` and the tag. Both are tracked edits: the
  item's history keeps the old version.
- **A new login for a passkey** (the browser named none): title = the RP's
  name, else the RP ID; username = `user.name`; URL = the page's origin,
  else `https://<rp_id>`. KeePassXC's own new entries are titled "<name>
  (Passkey)" in a group "KeePassXC-Browser Passkeys" with icon 13; Safe
  keeps its own items plain and top-level. On an existing login with an
  empty username, the username becomes `user.name`, as KeePassDX does.
- **What Safe answers** is what KeePassXC answers, byte for byte, apart from
  the AAGUID (Safe's is `452b824e-42d3-4324-bc6c-581888ca2851`): checked
  once against KeePassXC's own test vectors (its two ECDSA signatures, the
  authenticator data, the SPKI and the whole attestation object). ECDSA
  signatures are deterministic (RFC 6979) and DER, as Botan makes them.
  Sign count 0; BE and BS set.
- **Merge** (rule 3a below): a passkey survives another machine's or a
  phone's rewrite (the fields, their protection, the tag), and also two
  machines changing **the same login** before they sync: one adds a passkey
  at sign-in, the other changes the password. The passkey stays current
  whichever was newer; the password follows rule 3 (the newer version's
  stays, the other is in history). Both sides adding **different**
  passkeys to one login: the newer version's passkey stays, the other is in
  the item's history (the site has both; remove the lost one there).
- **Tested:** `crates/core/src/passkey.rs` (keys, CBOR with a separate
  reader, flags, the fields), `crates/core/tests/passkey.rs` (a file
  KeePassXC 2.7.12 wrote, `tests/passkeys/`, password `fixture`: Safe signs
  with its ES256 and EdDSA passkeys; OpenSSL reads Safe's keys and checks
  its signatures; merges; with `SAFE_KEEPASSXC_CLI` or `keepassxc-cli` on
  the PATH, KeePassXC shows a Safe passkey field by field and its rewrite
  keeps it), `crates/cli/tests/passkeys.rs` (the daemon over the socket).

## History

- **Oldest first**, as KeePass files list it. keepass-rs puts a tracked
  edit's old version *first* (F9), so `Safe::update` moves it to the end.
- **The cap** is `Meta/HistoryMaxItems` (10 when unset, no limit when
  negative). The newest versions stay.
- **A move is not an edit:** trash and restore change the place and
  `LocationChanged`, and add no history version.

## Deleting

- **Trash** moves an item to the recycle bin. **Purge** and **empty the
  bin** delete, and each deletion is written to `DeletedObjects` with its
  time (C3). Without that record, the next merge brings the item back from
  any copy that still has it.
- **A file two items share** stays when one of them goes (F11, fixed in the
  vendored keepass-rs).

## Merge

`safe_core::merge::merge(ours, theirs)` and `Safe::merge`. Both copies must
be writable (the guard), because Safe writes the result. A copy with a
different master key is not merge's business: the caller asks for the new
key and opens it first.

**Rules:**

1. **Matching.** Entries and groups are matched by UUID. Two unrelated files
   have different roots, and the other root is read as this one.
2. **New on either side** is kept, with its history as it is.
3. **Both changed an entry** (their content differs): the newer
   `LastModificationTime` wins. Equal times go to the larger SHA-256 of the
   content, so both machines pick the same version. The other version
   joins the entry's history.

   **3a. The passkey inside an entry.** Its fields (`KPEX_PASSKEY_*`,
   `KPXC_PASSKEY_USERNAME`) and the tag `Passkey` are looked at on their
   own. The base is the newest version both copies have (current or in
   history). When only the losing version changed the passkey since the
   base (added, replaced or removed it), its passkey goes onto the winner,
   and the winner's own version joins the history too, so no version is
   lost. When both changed it, the winner (the newer version) keeps its
   own. With no shared version (a copy that keeps no history), a passkey
   only the loser has is kept: losing one breaks a sign-in, keeping one
   breaks nothing. On a tie of times, the content without the passkey is
   compared first, so the result still wins when merged again (for an entry
   without a passkey this is rule 3's hash, unchanged). Other fields are not
   merged one by one: rule 3 decides them.
4. **History** is the union of both copies' histories plus the losing
   version. Identical versions are kept once. It is sorted oldest first by
   time (content hash on a tie). It grows to the cap and no further, but is
   never trimmed below what either copy already had.
5. **Content** means fields (with their protection), tags, creation, change
   and expiry times, custom data, the icon (a custom icon by its picture),
   colours, override URL, quality check, auto-type and attachments (name,
   protection, bytes). Last access and usage count are not content: they
   take the larger of the two.
6. **Place.** When the two copies put an entry or group in different
   folders, the newer `LocationChanged` wins. A tie goes to the larger
   folder UUID, and a copy's recycle bin counts as "the bin" (the largest),
   so a same-second trash wins over a move. A group move that would put a
   group inside itself is not made. The previous parent follows the winner
   where that folder exists, so restore still knows the way back.
7. **Deletions.** `DeletedObjects` is the union of both copies, keeping the
   later time per UUID. A deletion removes an object one copy still has
   when that object was last changed (or moved) at or before it. A later
   change keeps the object, and the record stays. A record with no time is
   honoured nowhere: keeping an item is the safe mistake. An object both
   copies still have is never deleted by a merge (the one exception is a
   second recycle bin, rule 10).
8. **Groups** take the newer change (name, notes, icon, settings). A group a
   deletion names goes only once nothing that survived the merge is left in
   it.
9. **Metadata.** Each part that has its own change time takes the newer
   one: name, description, default username, recycle bin, templates group.
   The settings (history cap, maintenance days, colour, master-key
   reminders, memory protection) go together, by `SettingsChanged`. Custom
   data is merged key by key; a removed key cannot be told from one never
   added, so keys only accumulate. The master-key change time takes the
   later of the two. The last-selected-group hints stay this copy's.
10. **Two recycle bins** (both machines trashed something before they
    synced) become the one the merged metadata names. The other bin's
    contents move into it, and the other bin's deletion is recorded.

**The result** keeps this copy's file settings (cipher, key derivation). It
is written and read back in memory once (`normalize`, a throwaway AES-KDF
key, never on disk). The read leaves no stale back-reference to a history
position, so the clean-up that follows is safe: the attachments nothing uses
any more (a version the cap let go) and the custom icons the merge made but
nothing uses are dropped.

**`Report`** gives counts only, never a title or a value: added, updated
(their version won), diverged (both changed), to_history, deleted, moved,
groups_added, groups_deleted.

**Not kept exactly:**

- A custom icon copied in from the other copy gets a new UUID (keepass-rs
  has no way to make one with a given id). It is matched by its picture, so
  the next merge finds it again and makes no second copy.
- The previous parent, when the folder it names is gone.

**Tested** in `crates/core/tests/merge.rs`:

- the spike's 14 cases, all passing (keepass-rs's own merge passed 10);
- the loser's file kept in history;
- two bins, a deleted group, icons by picture, the history cap;
- passkeys (3a), both merge directions and both clock orders: added here
  and password changed there; replaced here, password changed there;
  removed here, password changed there; removed here, replaced there; both
  added; a copy without history. Each case also checks the laws below;
- 300 seeded random pairs of copies, with passkeys added and removed among
  the edits (`SAFE_MERGE_SEEDS`, `SAFE_MERGE_SALT` for longer hunts: 3,000
  seeds with two salts passed on 2026-10-15). Each pair checks that merging both ways gives the same
  safe, that merging a copy with itself or merging an input again changes
  nothing, that nothing disappears without a deletion record, and that no
  version of a surviving item is lost.

Every merged result goes through a write and a read back. `tests/corpus.rs`
merges every writable corpus file with an edited copy of itself, both ways,
through the verified write.

## Gotchas (keep them true)

| | what | so |
|---|---|---|
| C1 | keepass-rs drops content it does not model (F1) | the write guard makes such a file read-only |
| C2 | keepass-rs's `_merge` loses data (M1, M2) | Safe merges itself; the `_merge` feature stays only for the spike's example |
| C3 | a plain `EntryMut::remove` records no deletion | delete through `track_changes().remove()` (purge, empty the bin); the merge's own removals are of objects a record already names |
| C4 | quick-xml's `overlapped-lists` decrypts every protected value to garbage (F2) | never enable it; CI checks the dependency tree |
| C5 | every write is KDBX 4.1 | tell the user before upgrading a 3.1 or 4.0 file |
| F6 | custom-data text that is valid base64 reads back as bytes | compare with `item::custom_text` |
| F7 | keepass-rs TOTP: 8 digits by default, padded secrets only | Safe computes codes (`otp`) |
| F8 | after a write the bookkeeping differs from memory | verify compares content (`digest`) |
| F9 | keepass-rs's `History::add_entry` puts a version first; files list history oldest first | `Safe::update` and the merge order history oldest first |
| F10 | keepass-rs removed an attachment from the database when the current version dropped it, though a history version still used it | fixed in the vendored keepass-rs (`vendor/keepass/PATCHED.md`) |
| F11 | after a file is read, keepass-rs's attachment back-references are empty, so deleting one item took a file another item shares | same fix; `tests/corpus.rs` guards it |
| F12 | keepass-rs's reader files a history version under the entry its own UUID names, not the entry it sits in | never put a version in another entry's history, not even in memory |
