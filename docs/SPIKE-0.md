# Spike 0 — can keepass-rs be Safe's engine?

*2026-10-14 · PLAN.md phase 0 · keepass-rs 0.15.2 (crate `keepass`,
features `save_kdbx4`, `totp`, `_merge`) · this machine: Intel Core Ultra 7
258V, Arch, rustc 1.99.*

## Verdict: **GO, with five conditions**

Every one of the 30 real files in the corpus round-trips through keepass-rs
with nothing lost: KDBX 3.1, 4.0 and 4.1, written by KeePassXC and
KeePass 2.x, with three ciphers, three KDFs and key files. The losses that
remain (F1–F4) are all in content keepass-rs does not model. A guard can
detect them before a write (condition C1). keepass-rs's merge, however,
loses data in two cases, so Safe writes its own (C2).

| | result |
|---|---|
| Fidelity, real files | **30 / 30 nothing lost** |
| Fidelity, synthetic stress files | 7 / 7 behave as documented below: 4 lose unknown content, 2 refuse to open, 1 loses only a fallback icon |
| keepass-rs merge | **10 / 14 cases pass**; 2 of the 4 failures lose data |
| Safe's own open/edit/write (`crates/core/tests/corpus.rs`) | all 37 corpus files: the guard agrees with the gate; every writable file takes an edit and survives the verified write |
| Argon2id, 64 MiB, 2 lanes | ~22 ms per iteration; **1 s ≈ 44 iterations** |

The conditions, all of them phase-1 work:

- **C1 — the write guard.** Before Safe writes a file that it didn't create
  itself, it scans the decrypted XML (`Database::get_xml`). It checks the
  scan against an allowlist of the (parent, child) element pairs and the
  attributes that keepass-rs writes back, which this corpus proves. Anything
  else makes the safe **read-only**, with a plain reason. `get_xml` costs a
  second key derivation, so run it in parallel with the parse; wall time
  stays at one derivation.
- **C2 — Safe owns merge** (`safe_core::merge`) and builds it on keepass-rs's
  model. The 14 cases below become its test suite.
- **C3 — deletes go through the tracked path** (`EntryTrack::remove` or the
  recycle bin). A plain `EntryMut::remove` records no `DeletedObjects`, so
  any merge brings the entry back.
- **C4 — never enable quick-xml's `overlapped-lists`.** It corrupts every
  password (F2). CI checks the whole dependency tree.
- **C5 — upgrade notice.** keepass-rs writes KDBX 4.1 only. Before the first
  write to a 3.1 or 4.0 file, Safe says that the file will be upgraded.

## 1. Fidelity

**Method.** `tests/fidelity/roundtrip.rs` opens each file with keepass-rs,
changes one entry's title the way Safe will (`edit_tracking`, which adds
history), saves it, and reopens it. `tests/fidelity/compare.py` then reads
the before and after files with an **independent reader** (pykeepass 4.2.0)
and flattens both decrypted XML trees into `path = value` lines:

- repeated children are keyed by UUID, Key or position;
- attachments are compared by content hash;
- times are compared to the second, because KDBX 3 writes ISO text and
  KDBX 4 writes base64 seconds.

The only differences allowed are the intended edit (the title, its history
entry and its times) and `Meta/Generator`. The corpus is in
`tests/corpus/README.md`. `tests/fidelity/run.sh` is the gate, and CI runs
it.

**Corpus.** There are 30 real files collected from the test suites of
keepass-rs, KeePassXC, kdbxweb (KeeWeb) and pykeepass. By version: 12 are
KDBX 3.1, 15 are KDBX 4.0, 3 are KDBX 4.1. They were written by KeePassXC
(up to 2.7.12) and KeePass 2.x. They use AES-256, ChaCha20 and Twofish;
AES-KDF, Argon2d and Argon2id; password only, password plus key file
(XML v2 and legacy formats), and an empty password. Seven synthetic files
start from the KeePassXC 2.7.12 KDBX 4.1 file and add, with pykeepass, what
the real ones lack. Everything listed here survived:

- **Logins:** passkey fields (`KPEX_PASSKEY_*`, including a protected private
  key), `otp`, `KP2A_URL_1/2`, an empty custom field, passwords and notes
  with leading and trailing spaces, non-ASCII titles.
- **Attachments and icons:** an attachment shared by two entries, a
  protected attachment, custom icons on an entry and a group (with the 4.1
  name and time).
- **History and dates:** two history versions, expiry.
- **Custom data with times:** on entries, groups and meta.
- **Entry details:** colours, override URL, `QualityCheck=False`, an
  auto-type window association, `PreviousParentGroup`.
- **Groups:** group settings (auto-type and search off, default sequence,
  tags).
- **The database:** a recycle bin, `DeletedObjects`.

**Also checked (outer header):** the cipher, KDF parameters, compression and
KeePassXC's public custom data (`KPXC_PUBLIC_UUID`) are all kept.

**What happens to each version:**

- **4.1:** saved back as 4.1.
- **4.0:** saved as 4.1 with the same crypto, because keepass-rs refuses to
  write 4.0.
- **3.1:** upgraded to 4.1 with Argon2id at 64 MiB and a ChaCha20 inner
  stream, the way Safe would. The outer cipher is kept.

**Representation-only differences.** The comparator treats these as equal:

- an empty element written or left out;
- `Protected="False"` left out;
- tags rewritten from `a,b` to `a;b` (readers accept both);
- `IconID` 0 left out next to a custom icon;
- default `QualityCheck`, and `null` for the auto-type and search switches;
- KDBX 3's `HeaderHash` and binary pool, which move into the KDBX 4 inner
  header.

### Findings

| # | what | severity | handling |
|---|---|---|---|
| **F1** | **Unknown content is silently dropped on save.** An element keepass-rs doesn't model is dropped wherever it sits: in `Meta`, `Entry` (including history) or `Root`. So is an unknown attribute on a `Value`. This includes real elements keepass-rs lacks, such as KeePass's `Meta/MasterKeyChangeForceOnce`, which isn't in its `Meta` struct (not in this corpus). An unknown element inside a **Group** makes the file fail to open: `unknown variant`. | data loss on write | C1 makes such files read-only. File upstream: tolerate and keep unknown elements. |
| **F2** | **Non-contiguous `String` fields make the open fail** (`duplicate field String`). pykeepass writes entries this way when a field is added after creation. KeePass and KeePassXC accept it. **Do not "fix" this with quick-xml's `overlapped-lists`.** I tried it: every protected value (passwords, the passkey key, the TOTP secret) decrypts to garbage and is saved that way. keepass-rs decrypts the inner stream in parse order, and the feature changes that order. | refuses to open (fine); the "fix" is catastrophic | C4 + the CI `cargo tree` check + the `synth_unknown_interleaved` canary in the gate. File upstream: unprotect in document order before deserialising. |
| **F3** | **The fallback `IconID` is dropped when a custom icon is set.** KeePass writes both; the number is what apps without custom icons show. In this corpus it is always 0, which is also the default. Only the synthetic `IconID 12` shows a loss. | cosmetic | Owner decision (below). File upstream. |
| **F4** | A group with **no `IsExpanded`** is written with `IsExpanded=false`. KeePass's default is true, so the group shows collapsed. | cosmetic | Accept; file upstream. |
| **F6** | **Custom-data values that are valid base64 are read back as bytes.** `"note"` comes back as `9e 8b 5e`, and `"true"` as bytes too. The text on disk is unchanged, but the in-memory value changes type between a write and the reread. | none on disk; trips naive checks | `safe_core::item::custom_value` / `custom_text` apply keepass-rs's exact rule (the same `base64` crate). The Note marker `ewe.kind = note` is compared as text. |
| **F7** | **keepass-rs's TOTP** defaults to **8 digits** when the URI has no `digits` (authenticator apps and the Key URI format use 6), and it accepts only *padded* base32 secrets, so a common 26-character unpadded secret fails. | wrong codes | Safe computes codes itself (`safe_core::otp`, RFC 6238 test vectors pass). keepass-rs's `totp` feature is off. File upstream. |
| **F8** | **A history-tracked edit of an entry with an attachment** copies the entry into history but doesn't add that copy to the attachment's list of users; rereading the file does. So the reread `Database` differs from memory by bookkeeping only, and `PartialEq` fails. | none on disk | Verify compares *content* (`safe_core::digest`: every field, time, tag, attachment and icon as a keyed hash, so no plaintext is kept), then adopts the reread copy. File upstream. |
| **F5** | **Every save writes KDBX 4.1.** Readers need 4.1 support: KeePassXC 2.7+ and KeePass 2.48+. KeePassDX, Strongbox and KeePassium: **not verified here**. | compatibility | C5, and phase 2's phone test. |

### Not verified

- **Files written by KeePassDX, Strongbox or KeePassium.** None of their
  repositories publishes test databases. Phase 2's gate covers them with a
  real phone.
- **KeePassXC opening keepass-rs's output.** `keepassxc-cli` isn't installed
  on this machine and the spike installed no system packages, so pykeepass
  was the independent reader. keepass-rs's own CI has KeePassXC writer-compat
  regression tests. Add `keepassxc-cli` (apt on the CI runner) as a second
  reader in phase 1.

## 2. Merge (`_merge`)

**API:** `Database::merge(&mut self, other: &Database) -> Result<MergeLog,
MergeError>`. It's a two-way merge, matched by UUID, where the newest wins.
`MergeLog` has `events` and `warnings`. It is gated behind the
underscore-prefixed `_merge` feature, which marks it as unstable. Upstream
three-way merge is in progress (keepass-rs PR #342). The case table is
`tests/fidelity/merge_spike.rs`; it uses fixed times, so every run gives the
same result. "Both directions" means merge(mine, theirs) and
merge(theirs, mine) agree.

| PLAN §7 rule | case | result |
|---|---|---|
| 1 | an entry new on either side is kept | PASS |
| 1 | a new entry's attachment comes across | PASS |
| 2 | both edited, theirs newer: theirs wins, mine kept in history, both directions | PASS |
| 2 | **both edited, mine newer: mine wins, theirs kept in history** | **FAIL (M1)**: theirs is thrown away, not added to history |
| 2 | **attachment added to an existing entry there (newer)** | **FAIL (M2)**: not merged (`TODO: attachments` in merge.rs) |
| 2 | **different edits in the same second** | **FAIL (M4)**: `MergeError` ("same modification time but have diverged"). `Times::now()` is whole seconds. |
| 3 | deleted there at 1, edited here at 2: the edit wins, both directions | PASS |
| 3 | edited here at 1, deleted there at 2: the deletion wins, both directions, and is recorded | PASS |
| 3 | merge deletes only what `DeletedObjects` names | PASS (C3) |
| 4 | group renamed on both sides: the newer wins (either side newer) | PASS ×2 |
| 4 | entry moved to another group there (newer): followed | PASS |
| 4 | **metadata (database name) changed on both sides: the newer wins** | **FAIL (M3)**: `merge` doesn't touch `Meta` |
| — | merging an identical copy changes nothing | PASS |

M1 and M2 **lose data**: two machines merge, and one machine's edit or file
is gone everywhere. M3 and M4 are fixable in a wrapper. Verdict: don't use
`_merge` as it is. **Safe owns merge (C2).** keepass-rs's code is the
reference, and M1–M4 are filed upstream.

*Built (phase 1): `safe_core::merge` passes all 14 cases, plus the
properties in `crates/core/tests/merge.rs`. Building it turned up F9–F12
(history order, two attachment-removal bugs, how history is read). The
rules as built, and the keepass-rs patch they needed, are in
[FORMAT.md](FORMAT.md).*

## 3. Argon2id timing (`tests/fidelity/kdf_timing.rs`)

The test safe has 200 logins and is about 12 KB on disk. Memory is 64 MiB
with 2 lanes, in a release build with the default target (no
`target-cpu=native`, since packages must be portable). Two runs:

| iterations | save ms | open ms |
|---|---|---|
| 1 | 27 | 27–30 |
| 8 | 176–199 | 184–187 |
| 16 | 353–360 | 356–357 |
| 24 | 536–537 | 536–538 |
| 32 | 731–749 | 714–716 |
| 40 | 903–970 | 915–938 |
| 48 | 1064–1088 | 1050–1076 |

**About 22 ms per iteration; 1 s ≈ 44 iterations.** The key derivation is
almost all of open and save; the entries cost nothing measurable. Safe
saves with "verify by reopen" and runs C1's scan in parallel, so:

- an unlock costs one derivation of wall time;
- a save costs two derivations, one to write and one to verify.

**Suggestion:** calibrate a new safe to ~1 s on the machine that creates it,
**capped at 40 iterations** until phase 2 measures a real phone in KeePassDX.
The plan wants a phone unlock to take "a few seconds".

## 4. For the owner

1. **F3:** accept losing the *fallback* icon number of entries that have a
   custom icon (recommended: every current KeePass app shows the custom
   icon), or make such files read-only until upstream fixes it?
2. **F5/C5:** OK that Safe upgrades a KDBX 3.1 or 4.0 file to 4.1 on its
   first write, after telling the user?
3. Upstream issues for F1–F4, F6–F8 and M1–M4 are written up here but
   **not filed**. Filing them is an outward action for the owner.

## Rerun

    tests/corpus/fetch.sh                                   # pinned downloads + synthetic files
    tests/fidelity/run.sh                                   # the gate: exit 0 = nothing new
    cargo run --release -p safe-core --example merge-spike  # merge case table
    cargo run --release -p safe-core --example kdf-timing   # Argon2id timing

Both scripts need `python3` with `pykeepass`. Full per-file reports land in
`tests/fidelity/out/*.json`.
