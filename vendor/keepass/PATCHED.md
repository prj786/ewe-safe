# keepass-rs 0.15.2, patched for ewe-safe

The source of the `keepass` crate 0.15.2 (MIT, `LICENSE`), as published on
crates.io, with one change in `src/db/types/entry.rs`. Cargo uses it through
`[patch.crates-io]` in the workspace `Cargo.toml`. Every change is marked
`ewe-safe patch`. Remove this folder and the patch line once upstream has a
fix.

## The bug (docs/FORMAT.md, F10 and F11)

keepass-rs decides whether an attachment is still needed from a
back-reference set on the attachment (`Attachment::entries`). That set is
wrong in two common states:

- **After a file is opened it is empty for every attachment.** The parser
  rebuilds the custom-icon back-references but not the attachment ones.
- **A history-tracked edit never adds the copy it puts into history.**

So `EntryMut::remove_attachment_by_name`, `remove_attachment_by_id` (also
reached through `add_attachment` replacing a name) and `EntryMut::remove`
(also reached through deleting a group) delete an attachment from the
database while another entry, or a history version of the same entry, still
refers to it. KeePass and KeePassXC store identical files once, so after
opening a real file:

- deleting one entry can take a file from a *different* entry;
- replacing or removing an entry's file takes it from that entry's history.

The file is then written with a reference to a position that holds another
attachment or none, and the next read drops or swaps the file. That is data
loss, and Safe's merge (which puts the losing version into history) would
hit it on every merge where only one version has a given file.

## The change

`attachment_in_use(database, id)` scans every entry and every history
version for the id. The three removal paths drop an attachment from the
database only when nothing uses it; otherwise they just update the
back-reference set as before. When nothing maps the attachment any more it
is removed from the database directly, so no stale back-reference (a history
position that no longer exists) is ever followed.

Cost: one scan of the entries per removal, which is nothing next to a key
derivation.

## Upstream

Not filed yet (an outward action for the owner). Suggested text: the
title "Attachments still in use are removed: back-references are empty
after parse and miss history copies", the two bullet points above, and this
patch as the proposed fix.
