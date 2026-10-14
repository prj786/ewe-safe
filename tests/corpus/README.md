# Fidelity corpus

KDBX files that other KeePass apps wrote, used by the phase-0 gate
(`tests/fidelity/run.sh`, results in `docs/SPIKE-0.md`). They are **not in
this repo**: `fetch.sh` downloads them at pinned commits into `files/`
(gitignored), because they are other projects' test data and some of it is
GPL. The passwords are the ones those projects publish in their own tests.

    tests/corpus/fetch.sh      # needs git + python3 with pykeepass
    tests/fidelity/run.sh      # needs cargo + python3 with pykeepass

## Sources

| name | repository | commit | licence |
|---|---|---|---|
| keepass-rs | https://github.com/sseemayer/keepass-rs | `28c078cfc824` | MIT |
| keepassxc | https://github.com/keepassxreboot/keepassxc | `52e2743b3a77` | GPL-2.0/3.0 |
| kdbxweb | https://github.com/keeweb/kdbxweb | `7601e45d2a43` | MIT |
| pykeepass | https://github.com/libkeepass/pykeepass | `aec256659e7b` | GPL-3.0 |
| synthetic | built here by `tests/fidelity/make_synthetic.py` from `test_db_kdbx41_features.kdbx` | — | — |

## Files

"Writer" is the file's own `Meta/Generator`. Older KeePassXC builds and
KeePass 2.x both write `KeePass`.

| source | file | writer | KDBX | credentials | what it covers |
|---|---|---|---|---|---|
| keepass-rs | `test_db_kdbx41_features.kdbx` | KeePassXC | 4.1 | `demopass` | KeePassXC 2.7.12, KDBX 4.1: tags, PreviousParentGroup, QualityCheck |
| keepass-rs | `test_db_kdbx41_with_password_aes.kdbx` | KeePass | 4.1 | `demopass` |  |
| keepass-rs | `test_db_kdbx4_with_password_argon2id.kdbx` | KeePassXC | 4.0 | `demopass` |  |
| keepass-rs | `test_db_kdbx4_with_password_argon2id_chacha20.kdbx` | KeePassXC | 4.0 | `demopass` |  |
| keepass-rs | `test_db_kdbx4_with_password_argon2_twofish.kdbx` | KeePassXC | 4.0 | `demopass` |  |
| keepass-rs | `test_db_kdbx4_with_password_deleted_entry.kdbx` | KeePassXC | 4.0 | `demopass` | DeletedObjects |
| keepass-rs | `test_db_kdbx4_with_totp_entry.kdbx` | KeePassXC | 4.0 | `test` | otp field |
| keepass-rs | `test_db_kdbx4_with_keyfile_v2.kdbx` | KeePassXC | 4.0 | `demopass` + `test_db_kdbx4_with_keyfile_v2.keyx` |  |
| keepass-rs | `test_db_kdbx3_with_attachments.kdbx` | t | 3.1 | `demopass` |  |
| keepass-rs | `test_db_with_password.kdbx` | KeePass | 3.1 | `demopass` |  |
| keepass-rs | `test_db_kdb3_with_file_larger_1mb.kdbx` | KeePass | 3.1 | `demopass` | 1 MB attachment |
| keepassxc | `Format400.kdbx` | KeePass | 4.0 | `t` |  |
| keepassxc | `NewDatabaseBrowser.kdbx` | KeePass | 4.0 | `a` | browser-integration custom data |
| keepassxc | `KeyFileProtected.kdbx` | KeePassXC | 4.0 | `a` + `KeyFileProtected.key` |  |
| keepassxc | `NewDatabase.kdbx` | KeePass | 3.1 | `a` |  |
| keepassxc | `NewDatabaseMulti.kdbx` | KeePass | 3.1 | `a` |  |
| keepassxc | `RecycleBinWithData.kdbx` | KeePassXC | 3.1 | `123` | recycle bin |
| keepassxc | `ProtectedStrings.kdbx` | KeePass | 3.1 | `masterpw` |  |
| keepassxc | `NonAscii.kdbx` | KeePass | 3.1 | `Δöض` |  |
| keepassxc | `Compressed.kdbx` | KeePass | 3.1 | (empty) |  |
| keepassxc | `SyncDatabase.kdbx` | KeePass | 3.1 | `a` |  |
| kdbxweb | `KDBX4.1.kdbx` | KeePass | 4.1 | `test` | KeePass 2.x, KDBX 4.1 |
| kdbxweb | `Argon2.kdbx` | KeePass | 4.0 | `demo` + `demo.key` |  |
| kdbxweb | `Argon2id.kdbx` | KeePass | 4.0 | `demo` + `demo.key` |  |
| kdbxweb | `Argon2ChaCha.kdbx` | KeePass | 4.0 | `demo` + `demo.key` |  |
| kdbxweb | `demo.kdbx` | KeePass | 3.1 | `demo` + `demo.key` |  |
| kdbxweb | `cyrillic.kdbx` | KeePass | 3.1 | `пароль` |  |
| pykeepass | `test4.kdbx` | KeePass | 4.0 | `password` + `test4.key` | KeePass 2.x, rich: attachments, history, icons |
| pykeepass | `test4_twofish_uncompressed.kdbx` | KeePassXC | 4.0 | `password` |  |
| pykeepass | `extra_content.kdbx` | KeePassXC | 4.0 | `password` |  |
| synthetic | `synth_rich.kdbx` | KeePassXC | 4.1 | `demopass` | test_db_kdbx41_features + passkeys, otp, KP2A URLs, shared attachments, history, custom icon (+ fallback IconID), custom data, colours, auto-type, expiry, recycle bin, deleted objects |
| synthetic | `synth_unknown_meta.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich + one unknown element in Meta |
| synthetic | `synth_unknown_group.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich + one unknown element in Group |
| synthetic | `synth_unknown_entry.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich + one unknown element in Entry |
| synthetic | `synth_unknown_root.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich + one unknown element in Root |
| synthetic | `synth_unknown_attr.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich + one unknown attribute on a Value |
| synthetic | `synth_unknown_interleaved.kdbx` | KeePassXC | 4.1 | `demopass` | synth_rich in pykeepass's own order: an entry's String fields not contiguous |

Not covered: files written by **KeePassDX, Strongbox or KeePassium**. Their
repositories publish no test databases. Phase 2's gate (a phone edit merges
back) covers them with a real phone.
