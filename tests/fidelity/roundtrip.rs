//! Fidelity round trip (PLAN.md phase 0): open a KDBX file written by another
//! app, edit one entry's title the way Safe will (history-tracked), save as
//! KDBX 4, and say what was done as one JSON line. `compare.py` then checks
//! the result with an independent reader.
//!
//!   cargo run -p safe-core --example fidelity-roundtrip -- \
//!       --in A.kdbx --out B.kdbx [--password P] [--keyfile K] [--no-edit]

use std::fs::File;

use keepass::config::{DatabaseVersion, InnerCipherConfig, KdfConfig};
use keepass::db::fields;
use keepass::{Database, DatabaseKey};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn key(args: &[String]) -> Result<DatabaseKey, Box<dyn std::error::Error>> {
    let mut key = DatabaseKey::new();
    if let Some(pw) = arg(args, "--password") {
        key = key.with_password(&pw);
    }
    if let Some(kf) = arg(args, "--keyfile") {
        key = key.with_keyfile(&mut File::open(kf)?)?;
    }
    Ok(key)
}

fn version(v: &DatabaseVersion) -> String {
    match v {
        DatabaseVersion::KDB(m) => format!("kdb-{m}"),
        DatabaseVersion::KDB2(m) => format!("kdbx2.{m}"),
        DatabaseVersion::KDB3(m) => format!("kdbx3.{m}"),
        DatabaseVersion::KDB4(m) => format!("kdbx4.{m}"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let input = arg(&args, "--in").ok_or("--in is required")?;
    let output = arg(&args, "--out").ok_or("--out is required")?;

    let mut db = Database::open(&mut File::open(&input)?, key(&args)?)?;
    let in_version = version(&db.config.version);

    let in_config = format!("{:?}", db.config);
    // keepass-rs writes KDBX 4.1 only: a 4.0 file is saved as 4.1 (same
    // crypto), and a KDBX 3 file is upgraded the way Safe would (Argon2id,
    // ChaCha20 inner stream), keeping the outer cipher.
    if let DatabaseVersion::KDB4(0) = db.config.version {
        db.config.version = DatabaseVersion::KDB4(1);
    }
    if let DatabaseVersion::KDB3(_) = db.config.version {
        db.config.version = DatabaseVersion::KDB4(1);
        db.config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        db.config.kdf_config = KdfConfig::Argon2id {
            iterations: 2,
            memory: 64 * 1024 * 1024,
            parallelism: 2,
            version: argon2::Version::Version13,
        };
    }

    let mut edited = serde_json::Value::Null;
    if !args.iter().any(|a| a == "--no-edit") {
        let target = db
            .iter_all_entries()
            .map(|e| e.id())
            .min_by_key(|id| id.uuid());
        if let Some(id) = target {
            let mut entry = db.entry_mut(id).ok_or("entry vanished")?;
            let old = entry.get(fields::TITLE).unwrap_or("").to_string();
            let new = format!("{old} (ewe)");
            entry.edit_tracking(|e| e.set_unprotected(fields::TITLE, new.clone()));
            edited = serde_json::json!({"uuid": id.uuid().to_string(), "old_title": old, "new_title": new});
        }
    }

    db.save(&mut File::create(&output)?, key(&args)?)?;
    let back = Database::open(&mut File::open(&output)?, key(&args)?)?;

    println!(
        "{}",
        serde_json::json!({
            "ok": true,
            "in": input,
            "in_version": in_version,
            "out_version": version(&back.config.version),
            "entries": back.num_entries(),
            "in_config": in_config,
            "out_config": format!("{:?}", back.config),
            "edited": edited,
        })
    );
    Ok(())
}
