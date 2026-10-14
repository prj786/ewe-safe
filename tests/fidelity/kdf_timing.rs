//! Argon2id timing (PLAN.md §5): how many iterations at 64 MiB and two lanes
//! take about a second on this machine, and what open + save of a
//! 200-login safe cost at that setting.
//!
//!   cargo run --release -p safe-core --example kdf-timing

use std::time::Instant;

use keepass::config::KdfConfig;
use keepass::db::fields;
use keepass::{Database, DatabaseKey};

fn safe_with(iterations: u64) -> Database {
    let mut db = Database::new();
    db.config.kdf_config = KdfConfig::Argon2id {
        iterations,
        memory: 64 * 1024 * 1024,
        parallelism: 2,
        version: argon2::Version::Version13,
    };
    for i in 0..200 {
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, format!("login {i}"));
            e.set_unprotected(fields::USERNAME, "sam");
            e.set_protected(fields::PASSWORD, "correct horse battery staple");
            e.set_unprotected(fields::URL, format!("https://site{i}.example"));
        });
    }
    db
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = || DatabaseKey::new().with_password("timing");
    println!("iterations  save_ms  open_ms  size_kb");
    for iterations in [1u64, 2, 4, 8, 16, 24, 32, 40, 48] {
        let db = safe_with(iterations);
        let mut buf = Vec::new();
        let s = Instant::now();
        db.save(&mut buf, key())?;
        let save_ms = s.elapsed().as_millis();
        let o = Instant::now();
        Database::parse(&buf, key())?;
        let open_ms = o.elapsed().as_millis();
        println!(
            "{iterations:>10}  {save_ms:>7}  {open_ms:>7}  {:>7}",
            buf.len() / 1024
        );
    }
    Ok(())
}
