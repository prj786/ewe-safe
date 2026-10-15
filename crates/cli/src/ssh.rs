//! `ewe-safe ssh <add|new|list|adopt|enable|disable|status>`
//! (docs/PROTOCOL.md, "SSH keys"): SSH keys in Safe, and the agent on and
//! off. One JSON object each, exit 0. A key's passphrase comes from the
//! terminal (no echo) or a stdin line, never from the command line.

use safe_client as client;
use safe_client::{FAST, SLOW};
use serde_json::{Map, Value, json};

use super::{bad, secret};

const SUBS: &[&str] = &["add", "new", "list", "adopt", "enable", "disable", "status"];
const VALUES: &[&str] = &["title", "folder", "type", "bits", "confirm"];
const FLAGS: &[&str] = &["dry-run", "passphrase-stdin"];

struct Parsed {
    sub: String,
    args: Map<String, Value>,
    positional: Vec<String>,
    passphrase_stdin: bool,
}

fn parse(argv: &[String]) -> Result<Parsed, Value> {
    let sub = argv.first().cloned().unwrap_or_default();
    if !SUBS.contains(&sub.as_str()) {
        let mut v = bad(if sub.is_empty() {
            "Usage: ewe-safe ssh <add|new|list|adopt|enable|disable|status> (docs/PROTOCOL.md)"
                .to_string()
        } else {
            format!("ssh has no {sub:?}.")
        });
        v["verbs"] = json!(SUBS.iter().map(|s| format!("ssh {s}")).collect::<Vec<_>>());
        return Err(v);
    }
    let mut p = Parsed {
        sub,
        args: Map::new(),
        positional: Vec::new(),
        passphrase_stdin: false,
    };
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        i += 1;
        let Some(opt) = a.strip_prefix("--") else {
            p.positional.push(a.clone());
            continue;
        };
        let (name, inline) = match opt.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (opt.to_string(), None),
        };
        if FLAGS.contains(&name.as_str()) {
            if name == "passphrase-stdin" {
                p.passphrase_stdin = true;
            } else {
                p.args.insert(name.replace('-', "_"), json!(true));
            }
            continue;
        }
        if !VALUES.contains(&name.as_str()) {
            return Err(bad(format!("ssh {} has no option --{name}", p.sub)));
        }
        let value = match inline {
            Some(v) => v,
            None if i < argv.len() => {
                i += 1;
                argv[i - 1].clone()
            }
            None => return Err(bad(format!("--{name} needs a value"))),
        };
        let v = if name == "bits" {
            match value.parse::<u64>() {
                Ok(n) => json!(n),
                Err(_) => return Err(bad("--bits needs a whole number")),
            }
        } else {
            json!(value)
        };
        p.args.insert(name, v);
    }
    let wanted = usize::from(p.sub == "add");
    if p.positional.len() != wanted {
        return Err(bad(match (p.sub.as_str(), p.positional.first()) {
            ("add", None) => "ssh add needs the private key's file".to_string(),
            (sub, Some(x)) if wanted == 0 => format!("ssh {sub} takes no {x:?}"),
            (sub, _) => format!("ssh {sub} takes one file"),
        }));
    }
    Ok(p)
}

/// A private key file's text: refused unread when it is bigger than a key.
fn read_key(file: &str) -> Result<zeroize::Zeroizing<String>, Value> {
    use std::io::Read;
    let cant = |e: std::io::Error| bad(format!("Safe can't read {file}: {e}"));
    let f = std::fs::File::open(file).map_err(cant)?;
    let size = f.metadata().map_err(cant)?.len();
    if size > safe_core::ssh::MAX_KEY_FILE {
        return Err(bad(format!("{file} is too big to be a private key.")));
    }
    // the exact size up front: a buffer that grew would leave copies behind
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(size as usize));
    f.take(safe_core::ssh::MAX_KEY_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(cant)?;
    match std::str::from_utf8(&bytes) {
        Ok(t) => Ok(zeroize::Zeroizing::new(t.to_string())),
        Err(_) => Err(bad(format!(
            "{file} isn't a private key file: it isn't text."
        ))),
    }
}

pub fn run(argv: &[String]) -> Value {
    let mut p = match parse(argv) {
        Ok(p) => p,
        Err(v) => return v,
    };
    match p.sub.as_str() {
        "add" => {
            // the key's text goes to the daemon as a secret (`private_key`),
            // read here: no file bigger than a key is read at all
            let file = p.positional[0].clone();
            let text = match read_key(&file) {
                Ok(t) => t,
                Err(v) => return v,
            };
            // a key with a passphrase needs it: asked here, sent as a secret
            let locked = safe_core::ssh::is_encrypted(text.as_bytes());
            if locked || p.passphrase_stdin {
                match secret(&format!("Passphrase for {file}: ")) {
                    Ok(pass) => {
                        p.args.insert("passphrase".into(), json!(pass.as_str()));
                    }
                    Err(v) => return v,
                }
            }
            p.args.insert("private_key".into(), json!(text.as_str()));
            drop(text);
            let name = std::path::Path::new(&file)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned());
            p.args.insert("file_name".into(), json!(name));
            client::call("ssh-add", Value::Object(p.args), SLOW)
        }
        "status" => {
            if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
                p.args
                    .insert("ssh_auth_sock".into(), json!(sock.to_string_lossy()));
            }
            client::call("ssh-status", Value::Object(p.args), FAST)
        }
        sub => {
            let verb = format!("ssh-{sub}");
            let wait = client::wait_for(&verb);
            client::call(&verb, Value::Object(p.args), wait)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, Value> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn subcommands_take_their_options() {
        let x = p(&[
            "new",
            "--title",
            "GitHub key",
            "--type=rsa",
            "--bits",
            "4096",
        ])
        .unwrap();
        assert_eq!(x.args["title"], "GitHub key");
        assert_eq!(x.args["type"], "rsa");
        assert_eq!(x.args["bits"], 4096);
        let x = p(&[
            "add",
            "id_ed25519",
            "--passphrase-stdin",
            "--folder",
            "Keys",
        ])
        .unwrap();
        assert_eq!(x.positional, ["id_ed25519"]);
        assert!(x.passphrase_stdin && !x.args.contains_key("passphrase_stdin"));
        let x = p(&["adopt", "--dry-run"]).unwrap();
        assert_eq!(x.args["dry_run"], true);
        let x = p(&["enable", "--confirm", "every-time"]).unwrap();
        assert_eq!(x.args["confirm"], "every-time");
    }

    #[test]
    fn mistakes_are_bad_requests() {
        for argv in [
            &[][..],
            &["sign"],
            &["add"],
            &["add", "a", "b"],
            &["list", "extra"],
            &["new", "--bits", "many"],
            &["new", "--colour", "x"],
            &["new", "--title"],
        ] {
            let e = p(argv).err().expect("an error");
            assert_eq!(e["error"], "bad-request", "{argv:?}");
        }
    }
}
