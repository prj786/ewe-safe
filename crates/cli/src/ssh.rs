//! `ewe-safe ssh <sub>` (docs/PROTOCOL.md, "SSH keys"; docs/GATE.md): SSH
//! keys in Safe, the agent and the gate on and off, moving SSH to Safe,
//! connecting to a service, hosts, signing Git commits. One JSON object
//! each, exit 0. A key's passphrase comes from the terminal (no echo) or a
//! stdin line, never from the command line.

use safe_client as client;
use safe_client::{FAST, SLOW};
use serde_json::{Map, Value, json};

use super::{bad, secret};

const SUBS: &[&str] = &[
    "add",
    "new",
    "list",
    "adopt",
    "enable",
    "disable",
    "status",
    // the gate (docs/GATE.md S23–S25)
    "takeover",
    "services",
    "connect",
    "test",
    "hosts",
    "host",
    "sign-commits",
];
const USAGE: &str = "Usage: ewe-safe ssh <add|new|list|adopt|enable|disable|status|takeover|services|connect|test|hosts|host set|host remove|sign-commits> (docs/PROTOCOL.md)";
const VALUES: &[&str] = &[
    "title", "folder", "type", "bits", "confirm", "key", "host", "user", "port", "alias", "org",
    "email",
];
const FLAGS: &[&str] = &[
    "dry-run",
    "passphrase-stdin",
    "replace",
    "sign",
    "no-open",
    "no-key",
    "off",
];
/// How many words each subcommand takes, and the socket arg they become.
fn positional(sub: &str) -> &'static [&'static str] {
    match sub {
        "add" => &["file"],
        "connect" => &["service"],
        "test" => &["target"],
        "host" => &["action", "alias"],
        "sign-commits" => &["item_id"],
        _ => &[],
    }
}

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
            USAGE.to_string()
        } else {
            format!("ssh has no {sub:?}.")
        });
        v["verbs"] = json!(
            SUBS.iter()
                .flat_map(|s| match *s {
                    "host" => vec!["ssh host set".to_string(), "ssh host remove".to_string()],
                    s => vec![format!("ssh {s}")],
                })
                .collect::<Vec<_>>()
        );
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
        let v = if name == "bits" || name == "port" {
            match value.parse::<u64>() {
                Ok(n) => json!(n),
                Err(_) => return Err(bad(format!("--{name} needs a whole number"))),
            }
        } else {
            json!(value)
        };
        p.args.insert(name, v);
    }
    let names = positional(&p.sub);
    if p.positional.len() != names.len() {
        return Err(bad(match (p.sub.as_str(), p.positional.first()) {
            ("add", None) => "ssh add needs the private key's file".to_string(),
            ("connect", None) => "ssh connect needs a service: ewe-safe ssh services lists them".to_string(),
            ("test", None) => "ssh test needs a host, a service or user@host".to_string(),
            ("host", _) => "Use: ewe-safe ssh host set ALIAS [--host H] [--user U] [--port N] [--key ID | --no-key], or ssh host remove ALIAS".to_string(),
            ("sign-commits", None) if p.args.contains_key("off") => return Ok(p),
            ("sign-commits", None) => "ssh sign-commits needs the key's item id (or --off)".to_string(),
            (sub, Some(x)) if names.is_empty() => format!("ssh {sub} takes no {x:?}"),
            (sub, _) => format!("ssh {sub} takes {} word(s)", names.len()),
        }));
    }
    if p.sub == "host" && !matches!(p.positional[0].as_str(), "set" | "remove") {
        return Err(bad("ssh host is ssh host set or ssh host remove"));
    }
    if p.sub != "add" {
        for (name, value) in names.iter().zip(&p.positional) {
            if *name != "action" {
                p.args.insert((*name).to_string(), json!(value));
            }
        }
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
            caller_sock(&mut p.args);
            client::call("ssh-status", Value::Object(p.args), FAST)
        }
        "takeover" => takeover(p.args),
        "connect" => {
            // the page and the clipboard are the session's
            if let Some(d) = std::env::var_os("WAYLAND_DISPLAY") {
                p.args
                    .insert("wayland_display".into(), json!(d.to_string_lossy()));
            }
            client::call(
                "ssh-connect",
                Value::Object(p.args),
                client::wait_for("ssh-connect"),
            )
        }
        "host" => {
            let verb = format!("ssh-host-{}", p.positional[0]);
            let wait = client::wait_for(&verb);
            client::call(&verb, Value::Object(p.args), wait)
        }
        "sign-commits" => client::call(
            "ssh-sign",
            Value::Object(p.args),
            client::wait_for("ssh-sign"),
        ),
        sub => {
            let verb = format!("ssh-{sub}");
            let wait = client::wait_for(&verb);
            client::call(&verb, Value::Object(p.args), wait)
        }
    }
}

/// The caller's `SSH_AUTH_SOCK`: another agent the gate looks at.
fn caller_sock(args: &mut Map<String, Value>) {
    if let Some(sock) = std::env::var_os("SSH_AUTH_SOCK") {
        args.insert("ssh_auth_sock".into(), json!(sock.to_string_lossy()));
    }
}

/// `ssh takeover`: on a terminal, a dry run first; each key file with a
/// passphrase asks for it (empty: leave that file out), then the move.
fn takeover(mut args: Map<String, Value>) -> Value {
    use std::io::IsTerminal;
    caller_sock(&mut args);
    let wait = client::wait_for("ssh-takeover");
    let dry = args.get("dry_run") == Some(&json!(true));
    if dry || !std::io::stdin().is_terminal() {
        return client::call("ssh-takeover", Value::Object(args), wait);
    }
    let mut first = args.clone();
    first.insert("dry_run".into(), json!(true));
    let seen = client::call("ssh-takeover", Value::Object(first), wait);
    if seen["ok"] != true {
        return seen;
    }
    let mut passes = Map::new();
    for f in seen["needs_passphrase"].as_array().into_iter().flatten() {
        let Some(f) = f.as_str() else { continue };
        match secret(&format!("Passphrase for {f} (empty: leave it out): ")) {
            Ok(p) if !p.is_empty() => {
                passes.insert(f.to_string(), json!(p.as_str()));
            }
            Ok(_) => {}
            Err(v) => return v,
        }
    }
    if !passes.is_empty() {
        args.insert("passphrases".into(), Value::Object(passes));
    }
    client::call("ssh-takeover", Value::Object(args), wait)
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
        let x = p(&[
            "connect",
            "github",
            "--alias",
            "github-work",
            "--port=2222",
            "--sign",
            "--no-open",
        ])
        .unwrap();
        assert_eq!(x.args["service"], "github");
        assert_eq!(x.args["alias"], "github-work");
        assert_eq!(x.args["port"], 2222);
        assert!(x.args["sign"] == true && x.args["no_open"] == true);
        let x = p(&["test", "git@github.com:22", "--key", "4f9c"]).unwrap();
        assert_eq!(
            (x.args["target"].clone(), x.args["key"].clone()),
            (json!("git@github.com:22"), json!("4f9c"))
        );
        let x = p(&["host", "set", "box", "--host", "10.0.0.2", "--no-key"]).unwrap();
        assert_eq!(x.args["alias"], "box");
        assert!(!x.args.contains_key("action") && x.args["no_key"] == true);
        let x = p(&["host", "remove", "box"]).unwrap();
        assert_eq!(x.positional[0], "remove");
        let x = p(&["sign-commits", "4f9c", "--email", "sam@example.com"]).unwrap();
        assert_eq!(x.args["item_id"], "4f9c");
        let x = p(&["sign-commits", "--off"]).unwrap();
        assert_eq!(x.args["off"], true);
        let x = p(&["takeover", "--dry-run"]).unwrap();
        assert_eq!(x.args["dry_run"], true);
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
            &["connect"],
            &["test"],
            &["host", "set"],
            &["host", "rename", "x"],
            &["sign-commits"],
            &["connect", "github", "--port", "many"],
            &["hosts", "extra"],
        ] {
            let e = p(argv).err().expect("an error");
            assert_eq!(e["error"], "bad-request", "{argv:?}");
        }
    }
}
