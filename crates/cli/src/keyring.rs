//! `ewe-safe keyring <status|repair|list|import|adopt|release|rm|unlock>`
//! (docs/PROTOCOL.md, "The keyring"; docs/KEYRING.md). One JSON object
//! each, exit 0. The login password comes from the terminal (no echo) or a
//! stdin line, never from the command line; `adopt` checks it with
//! `unix_chkpwd` before it is sent (the daemon can't).

use safe_client as client;
use serde_json::{Map, Value, json};

use super::{bad, secret};

const SUBS: &[&str] = &[
    "status", "repair", "list", "import", "adopt", "release", "rm", "unlock",
];

struct Parsed {
    sub: String,
    args: Map<String, Value>,
}

fn parse(argv: &[String]) -> Result<Parsed, Value> {
    let sub = argv.first().cloned().unwrap_or_default();
    if !SUBS.contains(&sub.as_str()) {
        let mut v = bad(if sub.is_empty() {
            "Usage: ewe-safe keyring <status|repair|list|import|adopt|release|rm|unlock> (docs/PROTOCOL.md)"
                .to_string()
        } else {
            format!("keyring has no {sub:?}.")
        });
        v["verbs"] = json!(
            SUBS.iter()
                .map(|s| format!("keyring {s}"))
                .collect::<Vec<_>>()
        );
        return Err(v);
    }
    let mut args = Map::new();
    let mut positional = Vec::new();
    for a in &argv[1..] {
        match a.strip_prefix("--") {
            Some("dry-run") if matches!(sub.as_str(), "repair" | "import") => {
                args.insert("dry_run".into(), json!(true));
            }
            Some(opt) => return Err(bad(format!("keyring {sub} has no option --{opt}"))),
            None => positional.push(a.clone()),
        }
    }
    match (sub.as_str(), positional.as_slice()) {
        ("rm", [id]) => {
            args.insert("id".into(), json!(id));
        }
        ("rm", _) => return Err(bad("keyring rm needs one app secret's id")),
        (_, [x, ..]) => return Err(bad(format!("keyring {sub} takes no {x:?}"))),
        _ => {}
    }
    Ok(Parsed { sub, args })
}

pub fn run(argv: &[String]) -> Value {
    let mut p = match parse(argv) {
        Ok(p) => p,
        Err(v) => return v,
    };
    if matches!(p.sub.as_str(), "adopt" | "unlock") {
        let pw = match secret("Login password: ") {
            Ok(pw) => pw,
            Err(v) => return v,
        };
        if p.sub == "adopt" {
            match client::chkpwd::check(&pw) {
                Ok(true) => {}
                Ok(false) => {
                    return json!({"ok": false, "error": "wrong-key",
                                  "message": "That isn't your login password."});
                }
                Err(e) => {
                    return json!({"ok": false, "error": "internal",
                                  "message": format!("The login password can't be checked: {e}.")});
                }
            }
        }
        p.args.insert("login_password".into(), json!(pw.as_str()));
    }
    let verb = format!("keyring-{}", p.sub);
    let wait = client::wait_for(&verb);
    client::call(&verb, Value::Object(p.args), wait)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, Value> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn subcommands_take_their_options() {
        assert_eq!(p(&["repair", "--dry-run"]).unwrap().args["dry_run"], true);
        assert_eq!(p(&["import", "--dry-run"]).unwrap().args["dry_run"], true);
        assert_eq!(p(&["rm", "/org/x/1"]).unwrap().args["id"], "/org/x/1");
        assert!(p(&["status"]).unwrap().args.is_empty());
    }

    #[test]
    fn mistakes_are_bad_requests() {
        for argv in [
            &[][..],
            &["fix"],
            &["rm"],
            &["rm", "a", "b"],
            &["list", "--dry-run"],
            &["status", "extra"],
            &["repair", "--force"],
        ] {
            let e = p(argv).err().expect("an error");
            assert_eq!(e["error"], "bad-request", "{argv:?}");
        }
    }
}
