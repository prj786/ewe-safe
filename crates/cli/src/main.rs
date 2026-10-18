//! `ewe-safe`: Safe's verbs, one JSON object each, exit 0 (house rule 5;
//! docs/PROTOCOL.md). Secrets come from the terminal (no echo) or from
//! stdin lines, never from the command line. Three exceptions to the JSON:
//! `reveal` without `--json` prints the bare value (nothing and exit 1 when
//! there is none), `unlock --ask` opens a prompt window and waits, and
//! `watch` prints one line per event until the daemon goes away. SSH keys
//! and the agent are `ewe-safe ssh …` ([`ssh`]).
//! `read`, `run`, `inject` and `git-credential` follow the tools they copy
//! (1Password's `op`, git's helpers): [`scripts`] and [`git`].

use std::collections::HashSet;
use std::io::{IsTerminal, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use safe_client as client;
use safe_client::{FAST, IMPORT, Next, SLOW};
use safe_core::generator;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

mod git;
mod login;
mod scripts;
mod ssh;

/// How long `unlock --ask` waits for the prompt.
const ASK_WAIT: Duration = Duration::from_secs(300);

const VALUES: &[&str] = &[
    "place",
    "location",
    "url",
    "user",
    "kind",
    "tag",
    "title",
    "username",
    "app",
    "folder",
    "length",
    "words",
    "class",
    "query",
    "limit",
    "field",
    "clear-after",
    "remove-app",
    "remove-tag",
    "vault",
    "account",
    "rp",
    // confirm (docs/SYSTEM.md §4): the sentence the window shows
    "reason",
];
const FLAGS: &[&str] = &[
    "json",
    "ask",
    "generate",
    "deleted",
    "reveal-notes",
    "no-symbols",
    "no-digits",
    "clear-url",
    "password-stdin",
    "notes-stdin",
    "dry-run",
    "skip-duplicates",
    "remove-passkey",
    // unlock/confirm with the login password (docs/SYSTEM.md §2, §4)
    "login",
];
/// Read here, never sent.
const LOCAL_FLAGS: &[&str] = &["json", "ask", "password-stdin", "notes-stdin", "login"];
const NUMBERS: &[&str] = &["length", "words", "limit", "clear-after"];
/// Repeatable in `add` and `edit` (and `--vault` in `import`).
const LISTS: &[&str] = &["url", "app", "tag", "remove-app", "remove-tag", "vault"];
const WITH_ID: &[&str] = &["show", "reveal", "copy", "edit", "rm", "restore"];
const VERBS: &[&str] = &[
    "status", "summary", "init", "open", "unlock", "lock", "list", "search", "match", "show",
    "reveal", "copy", "add", "edit", "rm", "restore", "generate", "sync", "place", "passwd",
    "import", "watch", "ping", "version", "passkey", "ssh", "confirm",
];

struct Parsed {
    verb: String,
    args: Map<String, Value>,
    local: HashSet<String>,
}

fn bad(message: impl Into<String>) -> Value {
    json!({"ok": false, "error": "bad-request", "message": message.into()})
}

fn parse(argv: &[String]) -> Result<Parsed, Value> {
    let verb = argv.first().cloned().unwrap_or_default();
    if !VERBS.contains(&verb.as_str()) {
        let mut v = bad(if verb.is_empty() {
            "Usage: ewe-safe <verb> [options] (docs/PROTOCOL.md)".to_string()
        } else {
            format!("There is no verb {verb:?}.")
        });
        v["verbs"] = json!([VERBS, scripts::VERBS].concat());
        return Err(v);
    }
    let lists = matches!(verb.as_str(), "add" | "edit" | "import");
    let mut args = Map::new();
    let mut local = HashSet::new();
    let mut positional: Vec<String> = Vec::new();
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        i += 1;
        let Some(opt) = a.strip_prefix("--") else {
            positional.push(a.clone());
            continue;
        };
        let (name, inline) = match opt.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (opt.to_string(), None),
        };
        if FLAGS.contains(&name.as_str()) {
            if LOCAL_FLAGS.contains(&name.as_str()) {
                local.insert(name);
            } else {
                args.insert(name.replace('-', "_"), json!(true));
            }
            continue;
        }
        if !VALUES.contains(&name.as_str()) {
            return Err(bad(format!("{verb} has no option --{name}")));
        }
        let value = match inline {
            Some(v) => v,
            None if i < argv.len() => {
                i += 1;
                argv[i - 1].clone()
            }
            None => return Err(bad(format!("--{name} needs a value"))),
        };
        let key = name.replace('-', "_");
        let v = if NUMBERS.contains(&name.as_str()) {
            match value.parse::<u64>() {
                Ok(n) => json!(n),
                Err(_) => return Err(bad(format!("--{name} needs a whole number"))),
            }
        } else {
            json!(value)
        };
        if lists && LISTS.contains(&name.as_str()) {
            let entry = args.entry(key).or_insert_with(|| json!([]));
            if let Value::Array(a) = entry {
                a.push(v);
            }
        } else {
            args.insert(key, v);
        }
    }
    if WITH_ID.contains(&verb.as_str()) {
        match positional.first() {
            Some(id) => {
                args.insert("id".into(), json!(id));
            }
            None => return Err(bad(format!("{verb} needs an item id"))),
        }
    } else if verb == "search" {
        args.insert("text".into(), json!(positional.join(" ")));
    } else if verb == "import" {
        // the daemon reads the file itself: it needs the full path
        match positional.as_slice() {
            [format] => {
                args.insert("format".into(), json!(format));
            }
            [format, file] => {
                let full = std::path::absolute(file)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| file.clone());
                args.insert("format".into(), json!(format));
                args.insert("file".into(), json!(full));
            }
            [] => return Err(bad("import needs a format: 1pux, 1password-csv or op")),
            [_, _, extra, ..] => return Err(bad(format!("import takes no {extra:?}"))),
        }
    } else if verb == "passkey" {
        // `passkey list`; making and using a passkey is the browser's, over
        // the socket (passkey-create, passkey-get)
        if !matches!(positional.as_slice(), [sub] if sub == "list") {
            return Err(bad("Usage: ewe-safe passkey list [--rp R]"));
        }
        if let Some(rp) = args.remove("rp") {
            args.insert("rp_id".into(), rp);
        }
    } else if let Some(p) = positional.first() {
        return Err(bad(format!("{verb} takes no {p:?}")));
    }
    Ok(Parsed { verb, args, local })
}

fn tty() -> bool {
    std::io::stdin().is_terminal()
}

/// One secret: from the terminal without echo, else the next stdin line.
fn secret(prompt: &str) -> Result<Zeroizing<String>, Value> {
    if tty() {
        return rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .map_err(|e| bad(format!("can't read the password: {e}")));
    }
    let mut line = Zeroizing::new(String::new());
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| bad(format!("can't read the password: {e}")))?;
    let trimmed = Zeroizing::new(line.trim_end_matches(['\n', '\r']).to_string());
    Ok(trimmed)
}

/// A new password, typed twice.
fn new_secret(what: &str) -> Result<Zeroizing<String>, Value> {
    let a = secret(&format!("New {what}: "))?;
    let b = secret(&format!("The {what} again: "))?;
    if *a != *b {
        return Err(bad("The two passwords differ."));
    }
    Ok(a)
}

fn put_secret(args: &mut Map<String, Value>, key: &str, value: &Zeroizing<String>) {
    args.insert(key.to_string(), json!(value.as_str()));
}

fn ok(v: &Value) -> bool {
    v.get("ok").and_then(Value::as_bool) == Some(true)
}

fn run(argv: &[String]) -> (Value, ExitCode) {
    if let Some(out) = scripts::dispatch(argv) {
        return out;
    }
    if argv.first().map(String::as_str) == Some("ssh") {
        return (ssh::run(&argv[1..]), ExitCode::SUCCESS);
    }
    // login unlock on/off (docs/SYSTEM.md §2): its own stdin/chkpwd handling
    if argv.first().map(String::as_str) == Some("login") {
        return (login::run(&argv[1..]), ExitCode::SUCCESS);
    }
    let mut p = match parse(argv) {
        Ok(p) => p,
        Err(v) => return (v, ExitCode::SUCCESS),
    };
    let done = |v: Value| (v, ExitCode::SUCCESS);
    match p.verb.as_str() {
        "generate" => done(generate(&p.args)),
        "init" => match new_secret("master password") {
            Ok(pw) => {
                put_secret(&mut p.args, "password", &pw);
                done(client::call("init", Value::Object(p.args), SLOW))
            }
            Err(v) => done(v),
        },
        "open" => match secret("Master password for Safe: ") {
            Ok(pw) => {
                put_secret(&mut p.args, "password", &pw);
                done(client::call("open", Value::Object(p.args), SLOW))
            }
            Err(v) => done(v),
        },
        "unlock" if p.local.contains("ask") => done(unlock_ask()),
        "unlock" if p.local.contains("login") => done(unlock_login(p.args)),
        "unlock" => done(unlock(p.args)),
        "confirm" if p.local.contains("ask") => done(confirm_ask(&p.args)),
        "confirm" => done(confirm(p.args, p.local.contains("login"))),
        "passwd" => done(passwd(p.args)),
        "add" | "edit" => {
            if p.local.contains("password-stdin") {
                match secret("Password: ") {
                    Ok(pw) => put_secret(&mut p.args, "password_value", &pw),
                    Err(v) => return done(v),
                }
            }
            if p.local.contains("notes-stdin") {
                let mut notes = Zeroizing::new(String::new());
                if let Err(e) = std::io::stdin().read_to_string(&mut notes) {
                    return done(bad(format!("can't read the notes: {e}")));
                }
                put_secret(&mut p.args, "notes", &notes);
            }
            done(client::call(&p.verb, Value::Object(p.args), SLOW))
        }
        "copy" => {
            if let Ok(d) = std::env::var("WAYLAND_DISPLAY") {
                p.args.insert("wayland_display".into(), json!(d));
            }
            done(client::call("copy", Value::Object(p.args), FAST))
        }
        "reveal" => {
            let v = client::call("reveal", Value::Object(p.args), FAST);
            if p.local.contains("json") {
                return done(v);
            }
            match v.get("value").and_then(Value::as_str) {
                Some(value) if ok(&v) => {
                    println!("{value}");
                    (Value::Null, ExitCode::SUCCESS)
                }
                _ => (Value::Null, ExitCode::from(1)),
            }
        }
        "sync" | "rm" | "restore" => done(client::call(&p.verb, Value::Object(p.args), SLOW)),
        "import" => done(client::call("import", Value::Object(p.args), IMPORT)),
        "passkey" => done(client::call("passkey-list", Value::Object(p.args), FAST)),
        "watch" => (Value::Null, watch()),
        verb => done(client::call(verb, Value::Object(p.args), FAST)),
    }
}

/// `watch`: the daemon's events as JSON lines for a shell or a script
/// that can't hold a socket (the desktop plugin's bridge). The first line
/// is `{"v": 1, "event": "status", "status": {…}}`, then every event as the
/// socket sends it, and `{"v": 1, "event": "daemon-gone"}` last.
fn watch() -> ExitCode {
    let mut out = std::io::stdout().lock();
    let mut line = |v: &Value| writeln!(out, "{v}").and_then(|_| out.flush()).is_ok();
    let gone = json!({"v": 1, "event": "daemon-gone"});
    let mut events = match client::subscribe() {
        Ok(e) => e,
        Err(_) => {
            line(&gone);
            return ExitCode::SUCCESS;
        }
    };
    let status = client::call("status", json!({}), FAST);
    if !line(&json!({"v": 1, "event": "status", "status": status})) {
        return ExitCode::SUCCESS;
    }
    loop {
        match events.next(Duration::from_secs(3600)) {
            Next::Event(mut v) => {
                v["v"] = json!(1);
                if !line(&v) {
                    return ExitCode::SUCCESS;
                }
            }
            Next::Quiet => {}
            Next::Closed => {
                line(&gone);
                return ExitCode::SUCCESS;
            }
        }
    }
}

fn generate(a: &Map<String, Value>) -> Value {
    let num = |k: &str| a.get(k).and_then(Value::as_u64).map(|n| n as usize);
    let flag = |k: &str| a.get(k).and_then(Value::as_bool).unwrap_or(false);
    let made = match num("words") {
        Some(w) => generator::passphrase(w, "-").map(|v| (v, generator::passphrase_bits(w))),
        None => {
            let len = num("length").unwrap_or(20);
            let (symbols, digits) = (!flag("no_symbols"), !flag("no_digits"));
            generator::password_with(len, symbols, digits)
                .map(|v| (v, generator::password_bits_with(len, symbols, digits)))
        }
    };
    match made {
        Ok((value, bits)) => json!({"ok": true, "value": value.as_str(), "bits": bits.round()}),
        Err(e) => bad(e.to_string()),
    }
}

/// From a terminal, three tries; from stdin, one.
fn unlock(args: Map<String, Value>) -> Value {
    let tries = if tty() { 3 } else { 1 };
    let mut last = Value::Null;
    for n in 0..tries {
        let pw = match secret("Master password for Safe: ") {
            Ok(pw) => pw,
            Err(v) => return v,
        };
        let mut a = args.clone();
        put_secret(&mut a, "password", &pw);
        last = client::call("unlock", Value::Object(a), SLOW);
        let wrong = last.get("error").and_then(Value::as_str) == Some("wrong-key");
        if !wrong || n + 1 == tries {
            break;
        }
        eprintln!("That password doesn't open the safe. Try again.");
    }
    last
}

/// `unlock --login` (docs/SYSTEM.md §2): the login password opens Safe, not
/// the master password. From a terminal, three tries.
fn unlock_login(args: Map<String, Value>) -> Value {
    let tries = if tty() { 3 } else { 1 };
    let mut last = Value::Null;
    for n in 0..tries {
        let pw = match secret("Your login password: ") {
            Ok(pw) => pw,
            Err(v) => return v,
        };
        let mut a = args.clone();
        a.insert("login_password".into(), json!(pw.as_str()));
        last = client::call("unlock", Value::Object(a), SLOW);
        let wrong = last.get("error").and_then(Value::as_str) == Some("wrong-key");
        if !wrong || n + 1 == tries {
            break;
        }
        eprintln!("That login password doesn't open Safe. Try again.");
    }
    last
}

/// `confirm` (docs/SYSTEM.md §4): type your password again for a sensitive
/// fill. The master password by default, the login password with `--login`.
fn confirm(mut args: Map<String, Value>, login: bool) -> Value {
    args.remove("reason");
    let prompt = if login {
        "Your login password: "
    } else {
        "Master password for Safe: "
    };
    let pw = match secret(prompt) {
        Ok(pw) => pw,
        Err(v) => return v,
    };
    let key = if login { "login_password" } else { "password" };
    args.insert(key.into(), json!(pw.as_str()));
    client::call("confirm", Value::Object(args), FAST)
}

/// `confirm --ask`: open the confirm window (`ewe-safe-app --confirm --reason
/// …`) and wait for it, exactly as `unlock --ask` does. The window calls
/// `confirm` itself; its exit code is the answer (0 = confirmed).
fn confirm_ask(args: &Map<String, Value>) -> Value {
    let reason = args
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or("Type your password to continue.");
    let mut prompt = match std::env::var("EWE_SAFE_ASK_CMD") {
        // a test (or a user) names the prompt
        Ok(cmd) => {
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd);
            c
        }
        Err(_) => match unlock_window() {
            Some(app) => {
                let mut c = Command::new(app);
                c.args(["--confirm", "--reason", reason]);
                c
            }
            None => {
                return json!({
                    "ok": false,
                    "error": "internal",
                    "message": "The Safe window isn't installed, so there's nothing to confirm with.",
                    "hint": "ewe-safe confirm (in a terminal)",
                });
            }
        },
    };
    let spawned = prompt
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "ok": false,
                "error": "internal",
                "message": format!("Couldn't open the confirm window ({e})."),
            });
        }
    };
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(200));
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    json!({"ok": true, "confirmed": true})
                } else {
                    json!({"ok": false, "error": "cancelled", "message": "Not confirmed."})
                };
            }
            Ok(None) if start.elapsed() > ASK_WAIT => {
                let _ = child.kill();
                let _ = child.wait();
                return json!({"ok": false, "error": "cancelled", "message": "The confirm window timed out."});
            }
            Ok(None) => {}
            Err(e) => return json!({"ok": false, "error": "internal", "message": e.to_string()}),
        }
    }
}

fn passwd(mut args: Map<String, Value>) -> Value {
    let st = client::call("status", json!({}), FAST);
    if !ok(&st) {
        return st;
    }
    if st.get("locked").and_then(Value::as_bool) == Some(true) {
        match secret("Current master password: ") {
            Ok(pw) => put_secret(&mut args, "password", &pw),
            Err(v) => return v,
        }
    }
    match new_secret("master password") {
        Ok(pw) => put_secret(&mut args, "new_password", &pw),
        Err(v) => return v,
    }
    client::call("passwd", Value::Object(args), SLOW)
}

/// `ewe-safe-app`, the Safe window, next to this binary or on the PATH.
fn unlock_window() -> Option<std::path::PathBuf> {
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("ewe-safe-app")));
    let on_path = std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join("ewe-safe-app"))
            .find(|p| p.is_file())
    });
    beside.filter(|p| p.is_file()).or(on_path)
}

/// `unlock --ask` (the Passwords plugin's Enter): open a small prompt
/// window and wait until the safe is unlocked or the window is gone — the
/// Safe window's `--unlock` mode, or phase 1's kitty bridge without it.
fn unlock_ask() -> Value {
    let st = client::call("status", json!({}), FAST);
    if !ok(&st) {
        return st;
    }
    if st.get("set_up").and_then(Value::as_bool) != Some(true) {
        return json!({
            "ok": false,
            "error": "not-set-up",
            "message": "There is no safe on this computer yet.",
            "hint": "ewe-safe init --place nextcloud, or ewe-safe open --place nextcloud",
        });
    }
    if st.get("locked").and_then(Value::as_bool) == Some(false) {
        return json!({"ok": true, "items": st.get("items")});
    }
    let mut prompt = match std::env::var("EWE_SAFE_ASK_CMD") {
        // a test (or a user) names the prompt; it runs `ewe-safe unlock`
        Ok(cmd) => {
            let mut c = Command::new("sh");
            c.arg("-c").arg(cmd);
            c
        }
        // the Safe window's own unlock prompt when it is installed
        Err(_) => match unlock_window() {
            Some(app) => {
                let mut c = Command::new(app);
                c.arg("--unlock");
                c
            }
            // phase 1's bridge: a small kitty asking in a terminal
            None => {
                let me = std::env::current_exe()
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| "ewe-safe".into());
                let mut c = Command::new("kitty");
                c.args([
                    "--class",
                    "ewe-safe-unlock",
                    "--title",
                    "Unlock Safe",
                    "-e",
                    &me,
                    "unlock",
                ]);
                c
            }
        },
    };
    // this command's stdout is its one JSON answer: the prompt's is its own
    let spawned = prompt
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            return json!({
                "ok": false,
                "error": "internal",
                "message": format!("Couldn't open the unlock prompt ({e})."),
                "hint": "ewe-safe unlock in a terminal",
            });
        }
    };
    let start = Instant::now();
    let unlocked = || {
        let st = client::call("status", json!({}), FAST);
        (st.get("locked").and_then(Value::as_bool) == Some(false)).then(|| st.get("items").cloned())
    };
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if let Some(items) = unlocked() {
            return json!({"ok": true, "items": items});
        }
        if let Ok(Some(_)) = child.try_wait() {
            if let Some(items) = unlocked() {
                return json!({"ok": true, "items": items});
            }
            return json!({
                "ok": false,
                "error": "cancelled",
                "message": "Safe is still locked: the prompt was closed.",
            });
        }
        if start.elapsed() > ASK_WAIT {
            let _ = child.kill();
            let _ = child.wait();
            return json!({
                "ok": false,
                "error": "cancelled",
                "message": "Safe is still locked: the prompt timed out.",
            });
        }
    }
}

fn main() -> ExitCode {
    // no core dump, no ptrace: reveal, read, run, inject and the git helper
    // hold values (`run` gives its command the core limit back)
    safe_core::hygiene::harden_soft();
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (v, code) = run(&argv);
    if !v.is_null() {
        println!("{v}");
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(args: &[&str]) -> Result<Parsed, Value> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn options_become_protocol_args() {
        let x = p(&[
            "match",
            "--class",
            "discord",
            "--title=Chat",
            "--limit",
            "8",
        ])
        .unwrap();
        assert_eq!(x.args["class"], "discord");
        assert_eq!(x.args["title"], "Chat");
        assert_eq!(x.args["limit"], 8);
        let x = p(&[
            "add",
            "--title",
            "T",
            "--url",
            "a",
            "--url",
            "b",
            "--generate",
        ])
        .unwrap();
        assert_eq!(x.args["url"], json!(["a", "b"]));
        assert_eq!(x.args["generate"], true);
        let x = p(&["copy", "4f9c", "--clear-after", "10"]).unwrap();
        assert_eq!(x.args["id"], "4f9c");
        assert_eq!(x.args["clear_after"], 10);
        let x = p(&["reveal", "id", "--field", "otp", "--json"]).unwrap();
        assert!(x.local.contains("json") && !x.args.contains_key("json"));
        let x = p(&["search", "git", "hub"]).unwrap();
        assert_eq!(x.args["text"], "git hub");
    }

    #[test]
    fn import_takes_a_format_a_full_path_and_vaults() {
        let x = p(&[
            "import",
            "1pux",
            "/tmp/a.1pux",
            "--dry-run",
            "--folder",
            "1P",
        ])
        .unwrap();
        assert_eq!(x.args["format"], "1pux");
        assert_eq!(x.args["file"], "/tmp/a.1pux");
        assert_eq!(x.args["dry_run"], true);
        assert_eq!(x.args["folder"], "1P");
        let x = p(&["import", "1password-csv", "export.csv"]).unwrap();
        assert!(
            x.args["file"].as_str().unwrap().starts_with('/'),
            "made absolute"
        );
        let x = p(&[
            "import",
            "op",
            "--vault",
            "Personal",
            "--vault",
            "Work",
            "--skip-duplicates",
        ])
        .unwrap();
        assert_eq!(x.args["vault"], json!(["Personal", "Work"]));
        assert_eq!(x.args["skip_duplicates"], true);
        assert!(x.args.get("file").is_none());
        for argv in [&["import"][..], &["import", "op", "a", "b"]] {
            assert_eq!(p(argv).err().expect("an error")["error"], "bad-request");
        }
    }

    #[test]
    fn passkey_list_and_remove() {
        let x = p(&["passkey", "list", "--rp", "github.com"]).unwrap();
        assert_eq!(x.args["rp_id"], "github.com");
        assert!(x.args.get("rp").is_none());
        assert!(p(&["passkey", "list"]).unwrap().args.is_empty());
        for argv in [
            &["passkey"][..],
            &["passkey", "add"],
            &["passkey", "list", "x"],
        ] {
            assert_eq!(p(argv).err().expect("an error")["error"], "bad-request");
        }
        let x = p(&["edit", "4f9c", "--remove-passkey"]).unwrap();
        assert_eq!(x.args["remove_passkey"], true);
    }

    #[test]
    fn mistakes_are_bad_requests() {
        for argv in [
            &["nope"][..],
            &["show"],
            &["list", "--colour", "x"],
            &["match", "--limit", "many"],
            &["lock", "extra"],
            &["match", "--class"],
        ] {
            let e = p(argv).err().expect("an error");
            assert_eq!(e["error"], "bad-request", "{argv:?}");
        }
    }

    #[test]
    fn generate_needs_no_daemon() {
        let v = generate(&Map::new());
        assert_eq!(v["value"].as_str().unwrap().len(), 20);
        let mut a = Map::new();
        a.insert("words".into(), json!(4));
        assert_eq!(
            generate(&a)["value"].as_str().unwrap().split('-').count(),
            4
        );
    }
}
