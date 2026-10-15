//! Safe from scripts, in the shapes 1Password's `op` made familiar
//! (docs/PROTOCOL.md, "References"): `read`, `run`, `inject`, and
//! `git-credential` ([`crate::git`]). Every `safe://` reference goes to the
//! daemon's `resolve` verb, so the rules live in one place
//! (`safe_core::refs`). A locked safe opens the unlock prompt once
//! (`unlock --ask`) and the reference is tried again.
//!
//! `read`, `run` and `inject` without `-o` print what a script consumes, not
//! JSON (documented exceptions to rule 5): a failure prints nothing on
//! stdout, one line on stderr, and exits non-zero.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitCode};

use safe_client as client;
use safe_core::refs::is_reference;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// The verbs this module answers (the CLI lists them with its own).
pub const VERBS: &[&str] = &["read", "run", "inject", "git-credential"];
/// `run`'s own failures, as env(1) has them: the child's code is the child's.
const RUN_FAILED: u8 = 125;
const RUN_CANNOT_EXEC: u8 = 126;
const RUN_NOT_FOUND: u8 = 127;

fn bad(message: impl Into<String>) -> Value {
    json!({"ok": false, "error": "bad-request", "message": message.into()})
}

fn ok(v: &Value) -> bool {
    v.get("ok").and_then(Value::as_bool) == Some(true)
}

/// The verbs this module answers; `None` for every other verb.
pub fn dispatch(argv: &[String]) -> Option<(Value, ExitCode)> {
    let rest = argv.get(1..).unwrap_or_default();
    match argv.first().map(String::as_str)? {
        "read" => Some(read(rest)),
        "run" => Some(run(rest)),
        "inject" => Some(inject_verb(rest)),
        "git-credential" => Some((Value::Null, crate::git::main(rest))),
        _ => None,
    }
}

/// One line on stderr for a failure a script will see as an exit code.
pub fn complain(verb: &str, v: &Value) {
    let msg = v
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("it didn't work.");
    match v.get("hint").and_then(Value::as_str) {
        Some(h) => eprintln!("ewe-safe {verb}: {msg} ({h})"),
        None => eprintln!("ewe-safe {verb}: {msg}"),
    }
}

/// References through the daemon, each asked once per run.
#[derive(Default)]
pub struct Resolver {
    asked: bool,
    seen: HashMap<String, Zeroizing<String>>,
}

impl Resolver {
    /// The daemon's `resolve` reply, `ok` or not. Locked: the unlock prompt
    /// once, then again.
    pub fn reply(&mut self, reference: &str) -> Value {
        let ask = || client::call("resolve", json!({"ref": reference.trim()}), client::FAST);
        let v = ask();
        if v.get("error").and_then(Value::as_str) != Some("locked") || self.asked {
            return v;
        }
        self.asked = true;
        let u = crate::unlock_ask();
        if !ok(&u) {
            return u;
        }
        ask()
    }

    /// The value, or the error reply.
    pub fn value(&mut self, reference: &str) -> Result<Zeroizing<String>, Value> {
        if let Some(v) = self.seen.get(reference.trim()) {
            return Ok(v.clone());
        }
        let mut v = self.reply(reference);
        if !ok(&v) {
            return Err(v);
        }
        let value = match v.get_mut("value").map(Value::take) {
            Some(Value::String(s)) => Zeroizing::new(s),
            _ => {
                return Err(
                    json!({"ok": false, "error": "internal", "message": "Safe's service gave no value."}),
                );
            }
        };
        self.seen
            .insert(reference.trim().to_string(), value.clone());
        Ok(value)
    }
}

// ── read ────────────────────────────────────────────────────────────────

/// `read <ref> [--json] [-n|--no-newline]`: the bare value and a newline
/// (like `op read`); nothing found → nothing printed, exit 1.
fn read(args: &[String]) -> (Value, ExitCode) {
    let (mut json_out, mut newline, mut refs) = (false, true, Vec::new());
    for a in args {
        match a.as_str() {
            "--json" => json_out = true,
            "-n" | "--no-newline" => newline = false,
            o if o.starts_with('-') && !is_reference(o) => {
                return finish_read(json_out, bad(format!("read has no option {o}")));
            }
            r => refs.push(r),
        }
    }
    let [reference] = refs.as_slice() else {
        return finish_read(
            json_out,
            bad("Usage: ewe-safe read \"safe://<folder>/<title>/<field>\""),
        );
    };
    let mut v = Resolver::default().reply(reference);
    if json_out || !ok(&v) {
        return finish_read(json_out, v);
    }
    let value = match v.get_mut("value").map(Value::take) {
        Some(Value::String(s)) => Zeroizing::new(s),
        _ => return finish_read(false, Value::Null),
    };
    let mut out = std::io::stdout().lock();
    let written = out
        .write_all(value.as_bytes())
        .and_then(|_| {
            if newline {
                out.write_all(b"\n")
            } else {
                Ok(())
            }
        })
        .and_then(|_| out.flush());
    match written {
        Ok(()) => (Value::Null, ExitCode::SUCCESS),
        Err(_) => (Value::Null, ExitCode::from(1)),
    }
}

fn finish_read(json_out: bool, v: Value) -> (Value, ExitCode) {
    if json_out {
        return (v, ExitCode::SUCCESS);
    }
    if !v.is_null() {
        complain("read", &v);
    }
    (Value::Null, ExitCode::from(1))
}

// ── templates ───────────────────────────────────────────────────────────

/// `{{ safe://… }}` replaced by the values; any other `{{ … }}` is left as it
/// is (it belongs to another template language). Returns the text and how
/// many references it held. The first reference that fails stops it.
pub fn fill_template(
    text: &str,
    resolve: &mut dyn FnMut(&str) -> Result<Zeroizing<String>, Value>,
) -> Result<(Zeroizing<String>, usize), Value> {
    let mut out = Zeroizing::new(String::with_capacity(text.len()));
    let mut n = 0;
    let mut rest = text;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else {
            out.push_str(&rest[open..]);
            return Ok((out, n));
        };
        let inner = &after[..close];
        if is_reference(inner) && !inner.contains('\n') {
            let value = resolve(inner.trim())?;
            out.push_str(&value);
            n += 1;
            rest = &after[close + 2..];
        } else {
            // not ours: keep the braces and look again after them
            out.push_str("{{");
            rest = after;
        }
    }
    out.push_str(rest);
    Ok((out, n))
}

/// A value for `run`'s child: a whole `safe://…` value, or one with
/// `{{ safe://… }}` inside. `None` when it holds no reference.
pub fn fill_value(
    value: &str,
    resolve: &mut dyn FnMut(&str) -> Result<Zeroizing<String>, Value>,
) -> Result<Option<Zeroizing<String>>, Value> {
    if is_reference(value) {
        return resolve(value.trim()).map(Some);
    }
    if !value.contains("{{") {
        return Ok(None);
    }
    let (filled, n) = fill_template(value, resolve)?;
    Ok((n > 0).then_some(filled))
}

// ── env files ───────────────────────────────────────────────────────────

/// A dotenv file: `KEY=value` lines, `export KEY=value`, `#` comments and
/// blank lines. A value may be `"double quoted"` (`\n`, `\t`, `\r`, `\\` and
/// `\"` escapes, several lines allowed), `'single quoted'` (as is, several
/// lines allowed) or bare (spaces around it trimmed, a ` #` starts a
/// comment). `$VAR` is not expanded.
pub fn parse_env(text: &str) -> Result<Vec<(String, String)>, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut out = Vec::new();
    let mut lines = text.lines().enumerate().peekable();
    while let Some((i, raw)) = lines.next() {
        let line_no = i + 1;
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line
            .strip_prefix("export")
            .filter(|r| r.starts_with([' ', '\t']))
            .map(str::trim_start)
            .unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_no}: no = in it"));
        };
        let key = key.trim();
        let good_key = key
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !good_key {
            return Err(format!("line {line_no}: {key:?} isn't a variable name"));
        }
        let value = value.trim_start();
        let parsed = match value.chars().next() {
            Some(q @ ('"' | '\'')) => {
                let mut body = String::new();
                let mut cur = value[1..].to_string();
                let mut end_line = line_no;
                loop {
                    match closing(&cur, q) {
                        Some((inside, after)) => {
                            body.push_str(&inside);
                            let tail = after.trim();
                            if !(tail.is_empty() || tail.starts_with('#')) {
                                return Err(format!(
                                    "line {end_line}: text after the closing quote"
                                ));
                            }
                            break;
                        }
                        None => {
                            body.push_str(&unescape(&cur, q));
                            body.push('\n');
                            match lines.next() {
                                Some((j, next)) => {
                                    end_line = j + 1;
                                    cur = next.to_string();
                                }
                                None => {
                                    return Err(format!("line {line_no}: the quote never closes"));
                                }
                            }
                        }
                    }
                }
                body
            }
            _ => {
                let cut = value.find(" #").or_else(|| value.find("\t#"));
                value[..cut.unwrap_or(value.len())].trim_end().to_string()
            }
        };
        out.push((key.to_string(), parsed));
    }
    Ok(out)
}

fn unescape(s: &str, quote: char) -> String {
    if quote == '\'' {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(e @ ('\\' | '"')) => out.push(e),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// The text up to the closing quote (unescaped) and what follows it.
fn closing(s: &str, quote: char) -> Option<(String, &str)> {
    let mut escaped = false;
    for (i, c) in s.char_indices() {
        if quote == '"' && c == '\\' && !escaped {
            escaped = true;
            continue;
        }
        if c == quote && !escaped {
            return Some((unescape(&s[..i], quote), &s[i + 1..]));
        }
        escaped = false;
    }
    None
}

// ── run ─────────────────────────────────────────────────────────────────

/// `run [--env-file F]… [--] <command> [args…]`: the command with every
/// `safe://` value in its environment resolved — its environment only.
/// ewe-safe becomes the command (exec), so the exit code is the command's;
/// ewe-safe's own failures exit 125, a command that can't run 126 or 127.
fn run(args: &[String]) -> (Value, ExitCode) {
    let fail = |msg: String| {
        eprintln!("ewe-safe run: {msg}");
        (Value::Null, ExitCode::from(RUN_FAILED))
    };
    let mut files: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            i += 1;
            break;
        }
        if let Some(f) = a.strip_prefix("--env-file=") {
            files.push(f.to_string());
        } else if a == "--env-file" {
            match args.get(i + 1) {
                Some(f) => files.push(f.clone()),
                None => return fail("--env-file needs a file".into()),
            }
            i += 1;
        } else if a.starts_with('-') {
            return fail(format!("run has no option {a}"));
        } else {
            break;
        }
        i += 1;
    }
    let Some((cmd, cmd_args)) = args[i.min(args.len())..].split_first() else {
        return fail("Usage: ewe-safe run [--env-file F] -- <command> [args…]".into());
    };

    let mut env: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    for f in &files {
        let text = match std::fs::read_to_string(f) {
            Ok(t) => Zeroizing::new(t),
            Err(e) => return fail(format!("can't read {f}: {e}")),
        };
        let pairs = match parse_env(&text) {
            Ok(p) => p,
            Err(e) => return fail(format!("{f}: {e}")),
        };
        for (k, v) in pairs {
            let k = OsString::from(k);
            env.retain(|(x, _)| *x != k);
            env.push((k, OsString::from(v)));
        }
    }
    let mut r = Resolver::default();
    let mut resolve = |reference: &str| r.value(reference);
    for (k, v) in env.iter_mut() {
        let Some(text) = v.to_str() else { continue };
        match fill_value(text, &mut resolve) {
            Ok(Some(filled)) => *v = OsString::from(filled.as_str()),
            Ok(None) => {}
            Err(e) => {
                let msg = e
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("it didn't resolve");
                return fail(format!("{}: {msg}", k.to_string_lossy()));
            }
        }
    }
    let err = Command::new(cmd)
        .args(cmd_args)
        .env_clear()
        .envs(env)
        .exec();
    eprintln!("ewe-safe run: can't run {cmd}: {err}");
    let code = if err.kind() == std::io::ErrorKind::NotFound {
        RUN_NOT_FOUND
    } else {
        RUN_CANNOT_EXEC
    };
    (Value::Null, ExitCode::from(code))
}

// ── inject ──────────────────────────────────────────────────────────────

/// `inject [-i <template>] [-o <file>]`: the template (stdin without `-i`)
/// with its `{{ safe://… }}` replaced. Without `-o` the result goes to
/// stdout (a failure: nothing there, a line on stderr, exit 1). With `-o`
/// the file is written whole (0600, atomic) and the answer is JSON:
/// `{"ok": true, "file": …, "references": n}`.
fn inject_verb(args: &[String]) -> (Value, ExitCode) {
    let (mut input, mut output) = (None::<String>, None::<String>);
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let (name, inline) = match a.split_once('=') {
            Some((n, v)) if n.starts_with("--") => (n, Some(v.to_string())),
            _ => (a, None),
        };
        let slot = match name {
            "-i" | "--in-file" => &mut input,
            "-o" | "--out-file" => &mut output,
            other => {
                return inject_fail(
                    output.is_some(),
                    bad(format!("inject has no option {other}")),
                );
            }
        };
        let value = match inline {
            Some(v) => v,
            None => match args.get(i + 1) {
                Some(v) => {
                    i += 1;
                    v.clone()
                }
                None => return inject_fail(output.is_some(), bad(format!("{name} needs a file"))),
            },
        };
        *slot = Some(value);
        i += 1;
    }
    let to_file = output.is_some();
    let mut text = Zeroizing::new(String::new());
    let read = match &input {
        Some(f) => std::fs::File::open(f).and_then(|mut h| h.read_to_string(&mut text)),
        None => std::io::stdin().read_to_string(&mut text),
    };
    if let Err(e) = read {
        let from = input.as_deref().unwrap_or("stdin");
        return inject_fail(to_file, bad(format!("can't read {from}: {e}")));
    }
    let mut r = Resolver::default();
    let (filled, n) = match fill_template(&text, &mut |x| r.value(x)) {
        Ok(x) => x,
        Err(e) => return inject_fail(to_file, e),
    };
    match output {
        None => {
            let mut out = std::io::stdout().lock();
            match out.write_all(filled.as_bytes()).and_then(|_| out.flush()) {
                Ok(()) => (Value::Null, ExitCode::SUCCESS),
                Err(_) => (Value::Null, ExitCode::from(1)),
            }
        }
        Some(f) => {
            let path = std::path::absolute(&f).unwrap_or_else(|_| f.clone().into());
            match safe_core::atomic::write(&path, filled.as_bytes()) {
                Ok(()) => (
                    json!({"ok": true, "file": path.to_string_lossy(), "references": n}),
                    ExitCode::SUCCESS,
                ),
                Err(e) => inject_fail(
                    true,
                    json!({"ok": false, "error": "internal", "message": format!("can't write {f}: {e}")}),
                ),
            }
        }
    }
}

fn inject_fail(to_file: bool, v: Value) -> (Value, ExitCode) {
    if to_file {
        return (v, ExitCode::SUCCESS);
    }
    complain("inject", &v);
    (Value::Null, ExitCode::from(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(reference: &str) -> Result<Zeroizing<String>, Value> {
        match reference {
            "safe://Personal/GitHub/password" => Ok(Zeroizing::new("gh-pw".into())),
            "safe://DB/prod/password" => Ok(Zeroizing::new("p@ss {{ x }}".into())),
            other => {
                Err(json!({"ok": false, "error": "not-found", "message": format!("no {other}")}))
            }
        }
    }

    #[test]
    fn templates_replace_only_safe_references() {
        let t = "token: {{ safe://Personal/GitHub/password }}\nname: {{ name }}\nurl: postgres://u:{{safe://DB/prod/password}}@h/db\n{{ unclosed";
        let (out, n) = fill_template(t, &mut fake).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            out.as_str(),
            // a value with braces in it is not looked at again
            "token: gh-pw\nname: {{ name }}\nurl: postgres://u:p@ss {{ x }}@h/db\n{{ unclosed"
        );
        assert_eq!(fill_template("", &mut fake).unwrap().1, 0);
        assert_eq!(
            fill_template("{{{{}}}}", &mut fake).unwrap().0.as_str(),
            "{{{{}}}}"
        );
        let e = fill_template("a {{ safe://Nope/x }} b", &mut fake)
            .err()
            .unwrap();
        assert_eq!(e["error"], "not-found");
        // a reference across lines is not one
        assert_eq!(
            fill_template("{{ safe://A/\nB/c }}", &mut fake).unwrap().1,
            0
        );
    }

    #[test]
    fn env_values_whole_or_inside_braces() {
        assert_eq!(
            fill_value(" safe://Personal/GitHub/password ", &mut fake)
                .unwrap()
                .unwrap()
                .as_str(),
            "gh-pw"
        );
        assert_eq!(
            fill_value("Bearer {{ safe://Personal/GitHub/password }}", &mut fake)
                .unwrap()
                .unwrap()
                .as_str(),
            "Bearer gh-pw"
        );
        assert!(fill_value("plain", &mut fake).unwrap().is_none());
        assert!(fill_value("{{ jinja }}", &mut fake).unwrap().is_none());
        assert!(fill_value("safe://Nope/x", &mut fake).is_err());
    }

    #[test]
    fn env_files_read_like_dotenv() {
        let text = "\u{feff}# a comment\n\nexport TOKEN=safe://Personal/GitHub/password\nPLAIN = some value  # a comment\nHASH=a#b\nDQ=\"line\\none \\\"q\\\" # kept\"  # gone\nSQ='as $is \\n'\nMULTI=\"first\nsecond\"\nEMPTY=\n_UNDER_1=x\n";
        let got = parse_env(text).unwrap();
        let want: Vec<(String, String)> = [
            ("TOKEN", "safe://Personal/GitHub/password"),
            ("PLAIN", "some value"),
            ("HASH", "a#b"),
            ("DQ", "line\none \"q\" # kept"),
            ("SQ", "as $is \\n"),
            ("MULTI", "first\nsecond"),
            ("EMPTY", ""),
            ("_UNDER_1", "x"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(got, want);
        for (bad_text, line) in [
            ("A=1\nnot a line\n", "line 2"),
            ("1A=x", "line 1"),
            ("A-B=x", "line 1"),
            ("A=\"open\nstill open", "line 1"),
            ("A=\"x\" trailing", "line 1"),
        ] {
            let e = parse_env(bad_text).unwrap_err();
            assert!(e.starts_with(line), "{bad_text:?}: {e}");
        }
        // `export` is a prefix only when a space follows
        assert_eq!(parse_env("exported=1").unwrap()[0].0, "exported");
    }

    #[test]
    fn read_and_inject_refuse_what_they_dont_know() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(read(&args(&["--json"])).0["error"], "bad-request");
        assert_eq!(
            read(&args(&["--json", "--frob", "safe://a/b"])).0["error"],
            "bad-request"
        );
        assert_eq!(
            inject_verb(&args(&["-o", "/nonexistent/x", "--frob"])).0["error"],
            "bad-request"
        );
        assert!(dispatch(&args(&["status"])).is_none());
    }
}
