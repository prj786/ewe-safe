//! `ewe-safe git-credential get|store|erase`: git's credential-helper
//! protocol (`git help credential`), so `git push` over https takes its
//! login from Safe. Set it up once:
//!
//!     git config --global credential.helper '!ewe-safe git-credential'
//!
//! - `get`: the logins whose website has git's protocol and host exactly
//!   (and, with `credential.useHttpPath`, a path the repository's path
//!   starts with), and git's username when it sent one. The best fit (the
//!   longest path, then the newest) answers `username=` and `password=`.
//!   Nothing fits → nothing printed: git asks its next helper, or you.
//!   Locked → the unlock prompt (`unlock --ask`), then once more.
//! - `store` (git used a login and it worked): nothing when Safe already has
//!   it. Otherwise Safe asks first — "Save the login …?" for a new one,
//!   "Update the password …?" when exactly one login with that host and
//!   username has another password — never silently. A locked safe, an
//!   OAuth token (`password_expiry_utc`, `oauth_refresh_token`) or an
//!   `ephemeral` credential is never stored.
//! - `erase` (the server refused a login) does nothing: a refusal can be a
//!   typo, an outage or a lapsed token, and Safe never deletes a login
//!   because another program said so.
//!
//! The question goes to `EWE_SAFE_CONFIRM_CMD` when set (a test hook: a
//! shell command that writes `yes` into the file `$EWE_SAFE_ANSWER`; the
//! question is in `$EWE_SAFE_QUESTION`), else to the terminal git runs in,
//! else to a small prompt window (kitty, as `unlock --ask` in phase 1). The
//! hook or the window unanswered for two minutes is a no. Every exit is 0,
//! as git expects.

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use safe_client as client;
use serde_json::{Value, json};
use zeroize::Zeroizing;

/// How long a save/update question waits for an answer.
const CONFIRM_WAIT: Duration = Duration::from_secs(120);

/// What git sent. Only the attributes Safe uses; the rest is discarded, as
/// the protocol says. (No `Debug`: it holds a password.)
#[derive(Default)]
pub struct Request {
    pub protocol: String,
    pub host: String,
    pub path: String,
    pub username: Option<String>,
    pub password: Option<Zeroizing<String>>,
    /// An OAuth token or an ephemeral credential: never stored.
    pub token: bool,
}

/// `key=value` lines up to a blank line or the end.
pub fn parse_request(input: &str) -> Request {
    let mut r = Request::default();
    let mut url = None;
    for line in input.lines() {
        if line.is_empty() {
            break;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "protocol" => r.protocol = v.to_lowercase(),
            "host" => r.host = v.to_lowercase(),
            "path" => r.path = v.to_string(),
            "username" => r.username = Some(v.to_string()),
            "password" => r.password = Some(Zeroizing::new(v.to_string())),
            "url" => url = Some(v.to_string()),
            "password_expiry_utc" | "oauth_refresh_token" => r.token = true,
            "ephemeral" => r.token |= matches!(v, "1" | "true" | "yes" | "on"),
            _ => {}
        }
    }
    // `url=` stands for its parts (git's own input; harmless from a helper)
    if let Some(u) = url
        && let Some(s) = site(&u, "")
    {
        if r.protocol.is_empty() {
            r.protocol = s.scheme;
        }
        if r.host.is_empty() {
            r.host = s.host;
        }
        if r.path.is_empty() {
            r.path = s.path;
        }
    }
    r
}

/// A website as git sees one: scheme, `host[:port]` (lower case, the
/// scheme's default port left out) and the path without slashes or `.git`.
#[derive(Debug, PartialEq, Eq)]
pub struct Site {
    pub scheme: String,
    pub host: String,
    pub path: String,
}

fn default_port(scheme: &str) -> &'static str {
    match scheme {
        "https" => "443",
        "http" => "80",
        _ => "",
    }
}

fn clean_host(host: &str, scheme: &str) -> String {
    let h = host.trim().to_lowercase();
    match h.rsplit_once(':') {
        Some((name, port)) if !name.ends_with(':') && port == default_port(scheme) => {
            name.to_string()
        }
        _ => h,
    }
}

fn clean_path(path: &str) -> String {
    let p = path.trim().trim_matches('/');
    p.strip_suffix(".git")
        .unwrap_or(p)
        .trim_end_matches('/')
        .to_string()
}

/// A website (`https://github.com/login`, or `github.com`, which counts as
/// https). `fallback` is the scheme for a website without one.
pub fn site(url: &str, fallback: &str) -> Option<Site> {
    let url = url.trim();
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_lowercase(), r),
        None => (
            if fallback.is_empty() {
                "https"
            } else {
                fallback
            }
            .to_string(),
            url,
        ),
    };
    let rest = rest.split(['?', '#']).next().unwrap_or("");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let host = authority
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(authority);
    if host.is_empty() {
        return None;
    }
    Some(Site {
        host: clean_host(host, &scheme),
        path: clean_path(path),
        scheme,
    })
}

/// How well a website fits the request: `None` = not at all; else the
/// length of its path (longer is a closer fit).
pub fn fits(website: &str, r: &Request) -> Option<usize> {
    let s = site(website, "https")?;
    if s.scheme != r.protocol || s.host != clean_host(&r.host, &r.protocol) {
        return None;
    }
    let want = clean_path(&r.path);
    if want.is_empty() || s.path.is_empty() {
        return Some(0);
    }
    (want == s.path || want.starts_with(&format!("{}/", s.path))).then_some(s.path.len())
}

/// A login from `list`: what matching needs (no secret).
#[derive(Debug, Clone)]
pub struct Login {
    pub id: String,
    pub title: String,
    pub username: String,
    pub urls: Vec<String>,
    pub has_password: bool,
    pub modified: String,
}

fn logins(list: &Value) -> Vec<Login> {
    list.get("items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|i| i.get("kind").and_then(Value::as_str) == Some("login"))
        .map(|i| {
            let s = |k: &str| i.get(k).and_then(Value::as_str).unwrap_or("").to_string();
            Login {
                id: s("id"),
                title: s("title"),
                username: s("username"),
                urls: i
                    .get("urls")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                has_password: i.get("has_password").and_then(Value::as_bool) == Some(true),
                modified: s("modified"),
            }
        })
        .collect()
}

/// The logins for this request, best first: the closest path, then the
/// newest, then by title. `username`: only that user's.
pub fn candidates(all: &[Login], r: &Request, username: Option<&str>) -> Vec<Login> {
    let mut hits: Vec<(usize, &Login)> = all
        .iter()
        .filter(|l| username.is_none_or(|u| l.username == u))
        .filter_map(|l| {
            l.urls
                .iter()
                .filter_map(|u| fits(u, r))
                .max()
                .map(|n| (n, l))
        })
        .collect();
    hits.sort_by(|(a, x), (b, y)| {
        b.cmp(a)
            .then_with(|| y.modified.cmp(&x.modified))
            .then_with(|| x.title.to_lowercase().cmp(&y.title.to_lowercase()))
    });
    hits.into_iter().map(|(_, l)| l.clone()).collect()
}

/// A value git can take: no newline, no NUL.
fn sendable(v: &str) -> bool {
    !v.contains(['\n', '\0'])
}

pub fn main(argv: &[String]) -> ExitCode {
    let op = argv.first().map(String::as_str).unwrap_or("");
    if op == "ask" {
        ask_here();
        return ExitCode::SUCCESS;
    }
    if !matches!(op, "get" | "store") {
        // erase, capability, anything newer: nothing to do
        drain();
        return ExitCode::SUCCESS;
    }
    let mut input = Zeroizing::new(String::new());
    let _ = std::io::stdin().take(1 << 20).read_to_string(&mut input);
    let r = parse_request(&input);
    if r.protocol.is_empty() || r.host.is_empty() {
        return ExitCode::SUCCESS;
    }
    if op == "get" {
        if let Some(answer) = get(&r) {
            let mut out = std::io::stdout().lock();
            let _ = out.write_all(answer.as_bytes()).and_then(|_| out.flush());
        }
    } else {
        store(&r);
    }
    ExitCode::SUCCESS
}

fn drain() {
    let _ = std::io::copy(&mut std::io::stdin().take(1 << 20), &mut std::io::sink());
}

fn reveal(id: &str, field: &str) -> Option<Zeroizing<String>> {
    let mut v = client::call("reveal", json!({"id": id, "field": field}), client::FAST);
    match v.get_mut("value").map(Value::take) {
        Some(Value::String(s)) => Some(Zeroizing::new(s)),
        _ => None,
    }
}

/// `get`: the answer lines, or `None` (git goes on without Safe).
fn get(r: &Request) -> Option<Zeroizing<String>> {
    let mut list = client::call("list", json!({"kind": "login"}), client::FAST);
    if list.get("error").and_then(Value::as_str) == Some("locked") {
        if crate::unlock_ask().get("ok").and_then(Value::as_bool) != Some(true) {
            return None;
        }
        list = client::call("list", json!({"kind": "login"}), client::FAST);
    }
    let all = logins(&list);
    for l in candidates(&all, r, r.username.as_deref()) {
        if !l.has_password || l.username.is_empty() || !sendable(&l.username) {
            continue;
        }
        let Some(pw) = reveal(&l.id, "password") else {
            continue;
        };
        if pw.is_empty() || !sendable(&pw) {
            continue;
        }
        return Some(Zeroizing::new(format!(
            "username={}\npassword={}\n",
            l.username,
            pw.as_str()
        )));
    }
    None
}

/// `store`: save or update, only with a yes.
fn store(r: &Request) {
    let (Some(user), Some(pw)) = (r.username.as_deref(), r.password.as_ref()) else {
        return;
    };
    if r.token || user.is_empty() || pw.is_empty() {
        return;
    }
    let list = client::call("list", json!({"kind": "login"}), client::FAST);
    if list.get("ok").and_then(Value::as_bool) != Some(true) {
        // locked, not set up, no daemon: git's login stays git's
        return;
    }
    let mine = candidates(&logins(&list), r, Some(user));
    for l in &mine {
        if reveal(&l.id, "password").is_some_and(|x| *x == **pw) {
            return;
        }
    }
    let host = clean_host(&r.host, &r.protocol);
    match mine.as_slice() {
        [] => {
            let q = format!("Save the login for {host} ({user}) in Safe?");
            if !confirm(&q) {
                return;
            }
            let path = clean_path(&r.path);
            let url = if path.is_empty() {
                format!("{}://{host}", r.protocol)
            } else {
                format!("{}://{host}/{path}", r.protocol)
            };
            let args = json!({
                "kind": "login",
                "title": host,
                "username": user,
                "url": [url],
                "password_value": pw.as_str(),
            });
            let _ = client::call("add", args, client::SLOW);
        }
        [one] => {
            let q = format!(
                "Update the password of \u{201c}{}\u{201d} ({user} on {host}) in Safe?",
                one.title
            );
            if confirm(&q) {
                let args = json!({"id": one.id, "password_value": pw.as_str()});
                let _ = client::call("edit", args, client::SLOW);
            }
        }
        // several logins with this host and username: Safe can't tell which
        _ => {}
    }
}

/// The answer file the prompt writes `yes` into.
fn answer_file() -> std::path::PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!("ewe-safe-answer-{}-{nanos}", std::process::id()))
}

/// Yes or no from the user: the test hook, the terminal, or a window.
fn confirm(question: &str) -> bool {
    if let Ok(cmd) = std::env::var("EWE_SAFE_CONFIRM_CMD") {
        let mut c = Command::new("sh");
        c.arg("-c").arg(cmd);
        return ask_with(c, question);
    }
    if std::env::var("GIT_TERMINAL_PROMPT").as_deref() != Ok("0")
        && let Some(yes) = ask_tty(question)
    {
        return yes;
    }
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        let me = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "ewe-safe".into());
        let mut c = Command::new("kitty");
        c.args([
            // the unlock prompt's class: ewe floats it as a small card
            "--class",
            "ewe-safe-unlock",
            "--title",
            "Safe",
            "-e",
            &me,
            "git-credential",
            "ask",
        ]);
        return ask_with(c, question);
    }
    false
}

/// The terminal git runs in, when there is one.
fn ask_tty(question: &str) -> Option<bool> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()?;
    let mut w = tty.try_clone().ok()?;
    write!(w, "{question} [y/N] ").ok()?;
    w.flush().ok()?;
    let mut line = String::new();
    BufReader::new(tty).read_line(&mut line).ok()?;
    Some(matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES"))
}

/// Run a prompt that writes `yes` into `$EWE_SAFE_ANSWER`; wait for it.
fn ask_with(mut c: Command, question: &str) -> bool {
    let answer = answer_file();
    let _ = std::fs::remove_file(&answer);
    let spawned = c
        .env("EWE_SAFE_QUESTION", question)
        .env("EWE_SAFE_ANSWER", &answer)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = spawned else {
        return false;
    };
    let start = Instant::now();
    loop {
        if let Ok(Some(_)) = child.try_wait() {
            break;
        }
        if start.elapsed() > CONFIRM_WAIT {
            let _ = child.kill();
            let _ = child.wait();
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let yes = std::fs::read_to_string(&answer).is_ok_and(|a| a.trim() == "yes");
    let _ = std::fs::remove_file(&answer);
    yes
}

/// `git-credential ask`: the prompt window's own step — the question,
/// y/N on this terminal, the answer into `$EWE_SAFE_ANSWER`.
fn ask_here() {
    let question = std::env::var("EWE_SAFE_QUESTION").unwrap_or_default();
    let Some(answer) = std::env::var_os("EWE_SAFE_ANSWER") else {
        return;
    };
    print!("{question} [y/N] ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let yes = matches!(line.trim(), "y" | "Y" | "yes" | "Yes" | "YES");
    let _ = std::fs::write(answer, if yes { "yes" } else { "no" });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(text: &str) -> Request {
        parse_request(text)
    }

    #[test]
    fn git_sends_key_value_lines() {
        let r = req(
            "capability[]=authtype\nprotocol=HTTPS\nhost=GitHub.com\npath=prj786/ewe-safe.git\nusername=sam\nwwwauth[]=Basic realm=\"GitHub\"\n\nprotocol=ignored\n",
        );
        assert_eq!(
            (
                r.protocol.as_str(),
                r.host.as_str(),
                r.path.as_str(),
                r.username.as_deref()
            ),
            ("https", "github.com", "prj786/ewe-safe.git", Some("sam"))
        );
        assert!(r.password.is_none() && !r.token);
        let r = req("protocol=https\nhost=x\nusername=u\npassword=p=q\n");
        assert_eq!(r.password.as_deref().map(|p| p.as_str()), Some("p=q"));
        assert!(req("protocol=https\nhost=x\npassword_expiry_utc=1\n").token);
        assert!(req("protocol=https\nhost=x\noauth_refresh_token=r\n").token);
        assert!(req("ephemeral=true\n").token && !req("ephemeral=false\n").token);
        let r = req("url=https://sam@git.example.org:8443/team/repo.git\n");
        assert_eq!(
            (r.protocol.as_str(), r.host.as_str(), r.path.as_str()),
            ("https", "git.example.org:8443", "team/repo")
        );
    }

    #[test]
    fn websites_read_as_git_sees_them() {
        let s = |u: &str| site(u, "https").unwrap();
        assert_eq!(
            s("https://GitHub.com/login"),
            Site {
                scheme: "https".into(),
                host: "github.com".into(),
                path: "login".into()
            }
        );
        assert_eq!(s("github.com").scheme, "https");
        assert_eq!(s("https://github.com:443/").host, "github.com");
        assert_eq!(s("http://intranet:80").host, "intranet");
        assert_eq!(
            s("https://git.example.org:8443/a/b.git?x=1#y").host,
            "git.example.org:8443"
        );
        assert_eq!(s("https://git.example.org:8443/a/b.git?x=1#y").path, "a/b");
        assert_eq!(s("https://user:pw@host.example/x").host, "host.example");
        assert_eq!(s("https://[::1]:8080/x").host, "[::1]:8080");
        assert!(site("https://", "https").is_none());
    }

    #[test]
    fn matching_is_strict_on_the_site() {
        let r = req("protocol=https\nhost=github.com\n");
        assert_eq!(fits("https://github.com/login", &r), Some(0));
        assert_eq!(fits("github.com", &r), Some(0));
        for other in [
            "https://gist.github.com",
            "https://www.github.com",
            "https://github.com.evil.example",
            "http://github.com",
            "https://github.com:8443",
            "ssh://github.com",
        ] {
            assert_eq!(fits(other, &r), None, "{other}");
        }
        // with credential.useHttpPath: a path the repository's starts with
        let r = req("protocol=https\nhost=github.com\npath=prj786/ewe-safe.git\n");
        assert_eq!(fits("https://github.com/", &r), Some(0));
        assert_eq!(fits("https://github.com/prj786", &r), Some(6));
        assert_eq!(fits("https://github.com/prj786/ewe-safe", &r), Some(15));
        assert_eq!(fits("https://github.com/prj7", &r), None);
        assert_eq!(fits("https://github.com/login", &r), None);
        let r = req("protocol=https\nhost=git.example.org:8443\n");
        assert_eq!(fits("https://git.example.org:8443/x", &r), Some(0));
        assert_eq!(fits("https://git.example.org/x", &r), None);
    }

    fn login(id: &str, title: &str, user: &str, url: &str, modified: &str) -> Login {
        Login {
            id: id.into(),
            title: title.into(),
            username: user.into(),
            urls: vec!["https://unrelated.example".into(), url.into()],
            has_password: true,
            modified: modified.into(),
        }
    }

    #[test]
    fn the_best_login_comes_first() {
        let all = vec![
            login(
                "a",
                "GitHub",
                "sam",
                "https://github.com/login",
                "2026-01-01T00:00:00Z",
            ),
            login(
                "b",
                "GitHub work",
                "sam-work",
                "https://github.com",
                "2026-09-01T00:00:00Z",
            ),
            login(
                "c",
                "Team",
                "bot",
                "https://github.com/prj786",
                "2025-01-01T00:00:00Z",
            ),
            login(
                "d",
                "Gist",
                "sam",
                "https://gist.github.com",
                "2026-10-01T00:00:00Z",
            ),
        ];
        let ids = |r: &Request, u: Option<&str>| {
            candidates(&all, r, u)
                .into_iter()
                .map(|l| l.id)
                .collect::<Vec<_>>()
        };
        let r = req("protocol=https\nhost=github.com\n");
        assert_eq!(ids(&r, None), ["b", "a", "c"], "the newest first");
        assert_eq!(ids(&r, Some("sam")), ["a"], "git's username picks");
        let r = req("protocol=https\nhost=github.com\npath=prj786/ewe-safe.git\n");
        assert_eq!(ids(&r, None), ["c", "b"], "the closest path first");
        let r = req("protocol=https\nhost=gitlab.com\n");
        assert!(ids(&r, None).is_empty());
    }

    #[test]
    fn list_replies_become_logins_notes_left_out() {
        let v = json!({"ok": true, "items": [
            {"id": "1", "kind": "login", "title": "A", "username": "u", "urls": ["https://a.example"], "has_password": true, "modified": "2026-10-14T16:02:11Z"},
            {"id": "2", "kind": "note", "title": "N", "username": "", "urls": [], "has_password": false, "modified": null},
        ]});
        let l = logins(&v);
        assert_eq!(l.len(), 1);
        assert_eq!((l[0].id.as_str(), l[0].urls.len()), ("1", 1));
        assert!(logins(&json!({"ok": false, "error": "locked"})).is_empty());
        assert!(sendable("p@ss w=rd") && !sendable("a\nb") && !sendable("a\0b"));
    }
}
