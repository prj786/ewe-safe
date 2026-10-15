//! `read`, `run`, `inject`, `git-credential` and the socket's `resolve`
//! with the real binaries (docs/PROTOCOL.md, "References"). Each test gets a
//! sandbox like tests/e2e.rs: its own XDG directories and HOME, a fake
//! `ewe-conf`, cheap key derivation, no logind; git runs with no system or
//! global config and no terminal prompt. Never the live safe, ewe.conf,
//! keyring or git config.
//!
//! Run from the workspace (`cargo test`), which builds both binaries.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const MASTER: &str = "correct horse battery";
const GH_PW: &str = "gh-Pw-7781!";
const TOKEN: &str = "ghp_token_5521";
const R1_PW: &str = "remedium-1-pw";
const R2_PW: &str = "remedium-2-pw";
const ACDC_PW: &str = "for those about";
const TOP_PW: &str = "top-level-pw";

static N: AtomicUsize = AtomicUsize::new(0);

fn cli_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ewe-safe"))
}

fn write_exec(path: &Path, body: &str) {
    std::fs::write(path, body).expect("script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}

struct Sandbox {
    root: PathBuf,
    run: PathBuf,
    extra: Vec<(String, String)>,
    daemon: Option<Child>,
}

impl Sandbox {
    fn new(name: &str) -> Sandbox {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!("safe-scr-{}-{n}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // the socket path must stay short (sun_path)
        let run = PathBuf::from(format!("/tmp/ss-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        for d in ["bin", "state", "config", "data", "home", "work"] {
            std::fs::create_dir_all(root.join(d)).expect("mkdir");
        }
        std::fs::create_dir_all(&run).expect("mkdir");
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        write_exec(
            &root.join("bin/ewe-conf"),
            "#!/bin/sh\n[ \"$1\" = get ] && { echo '{\"error\": \"no-key\"}'; exit 1; }\nexit 0\n",
        );
        let mut s = Sandbox {
            root,
            run,
            extra: Vec::new(),
            daemon: None,
        };
        s.start();
        s
    }

    fn env(&self) -> Vec<(String, String)> {
        let p = |d: &str| self.root.join(d).display().to_string();
        let mut env = vec![
            ("HOME".into(), p("home")),
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", self.root.join("bin").display()),
            ),
            ("XDG_RUNTIME_DIR".into(), self.run.display().to_string()),
            ("XDG_STATE_HOME".into(), p("state")),
            ("XDG_CONFIG_HOME".into(), p("config")),
            ("XDG_DATA_HOME".into(), p("data")),
            ("EWE_SAFE_NO_LOGIND".into(), "1".into()),
            ("EWE_SAFE_KDF_ITERATIONS".into(), "2".into()),
            // git: nothing from this machine's config, never a prompt
            ("GIT_CONFIG_NOSYSTEM".into(), "1".into()),
            ("GIT_TERMINAL_PROMPT".into(), "0".into()),
            // a question nobody answers is a no
            ("EWE_SAFE_CONFIRM_CMD".into(), "true".into()),
        ];
        for (k, v) in &self.extra {
            env.retain(|(x, _)| x != k);
            env.push((k.clone(), v.clone()));
        }
        env
    }

    fn start(&mut self) {
        let log = std::fs::File::create(self.root.join("daemon.log")).expect("log");
        let child = Command::new(cli_exe().with_file_name("ewe-safed"))
            .env_clear()
            .envs(self.env())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .expect("ewe-safed (run `cargo build --workspace` first)");
        self.daemon = Some(child);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(10) {
            if self.cli(&["ping"])["ok"] == true {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!("the daemon didn't answer");
    }

    /// stdout, stderr and the exit code.
    fn raw(&self, args: &[&str], stdin: &str) -> (String, String, i32) {
        let mut child = Command::new(cli_exe())
            .args(args)
            .env_clear()
            .envs(self.env())
            .current_dir(self.root.join("work"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("ewe-safe");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("wait");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    fn cli_in(&self, args: &[&str], stdin: &str) -> Value {
        let (out, _, code) = self.raw(args, stdin);
        assert_eq!(code, 0, "{args:?} exits 0");
        serde_json::from_str(&out).unwrap_or_else(|_| panic!("{args:?} printed {out:?}"))
    }

    fn cli(&self, args: &[&str]) -> Value {
        self.cli_in(args, "")
    }

    fn ok(&self, args: &[&str]) -> Value {
        let v = self.cli(args);
        assert_eq!(v["ok"], true, "{args:?}: {v}");
        v
    }

    fn add(&self, folder: &str, title: &str, user: &str, url: &str, pw: &str) -> String {
        let v = self.cli_in(
            &[
                "add",
                "--title",
                title,
                "--username",
                user,
                "--url",
                url,
                "--folder",
                folder,
                "--password-stdin",
            ],
            &format!("{pw}\n"),
        );
        assert_eq!(v["ok"], true, "{v}");
        v["item_id"].as_str().unwrap().to_string()
    }

    /// The safe the tests read: GitHub in Personal (with an API token in
    /// its notes' place: a custom field isn't settable from the CLI, so the
    /// token is a second login), two github.com in Remedium, a title with a
    /// slash, one at the top.
    fn fill(&self) -> String {
        let init = self.cli_in(
            &["init", "--place", "local"],
            &format!("{MASTER}\n{MASTER}\n"),
        );
        assert_eq!(init["ok"], true, "{init}");
        let gh = self.add(
            "Personal",
            "GitHub",
            "sam",
            "https://github.com/login",
            GH_PW,
        );
        self.add(
            "Personal",
            "GitHub token",
            "sam",
            "https://api.github.com",
            TOKEN,
        );
        self.add("Remedium", "github.com", "r1", "https://github.com", R1_PW);
        self.add("Remedium", "github.com", "r2", "https://github.com", R2_PW);
        self.add("Music", "AC/DC", "angus", "https://acdc.example", ACDC_PW);
        self.add("", "Top", "me", "https://top.example", TOP_PW);
        gh
    }

    fn git(&self, args: &[&str], stdin: &str) -> (String, i32) {
        let mut child = Command::new("git")
            .args(args)
            .env_clear()
            .envs(self.env())
            .current_dir(self.root.join("work"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("git");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("git");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    fn daemon_log(&self) -> String {
        std::fs::read_to_string(self.root.join("daemon.log")).unwrap_or_default()
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        if let Some(mut c) = self.daemon.take() {
            // by pid, never by name: a real ewe-safed runs on dev machines
            let _ = Command::new("kill")
                .arg("-TERM")
                .arg(c.id().to_string())
                .status();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.run);
        if std::env::var_os("SAFE_E2E_KEEP").is_none() {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }
}

#[test]
fn read_prints_the_bare_value_and_never_guesses() {
    let mut s = Sandbox::new("read");
    let gh = s.fill();

    let read = |s: &Sandbox, r: &str| s.raw(&["read", r], "");
    assert_eq!(
        read(&s, "safe://Personal/GitHub/password"),
        (format!("{GH_PW}\n"), String::new(), 0)
    );
    assert_eq!(read(&s, "safe://personal/github/username").0, "sam\n");
    assert_eq!(
        read(&s, "safe://GitHub/url").0,
        "https://github.com/login\n"
    );
    assert_eq!(
        read(&s, &format!("safe://{gh}/password")).0,
        format!("{GH_PW}\n")
    );
    assert_eq!(
        read(&s, "safe://Music/AC%2FDC/password").0,
        format!("{ACDC_PW}\n")
    );
    assert_eq!(read(&s, "safe:///Top/password").0, format!("{TOP_PW}\n"));
    assert_eq!(
        s.raw(&["read", "-n", "safe://Top/username"], "").0,
        "me",
        "-n: no newline"
    );

    // two items fit: nothing on stdout, exit 1, the reason on stderr
    let (out, err, code) = read(&s, "safe://Remedium/github.com/password");
    assert_eq!((out.as_str(), code), ("", 1));
    assert!(err.contains("2 items"), "{err}");
    let v = s.cli(&["read", "safe://Remedium/github.com/password", "--json"]);
    assert_eq!(v["error"], "ambiguous");
    assert!(
        !v.to_string().contains(R1_PW) && !v.to_string().contains(R2_PW),
        "no value in an error"
    );
    assert_eq!(
        s.cli(&["read", "safe://Personal/Nope/password", "--json"])["error"],
        "not-found"
    );
    assert_eq!(
        s.cli(&["read", "safe://Personal/GitHub/pin", "--json"])["error"],
        "not-found"
    );
    assert_eq!(
        s.cli(&["read", "op://Personal/GitHub/password", "--json"])["error"],
        "bad-request"
    );
    assert_eq!(read(&s, "safe://Personal/Nope/password").2, 1);

    let v = s.ok(&["read", "safe://Personal/GitHub/password", "--json"]);
    assert_eq!(
        (v["value"].clone(), v["item_id"].clone(), v["field"].clone()),
        (json!(GH_PW), json!(gh), json!("password"))
    );

    // locked: the unlock prompt once, then the value
    s.ok(&["lock"]);
    let me = cli_exe().display().to_string();
    s.extra.push((
        "EWE_SAFE_ASK_CMD".into(),
        format!("printf '{MASTER}\\n' | {me} unlock"),
    ));
    assert_eq!(read(&s, "safe://Top/password").0, format!("{TOP_PW}\n"));
    s.ok(&["lock"]);
    s.extra = vec![("EWE_SAFE_ASK_CMD".into(), "true".into())];
    let (out, err, code) = s.raw(&["read", "safe://Top/password"], "");
    assert_eq!((out.as_str(), code), ("", 1));
    assert!(err.contains("still locked"), "{err}");
}

#[test]
fn the_socket_resolves_and_keeps_its_envelope() {
    let s = Sandbox::new("socket");
    s.fill();
    let mut c = UnixStream::connect(s.run.join("ewe-safe.sock")).expect("socket");
    let mut r = BufReader::new(c.try_clone().unwrap());
    let mut ask = |req: Value| -> Value {
        writeln!(c, "{req}").unwrap();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    };
    let v =
        ask(json!({"v": 1, "id": 41, "verb": "resolve", "args": {"ref": "safe://Top/password"}}));
    assert_eq!(
        (v["id"].clone(), v["value"].clone()),
        (json!(41), json!(TOP_PW))
    );
    assert!(v["item_id"].is_string());
    let v = ask(json!({"v": 1, "id": 42, "verb": "resolve", "args": {}}));
    assert_eq!(v["error"], "bad-request");
    let v = ask(
        json!({"v": 1, "id": 43, "verb": "resolve", "args": {"ref": "safe://github.com/password"}}),
    );
    assert_eq!(v["error"], "ambiguous");
    assert!(v["hint"].as_str().unwrap().contains('-'), "the ids: {v}");
    drop(ask);
    // the daemon never logs a value or a reference
    let log = s.daemon_log();
    for secret in [TOP_PW, R1_PW, "safe://"] {
        assert!(!log.contains(secret), "{secret:?} in the log");
    }
}

#[test]
fn run_gives_the_child_the_values_and_its_exit_code() {
    let s = Sandbox::new("run");
    s.fill();
    let work = s.root.join("work");
    std::fs::write(
        work.join(".env"),
        "# for the test\nexport GH=safe://Personal/GitHub/password\nURL=\"https://sam:{{ safe:///Top/password }}@host\"\nPLAIN=kept\n",
    )
    .unwrap();
    let mut s = s;
    s.extra
        .push(("FROM_SHELL".into(), "safe://Music/AC%2FDC/password".into()));
    let (out, _, code) = s.raw(
        &[
            "run",
            "--env-file",
            ".env",
            "--",
            "sh",
            "-c",
            "printf '%s|%s|%s|%s' \"$GH\" \"$URL\" \"$PLAIN\" \"$FROM_SHELL\"; exit 7",
        ],
        "",
    );
    assert_eq!(code, 7, "the child's code");
    assert_eq!(
        out,
        format!("{GH_PW}|https://sam:{TOP_PW}@host|kept|{ACDC_PW}")
    );

    // a reference that doesn't resolve: the command never runs
    std::fs::write(work.join("bad.env"), "X=safe://Nope/password\n").unwrap();
    let (out, err, code) = s.raw(
        &["run", "--env-file=bad.env", "--", "sh", "-c", "echo ran"],
        "",
    );
    assert_eq!((out.as_str(), code), ("", 125));
    assert!(err.contains("X:"), "{err}");
    assert_eq!(s.raw(&["run", "--", "no-such-command-here"], "").2, 127);
    assert_eq!(
        s.raw(&["run", "--env-file", "missing.env", "--", "true"], "")
            .2,
        125
    );
    assert_eq!(s.raw(&["run"], "").2, 125);
}

#[test]
fn inject_fills_a_template_and_writes_it_private() {
    let s = Sandbox::new("inject");
    s.fill();
    let work = s.root.join("work");
    std::fs::write(
        work.join("config.tpl"),
        "user = {{ safe://Personal/GitHub/username }}\npass = {{safe://Personal/GitHub/password}}\nname = {{ name }}\n",
    )
    .unwrap();
    let want = format!("user = sam\npass = {GH_PW}\nname = {{{{ name }}}}\n");
    let (out, _, code) = s.raw(&["inject", "-i", "config.tpl"], "");
    assert_eq!((out.as_str(), code), (want.as_str(), 0));
    // stdin in, stdout out
    let (out, _, code) = s.raw(&["inject"], "t={{ safe:///Top/password }}");
    assert_eq!((out, code), (format!("t={TOP_PW}"), 0));

    let v = s.ok(&["inject", "-i", "config.tpl", "-o", "config.ini"]);
    assert_eq!(v["references"], 2);
    let file = work.join("config.ini");
    assert_eq!(v["file"], file.display().to_string());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), want);
    let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    // one bad reference: nothing written
    std::fs::write(
        work.join("bad.tpl"),
        "a={{ safe://Remedium/github.com/password }}\n",
    )
    .unwrap();
    let v = s.cli(&["inject", "-i", "bad.tpl", "-o", "bad.out"]);
    assert_eq!(v["error"], "ambiguous");
    assert!(!work.join("bad.out").exists());
    let (out, _, code) = s.raw(&["inject", "--in-file=bad.tpl"], "");
    assert_eq!((out.as_str(), code), ("", 1));
}

/// `git credential fill` with Safe as the helper, in a throwaway repo.
#[test]
fn git_takes_its_login_from_safe() {
    let s = Sandbox::new("git");
    s.fill();
    assert_eq!(s.git(&["init", "-q"], "").1, 0);
    let helper = format!("!{} git-credential", cli_exe().display());
    assert_eq!(s.git(&["config", "credential.helper", &helper], "").1, 0);
    let fill = |what: &str| s.git(&["credential", "fill"], what);

    // two github.com logins and GitHub: git's username picks
    let (out, code) = fill("protocol=https\nhost=github.com\nusername=sam\n\n");
    assert_eq!(code, 0);
    assert!(out.contains(&format!("password={GH_PW}\n")), "{out}");
    let (out, _) = fill("protocol=https\nhost=github.com\nusername=r2\n\n");
    assert!(out.contains(&format!("password={R2_PW}\n")), "{out}");
    // no username: one of github.com's (the newest: the unit tests), with
    // its own password, never another site's
    let (out, _) = fill("protocol=https\nhost=github.com\n\n");
    assert!(
        [("sam", GH_PW), ("r1", R1_PW), ("r2", R2_PW)]
            .iter()
            .any(|(u, p)| out.contains(&format!("username={u}\npassword={p}\n"))),
        "{out}"
    );
    // strict: nothing for a look-alike host, http, or another port
    for other in [
        "protocol=https\nhost=github.com.evil.example\n\n",
        "protocol=http\nhost=github.com\n\n",
        "protocol=https\nhost=github.com:8443\n\n",
        "protocol=https\nhost=gitlab.com\n\n",
    ] {
        let (out, code) = fill(other);
        assert!(code != 0 && !out.contains("password="), "{other:?}: {out}");
    }

    // store: a new login, saved only with a yes
    let new = "protocol=https\nhost=git.example.test\nusername=dev\npassword=new-pw-1\n\n";
    s.git(&["credential", "approve"], new);
    assert_eq!(
        fill("protocol=https\nhost=git.example.test\n\n").1,
        128,
        "no: not saved"
    );
    let mut s = s;
    s.extra.push((
        "EWE_SAFE_CONFIRM_CMD".into(),
        "echo yes > \"$EWE_SAFE_ANSWER\"".into(),
    ));
    s.git(&["credential", "approve"], new);
    let (out, _) = s.git(
        &["credential", "fill"],
        "protocol=https\nhost=git.example.test\n\n",
    );
    assert!(out.contains("username=dev\npassword=new-pw-1\n"), "{out}");
    let saved = s.ok(&["match", "--query", "git.example.test"])["items"][0].clone();
    assert_eq!(saved["title"], "git.example.test");
    assert_eq!(saved["urls"], json!(["https://git.example.test"]));

    // an update asks too; the same password again is no change at all
    s.git(
        &["credential", "approve"],
        "protocol=https\nhost=git.example.test\nusername=dev\npassword=new-pw-2\n\n",
    );
    let (out, _) = s.git(
        &["credential", "fill"],
        "protocol=https\nhost=git.example.test\n\n",
    );
    assert!(out.contains("password=new-pw-2\n"), "{out}");
    // an OAuth token is never stored
    s.git(
        &["credential", "approve"],
        "protocol=https\nhost=tokens.example.test\nusername=bot\npassword=gho_x\npassword_expiry_utc=4102444800\n\n",
    );
    assert_eq!(
        s.ok(&["match", "--query", "tokens.example.test"])["items"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|i| i["title"] == "tokens.example.test")
            .count(),
        0
    );
    // erase (git's reject) never deletes from Safe
    s.git(
        &["credential", "reject"],
        "protocol=https\nhost=git.example.test\nusername=dev\npassword=new-pw-2\n\n",
    );
    let (out, _) = s.git(
        &["credential", "fill"],
        "protocol=https\nhost=git.example.test\n\n",
    );
    assert!(out.contains("password=new-pw-2\n"), "still there: {out}");

    // locked: the prompt opens, then the login comes
    s.ok(&["lock"]);
    let me = cli_exe().display().to_string();
    s.extra.push((
        "EWE_SAFE_ASK_CMD".into(),
        format!("printf '{MASTER}\\n' | {me} unlock"),
    ));
    let (out, _) = s.git(
        &["credential", "fill"],
        "protocol=https\nhost=github.com\nusername=sam\n\n",
    );
    assert!(out.contains(&format!("password={GH_PW}\n")), "{out}");
}
