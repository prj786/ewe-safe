//! Where things are, and the settings: ewe.conf `[safe]` through `ewe-conf`
//! (house rule 1: never written here directly), and this machine's own
//! record, `machine.json`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::log;

pub const SSH_SOCKET: &str = "ewe-safe-ssh.sock";

pub struct Paths {
    /// `$XDG_STATE_HOME/ewe/safe`: the sync engine's files and `machine.json`.
    pub state: PathBuf,
    /// `$XDG_RUNTIME_DIR`: the socket, the clipboard gate's marker.
    pub runtime: PathBuf,
    /// `$XDG_DATA_HOME/ewe/safe`: a This-computer safe, unless told otherwise.
    pub data: PathBuf,
}

fn xdg(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let home = std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default();
            home.join(fallback)
        })
}

impl Paths {
    pub fn from_env() -> Paths {
        let uid = unsafe { libc::getuid() };
        Paths {
            state: safe_store::default_dir(),
            runtime: std::env::var_os("XDG_RUNTIME_DIR")
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}"))),
            data: xdg("XDG_DATA_HOME", ".local/share").join("ewe/safe"),
        }
    }

    pub fn socket(&self) -> PathBuf {
        self.runtime.join("ewe-safe.sock")
    }

    /// The SSH agent's socket (agent.rs).
    pub fn ssh_socket(&self) -> PathBuf {
        self.runtime.join(SSH_SOCKET)
    }

    /// `$XDG_STATE_HOME/ewe/safe/ssh-public.json`: the agent's keys while
    /// the safe is locked (public keys and their names only).
    pub fn ssh_public(&self) -> PathBuf {
        self.state.join("ssh-public.json")
    }

    pub fn machine(&self) -> PathBuf {
        self.state.join("machine.json")
    }

    /// docs/SYSTEM.md §2: W under the login password.
    pub fn login_key(&self) -> PathBuf {
        self.state.join(safe_login::LOGIN_KEY)
    }

    /// The master password under W (login unlock on).
    pub fn master_wrap(&self) -> PathBuf {
        self.state.join(safe_login::MASTER_WRAP)
    }

    /// The app secrets under W (Safe is the keyring).
    pub fn keyring(&self) -> PathBuf {
        self.state.join(safe_login::KEYRING)
    }

    /// Present = this user adopted Safe as the keyring; read by
    /// `pam_ewe_safe.so` to skip gnome-keyring at login.
    pub fn keyring_marker(&self) -> PathBuf {
        self.state.join("keyring.on")
    }

    pub fn default_local(&self) -> PathBuf {
        self.data.join("passwords.kdbx")
    }
}

/// ewe.conf `[safe]`, with PLAN.md §12's defaults.
#[derive(Clone, Debug, PartialEq)]
pub struct Settings {
    pub lock_after_minutes: u64,
    pub lock_on_screen_lock: bool,
    pub lock_on_sleep: bool,
    pub clipboard_clear_seconds: u64,
    pub generator_length: usize,
    pub generator_words: usize,
    /// `ssh_agent`: the agent answers (`ewe-safe ssh enable`); off, it
    /// lists no key and signs nothing.
    pub ssh_agent: bool,
    /// `ssh_confirm`: `first-use` | `every-time` | `never`.
    pub ssh_confirm: String,
    /// `unlock_at_login`: the key carried in the login keyring also unlocks the safe (not
    /// only the keyring), when login unlock is on (docs/SYSTEM.md §2).
    pub unlock_at_login: bool,
    /// `confirm_cards`: filling a card (the browser's `fields`) needs a
    /// password typed in the last 5 minutes (docs/SYSTEM.md D5).
    pub confirm_cards: bool,
    /// `place` and `location`: where the safe lives, as the machine that
    /// set it up recorded it. ewe-conf syncs them, so a machine that isn't
    /// set up yet knows which safe to offer (PLAN.md §12, the new machine).
    pub place: Option<String>,
    pub location: Option<String>,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            lock_after_minutes: 30,
            lock_on_screen_lock: true,
            lock_on_sleep: true,
            clipboard_clear_seconds: 30,
            generator_length: 20,
            generator_words: 5,
            ssh_agent: false,
            ssh_confirm: CONFIRM_FIRST_USE.to_string(),
            unlock_at_login: true,
            confirm_cards: true,
            place: None,
            location: None,
        }
    }
}

pub const CONFIRM_FIRST_USE: &str = "first-use";
pub const CONFIRMS: [&str; 3] = [CONFIRM_FIRST_USE, "every-time", "never"];

/// A boolean as JSON or as text ("true", "yes", "on", "1").
fn truthy(v: Option<&Value>, dflt: bool) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(t)) => match t.trim().to_lowercase().as_str() {
            "true" | "yes" | "on" | "1" => true,
            "false" | "no" | "off" | "0" => false,
            _ => dflt,
        },
        Some(Value::Number(n)) => n.as_u64().map_or(dflt, |n| n != 0),
        _ => dflt,
    }
}

impl Settings {
    fn from_table(t: &Value) -> Settings {
        let d = Settings::default();
        let num = |k: &str, dflt: u64| t.get(k).and_then(Value::as_u64).unwrap_or(dflt);
        let flag = |k: &str, dflt: bool| t.get(k).and_then(Value::as_bool).unwrap_or(dflt);
        let text = |k: &str| {
            t.get(k)
                .and_then(Value::as_str)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
        };
        Settings {
            lock_after_minutes: num("lock_after_minutes", d.lock_after_minutes),
            lock_on_screen_lock: flag("lock_on_screen_lock", d.lock_on_screen_lock),
            lock_on_sleep: flag("lock_on_sleep", d.lock_on_sleep),
            clipboard_clear_seconds: num("clipboard_clear_seconds", d.clipboard_clear_seconds),
            generator_length: num("generator_length", d.generator_length as u64) as usize,
            generator_words: num("generator_words", d.generator_words as u64) as usize,
            ssh_agent: truthy(t.get("ssh_agent"), d.ssh_agent),
            ssh_confirm: t
                .get("ssh_confirm")
                .and_then(Value::as_str)
                .map(|c| c.trim().to_lowercase())
                .filter(|c| CONFIRMS.contains(&c.as_str()))
                .unwrap_or(d.ssh_confirm),
            unlock_at_login: truthy(t.get("unlock_at_login"), d.unlock_at_login),
            confirm_cards: truthy(t.get("confirm_cards"), d.confirm_cards),
            place: text("place"),
            location: text("location"),
        }
    }

    /// `ewe-conf get safe`; anything missing or unreadable is a default.
    pub fn read() -> Settings {
        match ewe_conf(&["get", "safe"]) {
            Some(out) => match serde_json::from_slice::<Value>(&out) {
                Ok(t) if t.is_object() && t.get("error").is_none() => Settings::from_table(&t),
                _ => Settings::default(),
            },
            None => Settings::default(),
        }
    }
}

/// Store a `[safe]` key through `ewe-conf` (for the other machines: where
/// the safe lives). A failure is logged, never fatal: `machine.json` is what
/// this machine goes by.
pub fn conf_set(key: &str, value: &str) {
    if ewe_conf(&["set", &format!("safe.{key}"), value]).is_none() {
        log(&format!("ewe-conf could not store safe.{key}"));
    }
}

/// [`conf_set`], answering whether `ewe-conf` stored it.
pub fn conf_store(key: &str, value: &str) -> bool {
    let ok = ewe_conf(&["set", &format!("safe.{key}"), value]).is_some();
    if !ok {
        log(&format!("ewe-conf could not store safe.{key}"));
    }
    ok
}

fn ewe_conf(args: &[&str]) -> Option<Vec<u8>> {
    run("ewe-conf", args, Duration::from_secs(10))
}

/// Run a program as argv (never a shell); its stdout if it exits 0 in time.
pub fn run(program: &str, args: &[&str], limit: Duration) -> Option<Vec<u8>> {
    run_env(program, args, &[], limit)
}

pub fn run_env(
    program: &str,
    args: &[&str],
    envs: &[(String, String)],
    limit: Duration,
) -> Option<Vec<u8>> {
    let mut child = Command::new(program)
        .args(args)
        .envs(envs.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = Vec::new();
                child.stdout.take()?.read_to_end(&mut out).ok()?;
                return status.success().then_some(out);
            }
            Ok(None) if start.elapsed() < limit => std::thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
}

/// This machine's record: which place it opened. Never synced (the place
/// and location also go to ewe.conf, for the other machines).
#[derive(Clone, Debug, PartialEq)]
pub struct Machine {
    pub kind: String,
    pub location: String,
    pub set_up_at: String,
}

impl Machine {
    pub fn read(path: &Path) -> Option<Machine> {
        let v: Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        let place = v.get("place")?;
        Some(Machine {
            kind: place.get("kind")?.as_str()?.to_string(),
            location: place.get("location")?.as_str()?.to_string(),
            set_up_at: v
                .get("set_up_at")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        let v = json!({
            "place": {"kind": self.kind, "location": self.location},
            "set_up_at": self.set_up_at,
        });
        let mut bytes = serde_json::to_vec_pretty(&v).map_err(std::io::Error::other)?;
        bytes.push(b'\n');
        safe_core::atomic::write(path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_take_defaults_for_what_is_missing() {
        let s = Settings::from_table(&json!({"lock_after_minutes": 5, "lock_on_sleep": false}));
        assert_eq!(s.lock_after_minutes, 5);
        assert!(!s.lock_on_sleep);
        assert!(s.lock_on_screen_lock);
        assert_eq!(s.clipboard_clear_seconds, 30);
        assert_eq!(Settings::from_table(&json!({})), Settings::default());
    }

    #[test]
    fn unlock_at_login_defaults_on_and_reads_as_json_or_text() {
        assert!(Settings::default().unlock_at_login);
        assert!(!Settings::from_table(&json!({"unlock_at_login": false})).unlock_at_login);
        assert!(!Settings::from_table(&json!({"unlock_at_login": "off"})).unlock_at_login);
        assert!(Settings::from_table(&json!({})).unlock_at_login);
    }

    #[test]
    fn ssh_settings_read_as_json_or_text() {
        let d = Settings::default();
        assert!(!d.ssh_agent);
        assert_eq!(d.ssh_confirm, "first-use");
        let s = Settings::from_table(&json!({"ssh_agent": true, "ssh_confirm": "Every-Time"}));
        assert!(s.ssh_agent);
        assert_eq!(s.ssh_confirm, "every-time");
        let s = Settings::from_table(&json!({"ssh_agent": "true", "ssh_confirm": "sometimes"}));
        assert!(s.ssh_agent, "a fake ewe-conf stores text");
        assert_eq!(
            s.ssh_confirm, "first-use",
            "an unknown value is the default"
        );
    }

    #[test]
    fn filling_a_card_asks_again_unless_turned_off() {
        assert!(Settings::default().confirm_cards);
        assert!(!Settings::from_table(&json!({"confirm_cards": false})).confirm_cards);
        assert!(!Settings::from_table(&json!({"confirm_cards": "off"})).confirm_cards);
        assert!(Settings::from_table(&json!({"confirm_cards": "maybe"})).confirm_cards);
    }

    #[test]
    fn machine_round_trips() {
        let d = std::env::temp_dir().join(format!("safed-machine-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let m = Machine {
            kind: "nextcloud".into(),
            location: "ewe/safe/passwords.kdbx".into(),
            set_up_at: "2026-10-14T12:00:00Z".into(),
        };
        m.write(&d.join("machine.json")).unwrap();
        assert_eq!(Machine::read(&d.join("machine.json")), Some(m));
        let _ = std::fs::remove_dir_all(&d);
    }
}
