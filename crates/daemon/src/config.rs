//! Where things are, and the settings: ewe.conf `[safe]` through `ewe-conf`
//! (house rule 1: never written here directly), and this machine's own
//! record, `machine.json`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::log;

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

    pub fn machine(&self) -> PathBuf {
        self.state.join("machine.json")
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
        }
    }
}

impl Settings {
    fn from_table(t: &Value) -> Settings {
        let d = Settings::default();
        let num = |k: &str, dflt: u64| t.get(k).and_then(Value::as_u64).unwrap_or(dflt);
        let flag = |k: &str, dflt: bool| t.get(k).and_then(Value::as_bool).unwrap_or(dflt);
        Settings {
            lock_after_minutes: num("lock_after_minutes", d.lock_after_minutes),
            lock_on_screen_lock: flag("lock_on_screen_lock", d.lock_on_screen_lock),
            lock_on_sleep: flag("lock_on_sleep", d.lock_on_sleep),
            clipboard_clear_seconds: num("clipboard_clear_seconds", d.clipboard_clear_seconds),
            generator_length: num("generator_length", d.generator_length as u64) as usize,
            generator_words: num("generator_words", d.generator_words as u64) as usize,
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
