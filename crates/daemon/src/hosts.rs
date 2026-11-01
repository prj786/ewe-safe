//! SSH hosts (docs/GATE.md S24): the ones in ewe.conf
//! (`[[network.ssh.hosts]]`, changed only through `ewe-conf`, house rule 1)
//! and the user's own lines in `~/.ssh/config` (read, never written). Also
//! the small `ssh_config` reader the gate, `takeover` and `connect` share.
//!
//! ewe-conf writes the ewe.conf hosts into a marked block at the end of
//! `~/.ssh/config`; everything outside that block is the user's.

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::config;
use crate::daemon::{Daemon, Fail};

/// The lines ewe-conf puts around its managed block (ewe's `bin/ewe-conf`).
const MANAGED_BEGIN: &str = "# >>> ewe managed hosts";
const MANAGED_END: &str = "# <<< ewe managed hosts";

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_default()
}

pub fn ssh_dir() -> PathBuf {
    home().join(".ssh")
}

pub fn ssh_config_path() -> PathBuf {
    ssh_dir().join("config")
}

/// One `Host` block of an ssh_config file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Block {
    /// The patterns on the `Host` line.
    pub names: Vec<String>,
    /// Its options, in order, the keyword as written.
    pub options: Vec<(String, String)>,
    /// Inside ewe-conf's managed block.
    pub managed: bool,
}

impl Block {
    /// The first value of an option (ssh takes the first one).
    pub fn get(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// One plain name (no wildcard, no `!`): a host a user connects to.
    pub fn single(&self) -> Option<&str> {
        match self.names.as_slice() {
            [n] if plain(n) => Some(n),
            _ => None,
        }
    }
}

/// A host name without ssh's pattern characters.
pub fn plain(name: &str) -> bool {
    !name.is_empty()
        && !name
            .chars()
            .any(|c| matches!(c, '*' | '?' | '!' | ',') || c.is_whitespace())
}

/// What an ssh_config file says.
#[derive(Clone, Debug, Default)]
pub struct SshConfig {
    /// Options before the first `Host` or `Match` (they apply to all).
    pub top: Vec<(String, String)>,
    pub hosts: Vec<Block>,
    /// Every `Include` value, as written.
    pub includes: Vec<String>,
    /// Every `IdentityFile` and `IdentityAgent` value, as written.
    pub identity_files: Vec<String>,
    pub identity_agents: Vec<String>,
}

/// `Key value`, `Key=value`, `Key "quoted value"` → (key, value).
pub fn split_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let cut = line.find(|c: char| c.is_whitespace() || c == '=')?;
    let (k, rest) = line.split_at(cut);
    let mut v = rest.trim_start();
    if let Some(after) = v.strip_prefix('=') {
        v = after.trim_start();
    }
    let v = v.trim();
    let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        &v[1..v.len() - 1]
    } else {
        v
    };
    Some((k.to_string(), v.to_string()))
}

pub fn parse(text: &str) -> SshConfig {
    let mut out = SshConfig::default();
    let mut managed = false;
    // None: top level; Some(None): a Match block; Some(Some(i)): host i
    let mut cur: Option<Option<usize>> = None;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with(MANAGED_BEGIN) {
            managed = true;
            continue;
        }
        if t.starts_with(MANAGED_END) {
            managed = false;
            continue;
        }
        let Some((k, v)) = split_line(t) else {
            continue;
        };
        let key = k.to_ascii_lowercase();
        match key.as_str() {
            "host" => {
                out.hosts.push(Block {
                    names: v.split_whitespace().map(str::to_string).collect(),
                    options: Vec::new(),
                    managed,
                });
                cur = Some(Some(out.hosts.len() - 1));
                continue;
            }
            "match" => {
                cur = Some(None);
                continue;
            }
            "include" => out.includes.push(v.clone()),
            "identityfile" => out.identity_files.push(v.clone()),
            "identityagent" => out.identity_agents.push(v.clone()),
            _ => {}
        }
        match cur {
            None => out.top.push((k, v)),
            Some(Some(i)) => out.hosts[i].options.push((k, v)),
            Some(None) => {}
        }
    }
    out
}

pub fn read_config() -> SshConfig {
    parse(&std::fs::read_to_string(ssh_config_path()).unwrap_or_default())
}

/// A path as ssh reads it: `~/`, `%d` (home) and `${HOME}` expanded;
/// relative ones are under `~/.ssh` (as `Include` takes them). None for a
/// value with other tokens (`%h`, `%r`: per host).
pub fn expand(value: &str) -> Option<PathBuf> {
    let home = home();
    let h = home.to_string_lossy();
    let v = value.trim();
    let v = if let Some(rest) = v.strip_prefix("~/") {
        format!("{h}/{rest}")
    } else if v == "~" {
        h.to_string()
    } else {
        v.replace("%d", &h).replace("${HOME}", &h)
    };
    if v.contains('%') || v.contains("${") || v.is_empty() {
        return None;
    }
    let p = PathBuf::from(v);
    Some(if p.is_absolute() {
        p
    } else {
        ssh_dir().join(p)
    })
}

/// `*` and `?` in a file name (ssh's `Include` takes glob patterns).
fn glob_match(pat: &str, name: &str) -> bool {
    let (p, n): (Vec<char>, Vec<char>) = (pat.chars().collect(), name.chars().collect());
    let (mut pi, mut ni, mut star, mut mark) = (0, 0, None, 0);
    while ni < n.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// The files an `Include` value names (a glob in the last part only).
fn include_files(value: &str) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for word in value.split_whitespace() {
        let Some(p) = expand(word) else { continue };
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if name.contains(['*', '?']) {
            let Some(dir) = p.parent() else { continue };
            let mut found: Vec<PathBuf> = std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .filter(|e| glob_match(&name, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .collect();
            found.sort();
            out.extend(found);
        } else {
            out.push(p);
        }
    }
    out
}

/// `~/.ssh/config` and the files it includes (`skip` excepted: Safe's own
/// file), depth-first as ssh reads them, at most four levels.
pub fn config_and_includes(skip: &Path) -> Vec<(PathBuf, SshConfig)> {
    fn walk(p: &Path, skip: &Path, depth: usize, out: &mut Vec<(PathBuf, SshConfig)>) {
        if depth > 4 || p == skip || out.iter().any(|(q, _)| q == p) {
            return;
        }
        let Ok(text) = std::fs::read_to_string(p) else {
            return;
        };
        let c = parse(&text);
        let inc = c.includes.clone();
        out.push((p.to_path_buf(), c));
        for v in inc {
            for f in include_files(&v) {
                walk(&f, skip, depth + 1, out);
            }
        }
    }
    let mut out = Vec::new();
    walk(&ssh_config_path(), skip, 0, &mut out);
    out
}

// ── ewe.conf's hosts ────────────────────────────────────────────────────

/// One `[[network.ssh.hosts]]` entry: `{host, options: [[k, v], …]}`
/// (anything else it holds is kept as it is).
#[derive(Clone, Debug, PartialEq)]
pub struct EweHost {
    pub host: String,
    pub options: Vec<(String, String)>,
    rest: Map<String, Value>,
}

impl EweHost {
    pub fn new(host: &str) -> EweHost {
        EweHost {
            host: host.to_string(),
            options: Vec::new(),
            rest: Map::new(),
        }
    }

    fn from_json(v: &Value) -> Option<EweHost> {
        let o = v.as_object()?;
        let host = o.get("host")?.as_str()?.to_string();
        let options = o
            .get("options")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|kv| {
                        let kv = kv.as_array()?;
                        Some((
                            kv.first()?.as_str()?.to_string(),
                            kv.get(1).and_then(Value::as_str).unwrap_or("").to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut rest = o.clone();
        rest.remove("host");
        rest.remove("options");
        Some(EweHost {
            host,
            options,
            rest,
        })
    }

    fn to_json(&self) -> Value {
        let mut o = self.rest.clone();
        o.insert("host".into(), json!(self.host));
        o.insert(
            "options".into(),
            json!(
                self.options
                    .iter()
                    .map(|(k, v)| json!([k, v]))
                    .collect::<Vec<_>>()
            ),
        );
        Value::Object(o)
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.options
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }

    /// Set an option: the first one of that name changes (its spelling
    /// kept), the others go; a new one goes at the end.
    pub fn set(&mut self, key: &str, value: &str) {
        let mut seen = false;
        self.options.retain_mut(|(k, v)| {
            if !k.eq_ignore_ascii_case(key) {
                return true;
            }
            if seen {
                return false;
            }
            seen = true;
            *v = value.to_string();
            true
        });
        if !seen {
            self.options.push((key.to_string(), value.to_string()));
        }
    }

    pub fn remove(&mut self, key: &str) -> bool {
        let before = self.options.len();
        self.options.retain(|(k, _)| !k.eq_ignore_ascii_case(key));
        self.options.len() != before
    }

    pub fn as_block(&self) -> Block {
        Block {
            names: vec![self.host.clone()],
            options: self.options.clone(),
            managed: true,
        }
    }
}

/// ewe.conf's hosts: `Err` when ewe-conf didn't answer (never taken as
/// "none": a write after that would drop the others).
pub fn ewe_hosts() -> Result<Vec<EweHost>, Fail> {
    match config::conf_get("network.ssh.hosts") {
        Ok(None) => Ok(Vec::new()),
        Ok(Some(Value::Array(a))) => Ok(a.iter().filter_map(EweHost::from_json).collect()),
        Ok(Some(_)) => Ok(Vec::new()),
        Err(()) => Err(Fail::new(
            "internal",
            "ewe-conf didn't answer, so Safe can't read your SSH hosts",
        )
        .hint("Check that ewe-conf works: ewe-conf get network.ssh.hosts")),
    }
}

/// ewe.conf's hosts, or the managed block of `~/.ssh/config` when ewe-conf
/// can't be asked (for reading only).
pub fn ewe_hosts_or_block(file: &SshConfig) -> Vec<EweHost> {
    ewe_hosts().unwrap_or_else(|_| {
        file.hosts
            .iter()
            .filter(|b| b.managed)
            .filter_map(|b| {
                let mut h = EweHost::new(b.single()?);
                h.options = b.options.clone();
                Some(h)
            })
            .collect()
    })
}

/// Store ewe.conf's hosts (one `ewe-conf set` for all of them).
pub fn store_ewe_hosts(hosts: &[EweHost]) -> Result<(), Fail> {
    let v = json!(hosts.iter().map(EweHost::to_json).collect::<Vec<_>>());
    if config::conf_set_json("network.ssh.hosts", &v) {
        Ok(())
    } else {
        Err(
            Fail::new("internal", "ewe-conf could not store your SSH hosts")
                .hint("Check that ewe-conf works: ewe-conf get network.ssh.hosts"),
        )
    }
}

/// The user's own `Host` blocks (outside ewe-conf's managed block).
pub fn own_blocks(file: &SshConfig) -> Vec<&Block> {
    file.hosts.iter().filter(|b| !b.managed).collect()
}

/// The user's own lines name this alias on a `Host` line.
pub fn yours(file: &SshConfig, alias: &str) -> bool {
    own_blocks(file)
        .iter()
        .any(|b| b.names.iter().any(|n| n == alias))
}

/// A host name for a `Host` line: no space and none of `* ? ! ,`.
pub fn check_alias(alias: &str) -> Result<(), Fail> {
    if !plain(alias) || alias.starts_with('-') || alias.chars().any(char::is_control) {
        return Err(Fail::bad(format!(
            "{alias:?} can't be a host name: no spaces and none of * ? ! ,"
        )));
    }
    Ok(())
}

/// `ssh-hosts`, `ssh-host-set`, `ssh-host-remove`.
pub fn dispatch(d: &Daemon, verb: &str, a: &Map<String, Value>) -> Result<Value, Fail> {
    match verb {
        "ssh-hosts" => Ok(json!({"hosts": crate::connect::hosts_json(d)?})),
        "ssh-host-set" => crate::connect::host_set(d, a),
        "ssh-host-remove" => crate::connect::host_remove(a),
        other => Err(Fail::bad(format!("There is no verb {other:?}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
# Safe (ewe): every ssh asks Safe for keys. `ewe-safe ssh disable` removes these two lines.
Include ~/.ssh/ewe-safe/config
IdentityAgent ~/.1password/agent.sock

Host emoh
    HostName 192.168.1.5
    IdentityFile=~/.ssh/id_ed25519
Host *.lan box?
    User sam
Match host x
    IdentityAgent /tmp/nope
Host \"quoted\"
    IdentityAgent \"/tmp/a b.sock\"

# >>> ewe managed hosts (ewe-conf writes this block; edits inside are overwritten) >>>
Host work
    HostName work.example.com
    IdentityAgent ~/.1password/agent.sock
# <<< ewe managed hosts <<<
";

    #[test]
    fn a_config_reads_as_ssh_reads_it() {
        let c = parse(SAMPLE);
        assert_eq!(c.includes, ["~/.ssh/ewe-safe/config"]);
        assert_eq!(
            c.top,
            [
                ("Include".to_string(), "~/.ssh/ewe-safe/config".to_string()),
                (
                    "IdentityAgent".to_string(),
                    "~/.1password/agent.sock".to_string()
                )
            ]
        );
        let names: Vec<Option<&str>> = c.hosts.iter().map(Block::single).collect();
        assert_eq!(names, [Some("emoh"), None, Some("quoted"), Some("work")]);
        assert_eq!(c.hosts[0].get("identityfile"), Some("~/.ssh/id_ed25519"));
        assert_eq!(c.hosts[2].get("IdentityAgent"), Some("/tmp/a b.sock"));
        assert!(c.hosts[3].managed && !c.hosts[0].managed);
        // the Match block's options belong to no host
        assert!(
            c.hosts
                .iter()
                .all(|h| h.get("identityagent") != Some("/tmp/nope"))
        );
        assert!(yours(&c, "emoh") && yours(&c, "box?") && !yours(&c, "work"));
    }

    #[test]
    fn globs_and_aliases() {
        assert!(glob_match("*.conf", "a.conf"));
        assert!(glob_match("x?", "xy"));
        assert!(!glob_match("*.conf", "a.conf~"));
        assert!(check_alias("github-work").is_ok());
        for bad in ["a b", "*", "x?", "!x", "-oProxyCommand=x", ""] {
            assert!(check_alias(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn an_ewe_host_keeps_what_it_doesnt_know() {
        let v = json!({"host": "gh", "options": [["HostName", "github.com"], ["User", "git"]], "note": 1});
        let mut h = EweHost::from_json(&v).unwrap();
        h.set("user", "sam");
        h.set("Port", "2222");
        assert!(h.remove("HOSTNAME"));
        assert_eq!(
            h.to_json(),
            json!({"host": "gh", "options": [["User", "sam"], ["Port", "2222"]], "note": 1})
        );
    }
}
