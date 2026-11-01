//! Connect to a service (docs/GATE.md S24): the catalogue (one list; the
//! window and the CLI read it), `ssh-connect` (a key, its public file, the
//! host in ewe.conf, the key on the clipboard, the service's page in ewe
//! browser), `ssh-test` (the check a user would make by hand), and the
//! hosts (`ssh-hosts`, `ssh-host-set`, `ssh-host-remove`).
//!
//! Every URL and menu path here was checked against the service's own
//! documentation on 2026-11-01.

use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use safe_core::Kind;
use safe_core::ssh as keys;
use serde_json::{Map, Value, json};

use crate::config;
use crate::daemon::{Daemon, Fail, rd};
use crate::gate;
use crate::hosts::{self, EweHost};
use crate::log;

type Args = Map<String, Value>;

/// How a service says that a key works (`ssh -T`'s answer).
#[derive(Clone, Copy, PartialEq)]
enum Answer {
    /// "Hi sam! You've successfully authenticated, …"
    GitHub,
    /// "Welcome to GitLab, @sam!"
    GitLab,
    /// "authenticated via ssh key." (and "logged in as sam")
    Bitbucket,
    /// "Hi there, sam! You've successfully authenticated with the key …"
    Gitea,
    /// "remote: Shell access is not supported." = signed in
    Azure,
    /// a server: `true` ran, exit 0
    Exit,
}

pub struct Service {
    pub id: &'static str,
    pub name: &'static str,
    pub group: &'static str,
    /// The host to connect to, when the service has one.
    pub host: Option<&'static str>,
    /// The login name; None: the user's own (Google Cloud) or given (a server).
    pub user: Option<&'static str>,
    pub key_type: &'static str,
    pub key_bits: Option<u32>,
    /// What connect needs, and what it may take.
    pub needs: &'static [&'static str],
    pub optional: &'static [&'static str],
    pub signing: bool,
    pub steps: &'static [&'static str],
    pub signing_steps: &'static [&'static str],
    answer: Answer,
}

impl Service {
    pub fn git(&self) -> bool {
        self.group == "git"
    }

    /// The page where the key goes; `host` and `org` fill it in.
    pub fn page(&self, host: Option<&str>, org: Option<&str>) -> Option<String> {
        Some(match self.id {
            // docs.github.com, "Adding a new SSH key to your GitHub account"
            "github" => "https://github.com/settings/ssh/new".into(),
            // docs.gitlab.com/user/ssh: avatar → Edit profile → Access → SSH keys
            "gitlab" => format!(
                "https://{}/-/user_settings/ssh_keys",
                host.unwrap_or("gitlab.com")
            ),
            // learn.microsoft.com, "Use SSH key authentication": User settings → SSH public keys
            "azure-devops" => match org {
                Some(o) => format!("https://dev.azure.com/{o}/_usersSettings/keys"),
                None => "https://dev.azure.com/".into(),
            },
            // support.atlassian.com: Personal Bitbucket settings → SSH keys
            "bitbucket" => "https://bitbucket.org/account/settings/ssh-keys/".into(),
            // docs.codeberg.org/security/ssh-key
            "codeberg" => "https://codeberg.org/user/settings/keys".into(),
            "gitea" => format!("https://{}/user/settings/keys", host?),
            // learn.microsoft.com, "Create a Linux VM in the Azure portal"
            "azure-vm" => {
                "https://portal.azure.com/#browse/Microsoft.Compute%2FVirtualMachines".into()
            }
            // docs.aws.amazon.com, "Create a key pair … import the public key"
            "aws" => "https://console.aws.amazon.com/ec2/".into(),
            // docs.cloud.google.com, "Add SSH keys to VMs" (project metadata)
            "gcloud" => "https://console.cloud.google.com/compute/metadata/sshKeys".into(),
            // docs.digitalocean.com, "Upload SSH keys"
            "digitalocean" => "https://cloud.digitalocean.com/account/security".into(),
            // community.hetzner.com, "Add SSH key to your Hetzner Cloud"
            "hetzner" => "https://console.hetzner.cloud/".into(),
            _ => return None,
        })
    }

    /// The hosts that are this service (for `ssh hosts` and `ssh test`).
    fn is_host(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        match self.id {
            "azure-devops" => h == "ssh.dev.azure.com" || h == "vs-ssh.visualstudio.com",
            _ => self.host.is_some_and(|x| x == h),
        }
    }

    fn json(&self) -> Value {
        json!({
            "service": self.id,
            "name": self.name,
            "group": self.group,
            "host": self.host,
            "user": self.user,
            "key_type": self.key_type,
            "key_bits": self.key_bits,
            "page": self.page(None, None),
            "needs": self.needs,
            "optional": self.optional,
            "signing": self.signing,
            "steps": self.steps,
            "signing_steps": self.signing_steps,
        })
    }
}

const COPIED: &str = "Safe copied your public key.";
const CHECK: &str = "Come back and press Check.";

pub const SERVICES: &[Service] = &[
    Service {
        id: "github",
        name: "GitHub",
        group: "git",
        host: Some("github.com"),
        user: Some("git"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &[],
        signing: true,
        steps: &[
            COPIED,
            "On the GitHub page, paste it into Key, give it a title and press Add SSH key.",
            CHECK,
        ],
        signing_steps: &[
            "To sign commits, add the same key once more on that page with Key type: Signing Key.",
        ],
        answer: Answer::GitHub,
    },
    Service {
        id: "gitlab",
        name: "GitLab",
        group: "git",
        host: Some("gitlab.com"),
        user: Some("git"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host"],
        signing: true,
        steps: &[
            COPIED,
            "On the GitLab page, press Add new key, paste it into Key and press Add key.",
            CHECK,
        ],
        signing_steps: &[
            "Leave Usage type on Authentication & Signing, so GitLab shows your signed commits as Verified.",
        ],
        answer: Answer::GitLab,
    },
    Service {
        id: "azure-devops",
        name: "Azure DevOps",
        group: "git",
        host: Some("ssh.dev.azure.com"),
        user: Some("git"),
        key_type: "rsa",
        key_bits: Some(3072),
        needs: &[],
        optional: &["org"],
        signing: false,
        steps: &[
            "Safe copied your public key. Azure DevOps takes RSA keys only, so this key is RSA.",
            "In Azure DevOps, open User settings (the icon next to your picture, top right), then SSH public keys, then New Key.",
            "Paste the key into Public Key Data, give it a name and press Save. Then come back and press Check.",
        ],
        signing_steps: &[],
        answer: Answer::Azure,
    },
    Service {
        id: "bitbucket",
        name: "Bitbucket",
        group: "git",
        host: Some("bitbucket.org"),
        user: Some("git"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &[],
        signing: false,
        steps: &[
            COPIED,
            "On the Bitbucket page (Personal Bitbucket settings, SSH keys), press Add key, give it a label, paste it into Key and press Add key.",
            CHECK,
        ],
        signing_steps: &[],
        answer: Answer::Bitbucket,
    },
    Service {
        id: "codeberg",
        name: "Codeberg",
        group: "git",
        host: Some("codeberg.org"),
        user: Some("git"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &[],
        signing: false,
        steps: &[
            COPIED,
            "On the Codeberg page (SSH / GPG Keys), press Add key, give it a name, paste it into Content and press Add key.",
            CHECK,
        ],
        signing_steps: &[],
        answer: Answer::Gitea,
    },
    Service {
        id: "gitea",
        name: "Gitea or Forgejo",
        group: "git",
        host: None,
        user: Some("git"),
        key_type: "ed25519",
        key_bits: None,
        needs: &["host"],
        optional: &[],
        signing: false,
        steps: &[
            COPIED,
            "On your server's page (Settings, SSH / GPG Keys), press Add key, give it a name, paste it into Content and press Add key.",
            CHECK,
        ],
        signing_steps: &[],
        answer: Answer::Gitea,
    },
    Service {
        id: "azure-vm",
        name: "Azure virtual machine",
        group: "cloud",
        host: None,
        user: Some("azureuser"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host", "user"],
        signing: false,
        steps: &[
            COPIED,
            "When you create the VM, choose SSH public key, then Use existing public key, and paste it.",
            "For a VM you have: open it, then Help, Reset password, Reset SSH public key. Paste it and press Update.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
    Service {
        id: "aws",
        name: "AWS EC2",
        group: "cloud",
        host: None,
        user: Some("ec2-user"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host", "user"],
        signing: false,
        steps: &[
            COPIED,
            "In the EC2 console, open Key Pairs and press Import key pair.",
            "Give it a name, paste the key into Public key contents and press Import key pair. Choose it when you launch an instance.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
    Service {
        id: "gcloud",
        name: "Google Cloud VM",
        group: "cloud",
        host: None,
        user: None,
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host", "user"],
        signing: false,
        steps: &[
            "Safe copied your public key, with your user name at the end.",
            "On the Metadata page, open SSH keys, press Edit, then Add item.",
            "Paste the key into SSH key and press Save.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
    Service {
        id: "digitalocean",
        name: "DigitalOcean",
        group: "cloud",
        host: None,
        user: Some("root"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host", "user"],
        signing: false,
        steps: &[
            COPIED,
            "On the Security page, press Add SSH Key, paste it into Public Key, give it a name and press Add SSH Key.",
            "Choose this key when you create a Droplet.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
    Service {
        id: "hetzner",
        name: "Hetzner Cloud",
        group: "cloud",
        host: None,
        user: Some("root"),
        key_type: "ed25519",
        key_bits: None,
        needs: &[],
        optional: &["host", "user"],
        signing: false,
        steps: &[
            COPIED,
            "In the Hetzner Console, open your project, then Security, then SSH keys, and press Add SSH key. Paste it there.",
            "Choose this key when you create a server.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
    Service {
        id: "server",
        name: "A server you can log in to",
        group: "server",
        host: None,
        user: None,
        key_type: "ed25519",
        key_bits: None,
        needs: &["host", "user"],
        optional: &[],
        signing: false,
        steps: &[
            "Safe opens a terminal that copies your key to the server.",
            "Type the server's password there, once.",
            "Then press Check.",
        ],
        signing_steps: &[],
        answer: Answer::Exit,
    },
];

pub fn service(id: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.id == id)
}

/// The catalogue's service a host name belongs to.
fn service_of_host(host: &str) -> Option<&'static Service> {
    SERVICES.iter().find(|s| s.is_host(host))
}

pub fn services_json() -> Value {
    json!({"services": SERVICES.iter().map(Service::json).collect::<Vec<_>>()})
}

// ── arguments ───────────────────────────────────────────────────────────

fn s<'a>(a: &'a Args, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn b(a: &Args, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn port(a: &Args) -> Result<Option<u16>, Fail> {
    match a.get("port") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .or_else(|| v.as_str().and_then(|x| x.trim().parse().ok()))
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n > 0)
            .map(Some)
            .ok_or_else(|| Fail::bad("--port is a number from 1 to 65535")),
    }
}

/// A host name or a user name as ssh takes it: no space, no leading `-`.
fn check_word(what: &str, v: &str) -> Result<(), Fail> {
    if v.starts_with('-')
        || v.chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\'')
    {
        return Err(Fail::bad(format!("{v:?} can't be a {what}.")));
    }
    Ok(())
}

fn unlocked(d: &Daemon) -> Result<(), Fail> {
    let snap = rd(&d.snap);
    if !snap.set_up {
        return Err(Fail::not_set_up());
    }
    if snap.locked {
        return Err(Fail::locked());
    }
    Ok(())
}

/// An SSH key item of the unlocked safe: (id, title, public line).
fn key_item(d: &Daemon, id: &str) -> Result<(String, String, String), Fail> {
    let snap = rd(&d.snap);
    let item = snap
        .items
        .iter()
        .find(|x| x.id == id)
        .ok_or_else(|| Fail::new("not-found", format!("No item {id}.")))?;
    if item.kind != Kind::SshKey {
        return Err(Fail::bad("That item isn't an SSH key."));
    }
    let info = item
        .ssh
        .as_ref()
        .filter(|i| i.agent && keys::supported_line(&i.public_key))
        .ok_or_else(|| Fail::bad("Safe's agent can't use that key."))?;
    Ok((item.id.clone(), item.title.clone(), info.public_key.clone()))
}

/// The title of the Safe key an `IdentityFile` points at (by its tag or
/// its `.pub` content), else the file.
fn key_of_file(safe: &[gate::SafeKey], file: &str) -> Option<gate::SafeKey> {
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Some(t) = name
        .strip_prefix("key-")
        .and_then(|x| x.strip_suffix(".pub"))
        && let Some(k) = safe
            .iter()
            .find(|k| gate::tag(&k.fingerprint).as_deref() == Some(t))
    {
        return Some(k.clone());
    }
    let p = hosts::expand(file)?;
    let pubf = if name.ends_with(".pub") {
        p
    } else {
        let mut x = p.into_os_string();
        x.push(".pub");
        x.into()
    };
    let text = std::fs::read_to_string(pubf).ok()?;
    let fp = keys::fingerprint_of_line(text.lines().next()?)?;
    safe.iter().find(|k| k.fingerprint == fp).cloned()
}

// ── launching a page or a terminal ──────────────────────────────────────

/// Start a program the user sees (the page, a terminal) and don't wait for
/// it. `EWE_SAFE_OPEN` (tests) is called with the same argv instead. Under
/// systemd it runs as a transient user unit, outside the service's
/// sandbox (agent.rs, `prompt`).
fn launch(d: &Daemon, argv: &[String], display: Option<&str>) -> bool {
    let mut env = crate::agent::display_env(&d.paths);
    if let Some(w) = display {
        env.retain(|(k, _)| k != "WAYLAND_DISPLAY");
        env.push(("WAYLAND_DISPLAY".into(), w.to_string()));
    }
    let mut c = if let Some(fake) = std::env::var_os("EWE_SAFE_OPEN").filter(|v| !v.is_empty()) {
        let mut c = Command::new(fake);
        c.args(argv);
        c
    } else if let Some(run) =
        crate::agent::on_path("systemd-run").filter(|_| std::env::var_os("INVOCATION_ID").is_some())
    {
        let mut c = Command::new(run);
        c.args(["--user", "--quiet", "--collect"]);
        for (k, _) in &env {
            c.arg(format!("--setenv={k}"));
        }
        c.arg("--").args(argv);
        c
    } else {
        let mut c = Command::new(&argv[0]);
        c.args(&argv[1..]);
        c
    };
    c.envs(env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match c.spawn() {
        Ok(mut ch) => {
            std::thread::spawn(move || {
                let _ = ch.wait();
            });
            true
        }
        Err(e) => {
            log(&format!("can't start {}: {e}", argv[0]));
            false
        }
    }
}

/// The page in ewe browser, else the default browser.
fn open_page(d: &Daemon, url: &str, display: Option<&str>) -> bool {
    let argv: Vec<String> = if crate::agent::on_path("ewe-browser").is_some() {
        vec!["ewe-browser".into(), "open".into(), url.into()]
    } else {
        vec!["xdg-open".into(), url.into()]
    };
    launch(d, &argv, display)
}

/// A public key on the clipboard (`wl-copy`, no clear timer: it is public).
fn copy_public(text: &str, display: Option<&str>) -> bool {
    use std::io::Write;
    let mut c = Command::new("wl-copy");
    if let Some(w) = display
        .map(str::to_string)
        .or_else(|| std::env::var("WAYLAND_DISPLAY").ok())
    {
        c.env("WAYLAND_DISPLAY", w);
    }
    let Ok(mut ch) = c
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut i) = ch.stdin.take() {
        let _ = i.write_all(text.as_bytes());
    }
    ch.wait().is_ok_and(|s| s.success())
}

// ── ssh-connect ─────────────────────────────────────────────────────────

/// The host definition connect writes: `HostName` (only when the alias
/// isn't the host), `User`, `Port` (only when given and not 22),
/// `IdentityFile`, `IdentitiesOnly yes`; other options stay.
fn define(h: &mut EweHost, host: &str, user: Option<&str>, port: Option<u16>, file: &str) {
    if h.host == host {
        h.remove("HostName");
    } else {
        h.set("HostName", host);
    }
    if let Some(u) = user {
        h.set("User", u);
    }
    match port {
        Some(22) => {
            h.remove("Port");
        }
        Some(p) => h.set("Port", &p.to_string()),
        None => {}
    }
    h.set("IdentityFile", file);
    h.set("IdentitiesOnly", "yes");
}

pub fn connect(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let id = s(a, "service")
        .ok_or_else(|| Fail::bad("Which service? ewe-safe ssh services lists them."))?;
    let svc = service(id).ok_or_else(|| {
        Fail::bad(format!("There is no service {id:?}.")).hint("ewe-safe ssh services")
    })?;
    let host_arg = s(a, "host");
    let user_arg = s(a, "user");
    let org = s(a, "org");
    let port = port(a)?;
    for need in svc.needs {
        if s(a, need).is_none() {
            return Err(Fail::bad(format!("{} needs --{need}.", svc.name)));
        }
    }
    if let Some(h) = host_arg {
        check_word("host name", h)?;
    }
    if let Some(u) = user_arg {
        check_word("user name", u)?;
    }
    if let Some(o) = org {
        check_word("organization", o)?;
    }
    let display = s(a, "wayland_display");
    unlocked(d)?;

    // the host and its alias: git services always, others once given
    let host = host_arg.or(svc.host);
    let defined = svc.git() || host_arg.is_some();
    let alias = if defined {
        let al = s(a, "alias")
            .or(host)
            .ok_or_else(|| Fail::bad("Give --host"))?;
        hosts::check_alias(al)?;
        Some(al.to_string())
    } else {
        None
    };
    let user = user_arg.map(str::to_string).or_else(|| match svc.user {
        Some(u) => Some(u.to_string()),
        // Google Cloud names the login after the key's last word
        None if svc.id == "gcloud" => std::env::var("USER").ok().filter(|u| !u.is_empty()),
        None => None,
    });

    // the key that was asked for (checked before anything changes)
    let chosen = match s(a, "key") {
        Some(k) => {
            let (kid, title, line) = key_item(d, k)?;
            if svc.key_type == "rsa" && keys::key_type_of_line(&line).as_deref() != Some("rsa") {
                return Err(Fail::bad(format!(
                    "{} takes RSA keys only: pick an RSA key, or leave out --key and Safe makes one.",
                    svc.name
                )));
            }
            Some((kid, title, line))
        }
        None => None,
    };
    let chosen_file = chosen
        .as_ref()
        .and_then(|(_, _, l)| keys::fingerprint_of_line(l))
        .and_then(|fp| gate::key_file_tilde(&fp));

    // conflicts, before a new key is made
    let file_cfg = hosts::read_config();
    let mut ewe = if alias.is_some() {
        hosts::ewe_hosts()?
    } else {
        Vec::new()
    };
    let replace = b(a, "replace");
    if let Some(al) = &alias {
        if hosts::yours(&file_cfg, al) {
            return Err(Fail::conflict(
                al,
                format!(
                    "You set up {al} yourself in ~/.ssh/config. Change it there, or use --alias."
                ),
            ));
        }
        if let Some(h) = ewe.iter().find(|h| &h.host == al)
            && let Some(f) = h.get("identityfile")
            && chosen_file.as_deref() != Some(f)
            && !replace
        {
            let safe = gate::safe_keys(d);
            let which = key_of_file(&safe, f).map_or_else(|| f.to_string(), |k| k.title);
            return Err(Fail::conflict(
                al,
                format!(
                    "{al} already uses the key {which}. Use --replace, or --alias {}-2 for a second account.",
                    svc.id
                ),
            ));
        }
    }
    // --sign needs a Git email: asked before anything changes
    let sign = b(a, "sign");
    let email = if sign {
        Some(crate::signing::email(s(a, "email"))?)
    } else {
        None
    };

    let enabled_now = gate::ensure_on(d)?;

    // the key: the chosen one, or a new one (saved first, one save)
    let (item_id, title, line, sync) = match chosen {
        Some((kid, title, line)) => (kid, title, line, crate::daemon::sync_json(&rd(&d.snap))),
        None => {
            let title = s(a, "title").unwrap_or(svc.name).to_string();
            let key =
                keys::generate(svc.key_type, svc.key_bits, &title).map_err(|e| Fail::bad(e.0))?;
            let (kid, sync) =
                d.mutate(|safe| Ok((safe.add_ssh_key(&key, &title, "", "")?, true)))?;
            log(&format!("ssh connect: a new key for {}", svc.id));
            (kid, title, key.public_key.clone(), sync)
        }
    };
    let fp = keys::fingerprint_of_line(&line)
        .ok_or_else(|| Fail::new("internal", "The key has no fingerprint."))?;
    gate::write_key_file(&line, &title).map_err(|e| {
        Fail::new(
            "internal",
            format!("Safe can't write the key's public file: {e}"),
        )
    })?;
    let tilde = gate::key_file_tilde(&fp).unwrap_or_default();

    // the host in ewe.conf
    if let (Some(al), Some(h)) = (&alias, host) {
        let mut entry = ewe
            .iter()
            .find(|x| &x.host == al)
            .cloned()
            .unwrap_or_else(|| EweHost::new(al));
        define(&mut entry, h, user.as_deref(), port, &tilde);
        match ewe.iter_mut().find(|x| &x.host == al) {
            Some(x) => *x = entry,
            None => ewe.push(entry),
        }
        hosts::store_ewe_hosts(&ewe)?;
    }

    // the key on the clipboard, the page open
    let bare = keys::public_line(&keys::public_blob(&line).unwrap_or_default()).unwrap_or_default();
    let copy_text = match (svc.id, &user) {
        ("gcloud", Some(u)) => format!("{bare} {u}"),
        _ => gate::key_file_text(&line, &title)
            .unwrap_or_default()
            .trim_end()
            .to_string(),
    };
    let copied = copy_public(&copy_text, display);
    let page = svc.page(host_arg, org);
    let opened = if b(a, "no_open") {
        false
    } else if svc.id == "server" {
        let (h, u) = (host.unwrap_or_default(), user.clone().unwrap_or_default());
        let path = gate::key_file(&fp).unwrap_or_default();
        let mut argv: Vec<String> = vec![
            "kitty".into(),
            "--title".into(),
            format!("Safe: copy your key to {h}"),
            "ssh-copy-id".into(),
            "-f".into(),
            "-i".into(),
            path.to_string_lossy().into_owned(),
            // many keys in the agent would use up the server's tries
            // before the password is asked: the password first
            "-o".into(),
            "PreferredAuthentications=keyboard-interactive,password,publickey".into(),
        ];
        if let Some(p) = port {
            argv.extend(["-p".into(), p.to_string()]);
        }
        argv.push(format!("{u}@{h}"));
        launch(d, &argv, display)
    } else {
        page.as_deref().is_some_and(|u| open_page(d, u, display))
    };

    let signing = match email {
        Some(e) => Some(crate::signing::turn_on(d, &item_id, &e)?),
        None => None,
    };
    let mut steps: Vec<&str> = svc.steps.to_vec();
    if sign {
        steps.extend(svc.signing_steps);
    }
    let remote_hint = svc.git().then(|| {
        let al = alias.clone().unwrap_or_default();
        if svc.id == "azure-devops" {
            format!(
                "git@{al}:v3/{}/<project>/<repo>",
                org.unwrap_or("<organization>")
            )
        } else {
            format!("git@{al}:<owner>/<repo>.git")
        }
    });
    let summary = rd(&d.snap)
        .items
        .iter()
        .find(|x| x.id == item_id)
        .and_then(|x| x.ssh.as_ref().map(crate::sshkeys::ssh_json));
    let mut v = json!({
        "item_id": item_id,
        "ssh": summary,
        "service": svc.id,
        "alias": alias,
        "page": page,
        "copied": copied,
        "opened": opened,
        "steps": steps,
        "remote_hint": remote_hint,
        "enabled": enabled_now,
        "sync": sync,
    });
    if let Some(sg) = signing {
        v["signing"] = sg;
    }
    Ok(v)
}

// ── ssh-test ────────────────────────────────────────────────────────────

/// What `ssh -T` said, read the way a user reads it.
#[derive(Debug, PartialEq)]
pub struct Checked {
    pub connected: bool,
    pub account: Option<String>,
    pub host_key: &'static str,
    pub message: String,
}

fn between<'a>(text: &'a str, start: &str, end: &[char]) -> Option<&'a str> {
    let i = text.find(start)? + start.len();
    let rest = &text[i..];
    let j = rest.find(end).unwrap_or(rest.len());
    Some(rest[..j].trim()).filter(|x| !x.is_empty())
}

/// Read ssh's answer. `name` is what the message calls the other end.
fn read_answer(answer: Answer, name: &str, host: &str, code: i32, out: &str) -> Checked {
    let host_key = if out.contains("REMOTE HOST IDENTIFICATION HAS CHANGED")
        || out.contains("Host key verification failed")
    {
        "changed"
    } else if out.contains("Permanently added") {
        "added"
    } else {
        "known"
    };
    let (connected, account) = match answer {
        _ if host_key == "changed" => (false, None),
        Answer::GitHub => (
            out.contains("successfully authenticated"),
            between(out, "Hi ", &['!']).map(str::to_string),
        ),
        Answer::GitLab => (
            out.contains("Welcome to GitLab"),
            between(out, "Welcome to GitLab, ", &['!'])
                .map(|n| n.trim_start_matches('@').to_string()),
        ),
        Answer::Bitbucket => (
            out.contains("authenticated via ssh key")
                || out.contains("authenticated via a deploy key"),
            between(out, "logged in as ", &['.', '\n']).map(str::to_string),
        ),
        Answer::Gitea => (
            out.contains("successfully authenticated"),
            between(out, "Hi there, ", &['!']).map(str::to_string),
        ),
        Answer::Azure => (out.contains("Shell access is not supported"), None),
        Answer::Exit => (code == 0, None),
    };
    let message = if connected {
        match &account {
            Some(acc) => format!("Connected to {name} as {acc}."),
            None => format!("Connected to {name}."),
        }
    } else if host_key == "changed" {
        "The server's key changed. Safe stopped. Check with the server's owner.".to_string()
    } else if out.contains("Permission denied") || out.contains("Public key authentication failed")
    {
        if answer == Answer::Exit {
            format!("{name} doesn't know this key yet. Copy it to the server, then check again.")
        } else {
            format!("{name} doesn't know this key yet. Add it on the page, then check again.")
        }
    } else if out.contains("Could not resolve hostname") {
        format!("Safe can't find {host}. Check the address.")
    } else if out.contains("timed out")
        || out.contains("Connection refused")
        || out.contains("No route to host")
        || out.contains("Network is unreachable")
    {
        format!("Safe can't reach {host}. Check the address and your network.")
    } else {
        "The connection didn't work. The details say why.".to_string()
    };
    Checked {
        connected,
        account,
        host_key,
        message,
    }
}

/// `user@host[:port]`, or a bare host.
fn split_target(t: &str) -> (Option<&str>, &str, Option<u16>) {
    let (user, rest) = match t.split_once('@') {
        Some((u, r)) => (Some(u), r),
        None => (None, t),
    };
    match rest.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.parse::<u16>().is_ok() => (user, h, p.parse().ok()),
        _ => (user, rest, None),
    }
}

pub fn test(d: &Arc<Daemon>, a: &Args) -> Result<Value, Fail> {
    let target =
        s(a, "target").ok_or_else(|| Fail::bad("ssh test needs a host, a service or user@host"))?;
    check_word("target", target)?;
    unlocked(d)?;
    let file_cfg = hosts::read_config();
    let ewe = hosts::ewe_hosts_or_block(&file_cfg);
    let own = hosts::own_blocks(&file_cfg);
    let host_name_of = |alias: &str| -> Option<String> {
        own.iter()
            .find(|b| b.single() == Some(alias))
            .map(|b| b.get("hostname").unwrap_or(alias).to_string())
            .or_else(|| {
                ewe.iter()
                    .find(|h| h.host == alias)
                    .map(|h| h.get("hostname").unwrap_or(alias).to_string())
            })
    };
    // what to connect to, and which service answers
    let (svc, dest, port, host) = if let Some(svc) = service(target) {
        // a host of ewe.conf for this service first (its key applies)
        let mine = ewe
            .iter()
            .find(|h| svc.is_host(h.get("hostname").unwrap_or(&h.host)))
            .map(|h| h.host.clone());
        match (mine, svc.host) {
            (Some(al), _) => {
                let hn = host_name_of(&al).unwrap_or_else(|| al.clone());
                (Some(svc), al, None, hn)
            }
            (None, Some(h)) => (
                Some(svc),
                format!("{}@{h}", svc.user.unwrap_or("git")),
                None,
                h.to_string(),
            ),
            (None, None) => {
                return Err(Fail::bad(format!(
                    "Safe doesn't know where your {} is yet.",
                    svc.name
                ))
                .hint("ewe-safe ssh host set NAME --host ADDRESS --user USER"));
            }
        }
    } else if let Some(hn) = host_name_of(target) {
        (service_of_host(&hn), target.to_string(), None, hn)
    } else {
        let (user, h, p) = split_target(target);
        check_word("host name", h)?;
        let dest = match user {
            Some(u) => format!("{u}@{h}"),
            None => h.to_string(),
        };
        (service_of_host(h), dest, p, h.to_string())
    };
    let answer = svc.map_or(Answer::Exit, |s| s.answer);
    let name = svc
        .filter(|s| s.host.is_some())
        .map_or_else(|| host.clone(), |s| s.name.to_string());

    let program = std::env::var("EWE_SAFE_SSH")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "ssh".to_string());
    let sock = d.paths.ssh_socket();
    let mut args: Vec<String> = [
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "StrictHostKeyChecking=accept-new",
    ]
    .iter()
    .map(|x| x.to_string())
    .collect();
    args.extend(["-o".into(), format!("IdentityAgent={}", sock.display())]);
    if let Some(k) = s(a, "key") {
        let (_, title, line) = key_item(d, k)?;
        let path = gate::write_key_file(&line, &title).map_err(|e| {
            Fail::new(
                "internal",
                format!("Safe can't write the key's public file: {e}"),
            )
        })?;
        args.extend([
            "-i".into(),
            path.to_string_lossy().into_owned(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
        ]);
    }
    if let Some(p) = port {
        args.extend(["-p".into(), p.to_string()]);
    }
    args.push(dest);
    if answer == Answer::Exit {
        args.push("true".into());
    }
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    log(&format!(
        "ssh test: checking a connection ({})",
        svc.map_or("a server", |s| s.id)
    ));
    let env = [("LC_ALL".to_string(), "C".to_string())];
    let ran = config::run_full(&program, &argv, &env, Duration::from_secs(40));
    let Some((code, out, err)) = ran else {
        return Ok(json!({
            "connected": false,
            "account": null,
            "host_key": "known",
            "message": format!("Safe can't reach {host}. Check the address and your network."),
            "detail": "ssh didn't finish in 40 seconds",
        }));
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&err),
        String::from_utf8_lossy(&out)
    );
    let c = read_answer(answer, &name, &host, code, &text);
    // ssh's last lines, at most 400 characters
    let trimmed = text.trim_end();
    let start = trimmed.char_indices().rev().nth(399).map_or(0, |(i, _)| i);
    Ok(json!({
        "connected": c.connected,
        "account": c.account,
        "host_key": c.host_key,
        "message": c.message,
        "detail": &trimmed[start..],
        "service": svc.map(|s| s.id),
    }))
}

// ── hosts ───────────────────────────────────────────────────────────────

fn host_json(
    alias: &str,
    options: &[(String, String)],
    source: &str,
    safe: &[gate::SafeKey],
    gate_on: bool,
) -> Value {
    let get = |k: &str| {
        options
            .iter()
            .find(|(x, _)| x.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    let host_name = get("hostname");
    let file = get("identityfile");
    let key = file
        .as_deref()
        .and_then(|f| key_of_file(safe, f))
        .map(|k| k.json());
    let svc = service_of_host(host_name.as_deref().unwrap_or(alias)).map(|s| s.id);
    json!({
        "alias": alias,
        "host_name": host_name,
        "user": get("user"),
        "port": get("port").and_then(|p| p.parse::<u16>().ok()),
        "source": source,
        "key": key,
        "file": file,
        "service": svc,
        "agent": if gate_on { Some("safe".to_string()) } else { get("identityagent") },
    })
}

pub fn hosts_json(d: &Daemon) -> Result<Vec<Value>, Fail> {
    let file = hosts::read_config();
    let ewe = hosts::ewe_hosts_or_block(&file);
    let safe = gate::safe_keys(d);
    let gate_on = d.settings().ssh_agent && gate::is_on();
    let mut out = Vec::new();
    for b in hosts::own_blocks(&file) {
        if let Some(al) = b.single() {
            out.push(host_json(al, &b.options, "yours", &safe, gate_on));
        }
    }
    for h in &ewe {
        if !hosts::yours(&file, &h.host) {
            out.push(host_json(&h.host, &h.options, "ewe", &safe, gate_on));
        }
    }
    Ok(out)
}

pub fn host_set(d: &Daemon, a: &Args) -> Result<Value, Fail> {
    let alias = s(a, "alias").ok_or_else(|| Fail::bad("ssh host set needs a name"))?;
    hosts::check_alias(alias)?;
    let file = hosts::read_config();
    if hosts::yours(&file, alias) {
        return Err(Fail::conflict(
            alias,
            format!(
                "You set up {alias} yourself in ~/.ssh/config. Change it there, or use another name."
            ),
        ));
    }
    let port = port(a)?;
    let (host, user) = (s(a, "host"), s(a, "user"));
    if let Some(h) = host {
        check_word("host name", h)?;
    }
    if let Some(u) = user {
        check_word("user name", u)?;
    }
    if s(a, "key").is_some() && b(a, "no_key") {
        return Err(Fail::bad("--key or --no-key, not both"));
    }
    let key_file = match s(a, "key") {
        Some(k) => {
            let (_, title, line) = key_item(d, k)?;
            gate::write_key_file(&line, &title).map_err(|e| {
                Fail::new(
                    "internal",
                    format!("Safe can't write the key's public file: {e}"),
                )
            })?;
            keys::fingerprint_of_line(&line).and_then(|fp| gate::key_file_tilde(&fp))
        }
        None => None,
    };
    let mut ewe = hosts::ewe_hosts()?;
    let created = !ewe.iter().any(|h| h.host == alias);
    if created {
        ewe.push(EweHost::new(alias));
    }
    let h = ewe
        .iter_mut()
        .find(|h| h.host == alias)
        .expect("the host is there");
    if let Some(hn) = host {
        if hn == alias {
            h.remove("HostName");
        } else {
            h.set("HostName", hn);
        }
    }
    if let Some(u) = user {
        h.set("User", u);
    }
    match port {
        Some(22) => {
            h.remove("Port");
        }
        Some(p) => h.set("Port", &p.to_string()),
        None => {}
    }
    if let Some(f) = &key_file {
        h.set("IdentityFile", f);
        h.set("IdentitiesOnly", "yes");
    }
    if b(a, "no_key") {
        h.remove("IdentityFile");
        h.remove("IdentitiesOnly");
    }
    let entry = h.clone();
    hosts::store_ewe_hosts(&ewe)?;
    let safe = gate::safe_keys(d);
    let gate_on = d.settings().ssh_agent && gate::is_on();
    Ok(json!({
        "alias": alias,
        "created": created,
        "entry": host_json(alias, &entry.options, "ewe", &safe, gate_on),
    }))
}

pub fn host_remove(a: &Args) -> Result<Value, Fail> {
    let alias = s(a, "alias").ok_or_else(|| Fail::bad("ssh host remove needs a name"))?;
    let file = hosts::read_config();
    if hosts::yours(&file, alias) {
        return Err(Fail::conflict(
            alias,
            format!(
                "You set up {alias} yourself in ~/.ssh/config: Safe never changes your own lines."
            ),
        ));
    }
    let mut ewe = hosts::ewe_hosts()?;
    let before = ewe.len();
    ewe.retain(|h| h.host != alias);
    if ewe.len() == before {
        return Err(Fail::new(
            "not-found",
            format!("There is no host {alias} in ewe.conf."),
        ));
    }
    hosts::store_ewe_hosts(&ewe)?;
    Ok(json!({"alias": alias, "removed": true}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_service_answers_the_way_its_docs_say() {
        let gh = read_answer(
            Answer::GitHub,
            "GitHub",
            "github.com",
            1,
            "Hi sam! You've successfully authenticated, but GitHub does not provide shell access.\n",
        );
        assert_eq!(
            (gh.connected, gh.account.as_deref(), gh.message.as_str()),
            (true, Some("sam"), "Connected to GitHub as sam.")
        );
        let gl = read_answer(
            Answer::GitLab,
            "GitLab",
            "gitlab.com",
            0,
            "Welcome to GitLab, @sam!\n",
        );
        assert_eq!(gl.account.as_deref(), Some("sam"));
        let bb = read_answer(
            Answer::Bitbucket,
            "Bitbucket",
            "bitbucket.org",
            0,
            "authenticated via ssh key.\n\nYou can use git to connect to Bitbucket. Shell access is disabled\n",
        );
        assert!(bb.connected && bb.account.is_none());
        let cb = read_answer(
            Answer::Gitea,
            "Codeberg",
            "codeberg.org",
            0,
            "Hi there, sam! You've successfully authenticated with the key named GitHub, but Forgejo does not provide shell access.\n",
        );
        assert_eq!(cb.account.as_deref(), Some("sam"));
        let az = read_answer(
            Answer::Azure,
            "Azure DevOps",
            "ssh.dev.azure.com",
            1,
            "Warning: Permanently added 'ssh.dev.azure.com' (RSA) to the list of known hosts.\nremote: Shell access is not supported.\nshell request failed on channel 0\n",
        );
        assert_eq!((az.connected, az.host_key), (true, "added"));
        let no = read_answer(
            Answer::GitHub,
            "GitHub",
            "github.com",
            255,
            "git@github.com: Permission denied (publickey).\n",
        );
        assert_eq!(
            (no.connected, no.message.as_str()),
            (
                false,
                "GitHub doesn't know this key yet. Add it on the page, then check again."
            )
        );
        let changed = read_answer(
            Answer::Exit,
            "box",
            "box",
            255,
            "@@@ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED! @@@\nHost key verification failed.\n",
        );
        assert_eq!((changed.connected, changed.host_key), (false, "changed"));
        let gone = read_answer(
            Answer::Exit,
            "x.example",
            "x.example",
            255,
            "ssh: Could not resolve hostname x.example: Name or service not known\n",
        );
        assert!(gone.message.contains("can't find x.example"));
    }

    #[test]
    fn targets_and_the_catalogue() {
        assert_eq!(
            split_target("git@github.com"),
            (Some("git"), "github.com", None)
        );
        assert_eq!(
            split_target("sam@10.0.0.2:2222"),
            (Some("sam"), "10.0.0.2", Some(2222))
        );
        assert_eq!(split_target("box"), (None, "box", None));
        assert_eq!(
            service_of_host("vs-ssh.visualstudio.com").map(|s| s.id),
            Some("azure-devops")
        );
        assert_eq!(service("azure-devops").unwrap().key_bits, Some(3072));
        let ids: Vec<&str> = SERVICES.iter().map(|s| s.id).collect();
        assert_eq!(
            ids,
            [
                "github",
                "gitlab",
                "azure-devops",
                "bitbucket",
                "codeberg",
                "gitea",
                "azure-vm",
                "aws",
                "gcloud",
                "digitalocean",
                "hetzner",
                "server"
            ]
        );
        for s in SERVICES {
            assert!(
                (2..=3).contains(&s.steps.len()),
                "{}: two or three steps",
                s.id
            );
            assert!(s.steps.iter().all(|x| x.ends_with('.')));
            assert!(s.json().get("id").is_none(), "`id` is the socket's");
        }
        assert_eq!(
            service("gitlab")
                .unwrap()
                .page(Some("git.example.org"), None)
                .as_deref(),
            Some("https://git.example.org/-/user_settings/ssh_keys")
        );
        assert_eq!(
            service("azure-devops")
                .unwrap()
                .page(None, Some("fabrikam"))
                .as_deref(),
            Some("https://dev.azure.com/fabrikam/_usersSettings/keys")
        );
        assert_eq!(service("gitea").unwrap().page(None, None), None);
    }
}
