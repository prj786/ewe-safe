//! WebDAV: the ewe account's Nextcloud (credentials from `ewe-cloud`) and
//! any other WebDAV server. The guard is `If-Match` (`If-None-Match: *` for
//! a new file): the server itself refuses a save over a version the caller
//! hasn't seen. A server without ETags gets a content-hash compare before an
//! unconditional PUT — a short race, and the probe says so.
//!
//! Only https, except plain http to this machine when asked (tests, like
//! ewe-cloud's `EWE_CLOUD_SERVER_INSECURE`).

use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::Deserialize;
use ureq::http;
use ureq::tls::{RootCerts, TlsConfig};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::Error;
use crate::place::{Expect, Fetched, Place, PlaceInfo, Stored, Tag};

/// Where a safe lives in a remote place unless the user picks another path.
pub const REMOTE_LOCATION: &str = "ewe/safe/passwords.kdbx";
/// The scratch file the guard probe writes next to the safe.
pub const PROBE_NAME: &str = ".ewe-safe-probe";
const MAX_BODY: u64 = 64 * 1024 * 1024;

#[derive(Clone)]
pub struct Login {
    pub user: String,
    pub password: Zeroizing<String>,
}

/// Where the files are and who signs in. The password is asked for when a
/// request needs it and is never logged.
pub trait Credentials: Send + Sync {
    /// The WebDAV folder the safe's location is relative to.
    fn base(&self) -> Result<String, Error>;
    fn login(&self) -> Result<Login, Error>;
    /// Forget anything cached: the server refused it.
    fn forget(&self) {}
}

/// A server, a user and a password the caller already has (generic WebDAV:
/// the daemon reads the password from the keyring).
pub struct Fixed {
    base: String,
    login: Login,
}

impl Fixed {
    pub fn new(base: &str, user: &str, password: Zeroizing<String>) -> Fixed {
        Fixed {
            base: base.to_string(),
            login: Login {
                user: user.to_string(),
                password,
            },
        }
    }
}

impl Credentials for Fixed {
    fn base(&self) -> Result<String, Error> {
        Ok(self.base.clone())
    }

    fn login(&self) -> Result<Login, Error> {
        Ok(self.login.clone())
    }
}

/// The ewe account (RFC-005): `ewe-cloud webdav-url` and
/// `ewe-cloud token --json`, run as argv. The app password stays in
/// ewe-cloud's keyring item; Safe keeps a copy in memory only.
pub struct EweCloud {
    program: PathBuf,
    cached: Mutex<Option<(String, Login)>>,
}

impl EweCloud {
    pub fn new() -> EweCloud {
        EweCloud::with_program("ewe-cloud")
    }

    pub fn with_program(program: impl Into<PathBuf>) -> EweCloud {
        EweCloud {
            program: program.into(),
            cached: Mutex::new(None),
        }
    }

    fn run(&self, args: &[&str]) -> Result<(bool, Vec<u8>), Error> {
        let out = Command::new(&self.program)
            .args(args)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .map_err(|e| {
                Error::Place(format!(
                    "{} is not available ({e}): sign in with ewe-sync",
                    self.program.display()
                ))
            })?;
        Ok((out.status.success(), out.stdout))
    }

    fn ask(&self) -> Result<(String, Login), Error> {
        let signed_out =
            || Error::Place("not signed in to your ewe account: sign in with ewe-sync".into());

        let (ok, out) = self.run(&["webdav-url"])?;
        let base = String::from_utf8_lossy(&out).trim().to_string();
        if !ok || base.is_empty() || base.starts_with('{') {
            return Err(signed_out());
        }

        #[derive(Deserialize)]
        struct Reply {
            ok: bool,
            token: Option<String>,
            user: Option<String>,
        }
        let (_, mut out) = self.run(&["token", "--json"])?;
        let reply: Result<Reply, _> = serde_json::from_slice(&out);
        out.zeroize();
        match reply {
            Ok(Reply {
                ok: true,
                token: Some(token),
                user: Some(user),
            }) => Ok((
                base,
                Login {
                    user,
                    password: Zeroizing::new(token),
                },
            )),
            Ok(Reply { token, .. }) => {
                drop(token.map(Zeroizing::new));
                Err(signed_out())
            }
            Err(_) => Err(signed_out()),
        }
    }

    fn cached(&self) -> Result<(String, Login), Error> {
        let mut held = self.cached.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(c) = held.as_ref() {
            return Ok(c.clone());
        }
        let fresh = self.ask()?;
        *held = Some(fresh.clone());
        Ok(fresh)
    }
}

impl Default for EweCloud {
    fn default() -> Self {
        EweCloud::new()
    }
}

impl Credentials for EweCloud {
    fn base(&self) -> Result<String, Error> {
        Ok(self.cached()?.0)
    }

    fn login(&self) -> Result<Login, Error> {
        Ok(self.cached()?.1)
    }

    fn forget(&self) {
        *self.cached.lock().unwrap_or_else(|p| p.into_inner()) = None;
    }
}

struct Reply {
    status: u16,
    etag: Option<String>,
    body: Vec<u8>,
}

pub struct WebDav {
    kind: String,
    location: String,
    creds: Box<dyn Credentials>,
    agent: ureq::Agent,
    insecure_loopback: bool,
    guarded: AtomicBool,
}

impl WebDav {
    /// The ewe account's Nextcloud, through `ewe-cloud`.
    pub fn nextcloud(location: &str) -> WebDav {
        WebDav::new("nextcloud", location, Box::new(EweCloud::new()))
    }

    /// `kind` is what [`PlaceInfo`] reports: `nextcloud` or `webdav`.
    pub fn new(kind: &str, location: &str, creds: Box<dyn Credentials>) -> WebDav {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .allow_non_standard_methods(true)
            .timeout_connect(Some(Duration::from_secs(10)))
            .timeout_global(Some(Duration::from_secs(120)))
            .user_agent(format!("ewe-safe/{}", safe_core::VERSION))
            .tls_config(
                TlsConfig::builder()
                    .root_certs(RootCerts::PlatformVerifier)
                    .build(),
            )
            .build();
        WebDav {
            kind: kind.to_string(),
            location: location.trim_matches('/').to_string(),
            creds,
            agent: config.into(),
            insecure_loopback: std::env::var("EWE_SAFE_INSECURE_LOOPBACK").as_deref() == Ok("1"),
            guarded: AtomicBool::new(true),
        }
    }

    /// Allow plain http to this machine (tests' mock server).
    pub fn insecure_loopback(mut self, yes: bool) -> WebDav {
        self.insecure_loopback = yes;
        self
    }

    /// What an earlier probe found, so `info()` reports it before the next.
    pub fn assume_guarded(self, guarded: bool) -> WebDav {
        self.guarded.store(guarded, Ordering::Relaxed);
        self
    }

    fn segments(&self) -> Vec<&str> {
        self.location.split('/').filter(|s| !s.is_empty()).collect()
    }

    /// The URL of `path` (segments below the base); `folder` adds the
    /// trailing slash a collection has.
    fn url(&self, path: &[&str], folder: bool) -> Result<Url, Error> {
        let base = self.creds.base()?;
        let mut url =
            Url::parse(&base).map_err(|e| Error::Place(format!("not a server address ({e})")))?;
        match url.scheme() {
            "https" => {}
            "http" if self.insecure_loopback && is_loopback(&url) => {}
            _ => {
                return Err(Error::Place(
                    "Safe talks to a server only over https".into(),
                ));
            }
        }
        {
            let mut segs = url
                .path_segments_mut()
                .map_err(|_| Error::Place("not a server address".into()))?;
            segs.pop_if_empty();
            for s in path {
                segs.push(s);
            }
            if folder {
                segs.push("");
            }
        }
        Ok(url)
    }

    fn file_url(&self) -> Result<Url, Error> {
        self.url(&self.segments(), false)
    }

    fn probe_url(&self) -> Result<Url, Error> {
        let mut path = self.segments();
        path.pop();
        path.push(PROBE_NAME);
        self.url(&path, false)
    }

    /// One request; a refused sign-in is retried once with fresh credentials.
    fn send(
        &self,
        method: &str,
        url: &Url,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<Reply, Error> {
        for attempt in 0..2 {
            let login = self.creds.login()?;
            let mut pair = Zeroizing::new(format!("{}:{}", login.user, login.password.as_str()));
            let auth = Zeroizing::new(format!("Basic {}", STANDARD.encode(pair.as_bytes())));
            pair.zeroize();

            let mut req = http::Request::builder()
                .method(method)
                .uri(url.as_str())
                .header("Authorization", auth.as_str());
            for (k, v) in headers {
                req = req.header(*k, *v);
            }
            let sent = match body {
                Some(b) => self.agent.run(req.body(b).map_err(place_err)?),
                None => self.agent.run(req.body(()).map_err(place_err)?),
            };
            let mut resp = sent.map_err(classify)?;
            let status = resp.status().as_u16();
            if (status == 401 || status == 403) && attempt == 0 {
                self.creds.forget();
                continue;
            }
            let etag = header(&resp, "etag").or_else(|| header(&resp, "oc-etag"));
            let body = if method == "GET" && status == 200 {
                resp.body_mut()
                    .with_config()
                    .limit(MAX_BODY)
                    .read_to_vec()
                    .map_err(classify)?
            } else {
                Vec::new()
            };
            return Ok(Reply {
                status,
                etag: etag.map(|e| normalize_etag(&e)),
                body,
            });
        }
        Err(Error::Place("the server refused the sign-in".into()))
    }

    /// Make every folder above the safe; one that exists is fine.
    fn make_folders(&self) -> Result<(), Error> {
        let segs = self.segments();
        for n in 1..segs.len() {
            let url = self.url(&segs[..n], true)?;
            let r = self.send("MKCOL", &url, &[], None)?;
            match r.status {
                200..=299 | 405 => {}
                s => return Err(status_err("creating a folder", s)),
            }
        }
        Ok(())
    }

    fn put(&self, url: &Url, bytes: &[u8], cond: &[(&str, &str)]) -> Result<Reply, Error> {
        let mut headers = vec![("Content-Type", "application/octet-stream")];
        headers.extend_from_slice(cond);
        let r = self.send("PUT", url, &headers, Some(bytes))?;
        if r.status == 409 || r.status == 404 {
            // the folder isn't there yet (Nextcloud answers 409)
            self.make_folders()?;
            return self.send("PUT", url, &headers, Some(bytes));
        }
        Ok(r)
    }

    /// The version a successful PUT made: the reply's ETag, else a HEAD's,
    /// else the content hash.
    fn version_after_put(&self, url: &Url, reply: &Reply, bytes: &[u8]) -> Result<Tag, Error> {
        if let Some(e) = &reply.etag {
            return Ok(Tag::etag(e));
        }
        let head = self.send("HEAD", url, &[], None)?;
        Ok(match head.etag {
            Some(e) if (200..300).contains(&head.status) => Tag::etag(&e),
            _ => Tag::content(bytes),
        })
    }
}

impl Place for WebDav {
    fn info(&self) -> PlaceInfo {
        PlaceInfo {
            kind: self.kind.clone(),
            location: self.location.clone(),
            guarded: self.guarded.load(Ordering::Relaxed),
        }
    }

    fn fetch(&self, known: Option<&Tag>) -> Result<Fetched, Error> {
        let url = self.file_url()?;
        let quoted = known.and_then(Tag::as_etag).map(|e| format!("\"{e}\""));
        let headers: Vec<(&str, &str)> = quoted
            .as_deref()
            .map(|q| vec![("If-None-Match", q)])
            .unwrap_or_default();
        let r = self.send("GET", &url, &headers, None)?;
        match r.status {
            304 => Ok(Fetched::Unchanged),
            404 => Ok(Fetched::Missing),
            200 => {
                let tag = match &r.etag {
                    Some(e) => Tag::etag(e),
                    None => Tag::content(&r.body),
                };
                if known == Some(&tag) {
                    Ok(Fetched::Unchanged)
                } else {
                    Ok(Fetched::Bytes { bytes: r.body, tag })
                }
            }
            s => Err(status_err("reading the safe", s)),
        }
    }

    fn store(&self, bytes: &[u8], expect: &Expect) -> Result<Stored, Error> {
        let url = self.file_url()?;
        let quoted;
        let cond: Vec<(&str, &str)> = match expect {
            Expect::Absent => {
                self.make_folders()?;
                vec![("If-None-Match", "*")]
            }
            Expect::Tag(t) => match t.as_etag() {
                Some(e) => {
                    quoted = format!("\"{e}\"");
                    vec![("If-Match", quoted.as_str())]
                }
                None => {
                    // no ETags here: compare the content, then write (a short race)
                    match self.fetch(None)? {
                        Fetched::Bytes { tag, .. } if &tag == t => {}
                        _ => return Ok(Stored::Stale),
                    }
                    Vec::new()
                }
            },
        };
        let r = self.put(&url, bytes, &cond)?;
        match r.status {
            200..=299 => Ok(Stored::Ok(self.version_after_put(&url, &r, bytes)?)),
            412 => Ok(Stored::Stale),
            s => Err(status_err("saving the safe", s)),
        }
    }

    fn probe(&self) -> Result<bool, Error> {
        self.make_folders()?;
        let url = self.probe_url()?;
        let _ = self.send("DELETE", &url, &[], None)?;
        let first = self.send("PUT", &url, &[], Some(b"ewe-safe guard probe"))?;
        if !(200..300).contains(&first.status) {
            return Err(status_err("checking the server", first.status));
        }
        let stale_match = self.send(
            "PUT",
            &url,
            &[("If-Match", "\"ewe-safe-not-a-version\"")],
            Some(b"stale"),
        )?;
        let stale_new = self.send("PUT", &url, &[("If-None-Match", "*")], Some(b"stale"))?;
        let _ = self.send("DELETE", &url, &[], None);
        let guarded = stale_match.status == 412 && stale_new.status == 412;
        self.guarded.store(guarded, Ordering::Relaxed);
        Ok(guarded)
    }
}

fn header(resp: &http::Response<ureq::Body>, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// `W/"abc"`, `"abc"` and `abc` are the same version.
fn normalize_etag(raw: &str) -> String {
    let t = raw.trim();
    let t = t.strip_prefix("W/").unwrap_or(t);
    t.trim_matches('"').to_string()
}

fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(a)) => a.is_loopback(),
        Some(url::Host::Ipv6(a)) => a.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

fn status_err(doing: &str, status: u16) -> Error {
    let what = match status {
        401 | 403 => "the server refused the sign-in".to_string(),
        507 => "the account is full".to_string(),
        s => format!("the server answered {s}"),
    };
    Error::Place(format!("{what} ({doing})"))
}

fn place_err(e: http::Error) -> Error {
    Error::Place(e.to_string())
}

/// Can't reach it (offline) vs reached it and it failed (place-error).
fn classify(e: ureq::Error) -> Error {
    match e {
        ureq::Error::Io(_)
        | ureq::Error::Timeout(_)
        | ureq::Error::HostNotFound
        | ureq::Error::ConnectionFailed => Error::Offline(e.to_string()),
        e => Error::Place(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn etags_normalize() {
        assert_eq!(normalize_etag("W/\"abc\""), "abc");
        assert_eq!(normalize_etag("\"abc\""), "abc");
        assert_eq!(normalize_etag(" abc "), "abc");
    }

    #[test]
    fn plain_http_only_to_this_machine_and_only_when_asked() {
        let place = |base: &str, loopback: bool| {
            WebDav::new(
                "webdav",
                "ewe/safe/passwords.kdbx",
                Box::new(Fixed::new(base, "u", Zeroizing::new("p".into()))),
            )
            .insecure_loopback(loopback)
        };
        assert!(place("http://127.0.0.1:9/dav/", false).file_url().is_err());
        assert!(place("http://example.org/dav/", true).file_url().is_err());
        assert!(place("http://127.0.0.1:9/dav/", true).file_url().is_ok());
        let url = place("https://cloud.example/remote.php/dav/files/sam%20s/", false)
            .file_url()
            .expect("url");
        assert_eq!(
            url.as_str(),
            "https://cloud.example/remote.php/dav/files/sam%20s/ewe/safe/passwords.kdbx"
        );
    }

    #[test]
    fn odd_names_are_encoded_folders_end_in_a_slash() {
        let p = WebDav::new(
            "webdav",
            "/My Safe/a#b.kdbx",
            Box::new(Fixed::new("https://h/dav", "u", Zeroizing::new("p".into()))),
        );
        assert_eq!(
            p.file_url().expect("url").as_str(),
            "https://h/dav/My%20Safe/a%23b.kdbx"
        );
        assert_eq!(
            p.url(&["My Safe"], true).expect("url").as_str(),
            "https://h/dav/My%20Safe/"
        );
        assert_eq!(
            p.probe_url().expect("url").as_str(),
            "https://h/dav/My%20Safe/.ewe-safe-probe"
        );
    }
}
