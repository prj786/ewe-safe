//! The `import` verb (docs/PROTOCOL.md, docs/IMPORT.md): an export file the
//! daemon reads itself (same uid), or the 1Password app through `op`, run
//! as argv. The items are built in memory and added in one edit: one save,
//! one upload. Nothing but the safe is written to disk, and the export's
//! bytes and parsed JSON are wiped when done.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use safe_core::import::{self, Batch, Fetched, Format, OpFile, Options, Report};
use serde_json::{Map, Value, json};
use zeroize::{Zeroize, Zeroizing};

use crate::daemon::{Daemon, Fail, rd};
use crate::log;

/// An export bigger than this isn't read (it is held in memory).
const MAX_FILE: u64 = 2 * 1024 * 1024 * 1024;
/// The first `op` call may wait for the user to approve Safe in 1Password.
const OP_FIRST: Duration = Duration::from_secs(180);
const OP_EACH: Duration = Duration::from_secs(60);
pub const DELETE_HINT: &str = "Delete the export file now: it holds your passwords in plain text.";

fn s<'a>(a: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|v| !v.is_empty())
}

fn list(a: &Map<String, Value>, k: &str) -> Vec<String> {
    match a.get(k) {
        Some(Value::Array(v)) => v
            .iter()
            .filter_map(Value::as_str)
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_string)
            .collect(),
        Some(Value::String(x)) if !x.trim().is_empty() => vec![x.trim().to_string()],
        _ => Vec::new(),
    }
}

fn source(message: impl Into<String>) -> Fail {
    Fail::new("source-error", message)
}

pub fn report_json(r: &Report) -> Value {
    json!({
        "logins": r.logins,
        "notes": r.notes,
        "ssh_keys": r.ssh_keys,
        "cards": r.cards,
        "addresses": r.addresses,
        "attachments": r.attachments,
        "otps": r.otps,
        "duplicates": r.duplicates,
        "skipped": r.skipped.iter().map(|x| json!({"title": x.title, "reason": x.reason})).collect::<Vec<_>>(),
        "folders": r.folders,
    })
}

pub fn import(d: &Arc<Daemon>, a: &Map<String, Value>) -> Result<Value, Fail> {
    let name = s(a, "format").unwrap_or("");
    let format = Format::parse(name).ok_or_else(|| {
        Fail::bad(format!(
            "import needs a format: {}",
            Format::NAMES.join(", ")
        ))
    })?;
    {
        // before 1Password asks the user anything
        let snap = rd(&d.snap);
        if !snap.set_up {
            return Err(Fail::not_set_up());
        }
        if snap.locked {
            return Err(Fail::locked());
        }
    }
    let opts = Options {
        folder: s(a, "folder").unwrap_or("").to_string(),
        skip_duplicates: a.get("skip_duplicates").and_then(Value::as_bool) == Some(true),
    };
    let dry = a.get("dry_run").and_then(Value::as_bool) == Some(true);

    let batch = match format {
        Format::OnePux => {
            let bytes = read_file(s(a, "file"))?;
            import::read_1pux(&bytes).map_err(|e| source(e.0))?
        }
        Format::OnePasswordCsv => {
            let bytes = read_file(s(a, "file"))?;
            let text = utf8(bytes)?;
            import::read_1password_csv(&text).map_err(|e| source(e.0))?
        }
        Format::Op => {
            if s(a, "file").is_some() {
                return Err(Fail::bad(
                    "import op reads the 1Password app, not a file: leave the file out",
                ));
            }
            from_op(s(a, "account"), &list(a, "vault"))?
        }
    };

    let mut out = if dry {
        let report = d.with_held(|h| Ok(import::plan(&batch, &h.safe.items(), &opts).report))?;
        json!({"report": report_json(&report), "dry_run": true})
    } else {
        let (report, sync) = d.mutate(|safe| {
            let r = safe.import(&batch, &opts)?;
            let changed = r.logins + r.notes + r.ssh_keys + r.cards + r.addresses > 0;
            Ok((r, changed))
        })?;
        let mut keys = match report.ssh_keys {
            0 => String::new(),
            n => format!(", {n} SSH keys"),
        };
        if report.cards + report.addresses > 0 {
            keys.push_str(&format!(
                ", {} cards, {} addresses",
                report.cards, report.addresses
            ));
        }
        log(&format!(
            "imported {} logins and {} notes{keys} ({name})",
            report.logins, report.notes
        ));
        json!({"report": report_json(&report), "sync": sync})
    };
    drop(batch);
    if format != Format::Op {
        out["hint"] = json!(DELETE_HINT);
    }
    Ok(out)
}

/// The export's bytes, read whole into a buffer that is wiped when dropped.
fn read_file(path: Option<&str>) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let path = path.ok_or_else(|| Fail::bad("import needs the export file"))?;
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(Fail::bad("Give the export file's full path."));
    }
    let cant = |e: std::io::Error| source(format!("Safe can't read {}: {e}", p.display()));
    let f = std::fs::File::open(p).map_err(cant)?;
    let size = f.metadata().map_err(cant)?.len();
    if size > MAX_FILE {
        return Err(source(format!(
            "{} is too big to import ({} MB).",
            p.display(),
            size / (1024 * 1024)
        )));
    }
    // the exact size up front: a buffer that grew would leave copies behind
    let mut buf = Zeroizing::new(Vec::with_capacity(size as usize));
    f.take(MAX_FILE + 1).read_to_end(&mut buf).map_err(cant)?;
    Ok(buf)
}

fn utf8(mut bytes: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>, Fail> {
    let v = std::mem::take(&mut *bytes);
    match String::from_utf8(v) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            e.into_bytes().zeroize();
            Err(source("The CSV file isn't UTF-8 text."))
        }
    }
}

// ── op ──────────────────────────────────────────────────────────────────

fn not_installed() -> Fail {
    source("1Password's command-line tool (op) isn't installed.").hint(
        "Install 1password-cli, then in the 1Password app turn on Settings → Developer → Integrate with 1Password CLI",
    )
}

/// `op` from the PATH. `EWE_SAFE_OP` is a test switch: the tests name a fake
/// (or nothing) there, so the real 1Password is never asked.
fn op_program() -> std::ffi::OsString {
    std::env::var_os("EWE_SAFE_OP")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "op".into())
}

/// One `op` call as argv; its stdout, wiped when dropped.
fn op(args: &[&str], account: Option<&str>, wait: Duration) -> Result<Zeroizing<Vec<u8>>, Fail> {
    let mut c = Command::new(op_program());
    c.args(args);
    if let Some(acc) = account {
        c.args(["--account", acc]);
    }
    let mut child = c
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => not_installed(),
            _ => source(format!("Safe can't run op: {e}")),
        })?;
    let (Some(mut stdout), Some(mut stderr)) = (child.stdout.take(), child.stderr.take()) else {
        let _ = child.kill();
        return Err(source("Safe can't read op's answer."));
    };
    let out = std::thread::spawn(move || {
        let mut buf = Zeroizing::new(Vec::new());
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err = std::thread::spawn(move || {
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) if start.elapsed() > wait => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break None,
        }
    };
    let stdout = out.join().unwrap_or_default();
    let stderr = err.join().unwrap_or_default();
    match status {
        None => Err(source(
            "1Password didn't answer in time: approve Safe in the 1Password app, then import again.",
        )),
        Some(st) if st.success() => Ok(stdout),
        Some(_) => {
            drop(stdout);
            // op's own words, first line: no value is in an error
            let said: String = stderr
                .lines()
                .map(str::trim)
                .find(|l| !l.is_empty())
                .unwrap_or("it failed")
                .chars()
                .take(200)
                .collect();
            Err(source(format!("1Password's op said: {said}")))
        }
    }
}

fn op_json(args: &[&str], account: Option<&str>, wait: Duration) -> Result<Value, Fail> {
    let bytes = op(args, account, wait)?;
    serde_json::from_slice(&bytes).map_err(|_| source("op printed something that isn't JSON."))
}

/// Every item of the chosen vaults (all of them by default), archived ones
/// too, then the files they hold.
fn from_op(account: Option<&str>, wanted: &[String]) -> Result<Batch, Fail> {
    let mut vaults_json = op_json(&["vault", "list", "--format", "json"], account, OP_FIRST)?;
    let mut vaults: Vec<(String, String)> = vaults_json
        .as_array()
        .into_iter()
        .flatten()
        .map(|v| {
            (
                v.get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                v.get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .filter(|(id, _)| !id.is_empty())
        .collect();
    import::wipe(&mut vaults_json);
    if !wanted.is_empty() {
        for w in wanted {
            if !vaults
                .iter()
                .any(|(id, name)| id == w || name.eq_ignore_ascii_case(w))
            {
                return Err(Fail::bad(format!("1Password has no vault {w:?}.")));
            }
        }
        vaults.retain(|(id, name)| {
            wanted
                .iter()
                .any(|w| id == w || name.eq_ignore_ascii_case(w))
        });
    }

    let mut items: Vec<(Value, String)> = Vec::new();
    let fetched = (|| -> Result<(), Fail> {
        for (vid, vname) in &vaults {
            let mut listed = op_json(
                &[
                    "item",
                    "list",
                    "--vault",
                    vid,
                    "--format",
                    "json",
                    "--include-archive",
                ],
                account,
                OP_EACH,
            )?;
            let ids: Vec<(String, bool)> = listed
                .as_array()
                .into_iter()
                .flatten()
                .map(|i| {
                    (
                        i.get("id")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        i.get("state").and_then(Value::as_str).unwrap_or("") == "ARCHIVED",
                    )
                })
                .filter(|(id, _)| !id.is_empty())
                .collect();
            import::wipe(&mut listed);
            for (id, archived) in ids {
                let mut args = vec![
                    "item",
                    "get",
                    id.as_str(),
                    "--vault",
                    vid,
                    "--format",
                    "json",
                ];
                if archived {
                    args.push("--include-archive");
                }
                let mut item = op_json(&args, account, OP_EACH)?;
                if archived && item.get("state").is_none() {
                    item["state"] = json!("ARCHIVED");
                }
                let folder = if vname.trim().is_empty() {
                    "1Password".to_string()
                } else {
                    vname.trim().to_string()
                };
                items.push((item, folder));
            }
        }
        Ok(())
    })();
    if let Err(f) = fetched {
        for (v, _) in items.iter_mut() {
            import::wipe(v);
        }
        return Err(f);
    }

    let mut fetch = |f: &OpFile| -> Fetched {
        let got = if f.document {
            op(
                &["document", "get", &f.item, "--vault", &f.vault],
                account,
                OP_EACH,
            )
        } else {
            let reference = format!("op://{}/{}/{}", f.vault, f.item, f.file);
            op(&["read", "--no-newline", &reference], account, OP_EACH)
        };
        let data = got.map_err(|fail| fail.message)?;
        if data.len() as u64 > import::MAX_ATTACHMENT {
            return Err(format!(
                "it is bigger than {} MB: the whole safe travels on every save",
                import::MAX_ATTACHMENT / (1024 * 1024)
            ));
        }
        Ok(data)
    };
    let batch = import::read_op(&items, &mut fetch);
    for (v, _) in items.iter_mut() {
        import::wipe(v);
    }
    Ok(batch)
}
