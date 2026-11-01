//! Connect to a service (docs/GATE.md S24).

use serde_json::{Map, Value, json};

use crate::daemon::{Daemon, Fail};

pub fn services_json() -> Value {
    json!({"services": []})
}

pub fn connect(_d: &Daemon, _a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh connect isn't built yet"))
}

pub fn test(_d: &Daemon, _a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh test isn't built yet"))
}

pub fn hosts_json(_d: &Daemon) -> Result<Vec<Value>, Fail> {
    Ok(Vec::new())
}

pub fn host_set(_d: &Daemon, _a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh host set isn't built yet"))
}

pub fn host_remove(_a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh host remove isn't built yet"))
}
