//! Git commits signed with a key in Safe (docs/GATE.md S25).

use serde_json::{Map, Value};

use crate::daemon::{Daemon, Fail};

pub fn sign(_d: &Daemon, _a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh sign-commits isn't built yet"))
}

pub fn status_json(_d: &Daemon) -> Value {
    Value::Null
}

pub fn off_for_disable(_d: &Daemon) -> bool {
    false
}

pub fn converge(_d: &Daemon) {}
