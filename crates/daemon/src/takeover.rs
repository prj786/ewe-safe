//! `ssh-takeover` (docs/GATE.md S23): moving SSH to Safe.

use serde_json::{Map, Value};

use crate::daemon::{Daemon, Fail};

pub fn takeover(_d: &Daemon, _a: &Map<String, Value>) -> Result<Value, Fail> {
    Err(Fail::bad("ssh takeover isn't built yet"))
}
