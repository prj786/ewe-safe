//! `resolve`: the value a `safe://` reference names (docs/PROTOCOL.md,
//! "References"; the rules are `safe_core::refs`). The one resolver for
//! `ewe-safe read`, `run`, `inject`, and any other caller. It reads the
//! unlocked safe in memory and never waits for the place. Like `reveal`, its
//! reply carries a value; nothing here logs one, or the reference.

use safe_core::refs::{self, RefError};
use serde_json::{Map, Value, json};

use crate::daemon::{Daemon, Fail};

impl From<RefError> for Fail {
    fn from(e: RefError) -> Fail {
        let mut f = Fail::new(e.code(), e.message().to_string());
        if let RefError::Ambiguous(_, ids) = &e
            && !ids.is_empty()
        {
            f = f.hint(&format!("The items: {}", ids.join(", ")));
        }
        f
    }
}

pub fn resolve(d: &Daemon, a: &Map<String, Value>) -> Result<Value, Fail> {
    let text = a
        .get("ref")
        .and_then(Value::as_str)
        .ok_or_else(|| Fail::bad("resolve needs ref: a safe:// reference"))?;
    let r = refs::parse(text)?;
    let got = d.with_held(|h| refs::resolve(&h.safe, &r).map_err(Fail::from))?;
    let mut v = json!({
        "value": got.value.as_str(),
        "item_id": got.item_id,
        "field": got.field,
    });
    if let Some(left) = got.expires_in {
        v["expires_in"] = json!(left);
    }
    Ok(v)
}
