//! Passkeys on items (the fields, keys and answers are
//! [`crate::passkey`]). A change is a tracked edit, as [`Safe::update`]
//! makes one: the item's previous version goes to its history, so a
//! replaced or removed passkey can still be found there.

use keepass::db::{Times, fields};

use super::{Error, HISTORY_MAX_ITEMS, Safe, entry_id, settle_history};
use crate::item::{self, Draft};
use crate::passkey::{self, New, Secret};

impl Safe {
    fn history_max(&self) -> usize {
        self.db
            .meta
            .history_max_items
            .and_then(|n| usize::try_from(n).ok())
            .unwrap_or(HISTORY_MAX_ITEMS)
    }

    /// Put a passkey on an item outside the recycle bin, replacing the one
    /// it had (one per entry). An empty username takes the passkey's, as
    /// KeePassDX does.
    pub fn set_passkey(&mut self, id: &str, p: &New) -> Result<(), Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let parent = self
            .db
            .entry(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?
            .parent()
            .id();
        if self.in_recycle_bin(parent) {
            return Err(Error::NotFound(id.to_string()));
        }
        let max = self.history_max();
        let mut e = self
            .db
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        e.edit_tracking(|t| {
            passkey::store(t, p);
            let unnamed = t.get(fields::USERNAME).is_none_or(|u| u.trim().is_empty());
            if unnamed && !p.username.is_empty() {
                t.set_unprotected(fields::USERNAME, p.username.as_str());
            }
            t.times.last_modification = Some(Times::now());
        });
        settle_history(&mut e, max);
        Ok(())
    }

    /// A new login at the top holding a passkey; returns its id.
    pub fn add_passkey_login(&mut self, draft: &Draft, p: &New) -> Result<String, Error> {
        self.writable()?;
        let root = self.db.root().id();
        let id = self
            .db
            .group_mut(root)
            .ok_or_else(|| Error::NotFound("the top folder".to_string()))?
            .add_entry()
            .edit(|e| {
                item::apply(e, draft);
                passkey::store(e, p);
                e.times.last_modification = Some(Times::now());
            })
            .id();
        Ok(id.to_string())
    }

    /// Take the passkey off an item (its fields and the tag). Says whether
    /// there was one; an item without saves nothing.
    pub fn remove_passkey(&mut self, id: &str) -> Result<bool, Error> {
        self.writable()?;
        let eid = entry_id(id)?;
        let max = self.history_max();
        let mut e = self
            .db
            .entry_mut(eid)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        if !passkey::has_any(&e) {
            return Ok(false);
        }
        e.edit_tracking(|t| {
            passkey::remove(t);
            t.times.last_modification = Some(Times::now());
        });
        settle_history(&mut e, max);
        Ok(true)
    }

    /// What signing with an item's passkey needs; None when it has none.
    /// Never logged by the caller.
    pub fn passkey_secret(&self, id: &str) -> Result<Option<Secret>, Error> {
        let e = self
            .db
            .entry(entry_id(id)?)
            .ok_or_else(|| Error::NotFound(id.to_string()))?;
        Ok(passkey::secret_of(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::item::Kind;
    use crate::passkey::{Alg, Key};
    use keepass::config::KdfConfig;
    use zeroize::Zeroizing;

    fn cheap() -> KdfConfig {
        KdfConfig::Argon2id {
            iterations: 1,
            memory: 1024 * 1024,
            parallelism: 1,
            version: argon2::Version::Version13,
        }
    }

    fn new(rp: &str, user: &str) -> New {
        New {
            rp_id: rp.into(),
            username: user.into(),
            credential_id: passkey::b64url(&passkey::new_credential_id().expect("id")),
            pem: Key::generate(Alg::Es256).expect("key").pem,
            user_handle: "dXNlcg".into(),
        }
    }

    #[test]
    fn a_passkey_on_a_login_is_a_tracked_edit_that_survives_a_write() {
        let mut s = Safe::create("x", cheap());
        let id = s
            .add(&Draft {
                kind: Kind::Login,
                title: "GitHub".into(),
                password: Zeroizing::new("pw".into()),
                ..Draft::default()
            })
            .expect("add");
        let p = new("github.com", "sam");
        s.set_passkey(&id, &p).expect("set");
        let sum = s.summary(&id).expect("summary");
        assert_eq!(sum.username, "sam", "an empty username takes the passkey's");
        assert_eq!(
            sum.passkey.as_ref().map(|i| i.rp_id.as_str()),
            Some("github.com")
        );
        assert!(sum.tags.contains(&"Passkey".to_string()));

        let key = safe_key();
        let back = Safe::open(&s.to_bytes(&key).expect("write"), &key).expect("open");
        let secret = back.passkey_secret(&id).expect("read").expect("a passkey");
        assert_eq!(secret.pem.as_str(), p.pem.as_str());
        assert_eq!(secret.credential_id, p.credential_id);
        let e = back
            .database()
            .entry(entry_id(&id).expect("id"))
            .expect("entry");
        assert_eq!(e.history.as_ref().map(|h| h.get_entries().len()), Some(1));
        assert!(e.fields[passkey::PRIVATE_KEY_PEM].is_protected());

        // a second passkey replaces the first; the first stays in history
        let mut s = back;
        s.set_passkey(&id, &new("github.com", "sam2"))
            .expect("replace");
        let sum = s.summary(&id).expect("summary");
        assert_eq!(sum.username, "sam", "a username is never overwritten");
        assert_eq!(sum.passkey.expect("passkey").username, "sam2");

        assert!(s.remove_passkey(&id).expect("remove"));
        assert!(s.summary(&id).expect("summary").passkey.is_none());
        assert!(!s.remove_passkey(&id).expect("again"), "nothing to remove");
        assert_eq!(
            s.reveal(&id, &crate::item::Field::Password)
                .expect("pw")
                .as_str(),
            "pw"
        );
    }

    #[test]
    fn a_new_passkey_login_and_the_bin() {
        let mut s = Safe::create("x", cheap());
        let draft = Draft {
            kind: Kind::Login,
            title: "GitHub".into(),
            username: "sam".into(),
            websites: vec!["https://github.com".into()],
            ..Draft::default()
        };
        let id = s
            .add_passkey_login(&draft, &new("github.com", "sam"))
            .expect("add");
        let sum = s.summary(&id).expect("summary");
        assert_eq!(
            (sum.title.as_str(), sum.username.as_str(), sum.has_password),
            ("GitHub", "sam", false)
        );
        assert_eq!(sum.websites, ["https://github.com"]);
        assert_eq!(sum.tags, ["Passkey"]);
        s.trash(&id).expect("trash");
        assert!(matches!(
            s.set_passkey(&id, &new("github.com", "sam")),
            Err(Error::NotFound(_))
        ));
    }

    fn safe_key() -> keepass::DatabaseKey {
        super::super::key("correct horse", None).expect("key")
    }
}
