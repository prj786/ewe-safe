//! The write guard (docs/SPIKE-0.md, C1): keepass-rs silently drops XML it
//! does not model, so before Safe writes a file it did not create, the
//! decrypted XML is checked against what keepass-rs is known to write back.
//! Anything else makes the safe read-only, with the reason.
//!
//! The lists below are the (parent, child) element pairs and the attributes
//! that the phase-0 corpus proved to survive a round trip
//! (`tests/fidelity/run.sh`). Extend them only with a corpus file that
//! proves the new pair survives.

use std::collections::BTreeSet;

use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};

const ELEMENTS: &[(&str, &str)] = &[
    ("", "KeePassFile"),
    ("KeePassFile", "Meta"),
    ("KeePassFile", "Root"),
    ("Meta", "Generator"),
    ("Meta", "DatabaseName"),
    ("Meta", "DatabaseNameChanged"),
    ("Meta", "DatabaseDescription"),
    ("Meta", "DatabaseDescriptionChanged"),
    ("Meta", "DefaultUserName"),
    ("Meta", "DefaultUserNameChanged"),
    ("Meta", "MaintenanceHistoryDays"),
    ("Meta", "Color"),
    ("Meta", "MasterKeyChanged"),
    ("Meta", "MasterKeyChangeRec"),
    ("Meta", "MasterKeyChangeForce"),
    ("Meta", "MemoryProtection"),
    ("Meta", "CustomIcons"),
    ("Meta", "RecycleBinEnabled"),
    ("Meta", "RecycleBinUUID"),
    ("Meta", "RecycleBinChanged"),
    ("Meta", "EntryTemplatesGroup"),
    ("Meta", "EntryTemplatesGroupChanged"),
    ("Meta", "LastSelectedGroup"),
    ("Meta", "LastTopVisibleGroup"),
    ("Meta", "HistoryMaxItems"),
    ("Meta", "HistoryMaxSize"),
    ("Meta", "SettingsChanged"),
    ("Meta", "CustomData"),
    // KDBX 3 only: moved into the KDBX 4 inner header on save
    ("Meta", "HeaderHash"),
    ("Meta", "Binaries"),
    ("Binaries", "Binary"),
    ("MemoryProtection", "ProtectTitle"),
    ("MemoryProtection", "ProtectUserName"),
    ("MemoryProtection", "ProtectPassword"),
    ("MemoryProtection", "ProtectURL"),
    ("MemoryProtection", "ProtectNotes"),
    ("CustomIcons", "Icon"),
    ("Icon", "UUID"),
    ("Icon", "Data"),
    ("Icon", "Name"),
    ("Icon", "LastModificationTime"),
    ("CustomData", "Item"),
    ("Item", "Key"),
    ("Item", "Value"),
    ("Item", "LastModificationTime"),
    ("Root", "Group"),
    ("Root", "DeletedObjects"),
    ("DeletedObjects", "DeletedObject"),
    ("DeletedObject", "UUID"),
    ("DeletedObject", "DeletionTime"),
    ("Group", "UUID"),
    ("Group", "Name"),
    ("Group", "Notes"),
    ("Group", "IconID"),
    ("Group", "CustomIconUUID"),
    ("Group", "Times"),
    ("Group", "IsExpanded"),
    ("Group", "DefaultAutoTypeSequence"),
    ("Group", "EnableAutoType"),
    ("Group", "EnableSearching"),
    ("Group", "LastTopVisibleEntry"),
    ("Group", "PreviousParentGroup"),
    ("Group", "Tags"),
    ("Group", "CustomData"),
    ("Group", "Group"),
    ("Group", "Entry"),
    ("Entry", "UUID"),
    ("Entry", "IconID"),
    ("Entry", "CustomIconUUID"),
    ("Entry", "ForegroundColor"),
    ("Entry", "BackgroundColor"),
    ("Entry", "OverrideURL"),
    ("Entry", "QualityCheck"),
    ("Entry", "Tags"),
    ("Entry", "PreviousParentGroup"),
    ("Entry", "Times"),
    ("Entry", "String"),
    ("Entry", "Binary"),
    ("Entry", "AutoType"),
    ("Entry", "CustomData"),
    ("Entry", "History"),
    ("History", "Entry"),
    ("String", "Key"),
    ("String", "Value"),
    ("Binary", "Key"),
    ("Binary", "Value"),
    ("AutoType", "Enabled"),
    ("AutoType", "DataTransferObfuscation"),
    ("AutoType", "DefaultSequence"),
    ("AutoType", "Association"),
    ("Association", "Window"),
    ("Association", "KeystrokeSequence"),
    ("Times", "CreationTime"),
    ("Times", "LastModificationTime"),
    ("Times", "LastAccessTime"),
    ("Times", "ExpiryTime"),
    ("Times", "Expires"),
    ("Times", "UsageCount"),
    ("Times", "LocationChanged"),
];

const ATTRIBUTES: &[(&str, &str)] = &[
    ("Value", "Protected"),
    ("Value", "Ref"),
    // KDBX 3's binary pool
    ("Binary", "ID"),
    ("Binary", "Compressed"),
];

/// Most reasons listed; past this the list says "and more".
const MAX_REASONS: usize = 20;

/// What a write would lose.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Content keepass-rs would drop: the safe must stay read-only.
    pub unsupported: Vec<String>,
    /// Losses that change no data a person reads: today only the fallback
    /// icon number of an entry with a custom icon (SPIKE-0, F3).
    pub cosmetic: Vec<String>,
}

impl Report {
    pub fn writable(&self) -> bool {
        self.unsupported.is_empty()
    }
}

#[derive(Default)]
struct EntryIcons {
    custom: bool,
    builtin: Option<String>,
}

/// Scan a decrypted KDBX inner XML document (`Database::get_xml`).
pub fn scan(xml: &[u8]) -> Report {
    let mut reader = Reader::from_reader(xml);
    let mut buf = Vec::new();
    let mut stack: Vec<String> = Vec::new();
    let mut entries: Vec<EntryIcons> = Vec::new();
    let mut in_icon_id = false;
    let mut unsupported = BTreeSet::new();
    let mut cosmetic = BTreeSet::new();

    let open = |e: &BytesStart<'_>, stack: &Vec<String>, unsupported: &mut BTreeSet<String>| {
        let tag = e.name().into_inner().to_string();
        let parent = stack.last().map(String::as_str).unwrap_or("");
        if !ELEMENTS.contains(&(parent, tag.as_str())) {
            unsupported.insert(format!("element <{tag}> in <{parent}>"));
        }
        for a in e.attributes().flatten() {
            let key = a.key.into_inner().to_string();
            if !ATTRIBUTES.contains(&(tag.as_str(), key.as_str())) {
                unsupported.insert(format!("attribute {key} on <{tag}>"));
            }
        }
        tag
    };

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let tag = open(&e, &stack, &mut unsupported);
                match tag.as_str() {
                    "Entry" => entries.push(EntryIcons::default()),
                    "CustomIconUUID" if stack.last().is_some_and(|p| p == "Entry") => {
                        if let Some(top) = entries.last_mut() {
                            top.custom = true;
                        }
                    }
                    "IconID" => in_icon_id = stack.last().is_some_and(|p| p == "Entry"),
                    _ => {}
                }
                stack.push(tag);
            }
            Ok(Event::Empty(e)) => {
                open(&e, &stack, &mut unsupported);
            }
            Ok(Event::Text(t)) if in_icon_id => {
                if let Some(top) = entries.last_mut() {
                    top.builtin = Some(t.as_ref().trim().to_string());
                }
            }
            Ok(Event::End(_)) => {
                in_icon_id = false;
                if stack.pop().as_deref() == Some("Entry")
                    && let Some(icons) = entries.pop()
                    && icons.custom
                    && icons.builtin.is_some_and(|n| n != "0")
                {
                    cosmetic.insert(
                        "an entry's fallback icon number (it has a custom icon)".to_string(),
                    );
                }
            }
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => {
                unsupported.insert(format!("unreadable XML: {e}"));
                break;
            }
        }
        buf.clear();
    }

    let mut unsupported: Vec<String> = unsupported.into_iter().collect();
    if unsupported.len() > MAX_REASONS {
        unsupported.truncate(MAX_REASONS);
        unsupported.push("and more".to_string());
    }
    Report {
        unsupported,
        cosmetic: cosmetic.into_iter().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &str = r#"<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<KeePassFile><Meta><Generator>KeePassXC</Generator><MemoryProtection><ProtectPassword>True</ProtectPassword></MemoryProtection><CustomData/></Meta>
<Root><Group><UUID>AA==</UUID><Name>Root</Name><Times><LastModificationTime>x</LastModificationTime></Times>
<Entry><UUID>AQ==</UUID><IconID>0</IconID><CustomIconUUID>Ag==</CustomIconUUID>
<String><Key>Password</Key><Value Protected="True">c2VjcmV0</Value></String>
<History><Entry><UUID>AQ==</UUID><IconID>0</IconID></Entry></History></Entry></Group><DeletedObjects/></Root></KeePassFile>"#;

    #[test]
    fn a_known_file_is_writable() {
        let r = scan(PLAIN.as_bytes());
        assert_eq!(r, Report::default());
        assert!(r.writable());
    }

    #[test]
    fn an_unknown_element_anywhere_makes_it_read_only() {
        for (needle, insert) in [
            (
                "<CustomData/></Meta>",
                "<CustomData/><MasterKeyChangeForceOnce>True</MasterKeyChangeForceOnce></Meta>",
            ),
            (
                "<IconID>0</IconID><CustomIconUUID>",
                "<IconID>0</IconID><FutureThing/><CustomIconUUID>",
            ),
            (
                "<DeletedObjects/>",
                "<DeletedObjects/><FutureRoot>x</FutureRoot>",
            ),
            ("<Name>Root</Name>", "<Name>Root</Name><FutureGroup/>"),
        ] {
            let xml = PLAIN.replacen(needle, insert, 1);
            assert_ne!(xml, PLAIN, "fixture changed: {needle}");
            let r = scan(xml.as_bytes());
            assert!(!r.writable(), "{insert}");
            assert_eq!(r.unsupported.len(), 1, "{:?}", r.unsupported);
        }
    }

    #[test]
    fn an_unknown_attribute_makes_it_read_only() {
        let xml = PLAIN.replacen(r#"Protected="True""#, r#"Protected="True" Future="1""#, 1);
        let r = scan(xml.as_bytes());
        assert_eq!(
            r.unsupported,
            vec!["attribute Future on <Value>".to_string()]
        );
    }

    #[test]
    fn a_nonzero_fallback_icon_next_to_a_custom_icon_is_cosmetic() {
        let xml = PLAIN.replacen(
            "<IconID>0</IconID><CustomIconUUID>",
            "<IconID>12</IconID><CustomIconUUID>",
            1,
        );
        let r = scan(xml.as_bytes());
        assert!(r.writable());
        assert_eq!(r.cosmetic.len(), 1);
        // a history version without a custom icon keeps its number: not a loss
        let xml = PLAIN.replacen(
            "<History><Entry><UUID>AQ==</UUID><IconID>0</IconID>",
            "<History><Entry><UUID>AQ==</UUID><IconID>7</IconID>",
            1,
        );
        assert_eq!(scan(xml.as_bytes()), Report::default());
    }

    #[test]
    fn garbage_is_never_writable() {
        assert!(!scan(b"<KeePassFile><Meta></Root>").writable());
        assert!(!scan(b"<NotKeePass/>").writable());
    }
}
