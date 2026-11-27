//! When ewe Safe's window panics, say why in the journal before it is gone.
//!
//! The release build aborts on a panic (panic = "abort"), and a desktop
//! app's stderr goes nowhere: all the owner sees is a window that vanished.
//! `journalctl -t ewe-safe-app -p crit` now has the sentence and the place.

use std::os::unix::net::UnixDatagram;

const JOURNAL: &str = "/run/systemd/journal/socket";

/// Keep the default hook (stderr, for a run from a terminal) and add a line
/// in the journal. Call it first thing in `run()`.
pub fn log_panics() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        to_journal(&format!(
            "ewe-safe-app {}: {info}",
            env!("CARGO_PKG_VERSION")
        ));
        default(info);
    }));
}

/// One datagram in the journal's native protocol. A value with a newline
/// needs the binary form, so the message goes out as one line.
fn to_journal(message: &str) {
    let datagram = entry(message);
    if let Ok(sock) = UnixDatagram::unbound() {
        let _ = sock.send_to(datagram.as_bytes(), JOURNAL);
    }
}

fn entry(message: &str) -> String {
    let line = message.replace('\n', " | ");
    format!("PRIORITY=2\nSYSLOG_IDENTIFIER=ewe-safe-app\nMESSAGE={line}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_is_three_fields_and_one_line_of_message() {
        let e = entry("panicked at src/lib.rs:1:1:\nboom");
        assert_eq!(
            e,
            "PRIORITY=2\nSYSLOG_IDENTIFIER=ewe-safe-app\nMESSAGE=panicked at src/lib.rs:1:1: | boom\n"
        );
    }
}
