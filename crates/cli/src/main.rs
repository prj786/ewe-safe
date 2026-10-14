//! `ewe-safe`: JSON verbs over the daemon's socket (PLAN.md §11). Not built yet.

fn main() {
    println!(
        "{{\"ok\":false,\"error\":\"not-built\",\"version\":\"{}\"}}",
        safe_core::VERSION
    );
}
