//! What a process holding secrets owes the machine (PLAN.md §8): no core
//! dumps, no same-uid ptrace, and secrets kept out of swap where it's cheap.
//! One implementation, in safe-core, shared with the CLI.

pub use safe_core::hygiene::{Pinned, harden};
