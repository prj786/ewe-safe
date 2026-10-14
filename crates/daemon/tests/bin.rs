//! The binary itself (this file also makes `cargo test` build it for the
//! CLI's end-to-end tests).

#[test]
fn version_is_json() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_ewe-safed"))
        .arg("--version")
        .output()
        .expect("ewe-safed");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    assert_eq!(v["protocol"], 1);
    assert_eq!(v["ok"], true);
}
