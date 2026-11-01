//! Stamps the library with the sealbook commit it was built from, so
//! sealbook-app's CI can check its checked-in binaries against its pin.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    for path in ["crates", "Cargo.lock", ".git/HEAD", ".git/index"] {
        println!("cargo:rerun-if-changed={root}/{path}");
    }
    let commit = git(&["-C", root, "rev-parse", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let dirty = git(&["-C", root, "status", "--porcelain"]).is_none_or(|s| !s.is_empty());
    let stamp = if dirty {
        format!("{commit}-dirty")
    } else {
        commit
    };
    println!("cargo:rustc-env=SEALBOOK_COMMIT={stamp}");
}
