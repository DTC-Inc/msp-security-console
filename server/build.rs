//! Two things. The migrations are compiled into the binary (sqlx::migrate!), so a change to one rebuilds it. And, on a
//! Mac only (development; the image is Linux): ONNX Runtime's prebuilt macOS archive asks the OS's
//! version through clang's `__isPlatformVersionAtLeast`, which lives in clang's own runtime library. rustc links with
//! -nodefaultlibs, so that library isn't linked unless it's named here.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=migrations");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") { return; }
    let Ok(out) = std::process::Command::new("xcrun").args(["clang", "--print-resource-dir"]).output() else { return };
    let dir = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if dir.is_empty() { return; }
    println!("cargo:rustc-link-search=native={dir}/lib/darwin");
    println!("cargo:rustc-link-lib=static=clang_rt.osx");
}
