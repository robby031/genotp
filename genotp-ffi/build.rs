//! Build script — auto-generate `include/genotp.h` from `src/lib.rs`
//! using cbindgen. Keeps the C header always in sync with the Rust FFI
//! surface.
//!
//! **Opt-out:** set `GENOTP_FFI_SKIP_CBINDGEN=1` for hermetic builds
//! (e.g. docs.rs, CI sandbox where source tree must not be modified).
//! The previously-committed header in the source tree will be used.

use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo when to rerun this script.
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=GENOTP_FFI_SKIP_CBINDGEN");

    // Skip on docs.rs (source tree is read-only) or explicit opt-out.
    if env::var("DOCS_RS").is_ok() {
        println!("cargo:warning=genotp-ffi: DOCS_RS set, skipping cbindgen");
        return;
    }
    if env::var("GENOTP_FFI_SKIP_CBINDGEN").is_ok() {
        println!("cargo:warning=genotp-ffi: GENOTP_FFI_SKIP_CBINDGEN set, skipping cbindgen");
        return;
    }

    let crate_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let output = crate_dir.join("include").join("genotp.h");

    // Ensure include/ exists.
    if let Some(parent) = output.parent()
        && !parent.exists()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        println!("cargo:warning=genotp-ffi: failed to create {parent:?}: {e}");
        return;
    }

    let config = cbindgen::Config::from_file(crate_dir.join("cbindgen.toml"))
        .expect("cbindgen.toml must parse");

    match cbindgen::Builder::new()
        .with_crate(&crate_dir)
        .with_config(config)
        .generate()
    {
        Ok(bindings) => {
            bindings.write_to_file(&output);
            println!("cargo:warning=genotp-ffi: regenerated {}", output.display());
        }
        Err(e) => {
            // Don't fail the build — fall back to whatever header is on disk.
            // Helpful during incremental development with WIP FFI changes.
            println!("cargo:warning=genotp-ffi: cbindgen failed (using existing header): {e}");
        }
    }
}
