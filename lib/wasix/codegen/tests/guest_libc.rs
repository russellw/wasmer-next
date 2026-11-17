//! Checks the guest libc C glue against the canonical WIT and generator.
//! Set `WASIXV2_LIBC_BLESS=1` to regenerate it.

use std::path::Path;

use wasixv2_codegen::{Target, generate_c};

#[test]
fn guest_libc_is_up_to_date() {
    let codegen = Path::new(env!("CARGO_MANIFEST_DIR"));
    let libc = codegen.join("../../../guest/libc");
    let files = generate_c(&codegen.join("wit"), Target::WASM32).unwrap();
    for file in files {
        let path = libc.join(file.path);
        if std::env::var_os("WASIXV2_LIBC_BLESS").is_some() {
            std::fs::write(&path, &file.contents).unwrap();
        }
        let current = std::fs::read_to_string(&path).unwrap();
        assert!(
            file.contents == current,
            "guest/libc/{} is stale; run WASIXV2_LIBC_BLESS=1 cargo test -p wasixv2-codegen --test guest_libc --locked",
            file.path
        );
    }
}
