use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();

    cbindgen::Builder::new()
        .with_crate(crate_dir)
        .with_language(cbindgen::Language::C)
        .include_item("Response")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("pq_message_lib.h");
}
