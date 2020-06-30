use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-rerun-if-changed=src");
    println!("cargo:rustc-link-search=src");
    println!("cargo:rustc-link-lib=ip6tables");
    println!("cargo:rustc-link-lib=ip6tc");
    println!("cargo:rustc-link-lib=ip4tc");
    println!("cargo:rustc-link-lib=xtables");

    cc::Build::new()
        .file("src/ip6tables.c")
        .include("src")
        .compile("ip6tables");

    let bindings = bindgen::Builder::default()
        .header("src/wrapper.h")
        .derive_default(true)
        .derive_debug(true)
        .blacklist_item("xt_entry_target")
        .blacklist_item("xt_entry_match")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
