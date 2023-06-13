use std::{env, path::PathBuf};

fn main() {
    // these headers cause problems with circular includes, so we don't generate bindings for them
    let disallowed_headers = vec!["fifo.h".into(), "rastaredundancy.h".into()];

    println!("cargo:rerun-if-changed=rasta-sys");

    // Right now, we have to overwrite the cmake options because librasta will not compile with -Werror.
    std::fs::copy(concat!(env!("CARGO_MANIFEST_DIR"), "/CompileOptions.cmake"), "rasta-protocol/cmake/CompileOptions.cmake").expect("Failed to copy CmakeOptions file");

    let mut dst = cmake::build("rasta-protocol");
    dst.push("lib");

    println!("cargo:rustc-link-search=native={}", dst.display());
    println!("cargo:rustc-link-lib=dylib=rasta_tcp"); // choose which protocol to use

    let mut bindings = bindgen::Builder::default().clang_arg("-Irasta-protocol/src/include/");
    for header in
        std::fs::read_dir("rasta-protocol/src/include/rasta").expect("Failed to read directory")
    {
        let header = header.unwrap();
        if !disallowed_headers.contains(&header.file_name().to_string_lossy().into_owned()) {
            bindings = bindings.header(header.path().to_string_lossy());
        }
    }
    bindings = bindings.header("rasta-protocol/examples/common/headers/configfile.h");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .generate()
        .unwrap()
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
