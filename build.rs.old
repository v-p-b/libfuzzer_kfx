use cc;

fn main(){
    println!("cargo:rustc-link-search=target/release");
    println!("cargo:rustc-link-lib=libfuzzer_libkfx_dummy");
    cc::Build::new()
        .file("afl.c")
        .file("harness.c")
        .include("target/release")
        //.link_staticlib("target/release", "libfuzzer_libkfx_dummy")
        .compile("kfx_built")

}
