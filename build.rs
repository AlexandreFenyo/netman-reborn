use std::env;
use std::path::PathBuf;

fn main() {
    // Windows : lier wpcap.lib depuis le SDK Npcap vendorisé, en delay-load
    // pour pouvoir appeler SetDllDirectoryW avant la résolution de wpcap.dll
    // (Npcap installe ses DLLs dans System32\Npcap, hors du chemin de
    // recherche par défaut du loader). Voir RESEARCH.md.
    if env::var("CARGO_CFG_WINDOWS").is_ok() {
        let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
        let arch = env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH");
        let libdir = match arch.as_str() {
            "x86_64" => "x64",
            "aarch64" => "ARM64",
            other => panic!("unsupported Windows arch for Npcap SDK: {other}"),
        };
        let sdk_lib = manifest.join("third_party/npcap-sdk-1.16/Lib").join(libdir);
        println!("cargo:rustc-link-search=native={}", sdk_lib.display());
        println!("cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll");
        println!("cargo:rustc-link-lib=delayimp");
    }
}
