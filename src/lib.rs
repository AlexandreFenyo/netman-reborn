//! Netman Reborn — bibliothèque : capture, modèle d'agrégation.
//! Le binaire (`main.rs`) ne fait que le câblage CLI/threads.

pub mod capture;
pub mod model;
pub mod resolve;
pub mod server;
pub mod wsproto;

/// Npcap installe wpcap.dll dans System32\Npcap, hors du chemin de recherche
/// du loader. wpcap.dll est liée en delay-load (build.rs) : ce répertoire doit
/// être ajouté AVANT le premier appel pcap (binaire ET tests). Voir RESEARCH.md.
#[cfg(windows)]
pub fn setup_npcap_dll_path() {
    use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let dir = format!(r"{sysroot}\System32\Npcap");
    let wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` est une chaîne UTF-16 terminée par NUL, valide pendant l'appel.
    unsafe {
        SetDllDirectoryW(wide.as_ptr());
    }
}

#[cfg(not(windows))]
pub fn setup_npcap_dll_path() {}
