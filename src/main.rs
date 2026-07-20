//! Netman Reborn — Etherman (L2) + Interman (L3), moniteur passif.
//! Jalon 1 : capture promiscuous + compteur trames/s en console.

mod capture;

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;

use capture::CaptureStats;

#[derive(Parser, Debug)]
#[command(
    name = "netman",
    about = "Etherman + Interman — passive network monitor"
)]
struct Cli {
    /// Capture interface: index or name substring (interactive prompt if omitted)
    #[arg(long)]
    iface: Option<String>,

    /// Replay a .pcap file instead of capturing live (offline mode)
    #[arg(long, value_name = "FILE", conflicts_with = "iface")]
    pcap_file: Option<PathBuf>,

    /// HTTP/WebSocket listen port (used from milestone 3 on)
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Fade timeout in seconds: nodes/edges unseen for this long are removed
    #[arg(long, default_value_t = 60)]
    fade: u64,
}

/// Npcap installe wpcap.dll dans System32\Npcap, hors du chemin de recherche
/// du loader. wpcap.dll est liée en delay-load (build.rs) : ce répertoire doit
/// être ajouté AVANT le premier appel pcap. Voir RESEARCH.md.
#[cfg(windows)]
fn setup_npcap_dll_path() {
    use windows_sys::Win32::System::LibraryLoader::SetDllDirectoryW;
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let dir = format!(r"{sysroot}\System32\Npcap");
    let wide: Vec<u16> = dir.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` est une chaîne UTF-16 terminée par NUL, valide pendant l'appel.
    unsafe {
        SetDllDirectoryW(wide.as_ptr());
    }
}

fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    setup_npcap_dll_path();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netman=info".into()),
        )
        .init();

    let cli = Cli::parse();
    tracing::info!(
        port = cli.port,
        fade = cli.fade,
        "netman starting (milestone 1)"
    );

    let stats = Arc::new(CaptureStats::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            eprintln!("\nshutting down...");
            shutdown.store(true, Ordering::Relaxed);
        })
        .context("failed to install Ctrl-C handler")?;
    }

    // Thread OS dédié à la boucle pcap bloquante (invariant 2).
    let capture_thread = if let Some(file) = cli.pcap_file.clone() {
        println!("Replaying {} (offline mode)...", file.display());
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("pcap-capture".into())
            .spawn(move || capture::run_file(&file, stats, shutdown))
            .context("failed to spawn capture thread")?
    } else {
        let devices = capture::list_devices().context("cannot enumerate capture interfaces")?;
        let device = match &cli.iface {
            Some(wanted) => capture::find_device(&devices, wanted)?,
            None => prompt_device(&devices)?,
        };
        println!(
            "Capturing on: {} (promiscuous)",
            capture::device_label(&device)
        );
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("pcap-capture".into())
            .spawn(move || capture::run_live(device, stats, shutdown))
            .context("failed to spawn capture thread")?
    };

    // Affichage 1 Hz : trames/s, débit, drops kernel, totaux.
    let mut last_frames = 0u64;
    let mut last_bytes = 0u64;
    while !shutdown.load(Ordering::Relaxed) && !capture_thread.is_finished() {
        std::thread::sleep(Duration::from_secs(1));
        let frames = stats.frames.load(Ordering::Relaxed);
        let bytes = stats.bytes.load(Ordering::Relaxed);
        let drops = stats.kernel_drops.load(Ordering::Relaxed);
        println!(
            "{:>8} frames/s | {:>10}/s | drops {:>6} | total {} frames, {}",
            frames - last_frames,
            human_bytes(bytes - last_bytes),
            drops,
            frames,
            human_bytes(bytes),
        );
        last_frames = frames;
        last_bytes = bytes;
    }

    shutdown.store(true, Ordering::Relaxed);
    match capture_thread.join() {
        Ok(result) => result.context("capture failed")?,
        Err(_) => anyhow::bail!("capture thread panicked"),
    }
    println!(
        "Done: {} frames, {} captured.",
        stats.frames.load(Ordering::Relaxed),
        human_bytes(stats.bytes.load(Ordering::Relaxed)),
    );
    Ok(())
}

/// Sélection interactive : liste numérotée, choix au clavier.
fn prompt_device(devices: &[pcap::Device]) -> anyhow::Result<pcap::Device> {
    println!("Available capture interfaces:");
    for (i, dev) in devices.iter().enumerate() {
        println!("  [{i}] {}", capture::device_label(dev));
    }
    loop {
        print!("Interface number: ");
        std::io::stdout().flush()?;
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("failed to read interface choice")?;
        if line.is_empty() {
            anyhow::bail!("stdin closed before an interface was chosen");
        }
        match line.trim().parse::<usize>() {
            Ok(i) if i < devices.len() => return Ok(devices[i].clone()),
            _ => println!("Invalid choice, expected 0..{}", devices.len() - 1),
        }
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "kB", "MB", "GB", "TB"];
    let mut value = n as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{n} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
