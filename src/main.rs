//! Netman Reborn — Etherman (L2) + Interman (L3), moniteur passif.
//! Jalon 2 : parsing + double agrégation, top talkers en console.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{RecvTimeoutError, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context;
use clap::Parser;

use netman::capture::{self, CaptureStats};
use netman::model::packet::{self, PacketMeta};
use netman::model::tables::Tables;

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

/// Capacité du channel capture→agrégateur. Plein ⇒ on jette (invariant 5).
const CHANNEL_CAPACITY: usize = 65536;

fn main() -> anyhow::Result<()> {
    netman::setup_npcap_dll_path();

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
        "netman starting (milestone 2)"
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

    // Channel capture → agrégateur (découplage, invariant 2).
    let (tx, rx) = std::sync::mpsc::sync_channel::<PacketMeta>(CHANNEL_CAPACITY);

    // Thread OS dédié à la boucle pcap bloquante. Il ne fait que :
    // capture → parse → try_send (jamais bloquant, invariant 5).
    let capture_thread = {
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        let on_packet = {
            let stats = Arc::clone(&stats);
            move |data: &[u8], wire_len: u32| match packet::parse_frame(data, wire_len) {
                Some(meta) => {
                    if let Err(TrySendError::Full(_)) = tx.try_send(meta) {
                        stats.chan_drops.fetch_add(1, Ordering::Relaxed);
                    }
                }
                None => {
                    stats.parse_errors.fetch_add(1, Ordering::Relaxed);
                }
            }
        };

        if let Some(file) = cli.pcap_file.clone() {
            println!("Replaying {} (offline mode)...", file.display());
            std::thread::Builder::new()
                .name("pcap-capture".into())
                .spawn(move || capture::run_file(&file, stats, shutdown, on_packet))
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
            std::thread::Builder::new()
                .name("pcap-capture".into())
                .spawn(move || capture::run_live(device, stats, shutdown, on_packet))
                .context("failed to spawn capture thread")?
        }
    };

    // Agrégateur : consomme les PacketMeta, maintient les deux tables,
    // affiche stats + top talkers toutes les 2 s.
    let mut tables = Tables::new();
    let mut last_dump = Instant::now();
    let mut last_frames = 0u64;
    let mut last_bytes = 0u64;
    loop {
        match rx.recv_timeout(Duration::from_millis(200)) {
            Ok(meta) => tables.ingest(&meta, Instant::now()),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break, // thread capture terminé
        }
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        if last_dump.elapsed() >= Duration::from_secs(2) {
            last_dump = Instant::now();
            let frames = stats.frames.load(Ordering::Relaxed);
            let bytes = stats.bytes.load(Ordering::Relaxed);
            dump_top_talkers(
                &tables,
                (frames - last_frames) / 2,
                (bytes - last_bytes) / 2,
                &stats,
            );
            last_frames = frames;
            last_bytes = bytes;
        }
    }

    // Draine ce qui reste (fin de fichier pcap notamment) avant le bilan.
    while let Ok(meta) = rx.try_recv() {
        tables.ingest(&meta, Instant::now());
    }

    shutdown.store(true, Ordering::Relaxed);
    match capture_thread.join() {
        Ok(result) => result.context("capture failed")?,
        Err(_) => anyhow::bail!("capture thread panicked"),
    }

    println!("\n=== Final summary ===");
    dump_top_talkers(&tables, 0, 0, &stats);
    Ok(())
}

fn dump_top_talkers(tables: &Tables, fps: u64, bps: u64, stats: &CaptureStats) {
    println!(
        "\n-- {} frames/s | {}/s | L2 convs: {} | L3 convs: {} | kernel drops {} | chan drops {} | unparsed {}",
        fps,
        human_bytes(bps),
        tables.l2.len(),
        tables.l3.len(),
        stats.kernel_drops.load(Ordering::Relaxed),
        stats.chan_drops.load(Ordering::Relaxed),
        stats.parse_errors.load(Ordering::Relaxed),
    );
    println!("   Top talkers — Etherman (L2/MAC):");
    for (key, conv) in tables.top_l2(5) {
        println!(
            "     {} <-> {}  {:<10} {:>10}  {:>7} pkts",
            key.0,
            key.1,
            conv.dominant_proto().to_string(),
            human_bytes(conv.bytes),
            conv.packets,
        );
    }
    println!("   Top talkers — Interman (L3/IP):");
    for (key, conv) in tables.top_l3(5) {
        println!(
            "     {} <-> {}  {:<10} {:>10}  {:>7} pkts",
            key.0,
            key.1,
            conv.dominant_proto().to_string(),
            human_bytes(conv.bytes),
            conv.packets,
        );
    }
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
