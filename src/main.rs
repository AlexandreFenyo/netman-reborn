//! Netman Reborn — Etherman (L2) + Interman (L3), moniteur passif.
//! Jalon 3 : serveur axum + WebSocket diffusant les deltas de graphe.

use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context;
use axum::extract::ws::Utf8Bytes;
use clap::Parser;
use tokio::sync::{broadcast, mpsc};

use netman::capture::{self, CaptureStats};
use netman::model::packet::PacketMeta;
use netman::model::tables::Tables;
use netman::resolve;
use netman::server::{self, AppState, IfaceState};
use netman::wsproto::IfaceInfo;

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

    /// HTTP/WebSocket listen port
    #[arg(long, default_value_t = 8080)]
    port: u16,

    /// Fade timeout in seconds: nodes/edges unseen for this long are removed
    #[arg(long, default_value_t = 60)]
    fade: u64,

    /// Directory of frontend static files served at /
    #[arg(long, default_value = "static")]
    static_dir: String,
}

/// Capacité du channel capture→agrégateur. Plein ⇒ on jette (invariant 5).
const CHANNEL_CAPACITY: usize = 65536;
/// Capacité du broadcast des deltas (ring ; les clients lents « laggent »).
const BROADCAST_CAPACITY: usize = 4096;
/// Période du tick de diffusion.
const TICK: Duration = Duration::from_millis(250);

fn main() -> anyhow::Result<()> {
    netman::setup_npcap_dll_path();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "netman=info".into()),
        )
        .init();

    let cli = Cli::parse();
    let stats = Arc::new(CaptureStats::default());
    let shutdown = Arc::new(AtomicBool::new(false));

    // Channel capture → agrégateur (découplage, invariant 2).
    let (meta_tx, meta_rx) = mpsc::channel::<PacketMeta>(CHANNEL_CAPACITY);

    // Mode fichier : thread de rejeu simple. Mode live : contrôleur de
    // capture (permet la bascule d'interface depuis le navigateur).
    let mut offline_thread = None;
    let mut controller = None;
    let iface_state = Arc::new(Mutex::new(IfaceState::default()));

    if let Some(file) = cli.pcap_file.clone() {
        println!("Replaying {} (offline mode)...", file.display());
        let stats = Arc::clone(&stats);
        let shutdown = Arc::clone(&shutdown);
        let on_packet = capture::make_on_packet(Arc::clone(&stats), meta_tx.clone());
        offline_thread = Some(
            std::thread::Builder::new()
                .name("pcap-capture".into())
                .spawn(move || capture::run_file(&file, stats, shutdown, on_packet))
                .context("failed to spawn capture thread")?,
        );
    } else {
        let devices = capture::list_devices().context("cannot enumerate capture interfaces")?;
        let device = match &cli.iface {
            Some(wanted) => capture::find_device(&devices, wanted)?,
            None => prompt_device(&devices)?,
        };
        let ctl = Arc::new(capture::Controller::new(
            Arc::clone(&stats),
            meta_tx.clone(),
        ));
        let label = ctl.switch_to(&device.name)?;
        println!("Capturing on: {label} (promiscuous)");
        refresh_iface_state(&ctl, &iface_state);
        controller = Some(ctl);
    }
    drop(meta_tx); // les threads de capture détiennent leurs clones

    // Runtime tokio : agrégateur + serveur HTTP/WS.
    let runtime = tokio::runtime::Runtime::new().context("failed to start tokio runtime")?;
    let result = runtime.block_on(async_main(
        &cli,
        Arc::clone(&stats),
        meta_rx,
        controller.clone(),
        Arc::clone(&iface_state),
    ));

    // Arrêt : flag/stop pour la boucle pcap (réveillée par son timeout), puis
    // join hors runtime (jamais de join bloquant dans une tâche async).
    shutdown.store(true, Ordering::Relaxed);
    drop(runtime);
    if let Some(ctl) = controller {
        ctl.stop();
    }
    if let Some(thread) = offline_thread {
        match thread.join() {
            Ok(capture_result) => capture_result.context("capture failed")?,
            Err(_) => anyhow::bail!("capture thread panicked"),
        }
    }
    tracing::info!(
        frames = stats.frames.load(Ordering::Relaxed),
        kernel_drops = stats.kernel_drops.load(Ordering::Relaxed),
        chan_drops = stats.chan_drops.load(Ordering::Relaxed),
        "netman stopped"
    );
    result
}

/// Rafraîchit l'état partagé interfaces disponibles + interface active.
fn refresh_iface_state(ctl: &capture::Controller, iface_state: &Arc<Mutex<IfaceState>>) {
    let interfaces = capture::list_devices()
        .map(|devices| {
            devices
                .iter()
                .map(|d| IfaceInfo {
                    id: d.name.clone(),
                    label: capture::device_label(d),
                })
                .collect()
        })
        .unwrap_or_default();
    if let Ok(mut state) = iface_state.lock() {
        state.current = ctl.current();
        state.interfaces = interfaces;
    }
}

async fn async_main(
    cli: &Cli,
    stats: Arc<CaptureStats>,
    meta_rx: mpsc::Receiver<PacketMeta>,
    controller: Option<Arc<capture::Controller>>,
    iface_state: Arc<Mutex<IfaceState>>,
) -> anyhow::Result<()> {
    let tables = Arc::new(Mutex::new(Tables::new()));
    let (deltas_tx, _) = broadcast::channel::<Utf8Bytes>(BROADCAST_CAPACITY);
    let fade_secs = Arc::new(AtomicU64::new(
        cli.fade
            .clamp(netman::server::FADE_MIN_SECS, netman::server::FADE_MAX_SECS),
    ));

    tokio::spawn(aggregate_loop(
        meta_rx,
        Arc::clone(&tables),
        deltas_tx.clone(),
        Arc::clone(&stats),
        Arc::clone(&fade_secs),
    ));

    // Bascule d'interface pilotée depuis le navigateur (mode live seulement).
    let iface_tx = controller.map(|ctl| {
        let (iface_tx, iface_rx) = mpsc::channel::<String>(8);
        tokio::spawn(iface_switch_loop(
            iface_rx,
            ctl,
            Arc::clone(&iface_state),
            Arc::clone(&tables),
            deltas_tx.clone(),
        ));
        iface_tx
    });

    let state = AppState {
        tables,
        deltas_tx,
        fade_secs,
        iface_state,
        iface_tx,
    };
    let app = server::router(state, &cli.static_dir);
    let addr = format!("127.0.0.1:{}", cli.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("cannot listen on {addr}"))?;
    println!("Serving on http://{addr} (Ctrl-C to stop)");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
            eprintln!("\nshutting down...");
        })
        .await
        .context("http server failed")?;
    Ok(())
}

/// Applique les demandes de changement d'interface : stop + join de la boucle
/// pcap courante puis démarrage sur la nouvelle carte (hors runtime via
/// spawn_blocking), et rediffusion de l'état interfaces à tous les clients.
async fn iface_switch_loop(
    mut iface_rx: mpsc::Receiver<String>,
    ctl: Arc<capture::Controller>,
    iface_state: Arc<Mutex<IfaceState>>,
    tables: Arc<Mutex<Tables>>,
    deltas_tx: broadcast::Sender<Utf8Bytes>,
) {
    while let Some(wanted) = iface_rx.recv().await {
        let ctl_for_switch = Arc::clone(&ctl);
        let switched = tokio::task::spawn_blocking(move || ctl_for_switch.switch_to(&wanted)).await;
        match switched {
            Ok(Ok(label)) => {
                tracing::info!(label, "capture switched by client");
                // Nouvelle interface ⇒ historique vierge (caches DNS gardés).
                server::reset_history(&tables, &deltas_tx);
            }
            Ok(Err(e)) => tracing::warn!(error = %e, "interface switch failed"),
            Err(e) => tracing::error!(error = %e, "interface switch task failed"),
        }
        // L'état diffusé reflète la réalité (échec ⇒ le sélecteur se recale).
        refresh_iface_state(&ctl, &iface_state);
        let message = match iface_state.lock() {
            Ok(state) => server::encode_info(&state.to_message()),
            Err(_) => None,
        };
        if let Some(msg) = message {
            let _ = deltas_tx.send(msg);
        }
    }
}

/// Agrégateur : consomme les PacketMeta par lots, maintient les tables,
/// diffuse les deltas des entrées modifiées à chaque tick.
async fn aggregate_loop(
    mut meta_rx: mpsc::Receiver<PacketMeta>,
    tables: Arc<Mutex<Tables>>,
    deltas_tx: broadcast::Sender<Utf8Bytes>,
    stats: Arc<CaptureStats>,
    fade_secs: Arc<AtomicU64>,
) {
    let mut buf: Vec<PacketMeta> = Vec::with_capacity(4096);
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut capture_done = false;
    let mut last_log = Instant::now();

    // Résolveur PTR : demandes déclenchées une seule fois par IP (les échecs
    // d'envoi — file pleine — seront retentés au tick suivant).
    let (ptr_results_tx, mut ptr_results_rx) =
        mpsc::channel::<(std::net::IpAddr, String)>(resolve::dns::REQUEST_QUEUE);
    let ptr_req_tx = resolve::dns::spawn(ptr_results_tx);
    let mut ptr_requested: std::collections::HashSet<std::net::IpAddr> =
        std::collections::HashSet::new();

    loop {
        tokio::select! {
            biased;
            received = meta_rx.recv_many(&mut buf, 4096), if !capture_done => {
                if received == 0 {
                    // Fin de capture (fichier rejoué) : on continue à servir.
                    capture_done = true;
                    continue;
                }
                let Ok(mut tables) = tables.lock() else { return };
                let now = Instant::now();
                for meta in buf.drain(..) {
                    tables.ingest(&meta, now);
                }
            }
            resolved = ptr_results_rx.recv() => {
                let Some((ip, name)) = resolved else { return };
                let Ok(mut tables) = tables.lock() else { return };
                tables.set_l3_label(ip, name);
            }
            _ = tick.tick() => {
                let (deltas, dirty_ips) = {
                    let Ok(mut tables) = tables.lock() else { return };
                    let dirty_ips = tables.dirty_l3_node_ips();
                    let mut deltas = tables.drain_deltas();
                    // Vieillissement : suppressions explicites (invariant 7).
                    let max_age = Duration::from_secs(fade_secs.load(Ordering::Relaxed));
                    deltas.extend(tables.fade_sweep(Instant::now(), max_age));
                    (deltas, dirty_ips)
                };
                for ip in dirty_ips {
                    if resolve::dns::is_resolvable(&ip)
                        && !ptr_requested.contains(&ip)
                        && ptr_req_tx.try_send(ip).is_ok()
                    {
                        ptr_requested.insert(ip);
                    }
                }
                for delta in &deltas {
                    if let Some(msg) = server::encode_delta(delta) {
                        // Erreur = aucun client connecté : sans importance.
                        let _ = deltas_tx.send(msg);
                    }
                }
                if last_log.elapsed() >= Duration::from_secs(10) {
                    last_log = Instant::now();
                    let (l2, l3) = {
                        let Ok(tables) = tables.lock() else { return };
                        (tables.l2.len(), tables.l3.len())
                    };
                    tracing::info!(
                        frames = stats.frames.load(Ordering::Relaxed),
                        l2_convs = l2,
                        l3_convs = l3,
                        clients = deltas_tx.receiver_count(),
                        chan_drops = stats.chan_drops.load(Ordering::Relaxed),
                        "aggregator status"
                    );
                }
            }
        }
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
