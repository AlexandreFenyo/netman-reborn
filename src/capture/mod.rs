//! Boucle de capture pcap : un thread OS dédié, bloquant, découplé du reste.
//!
//! Invariants (CLAUDE.md §2) : une seule capture, jamais bloquée par un
//! consommateur, aucune résolution/IO sur le chemin du paquet.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pcap::{Active, Capture, Device};

#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    #[error("pcap: {0}")]
    Pcap(#[from] pcap::Error),
    #[error("no capture interface available")]
    NoDevice,
    #[error("interface '{0}' not found (use --iface with an index or a name substring)")]
    IfaceNotFound(String),
    #[error("cannot spawn capture thread: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("capture controller state poisoned")]
    Poisoned,
}

/// Compteurs partagés entre le thread de capture et l'affichage.
/// Le thread de capture ne fait qu'incrémenter des atomiques : aucun lock.
#[derive(Debug, Default)]
pub struct CaptureStats {
    pub frames: AtomicU64,
    pub bytes: AtomicU64,
    /// Paquets perdus par le kernel/Npcap (compteur cumulatif `ps_drop`).
    pub kernel_drops: AtomicU64,
    /// Trames non décodables (pas Ethernet II, tronquées…).
    pub parse_errors: AtomicU64,
    /// Métadonnées jetées car le channel vers l'agrégateur était plein
    /// (invariant 5 : on jette plutôt que de bloquer la capture).
    pub chan_drops: AtomicU64,
}

pub fn list_devices() -> Result<Vec<Device>, CaptureError> {
    let devices = Device::list()?;
    if devices.is_empty() {
        return Err(CaptureError::NoDevice);
    }
    Ok(devices)
}

/// Nom affichable d'un device : sous Windows `name` est un GUID NPF,
/// `desc` le nom convivial.
pub fn device_label(dev: &Device) -> String {
    let addrs: Vec<String> = dev.addresses.iter().map(|a| a.addr.to_string()).collect();
    let desc = dev.desc.as_deref().unwrap_or(&dev.name);
    if addrs.is_empty() {
        desc.to_string()
    } else {
        format!("{desc} [{}]", addrs.join(", "))
    }
}

/// Résout `--iface` : index dans la liste, sinon sous-chaîne (insensible à la
/// casse) du nom convivial ou du nom NPF.
pub fn find_device(devices: &[Device], wanted: &str) -> Result<Device, CaptureError> {
    if let Ok(idx) = wanted.parse::<usize>() {
        if let Some(d) = devices.get(idx) {
            return Ok(d.clone());
        }
    }
    let lower = wanted.to_lowercase();
    devices
        .iter()
        .find(|d| {
            d.name.to_lowercase().contains(&lower)
                || d.desc
                    .as_deref()
                    .is_some_and(|s| s.to_lowercase().contains(&lower))
        })
        .cloned()
        .ok_or_else(|| CaptureError::IfaceNotFound(wanted.to_string()))
}

fn open_live(device: Device) -> Result<Capture<Active>, CaptureError> {
    // immediate_mode : indispensable sous Npcap, sinon le buffering kernel
    // (min_to_copy) retient les paquets. timeout(500) : next_packet() rend
    // TimeoutExpired périodiquement → point de contrôle du flag d'arrêt.
    let cap = Capture::from_device(device)?
        .promisc(true)
        .immediate_mode(true)
        .snaplen(65535)
        .buffer_size(16 * 1024 * 1024)
        .timeout(500)
        .open()?;
    Ok(cap)
}

/// Boucle de capture live. À exécuter sur un thread OS dédié.
/// S'arrête quand `shutdown` passe à true (testé à chaque timeout pcap).
/// `on_packet(data, wire_len)` est appelé pour chaque trame — il doit rester
/// non bloquant (parse + try_send, rien d'autre).
pub fn run_live(
    device: Device,
    stats: Arc<CaptureStats>,
    shutdown: Arc<AtomicBool>,
    mut on_packet: impl FnMut(&[u8], u32),
) -> Result<(), CaptureError> {
    let mut cap = open_live(device)?;
    let mut last_kstats = Instant::now();
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        match cap.next_packet() {
            Ok(packet) => {
                stats.frames.fetch_add(1, Ordering::Relaxed);
                // `len` = longueur réelle sur le fil (pas `caplen`).
                stats
                    .bytes
                    .fetch_add(u64::from(packet.header.len), Ordering::Relaxed);
                on_packet(packet.data, packet.header.len);
                // Rafraîchit les stats kernel ~1×/s même sous charge continue.
                if last_kstats.elapsed() >= Duration::from_secs(1) {
                    last_kstats = Instant::now();
                    if let Ok(s) = cap.stats() {
                        stats
                            .kernel_drops
                            .store(u64::from(s.dropped), Ordering::Relaxed);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                // Non fatal : période creuse → en profite pour les stats kernel.
                if let Ok(s) = cap.stats() {
                    stats
                        .kernel_drops
                        .store(u64::from(s.dropped), Ordering::Relaxed);
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Fabrique le callback par-trame standard : parse → try_send, rien d'autre
/// (jamais bloquant, invariant 5).
pub fn make_on_packet(
    stats: Arc<CaptureStats>,
    meta_tx: tokio::sync::mpsc::Sender<crate::model::packet::PacketMeta>,
) -> impl FnMut(&[u8], u32) {
    move |data, wire_len| match crate::model::packet::parse_frame(data, wire_len) {
        Some(meta) => {
            if meta_tx.try_send(meta).is_err() {
                stats.chan_drops.fetch_add(1, Ordering::Relaxed);
            }
        }
        None => {
            stats.parse_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

struct RunningCapture {
    device_id: String,
    shutdown: Arc<AtomicBool>,
    thread: std::thread::JoinHandle<()>,
}

/// Contrôleur de capture live : permet d'arrêter puis relancer la boucle pcap
/// sur une autre interface (sélection depuis le navigateur). Il n'y a jamais
/// qu'UNE capture à la fois (invariant 1) : `switch_to` arrête et joint
/// l'ancienne boucle avant d'ouvrir la nouvelle. Appels bloquants (join ≤
/// timeout pcap) : à exécuter hors du runtime (spawn_blocking).
pub struct Controller {
    stats: Arc<CaptureStats>,
    meta_tx: tokio::sync::mpsc::Sender<crate::model::packet::PacketMeta>,
    running: std::sync::Mutex<Option<RunningCapture>>,
}

impl Controller {
    pub fn new(
        stats: Arc<CaptureStats>,
        meta_tx: tokio::sync::mpsc::Sender<crate::model::packet::PacketMeta>,
    ) -> Self {
        Controller {
            stats,
            meta_tx,
            running: std::sync::Mutex::new(None),
        }
    }

    /// Id (nom NPF) de l'interface en cours de capture.
    pub fn current(&self) -> Option<String> {
        self.running
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|r| r.device_id.clone()))
    }

    /// Bascule la capture sur `wanted` (index, sous-chaîne ou nom NPF).
    /// Renvoie le label convivial de la nouvelle interface.
    pub fn switch_to(&self, wanted: &str) -> Result<String, CaptureError> {
        let devices = list_devices()?;
        let device = find_device(&devices, wanted)?;
        let label = device_label(&device);
        let device_id = device.name.clone();

        self.stop();

        let shutdown = Arc::new(AtomicBool::new(false));
        let thread = {
            let stats = Arc::clone(&self.stats);
            let shutdown = Arc::clone(&shutdown);
            let on_packet = make_on_packet(Arc::clone(&self.stats), self.meta_tx.clone());
            std::thread::Builder::new()
                .name("pcap-capture".into())
                .spawn(move || {
                    if let Err(e) = run_live(device, stats, shutdown, on_packet) {
                        tracing::error!(error = %e, "capture loop failed");
                    }
                })?
        };
        let mut guard = self.running.lock().map_err(|_| CaptureError::Poisoned)?;
        *guard = Some(RunningCapture {
            device_id,
            shutdown,
            thread,
        });
        Ok(label)
    }

    /// Arrête la capture courante (flag + join ; la boucle se réveille sur son
    /// timeout pcap en ≤ ~500 ms).
    pub fn stop(&self) {
        let running = match self.running.lock() {
            Ok(mut guard) => guard.take(),
            Err(_) => return,
        };
        if let Some(running) = running {
            running.shutdown.store(true, Ordering::Relaxed);
            if running.thread.join().is_err() {
                tracing::error!("capture thread panicked");
            }
        }
    }
}

/// Rejoue un fichier .pcap (mode offline, tests déterministes — CLAUDE.md §8).
pub fn run_file(
    path: &Path,
    stats: Arc<CaptureStats>,
    shutdown: Arc<AtomicBool>,
    mut on_packet: impl FnMut(&[u8], u32),
) -> Result<(), CaptureError> {
    let mut cap = Capture::from_file(path)?;
    loop {
        if shutdown.load(Ordering::Relaxed) {
            return Ok(());
        }
        match cap.next_packet() {
            Ok(packet) => {
                stats.frames.fetch_add(1, Ordering::Relaxed);
                stats
                    .bytes
                    .fetch_add(u64::from(packet.header.len), Ordering::Relaxed);
                on_packet(packet.data, packet.header.len);
            }
            Err(pcap::Error::NoMorePackets) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }
}
