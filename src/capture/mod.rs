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
