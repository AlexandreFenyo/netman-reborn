//! Reverse-DNS (PTR) actif pour les nœuds Interman.
//!
//! Tâche tokio dédiée : les demandes arrivent par channel, les lookups
//! s'exécutent sur le pool bloquant (getnameinfo via `dns-lookup`, résolveur
//! système) avec une concurrence bornée, les résultats repartent par channel
//! vers l'agrégateur qui met à jour les labels. Le chemin de capture n'est
//! jamais impliqué (invariant 4).
//!
//! Cache : une IP n'est résolue qu'une fois par session (succès comme échec).
//! Les noms obtenus sont conservés dans `Tables::l3_labels` et resservent à
//! tous les upserts/snapshots suivants sans nouvelle requête.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, Semaphore};

/// Lookups PTR simultanés au maximum (threads bloquants du pool tokio).
const CONCURRENT_LOOKUPS: usize = 8;
/// File d'attente des demandes. Pleine ⇒ l'agrégateur retentera plus tard.
pub const REQUEST_QUEUE: usize = 1024;

/// Démarre la tâche résolveur. Renvoie l'entrée des demandes ; les couples
/// `(ip, nom)` résolus sortent sur `results_tx`.
pub fn spawn(results_tx: mpsc::Sender<(IpAddr, String)>) -> mpsc::Sender<IpAddr> {
    let (req_tx, mut req_rx) = mpsc::channel::<IpAddr>(REQUEST_QUEUE);
    tokio::spawn(async move {
        // Cache négatif + anti-doublon : une IP n'est tentée qu'une fois.
        let mut attempted: HashSet<IpAddr> = HashSet::new();
        let semaphore = Arc::new(Semaphore::new(CONCURRENT_LOOKUPS));
        while let Some(ip) = req_rx.recv().await {
            if !is_resolvable(&ip) || !attempted.insert(ip) {
                continue;
            }
            // Attendre un slot ICI applique la contre-pression sur la file
            // des demandes, pas sur l'agrégateur (qui fait try_send).
            let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
                return;
            };
            let results_tx = results_tx.clone();
            tokio::spawn(async move {
                let looked_up =
                    tokio::task::spawn_blocking(move || dns_lookup::lookup_addr(&ip).ok()).await;
                drop(permit);
                if let Ok(Some(name)) = looked_up {
                    // getnameinfo renvoie la forme numérique quand il n'y a
                    // pas de PTR : ce n'est pas un nom.
                    if name != ip.to_string() {
                        tracing::debug!(%ip, name, "resolved PTR");
                        let _ = results_tx.send((ip, name)).await;
                    }
                }
            });
        }
    });
    req_tx
}

/// Écarte les adresses sans PTR utile (multicast, broadcast, link-local…).
pub fn is_resolvable(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !v4.is_loopback()
                && !v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            !v6.is_multicast()
                && !v6.is_unspecified()
                && !v6.is_loopback()
                // link-local fe80::/10 : pas de PTR global.
                && (v6.segments()[0] & 0xffc0) != 0xfe80
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolvable_filter() {
        let yes = ["192.168.0.21", "8.8.8.8", "2a01:e0a::1", "fd00::1"];
        let no = [
            "224.0.0.251",
            "255.255.255.255",
            "0.0.0.0",
            "127.0.0.1",
            "169.254.1.2",
            "ff02::fb",
            "fe80::1",
            "::",
        ];
        for ip in yes {
            assert!(is_resolvable(&ip.parse().unwrap()), "{ip} should resolve");
        }
        for ip in no {
            assert!(
                !is_resolvable(&ip.parse().unwrap()),
                "{ip} should be skipped"
            );
        }
    }
}
