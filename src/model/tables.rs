//! Les deux tables d'agrégation en mémoire (invariant 1 : une capture, deux
//! projections du même flux).
//!
//! - Table Etherman (L2) : clé = paire de MAC, non orientée.
//! - Table Interman (L3) : clé = paire d'IP (v4+v6), non orientée.
//!
//! La clé est normalisée (min, max) pour agréger les deux sens d'une même
//! conversation, comme EtherApe.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::time::{Duration, Instant};

use super::packet::{Mac, PacketMeta, Proto};
use crate::wsproto::{Delta, View};

/// Conversation L2 : paire de MAC ordonnée.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct L2Key(pub Mac, pub Mac);

impl L2Key {
    pub fn new(a: Mac, b: Mac) -> Self {
        if a <= b {
            L2Key(a, b)
        } else {
            L2Key(b, a)
        }
    }
}

/// Conversation L3 : paire d'IP ordonnée (v4 et v6 mélangées sans collision).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct L3Key(pub IpAddr, pub IpAddr);

impl L3Key {
    pub fn new(a: IpAddr, b: IpAddr) -> Self {
        if a <= b {
            L3Key(a, b)
        } else {
            L3Key(b, a)
        }
    }
}

/// Statistiques d'une conversation (ou d'un nœud).
#[derive(Clone, Debug)]
pub struct ConvStats {
    pub bytes: u64,
    pub packets: u64,
    /// Octets émis / reçus par ce nœud (perspective du nœud ; reste à 0 pour
    /// une arête, dont `bytes` couvre déjà les deux sens).
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_seen: Instant,
    /// Octets par protocole, pour déterminer le protocole dominant.
    proto_bytes: HashMap<Proto, u64>,
}

impl ConvStats {
    fn new(now: Instant) -> Self {
        ConvStats {
            bytes: 0,
            packets: 0,
            tx_bytes: 0,
            rx_bytes: 0,
            last_seen: now,
            proto_bytes: HashMap::new(),
        }
    }

    fn add(&mut self, bytes: u64, proto: Proto, now: Instant) {
        self.bytes += bytes;
        self.packets += 1;
        self.last_seen = now;
        *self.proto_bytes.entry(proto).or_insert(0) += bytes;
    }

    /// Protocole dominant en octets cumulés.
    pub fn dominant_proto(&self) -> Proto {
        self.proto_bytes
            .iter()
            .max_by_key(|(_, bytes)| **bytes)
            .map(|(proto, _)| *proto)
            .unwrap_or(Proto::Named("?"))
    }
}

/// Les deux tables (conversations + nœuds), mises à jour par l'agrégateur
/// (jamais par le thread de capture directement — découplage par channel,
/// invariant 2). Les entrées modifiées depuis le dernier tick sont marquées
/// « dirty » pour ne diffuser que des deltas.
#[derive(Default)]
pub struct Tables {
    pub l2: HashMap<L2Key, ConvStats>,
    pub l3: HashMap<L3Key, ConvStats>,
    pub l2_nodes: HashMap<Mac, ConvStats>,
    pub l3_nodes: HashMap<IpAddr, ConvStats>,
    /// Noms résolus (reverse DNS) : cache de session, survit au fade.
    l3_labels: HashMap<IpAddr, String>,
    dirty_l2: HashSet<L2Key>,
    dirty_l3: HashSet<L3Key>,
    dirty_l2_nodes: HashSet<Mac>,
    dirty_l3_nodes: HashSet<IpAddr>,
}

impl Tables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Projette une trame sur les deux tables (conversations + nœuds).
    pub fn ingest(&mut self, meta: &PacketMeta, now: Instant) {
        let l2_key = L2Key::new(meta.src_mac, meta.dst_mac);
        self.l2
            .entry(l2_key)
            .or_insert_with(|| ConvStats::new(now))
            .add(meta.wire_len, meta.l2_proto, now);
        self.dirty_l2.insert(l2_key);
        for (mac, is_src) in [(meta.src_mac, true), (meta.dst_mac, false)] {
            let node = self
                .l2_nodes
                .entry(mac)
                .or_insert_with(|| ConvStats::new(now));
            node.add(meta.wire_len, meta.l2_proto, now);
            if is_src {
                node.tx_bytes += meta.wire_len;
            } else {
                node.rx_bytes += meta.wire_len;
            }
            self.dirty_l2_nodes.insert(mac);
        }

        if let Some(l3) = &meta.l3 {
            let l3_key = L3Key::new(l3.src, l3.dst);
            self.l3
                .entry(l3_key)
                .or_insert_with(|| ConvStats::new(now))
                .add(meta.wire_len, l3.proto, now);
            self.dirty_l3.insert(l3_key);
            for (ip, is_src) in [(l3.src, true), (l3.dst, false)] {
                let node = self
                    .l3_nodes
                    .entry(ip)
                    .or_insert_with(|| ConvStats::new(now));
                node.add(meta.wire_len, l3.proto, now);
                if is_src {
                    node.tx_bytes += meta.wire_len;
                } else {
                    node.rx_bytes += meta.wire_len;
                }
                self.dirty_l3_nodes.insert(ip);
            }
        }
    }

    /// Deltas des entrées modifiées depuis le dernier appel (puis reset).
    /// Nœuds avant arêtes, pour que le frontend crée les extrémités d'abord.
    pub fn drain_deltas(&mut self) -> Vec<Delta> {
        let mut out = Vec::with_capacity(
            self.dirty_l2_nodes.len()
                + self.dirty_l3_nodes.len()
                + self.dirty_l2.len()
                + self.dirty_l3.len(),
        );
        for mac in std::mem::take(&mut self.dirty_l2_nodes) {
            if let Some(stats) = self.l2_nodes.get(&mac) {
                out.push(node_delta(
                    View::Ether,
                    mac.to_string(),
                    crate::resolve::oui::label(&mac),
                    stats,
                ));
            }
        }
        for ip in std::mem::take(&mut self.dirty_l3_nodes) {
            if let Some(stats) = self.l3_nodes.get(&ip) {
                out.push(node_delta(
                    View::Inter,
                    ip.to_string(),
                    self.l3_label(&ip),
                    stats,
                ));
            }
        }
        for key in self.dirty_l2.drain() {
            if let Some(stats) = self.l2.get(&key) {
                out.push(edge_delta(
                    View::Ether,
                    key.0.to_string(),
                    key.1.to_string(),
                    stats,
                ));
            }
        }
        for key in self.dirty_l3.drain() {
            if let Some(stats) = self.l3.get(&key) {
                out.push(edge_delta(
                    View::Inter,
                    key.0.to_string(),
                    key.1.to_string(),
                    stats,
                ));
            }
        }
        out
    }

    /// Enregistre un nom résolu ; si le nœud est affiché, il repart en upsert
    /// au prochain tick avec son nouveau label. Le nom est conservé même si
    /// le nœud a disparu entre-temps (il resservira s'il réapparaît).
    pub fn set_l3_label(&mut self, ip: IpAddr, label: String) {
        if self.l3_nodes.contains_key(&ip) {
            self.dirty_l3_nodes.insert(ip);
        }
        self.l3_labels.insert(ip, label);
    }

    /// Label affiché d'un nœud L3 : nom résolu, sinon l'adresse.
    fn l3_label(&self, ip: &IpAddr) -> String {
        self.l3_labels
            .get(ip)
            .cloned()
            .unwrap_or_else(|| ip.to_string())
    }

    /// IPs des nœuds L3 modifiés depuis le dernier tick (pour déclencher les
    /// résolutions PTR côté agrégateur, avant `drain_deltas`).
    pub fn dirty_l3_node_ips(&self) -> Vec<IpAddr> {
        self.dirty_l3_nodes.iter().copied().collect()
    }

    /// Efface tout l'historique (comme si aucun paquet n'avait été reçu),
    /// en CONSERVANT les caches de résolution (labels DNS `l3_labels`) :
    /// une IP déjà résolue réaffiche son nom dès son premier nouveau paquet.
    pub fn reset(&mut self) {
        self.l2.clear();
        self.l3.clear();
        self.l2_nodes.clear();
        self.l3_nodes.clear();
        self.dirty_l2.clear();
        self.dirty_l3.clear();
        self.dirty_l2_nodes.clear();
        self.dirty_l3_nodes.clear();
    }

    /// Vieillissement (invariant 7) : retire les conversations et nœuds non
    /// revus depuis `max_age` et produit les deltas `remove_*` explicites.
    /// Arêtes d'abord, puis nœuds (un nœud périmé implique que toutes ses
    /// arêtes le sont : son last_seen est rafraîchi par chacune d'elles).
    pub fn fade_sweep(&mut self, now: Instant, max_age: Duration) -> Vec<Delta> {
        let mut out = Vec::new();
        let stale = |stats: &ConvStats| now.duration_since(stats.last_seen) > max_age;

        let stale_l2: Vec<L2Key> = self
            .l2
            .iter()
            .filter(|(_, s)| stale(s))
            .map(|(k, _)| *k)
            .collect();
        for key in stale_l2 {
            self.l2.remove(&key);
            self.dirty_l2.remove(&key);
            out.push(Delta::RemoveEdge {
                view: View::Ether,
                id: edge_id(&key.0.to_string(), &key.1.to_string()),
            });
        }
        let stale_l3: Vec<L3Key> = self
            .l3
            .iter()
            .filter(|(_, s)| stale(s))
            .map(|(k, _)| *k)
            .collect();
        for key in stale_l3 {
            self.l3.remove(&key);
            self.dirty_l3.remove(&key);
            out.push(Delta::RemoveEdge {
                view: View::Inter,
                id: edge_id(&key.0.to_string(), &key.1.to_string()),
            });
        }

        let stale_macs: Vec<Mac> = self
            .l2_nodes
            .iter()
            .filter(|(_, s)| stale(s))
            .map(|(k, _)| *k)
            .collect();
        for mac in stale_macs {
            self.l2_nodes.remove(&mac);
            self.dirty_l2_nodes.remove(&mac);
            out.push(Delta::RemoveNode {
                view: View::Ether,
                id: mac.to_string(),
            });
        }
        let stale_ips: Vec<IpAddr> = self
            .l3_nodes
            .iter()
            .filter(|(_, s)| stale(s))
            .map(|(k, _)| *k)
            .collect();
        for ip in stale_ips {
            self.l3_nodes.remove(&ip);
            self.dirty_l3_nodes.remove(&ip);
            out.push(Delta::RemoveNode {
                view: View::Inter,
                id: ip.to_string(),
            });
        }
        out
    }

    /// État complet sous forme de deltas (snapshot pour un client qui arrive).
    pub fn snapshot_deltas(&self) -> Vec<Delta> {
        let mut out = Vec::with_capacity(
            self.l2_nodes.len() + self.l3_nodes.len() + self.l2.len() + self.l3.len(),
        );
        for (mac, stats) in &self.l2_nodes {
            out.push(node_delta(
                View::Ether,
                mac.to_string(),
                crate::resolve::oui::label(mac),
                stats,
            ));
        }
        for (ip, stats) in &self.l3_nodes {
            out.push(node_delta(
                View::Inter,
                ip.to_string(),
                self.l3_label(ip),
                stats,
            ));
        }
        for (key, stats) in &self.l2 {
            out.push(edge_delta(
                View::Ether,
                key.0.to_string(),
                key.1.to_string(),
                stats,
            ));
        }
        for (key, stats) in &self.l3 {
            out.push(edge_delta(
                View::Inter,
                key.0.to_string(),
                key.1.to_string(),
                stats,
            ));
        }
        out
    }

    /// Top conversations L2 par octets cumulés.
    pub fn top_l2(&self, n: usize) -> Vec<(&L2Key, &ConvStats)> {
        let mut v: Vec<_> = self.l2.iter().collect();
        v.sort_by_key(|(_, conv)| std::cmp::Reverse(conv.bytes));
        v.truncate(n);
        v
    }

    /// Top conversations L3 par octets cumulés.
    pub fn top_l3(&self, n: usize) -> Vec<(&L3Key, &ConvStats)> {
        let mut v: Vec<_> = self.l3.iter().collect();
        v.sort_by_key(|(_, conv)| std::cmp::Reverse(conv.bytes));
        v.truncate(n);
        v
    }
}

/// Identifiant d'arête stable : les clés étant normalisées, `a|b` est unique.
fn edge_id(a: &str, b: &str) -> String {
    format!("{a}|{b}")
}

fn node_delta(view: View, id: String, label: String, stats: &ConvStats) -> Delta {
    Delta::UpsertNode {
        view,
        id,
        label,
        bytes: stats.bytes,
        bytes_in: stats.rx_bytes,
        bytes_out: stats.tx_bytes,
        packets: stats.packets,
        proto: stats.dominant_proto().to_string(),
    }
}

fn edge_delta(view: View, a: String, b: String, stats: &ConvStats) -> Delta {
    Delta::UpsertEdge {
        view,
        id: edge_id(&a, &b),
        source: a,
        target: b,
        bytes: stats.bytes,
        packets: stats.packets,
        proto: stats.dominant_proto().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::packet::L3Meta;

    const MAC_A: Mac = Mac([0x02, 0, 0, 0, 0, 0x0a]);
    const MAC_B: Mac = Mac([0x02, 0, 0, 0, 0, 0x0b]);

    fn meta(
        src_mac: Mac,
        dst_mac: Mac,
        bytes: u64,
        l2: Proto,
        l3: Option<(IpAddr, IpAddr, Proto)>,
    ) -> PacketMeta {
        PacketMeta {
            wire_len: bytes,
            src_mac,
            dst_mac,
            l2_proto: l2,
            l3: l3.map(|(src, dst, proto)| L3Meta { src, dst, proto }),
            arp_pair: None,
        }
    }

    #[test]
    fn both_directions_merge_into_one_conversation() {
        let mut tables = Tables::new();
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        let https = Proto::Named("HTTPS");
        let ipv4 = Proto::Named("IPv4");

        tables.ingest(
            &meta(MAC_A, MAC_B, 100, ipv4, Some((ip_a, ip_b, https))),
            now,
        );
        tables.ingest(
            &meta(MAC_B, MAC_A, 50, ipv4, Some((ip_b, ip_a, https))),
            now,
        );

        assert_eq!(tables.l2.len(), 1, "A→B et B→A = une seule conversation L2");
        assert_eq!(tables.l3.len(), 1, "idem en L3");
        let conv = &tables.l2[&L2Key::new(MAC_A, MAC_B)];
        assert_eq!(conv.bytes, 150);
        assert_eq!(conv.packets, 2);

        // Compteurs directionnels des nœuds : A a émis 100 et reçu 50.
        let node_a = &tables.l2_nodes[&MAC_A];
        assert_eq!((node_a.tx_bytes, node_a.rx_bytes), (100, 50));
        let node_b = &tables.l2_nodes[&MAC_B];
        assert_eq!((node_b.tx_bytes, node_b.rx_bytes), (50, 100));
        let ip_node_a = &tables.l3_nodes[&ip_a];
        assert_eq!((ip_node_a.tx_bytes, ip_node_a.rx_bytes), (100, 50));
    }

    #[test]
    fn arp_only_touches_l2() {
        let mut tables = Tables::new();
        tables.ingest(
            &meta(MAC_A, MAC_B, 42, Proto::Named("ARP"), None),
            Instant::now(),
        );
        assert_eq!(tables.l2.len(), 1);
        assert!(tables.l3.is_empty());
    }

    #[test]
    fn dominant_proto_by_bytes() {
        let mut tables = Tables::new();
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
        let ipv4 = Proto::Named("IPv4");

        // 3 petits paquets DNS, 1 gros paquet HTTPS → HTTPS domine (octets).
        for _ in 0..3 {
            tables.ingest(
                &meta(
                    MAC_A,
                    MAC_B,
                    80,
                    ipv4,
                    Some((ip_a, ip_b, Proto::Named("DNS"))),
                ),
                now,
            );
        }
        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                1500,
                ipv4,
                Some((ip_a, ip_b, Proto::Named("HTTPS"))),
            ),
            now,
        );

        let conv = &tables.l3[&L3Key::new(ip_a, ip_b)];
        assert_eq!(conv.dominant_proto(), Proto::Named("HTTPS"));
        assert_eq!(conv.packets, 4);
        assert_eq!(conv.bytes, 3 * 80 + 1500);
    }

    #[test]
    fn top_talkers_sorted_by_bytes() {
        let mut tables = Tables::new();
        let now = Instant::now();
        let ipv4 = Proto::Named("IPv4");
        let mac_c = Mac([0x02, 0, 0, 0, 0, 0x0c]);

        tables.ingest(&meta(MAC_A, MAC_B, 100, ipv4, None), now);
        tables.ingest(&meta(MAC_A, mac_c, 500, ipv4, None), now);

        let top = tables.top_l2(10);
        assert_eq!(top.len(), 2);
        assert_eq!(*top[0].0, L2Key::new(MAC_A, mac_c), "plus gros en premier");
        assert_eq!(top[0].1.bytes, 500);
    }

    #[test]
    fn resolved_label_replaces_ip_and_survives_fade() {
        use crate::wsproto::Delta;
        let mut tables = Tables::new();
        let t0 = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                100,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            t0,
        );
        // Avant résolution : label = IP.
        let label_of = |deltas: &[Delta], ip: &str| -> Option<String> {
            deltas.iter().find_map(|d| match d {
                Delta::UpsertNode { id, label, .. } if id == ip => Some(label.clone()),
                _ => None,
            })
        };
        let deltas = tables.drain_deltas();
        assert_eq!(label_of(&deltas, "10.0.0.1").unwrap(), "10.0.0.1");

        // Résolution → le nœud repart en upsert avec le nom.
        tables.set_l3_label(ip_a, "nas.local".into());
        let deltas = tables.drain_deltas();
        assert_eq!(deltas.len(), 1, "seul le nœud résolu est re-diffusé");
        assert_eq!(label_of(&deltas, "10.0.0.1").unwrap(), "nas.local");

        // Le snapshot utilise aussi le nom.
        let snap = tables.snapshot_deltas();
        assert_eq!(label_of(&snap, "10.0.0.1").unwrap(), "nas.local");
        assert_eq!(label_of(&snap, "10.0.0.2").unwrap(), "10.0.0.2");

        // Fade complet puis retour du trafic : le nom (cache) est réutilisé.
        tables.fade_sweep(t0 + Duration::from_secs(120), Duration::from_secs(60));
        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                10,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            t0 + Duration::from_secs(121),
        );
        let deltas = tables.drain_deltas();
        assert_eq!(label_of(&deltas, "10.0.0.1").unwrap(), "nas.local");
    }

    #[test]
    fn reset_wipes_history_but_keeps_dns_cache() {
        use crate::wsproto::Delta;
        let mut tables = Tables::new();
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                100,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            now,
        );
        tables.set_l3_label(ip_a, "nas.local".into());
        tables.reset();

        assert!(tables.l2.is_empty() && tables.l3.is_empty());
        assert!(tables.l2_nodes.is_empty() && tables.l3_nodes.is_empty());
        assert!(tables.drain_deltas().is_empty(), "plus rien de dirty");
        assert!(tables.snapshot_deltas().is_empty());

        // Le cache DNS survit : le nom réapparaît au premier nouveau paquet.
        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                10,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            now,
        );
        let label = tables.drain_deltas().iter().find_map(|d| match d {
            Delta::UpsertNode { id, label, .. } if id == "10.0.0.1" => Some(label.clone()),
            _ => None,
        });
        assert_eq!(label.unwrap(), "nas.local");
        // Et les compteurs sont bien repartis de zéro.
        assert_eq!(tables.l3_nodes[&ip_a].bytes, 10);
    }

    #[test]
    fn fade_sweep_removes_stale_and_emits_deltas() {
        use crate::wsproto::Delta;
        let mut tables = Tables::new();
        let t0 = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                100,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            t0,
        );
        tables.drain_deltas();

        // Avant expiration : rien ne bouge.
        assert!(tables
            .fade_sweep(t0 + Duration::from_secs(30), Duration::from_secs(60))
            .is_empty());

        // Après expiration : tout est retiré, avec les remove_* explicites,
        // arêtes avant nœuds.
        let deltas = tables.fade_sweep(t0 + Duration::from_secs(61), Duration::from_secs(60));
        assert_eq!(deltas.len(), 6, "2 arêtes + 4 nœuds");
        assert!(matches!(deltas[0], Delta::RemoveEdge { .. }));
        assert!(matches!(deltas[1], Delta::RemoveEdge { .. }));
        assert!(deltas[2..]
            .iter()
            .all(|d| matches!(d, Delta::RemoveNode { .. })));
        assert!(tables.l2.is_empty() && tables.l3.is_empty());
        assert!(tables.l2_nodes.is_empty() && tables.l3_nodes.is_empty());

        // Re-trafic → tout est recréé proprement (upserts).
        tables.ingest(&meta(MAC_A, MAC_B, 10, Proto::Named("ARP"), None), t0);
        assert_eq!(tables.drain_deltas().len(), 3);
    }

    #[test]
    fn drain_deltas_only_dirty_then_empty() {
        use crate::wsproto::Delta;
        let mut tables = Tables::new();
        let now = Instant::now();
        let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
        let ip_b: IpAddr = "10.0.0.2".parse().unwrap();

        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                100,
                Proto::Named("IPv4"),
                Some((ip_a, ip_b, Proto::Named("DNS"))),
            ),
            now,
        );

        // 2 nœuds L2 + 2 nœuds L3 + 1 arête L2 + 1 arête L3 = 6 deltas.
        let deltas = tables.drain_deltas();
        assert_eq!(deltas.len(), 6);
        let edges = deltas
            .iter()
            .filter(|d| matches!(d, Delta::UpsertEdge { .. }))
            .count();
        assert_eq!(edges, 2);

        // Rien de modifié depuis → aucun delta.
        assert!(tables.drain_deltas().is_empty());

        // Le snapshot, lui, redonne toujours l'état complet.
        assert_eq!(tables.snapshot_deltas().len(), 6);

        // Nouvelle trame → seuls les éléments touchés repartent.
        tables.ingest(&meta(MAC_A, MAC_B, 50, Proto::Named("ARP"), None), now);
        let deltas = tables.drain_deltas();
        assert_eq!(deltas.len(), 3, "2 nœuds L2 + 1 arête L2, rien côté L3");
    }

    #[test]
    fn ipv4_and_ipv6_coexist() {
        let mut tables = Tables::new();
        let now = Instant::now();
        let v4: IpAddr = "10.0.0.1".parse().unwrap();
        let v4b: IpAddr = "10.0.0.2".parse().unwrap();
        let v6: IpAddr = "fe80::1".parse().unwrap();
        let v6b: IpAddr = "ff02::fb".parse().unwrap();

        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                100,
                Proto::Named("IPv4"),
                Some((v4, v4b, Proto::Named("DNS"))),
            ),
            now,
        );
        tables.ingest(
            &meta(
                MAC_A,
                MAC_B,
                200,
                Proto::Named("IPv6"),
                Some((v6, v6b, Proto::Named("mDNS"))),
            ),
            now,
        );

        assert_eq!(tables.l3.len(), 2);
        assert_eq!(tables.l2.len(), 1, "même paire MAC → une conversation L2");
    }
}
