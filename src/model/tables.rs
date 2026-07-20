//! Les deux tables d'agrégation en mémoire (invariant 1 : une capture, deux
//! projections du même flux).
//!
//! - Table Etherman (L2) : clé = paire de MAC, non orientée.
//! - Table Interman (L3) : clé = paire d'IP (v4+v6), non orientée.
//!
//! La clé est normalisée (min, max) pour agréger les deux sens d'une même
//! conversation, comme EtherApe.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use super::packet::{Mac, PacketMeta, Proto};

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
    pub last_seen: Instant,
    /// Octets par protocole, pour déterminer le protocole dominant.
    proto_bytes: HashMap<Proto, u64>,
}

impl ConvStats {
    fn new(now: Instant) -> Self {
        ConvStats {
            bytes: 0,
            packets: 0,
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

/// Les deux tables, mises à jour par l'agrégateur (jamais par le thread de
/// capture directement — découplage par channel, invariant 2).
#[derive(Default)]
pub struct Tables {
    pub l2: HashMap<L2Key, ConvStats>,
    pub l3: HashMap<L3Key, ConvStats>,
}

impl Tables {
    pub fn new() -> Self {
        Self::default()
    }

    /// Projette une trame sur les deux tables.
    pub fn ingest(&mut self, meta: &PacketMeta, now: Instant) {
        self.l2
            .entry(L2Key::new(meta.src_mac, meta.dst_mac))
            .or_insert_with(|| ConvStats::new(now))
            .add(meta.wire_len, meta.l2_proto, now);

        if let Some(l3) = &meta.l3 {
            self.l3
                .entry(L3Key::new(l3.src, l3.dst))
                .or_insert_with(|| ConvStats::new(now))
                .add(meta.wire_len, l3.proto, now);
        }
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
