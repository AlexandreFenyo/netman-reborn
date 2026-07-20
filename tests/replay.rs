//! Test d'intégration : rejeu déterministe de la fixture .pcap (CLAUDE.md §8).
//!
//! La fixture est générée par ce test si absente (frames construites avec
//! etherparse::PacketBuilder + un ARP forgé) puis figée : le test vérifie
//! ensuite que le fichier committé correspond octet pour octet au générateur.

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use etherparse::PacketBuilder;

use netman::capture::{self, CaptureStats};
use netman::model::packet::{self, Mac, Proto};
use netman::model::tables::{L2Key, L3Key, Tables};

const MAC_A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0a];
const MAC_B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0b];
const MAC_C: [u8; 6] = [0x02, 0, 0, 0, 0, 0x0c];
const BROADCAST: [u8; 6] = [0xff; 6];

const IP_A: [u8; 4] = [10, 0, 0, 1];
const IP_B: [u8; 4] = [10, 0, 0, 2];
const IP_C: [u8; 4] = [10, 0, 0, 53];

/// Les 7 trames de référence, déterministes.
fn build_frames() -> Vec<Vec<u8>> {
    let mut frames = Vec::new();

    // [0] ARP request A → broadcast (forgée à la main, 42 octets).
    let mut arp = Vec::new();
    arp.extend_from_slice(&BROADCAST);
    arp.extend_from_slice(&MAC_A);
    arp.extend_from_slice(&[0x08, 0x06]); // EtherType ARP
    arp.extend_from_slice(&[0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]);
    arp.extend_from_slice(&MAC_A);
    arp.extend_from_slice(&IP_A);
    arp.extend_from_slice(&[0u8; 6]);
    arp.extend_from_slice(&IP_B);
    frames.push(arp);

    // [1] IPv4 TCP 443 A→B (400 octets de payload) — HTTPS.
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_A, MAC_B)
        .ipv4(IP_A, IP_B, 64)
        .tcp(51000, 443, 1, 64240)
        .write(&mut f, &[0xAA; 400])
        .expect("build https frame");
    frames.push(f);

    // [2] IPv4 TCP 443 B→A (1200 octets) — HTTPS retour.
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_B, MAC_A)
        .ipv4(IP_B, IP_A, 64)
        .tcp(443, 51000, 900, 64240)
        .write(&mut f, &[0xBB; 1200])
        .expect("build https back frame");
    frames.push(f);

    // [3] IPv4 UDP 53 A→C (requête DNS, 30 octets).
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_A, MAC_C)
        .ipv4(IP_A, IP_C, 64)
        .udp(50123, 53)
        .write(&mut f, &[0x11; 30])
        .expect("build dns query frame");
    frames.push(f);

    // [4] IPv4 UDP 53 C→A (réponse DNS, 90 octets).
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_C, MAC_A)
        .ipv4(IP_C, IP_A, 64)
        .udp(53, 50123)
        .write(&mut f, &[0x22; 90])
        .expect("build dns answer frame");
    frames.push(f);

    // [5] IPv6 UDP 5353 A→multicast — mDNS.
    let src6 = "fe80::1".parse::<std::net::Ipv6Addr>().unwrap();
    let dst6 = "ff02::fb".parse::<std::net::Ipv6Addr>().unwrap();
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_A, [0x33, 0x33, 0, 0, 0, 0xfb])
        .ipv6(src6.octets(), dst6.octets(), 255)
        .udp(5353, 5353)
        .write(&mut f, &[0x33; 100])
        .expect("build mdns frame");
    frames.push(f);

    // [6] VLAN 42 + IPv4 ICMP echo request A→B.
    let mut f = Vec::new();
    PacketBuilder::ethernet2(MAC_A, MAC_B)
        .single_vlan(42.try_into().unwrap())
        .ipv4(IP_A, IP_B, 64)
        .icmpv4_echo_request(7, 1)
        .write(&mut f, &[0x44; 32])
        .expect("build vlan icmp frame");
    frames.push(f);

    frames
}

/// Sérialise en format pcap classique (LE, linktype 1 = Ethernet).
fn pcap_bytes(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
    out.extend_from_slice(&2u16.to_le_bytes()); // version major
    out.extend_from_slice(&4u16.to_le_bytes()); // version minor
    out.extend_from_slice(&0u32.to_le_bytes()); // thiszone
    out.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    out.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    out.extend_from_slice(&1u32.to_le_bytes()); // linktype Ethernet
    for (i, frame) in frames.iter().enumerate() {
        let len = frame.len() as u32;
        out.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
        out.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        out.extend_from_slice(&len.to_le_bytes()); // incl_len
        out.extend_from_slice(&len.to_le_bytes()); // orig_len
        out.extend_from_slice(frame);
    }
    out
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("sample.pcap")
}

#[test]
fn replay_fixture_and_aggregate() {
    netman::setup_npcap_dll_path();

    let frames = build_frames();
    let expected_bytes = pcap_bytes(&frames);
    let path = fixture_path();

    if !path.exists() {
        std::fs::create_dir_all(path.parent().expect("fixture dir")).expect("mkdir fixtures");
        std::fs::write(&path, &expected_bytes).expect("write fixture");
    }
    let on_disk = std::fs::read(&path).expect("read fixture");
    assert_eq!(
        on_disk, expected_bytes,
        "tests/fixtures/sample.pcap ne correspond plus au générateur — \
         supprimer le fichier pour le régénérer"
    );

    // Rejeu via le même chemin de code que le binaire (capture::run_file).
    let stats = Arc::new(CaptureStats::default());
    let shutdown = Arc::new(AtomicBool::new(false));
    let mut tables = Tables::new();
    let now = Instant::now();
    capture::run_file(&path, Arc::clone(&stats), shutdown, |data, wire_len| {
        if let Some(meta) = packet::parse_frame(data, wire_len) {
            tables.ingest(&meta, now);
        }
    })
    .expect("replay fixture");

    use std::sync::atomic::Ordering;
    assert_eq!(stats.frames.load(Ordering::Relaxed), 7);

    // --- Table Etherman (L2) : 4 conversations attendues.
    assert_eq!(tables.l2.len(), 4, "A-bcast, A-B, A-C, A-mcast(mDNS)");
    let l2_ab = &tables.l2[&L2Key::new(Mac(MAC_A), Mac(MAC_B))];
    // A-B : trames 1, 2 (HTTPS) et 6 (VLAN ICMP) — IPv4 domine en octets.
    assert_eq!(l2_ab.packets, 3);
    assert_eq!(
        l2_ab.bytes,
        (frames[1].len() + frames[2].len() + frames[6].len()) as u64
    );
    assert_eq!(l2_ab.dominant_proto(), Proto::Named("IPv4"));

    let l2_arp = &tables.l2[&L2Key::new(Mac(MAC_A), Mac(BROADCAST))];
    assert_eq!(l2_arp.dominant_proto(), Proto::Named("ARP"));
    assert_eq!(l2_arp.packets, 1);

    // --- Table Interman (L3) : 3 conversations attendues
    // (le ping VLAN partage la paire A-B avec l'HTTPS).
    assert_eq!(tables.l3.len(), 3);
    let ip_a: IpAddr = "10.0.0.1".parse().unwrap();
    let ip_b: IpAddr = "10.0.0.2".parse().unwrap();
    let ip_c: IpAddr = "10.0.0.53".parse().unwrap();

    let l3_ab = &tables.l3[&L3Key::new(ip_a, ip_b)];
    // HTTPS (1600 octets de payload) domine largement l'ICMP du VLAN.
    assert_eq!(l3_ab.dominant_proto(), Proto::Named("HTTPS"));
    assert_eq!(l3_ab.packets, 3);

    let l3_dns = &tables.l3[&L3Key::new(ip_a, ip_c)];
    assert_eq!(l3_dns.dominant_proto(), Proto::Named("DNS"));
    assert_eq!(l3_dns.packets, 2);
    assert_eq!(l3_dns.bytes, (frames[3].len() + frames[4].len()) as u64);

    let v6a: IpAddr = "fe80::1".parse().unwrap();
    let v6m: IpAddr = "ff02::fb".parse().unwrap();
    let l3_mdns = &tables.l3[&L3Key::new(v6a, v6m)];
    assert_eq!(l3_mdns.dominant_proto(), Proto::Named("mDNS"));
}
