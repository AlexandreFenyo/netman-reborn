//! OUI : préfixe MAC → fabricant, à partir du fichier Wireshark `manuf`
//! embarqué dans le binaire (`src/resolve/data/manuf`, rafraîchissable en le
//! re-téléchargeant — voir RESEARCH.md).
//!
//! Lookup purement en mémoire, O(1) : /36 puis /28 (MA-S/MA-M) puis /24.
//! Parse paresseux au premier appel (OnceLock), hors du chemin de capture.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::model::packet::Mac;

const MANUF: &str = include_str!("data/manuf");

struct OuiDb {
    /// Blocs /24 (MA-L) : 3 octets.
    h24: HashMap<[u8; 3], &'static str>,
    /// Blocs /28 (MA-M) : 4 octets, quartet bas du 4e à zéro.
    h28: HashMap<[u8; 4], &'static str>,
    /// Blocs /36 (MA-S) : 5 octets, quartet bas du 5e à zéro.
    h36: HashMap<[u8; 5], &'static str>,
}

fn parse_mac_prefix(text: &str) -> Option<Vec<u8>> {
    text.split(':')
        .map(|b| u8::from_str_radix(b, 16).ok())
        .collect()
}

fn build_db() -> OuiDb {
    let mut db = OuiDb {
        h24: HashMap::new(),
        h28: HashMap::new(),
        h36: HashMap::new(),
    };
    for line in MANUF.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Colonnes séparées par des tabulations mais paddées d'espaces.
        let mut cols = line.split('\t').map(str::trim);
        let (Some(prefix), Some(short)) = (cols.next(), cols.next()) else {
            continue;
        };
        if short.is_empty() {
            continue;
        }
        let (mac_part, bits) = match prefix.split_once('/') {
            Some((mac, len)) => (mac, len.parse::<u8>().unwrap_or(0)),
            None => (prefix, 24),
        };
        let Some(bytes) = parse_mac_prefix(mac_part) else {
            continue;
        };
        match (bits, bytes.as_slice()) {
            (24, [a, b, c, ..]) => {
                db.h24.insert([*a, *b, *c], short);
            }
            (28, [a, b, c, d, ..]) => {
                db.h28.insert([*a, *b, *c, *d & 0xf0], short);
            }
            (36, [a, b, c, d, e, ..]) => {
                db.h36.insert([*a, *b, *c, *d, *e & 0xf0], short);
            }
            _ => {}
        }
    }
    db
}

fn db() -> &'static OuiDb {
    static DB: OnceLock<OuiDb> = OnceLock::new();
    DB.get_or_init(build_db)
}

/// Nom court du fabricant, si le préfixe est enregistré.
/// Les adresses localement administrées (bit U/L) — MAC randomisées,
/// machines virtuelles… — n'ont pas de fabricant par construction.
pub fn vendor(mac: &Mac) -> Option<&'static str> {
    let m = mac.0;
    if m[0] & 0x02 != 0 {
        return None; // localement administrée
    }
    let d = db();
    d.h36
        .get(&[m[0], m[1], m[2], m[3], m[4] & 0xf0])
        .or_else(|| d.h28.get(&[m[0], m[1], m[2], m[3] & 0xf0]))
        .or_else(|| d.h24.get(&[m[0], m[1], m[2]]))
        .copied()
}

/// Label Etherman : `Fabricant xx:yy:zz` (3 derniers octets), sinon la MAC.
pub fn label(mac: &Mac) -> String {
    match vendor(mac) {
        Some(name) => {
            let m = mac.0;
            format!("{name} {:02x}:{:02x}:{:02x}", m[3], m[4], m[5])
        }
        None => mac.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendors_resolve() {
        // Préfixes stables depuis des décennies.
        let apple = Mac([0x00, 0x03, 0x93, 0x12, 0x34, 0x56]); // Apple, Inc.
        let vmware = Mac([0x00, 0x0c, 0x29, 0xea, 0x4d, 0xf1]); // VMware
        assert!(vendor(&apple).is_some(), "Apple OUI should be known");
        assert!(vendor(&vmware).is_some(), "VMware OUI should be known");
        let label = label(&vmware);
        assert!(
            label.ends_with("ea:4d:f1") && !label.starts_with("00:0c:29"),
            "vendor label expected, got {label}"
        );
    }

    #[test]
    fn locally_administered_and_unknown_fall_back_to_mac() {
        let random = Mac([0x02, 0x00, 0x00, 0x00, 0x00, 0x0a]); // bit U/L
        assert_eq!(vendor(&random), None);
        assert_eq!(label(&random), "02:00:00:00:00:0a");
        let broadcast = Mac([0xff; 6]);
        assert_eq!(vendor(&broadcast), None);
    }

    #[test]
    fn db_is_populated() {
        assert!(db().h24.len() > 10_000, "manuf file should be substantial");
    }
}
