//! Contrat WebSocket (CLAUDE.md §6) — enum serde taguée sur `type`.
//!
//! Une mutation de graphe = un message. Le frontend applique, il ne
//! recalcule pas. Toute modification de ce schéma met à jour backend ET
//! frontend dans le même commit.

use serde::{Deserialize, Serialize};

/// Vue ciblée par un delta : graphe Etherman (L2) ou Interman (L3).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "lowercase")]
pub enum View {
    Ether,
    Inter,
}

/// Mutation atomique d'un des deux graphes.
///
/// Les valeurs `bytes`/`packets` sont des **cumuls absolus** (pas des
/// incréments) : un upsert manqué est réparé par le suivant.
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Delta {
    UpsertNode {
        view: View,
        id: String,
        label: String,
        bytes: u64,
        packets: u64,
        proto: String,
    },
    UpsertEdge {
        view: View,
        id: String,
        source: String,
        target: String,
        bytes: u64,
        packets: u64,
        proto: String,
    },
    RemoveNode {
        view: View,
        id: String,
    },
    RemoveEdge {
        view: View,
        id: String,
    },
}

/// Message de contrôle client → serveur.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientCommand {
    /// Règle le délai de fade (nœuds/arêtes non revus depuis N s → retirés).
    SetFade { seconds: u64 },
}

/// Message d'information serveur → client, hors mutations de graphe.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerInfo {
    /// Configuration courante (envoyée à la connexion et à chaque changement).
    Config { fade_secs: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Non-régression du contrat : la forme JSON exacte est figée.
    #[test]
    fn json_contract_shape() {
        let node = Delta::UpsertNode {
            view: View::Ether,
            id: "aa:bb:cc:dd:ee:ff".into(),
            label: "aa:bb:cc:dd:ee:ff".into(),
            bytes: 1500,
            packets: 10,
            proto: "IPv4".into(),
        };
        assert_eq!(
            serde_json::to_string(&node).unwrap(),
            r#"{"type":"upsert_node","view":"ether","id":"aa:bb:cc:dd:ee:ff","label":"aa:bb:cc:dd:ee:ff","bytes":1500,"packets":10,"proto":"IPv4"}"#
        );

        let edge = Delta::UpsertEdge {
            view: View::Inter,
            id: "10.0.0.1|10.0.0.2".into(),
            source: "10.0.0.1".into(),
            target: "10.0.0.2".into(),
            bytes: 42,
            packets: 1,
            proto: "DNS".into(),
        };
        assert_eq!(
            serde_json::to_string(&edge).unwrap(),
            r#"{"type":"upsert_edge","view":"inter","id":"10.0.0.1|10.0.0.2","source":"10.0.0.1","target":"10.0.0.2","bytes":42,"packets":1,"proto":"DNS"}"#
        );

        let rm = Delta::RemoveEdge {
            view: View::Inter,
            id: "10.0.0.1|10.0.0.2".into(),
        };
        assert_eq!(
            serde_json::to_string(&rm).unwrap(),
            r#"{"type":"remove_edge","view":"inter","id":"10.0.0.1|10.0.0.2"}"#
        );
    }

    #[test]
    fn control_messages_shape() {
        assert_eq!(
            serde_json::to_string(&ServerInfo::Config { fade_secs: 60 }).unwrap(),
            r#"{"type":"config","fade_secs":60}"#
        );
        let cmd: ClientCommand =
            serde_json::from_str(r#"{"type":"set_fade","seconds":120}"#).unwrap();
        assert_eq!(cmd, ClientCommand::SetFade { seconds: 120 });
    }

    #[test]
    fn json_roundtrip() {
        let deltas = vec![
            Delta::UpsertNode {
                view: View::Inter,
                id: "fe80::1".into(),
                label: "fe80::1".into(),
                bytes: 0,
                packets: 0,
                proto: "mDNS".into(),
            },
            Delta::RemoveNode {
                view: View::Ether,
                id: "aa:bb:cc:dd:ee:ff".into(),
            },
        ];
        for d in deltas {
            let json = serde_json::to_string(&d).unwrap();
            let back: Delta = serde_json::from_str(&json).unwrap();
            assert_eq!(back, d);
        }
    }
}
