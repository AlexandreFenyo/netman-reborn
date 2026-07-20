//! Serveur axum : fichiers statiques + WebSocket `/ws` diffusant les deltas.
//!
//! Chaque client reçoit à la connexion un snapshot complet (les messages
//! broadcast antérieurs à `subscribe()` sont invisibles), puis le flux des
//! deltas. Un client trop lent est « laggé » (déconnecté du ring buffer) :
//! on saute les deltas manqués, les upserts suivants réparent (valeurs
//! absolues). La capture n'est jamais ralentie (invariant 5).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::ws::{Message, Utf8Bytes, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;

use crate::model::tables::Tables;
use crate::wsproto::{ClientCommand, Delta, IfaceInfo, ServerInfo};

/// Bornes du délai de fade réglable depuis l'IHM.
pub const FADE_MIN_SECS: u64 = 5;
pub const FADE_MAX_SECS: u64 = 3600;

/// Interfaces disponibles + interface active, tenues à jour par le
/// contrôleur de capture. Vide en mode fichier (sélecteur masqué).
#[derive(Default)]
pub struct IfaceState {
    pub current: Option<String>,
    pub interfaces: Vec<IfaceInfo>,
}

impl IfaceState {
    pub fn to_message(&self) -> ServerInfo {
        ServerInfo::Interfaces {
            current: self.current.clone(),
            interfaces: self.interfaces.clone(),
        }
    }
}

/// État partagé du serveur.
#[derive(Clone)]
pub struct AppState {
    /// Tables possédées par l'agrégateur ; lues ici uniquement pour le
    /// snapshot de connexion (verrou bref, jamais tenu à travers un await).
    pub tables: Arc<Mutex<Tables>>,
    pub deltas_tx: broadcast::Sender<Utf8Bytes>,
    /// Délai de fade courant (secondes), réglable par les clients.
    pub fade_secs: Arc<AtomicU64>,
    pub iface_state: Arc<Mutex<IfaceState>>,
    /// Demandes de changement d'interface (None en mode fichier).
    pub iface_tx: Option<tokio::sync::mpsc::Sender<String>>,
}

/// Construit le routeur : `/ws` + fichiers statiques (frontend).
pub fn router(state: AppState, static_dir: &str) -> Router {
    Router::new()
        .route("/ws", get(ws_handler))
        .fallback_service(ServeDir::new(static_dir))
        .with_state(state)
}

/// Sérialise un delta une seule fois, prêt à diffuser (zéro-copie ensuite).
pub fn encode_delta(delta: &Delta) -> Option<Utf8Bytes> {
    match serde_json::to_string(delta) {
        Ok(json) => Some(Utf8Bytes::from(json)),
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize delta");
            None
        }
    }
}

async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> Response {
    ws.on_upgrade(move |socket| client_loop(socket, state))
}

/// Encode un message d'information serveur → client.
pub fn encode_info(info: &ServerInfo) -> Option<Utf8Bytes> {
    match serde_json::to_string(info) {
        Ok(json) => Some(Utf8Bytes::from(json)),
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize server info");
            None
        }
    }
}

/// Traite un message texte reçu d'un client.
fn handle_client_command(text: &str, state: &AppState) {
    match serde_json::from_str::<ClientCommand>(text) {
        Ok(ClientCommand::SetFade { seconds }) => {
            let clamped = seconds.clamp(FADE_MIN_SECS, FADE_MAX_SECS);
            state.fade_secs.store(clamped, Ordering::Relaxed);
            tracing::info!(fade_secs = clamped, "fade timeout updated by client");
            // Propage la nouvelle config à tous les clients connectés.
            if let Some(msg) = encode_info(&ServerInfo::Config { fade_secs: clamped }) {
                let _ = state.deltas_tx.send(msg);
            }
        }
        Ok(ClientCommand::SetInterface { id }) => match &state.iface_tx {
            Some(tx) => {
                if tx.try_send(id).is_err() {
                    tracing::warn!("interface switch request dropped (queue full)");
                }
            }
            None => tracing::warn!("interface switch requested in offline mode, ignored"),
        },
        Err(e) => tracing::warn!(error = %e, text, "unrecognized client message"),
    }
}

async fn client_loop(socket: WebSocket, state: AppState) {
    // S'abonner AVANT de construire le snapshot : on ne peut rien rater,
    // au pire on reçoit des upserts en double (valeurs absolues → sans effet).
    let mut deltas_rx = state.deltas_tx.subscribe();

    let snapshot: Vec<Utf8Bytes> = {
        let Ok(tables) = state.tables.lock() else {
            tracing::error!("tables mutex poisoned, closing client");
            return;
        };
        tables
            .snapshot_deltas()
            .iter()
            .filter_map(encode_delta)
            .collect()
    };

    let (mut sink, mut stream) = socket.split();
    // Configuration + interfaces d'abord (les contrôles s'initialisent),
    // puis snapshot.
    let mut preamble: Vec<Utf8Bytes> = Vec::with_capacity(2);
    if let Some(msg) = encode_info(&ServerInfo::Config {
        fade_secs: state.fade_secs.load(Ordering::Relaxed),
    }) {
        preamble.push(msg);
    }
    if let Ok(iface_state) = state.iface_state.lock() {
        if let Some(msg) = encode_info(&iface_state.to_message()) {
            preamble.push(msg);
        }
    }
    for msg in preamble {
        if sink.send(Message::Text(msg)).await.is_err() {
            return;
        }
    }
    for msg in snapshot {
        if sink.send(Message::Text(msg)).await.is_err() {
            return;
        }
    }
    tracing::info!("websocket client connected");

    loop {
        tokio::select! {
            received = deltas_rx.recv() => match received {
                Ok(msg) => {
                    if sink.send(Message::Text(msg)).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    // Client trop lent : deltas sautés, les upserts suivants
                    // réparent (valeurs absolues + capacité généreuse).
                    tracing::warn!(skipped, "slow websocket client lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Text(text))) => handle_client_command(text.as_str(), &state),
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {}
            },
        }
    }
    tracing::info!("websocket client disconnected");
}
