//! Serveur axum : fichiers statiques + WebSocket `/ws` diffusant les deltas.
//!
//! Chaque client reçoit à la connexion un snapshot complet (les messages
//! broadcast antérieurs à `subscribe()` sont invisibles), puis le flux des
//! deltas. Un client trop lent est « laggé » (déconnecté du ring buffer) :
//! on saute les deltas manqués, les upserts suivants réparent (valeurs
//! absolues). La capture n'est jamais ralentie (invariant 5).

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
use crate::wsproto::Delta;

/// État partagé du serveur.
#[derive(Clone)]
pub struct AppState {
    /// Tables possédées par l'agrégateur ; lues ici uniquement pour le
    /// snapshot de connexion (verrou bref, jamais tenu à travers un await).
    pub tables: Arc<Mutex<Tables>>,
    pub deltas_tx: broadcast::Sender<Utf8Bytes>,
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
                    // réparent. Les remove_* manqués seront re-traités au
                    // jalon fade (valeurs absolues + capacité généreuse).
                    tracing::warn!(skipped, "slow websocket client lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = stream.next() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => {} // rien d'attendu du client pour l'instant
            },
        }
    }
    tracing::info!("websocket client disconnected");
}
