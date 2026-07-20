/*
 * Netman Reborn — client WebSocket + deux graphes sigma.js/ForceAtlas2.
 *
 * Le backend envoie des mutations atomiques (contrat wsproto, CLAUDE.md §6) :
 *   { type: upsert_node|upsert_edge|remove_node|remove_edge,
 *     view: "ether"|"inter", id, [source, target,] bytes, packets, proto, label }
 * plus { type: "config", fade_secs } (état des réglages, le serveur fait foi).
 * Le client APPLIQUE, il ne recalcule pas. bytes/packets sont des cumuls
 * absolus : un delta manqué est réparé par le suivant.
 *
 * Mapping visuel (fixe, documenté, légende en pied de page) :
 *   - taille de nœud   ∝ log2(octets cumulés)  [2 .. 18]
 *   - épaisseur d'arête ∝ log2(octets cumulés) [0.5 .. 7]
 *   - couleur = protocole dominant (palette PROTO_COLORS)
 */

"use strict";

/* Palette protocole → couleur. */
const PROTO_COLORS = {
  IPv4: "#4c9be8",
  IPv6: "#8e6ee8",
  ARP: "#f1c40f",
  HTTP: "#2ecc71",
  HTTPS: "#27ae60",
  QUIC: "#1abc9c",
  DNS: "#f39c12",
  mDNS: "#e67e22",
  LLMNR: "#e67e22",
  SSDP: "#d35400",
  TCP: "#3498db",
  UDP: "#9b59b6",
  ICMP: "#e74c3c",
  ICMPv6: "#c0392b",
  SSH: "#16a085",
  SMB: "#e84c9b",
  NetBIOS: "#e84c9b",
  DHCP: "#7f8c8d",
  DHCPv6: "#7f8c8d",
  NTP: "#95a5a6",
  IGMP: "#a04000",
};
const OTHER_COLOR = "#697386";
const DIMMED_COLOR = "#2a3040";
/* Transparence des arêtes (alpha hex) : les chevauchements se voient par
 * accumulation — deux liens superposés apparaissent plus denses qu'un seul. */
const EDGE_ALPHA = "8c"; /* ≈ 55 % */

function protoColor(proto) {
  return PROTO_COLORS[proto] || OTHER_COLOR;
}

function edgeColor(proto) {
  return protoColor(proto) + EDGE_ALPHA;
}

function nodeSize(bytes) {
  return Math.min(18, Math.max(2, 2 + Math.log2(1 + bytes) * 0.75));
}

function edgeSize(bytes) {
  return Math.min(7, Math.max(0.5, 0.5 + Math.log2(1 + bytes) * 0.35));
}

/* --- Filtre protocole (piloté par le <select>, appliqué via les reducers
 * sigma : les arêtes d'un autre protocole sont masquées, leurs nœuds
 * estompés — aucune mutation des graphes, purement visuel). */

let protoFilter = "";

const SIGMA_SETTINGS = {
  labelColor: { color: "#aeb6c4" },
  labelSize: 11,
  labelRenderedSizeThreshold: 5,
  defaultNodeColor: OTHER_COLOR,
  defaultEdgeColor: "#333a48",
  minCameraRatio: 0.05,
  maxCameraRatio: 20,
  nodeReducer: (_node, data) => {
    if (protoFilter && data.proto !== protoFilter) {
      return { ...data, color: DIMMED_COLOR, label: null, size: Math.min(data.size, 3) };
    }
    return data;
  },
  edgeReducer: (_edge, data) => {
    if (protoFilter && data.proto !== protoFilter) {
      return { ...data, hidden: true };
    }
    return data;
  },
};

/* --- Deux vues indépendantes : graphe graphology + sigma + supervisor FA2. */

class GraphView {
  constructor(containerId) {
    this.graph = new graphology.Graph();
    this.renderer = new Sigma(this.graph, document.getElementById(containerId), SIGMA_SETTINGS);
    this.layout = null;
  }

  /* FA2 refuse un graphe vide : démarrage paresseux au premier nœud.
   * Le supervisor tolère les mutations à chaud (respawn debouncé du worker). */
  ensureLayout() {
    if (this.layout || this.graph.order === 0) return;
    const settings = graphologyLibrary.layoutForceAtlas2.inferSettings(this.graph);
    settings.slowDown = 5; /* placement plus stable pour un graphe vivant */
    this.layout = new graphologyLibrary.FA2Layout(this.graph, { settings });
    this.layout.start();
  }

  /* Position initiale près du barycentre des nœuds existants. */
  spawnPosition() {
    const order = this.graph.order;
    if (order === 0) return { x: 0, y: 0 };
    let cx = 0;
    let cy = 0;
    this.graph.forEachNode((_, attrs) => {
      cx += attrs.x || 0;
      cy += attrs.y || 0;
    });
    cx /= order;
    cy /= order;
    const angle = Math.random() * 2 * Math.PI;
    const radius = 5 + Math.random() * 10;
    return { x: cx + Math.cos(angle) * radius, y: cy + Math.sin(angle) * radius };
  }

  upsertNode(id, label, bytes, packets, proto) {
    registerProto(proto);
    const attrs = {
      label,
      size: nodeSize(bytes),
      color: protoColor(proto),
      bytes,
      packets,
      proto,
    };
    /* sigma v3 exige x/y AU MOMENT de l'ajout : la position fait partie des
     * attributs du merge. Jamais écrasée ensuite (FA2 la fait vivre). */
    const isNew = !this.graph.hasNode(id);
    if (isNew) {
      const pos = this.spawnPosition();
      attrs.x = pos.x;
      attrs.y = pos.y;
    }
    this.graph.mergeNode(id, attrs);
    if (isNew) this.ensureLayout();
  }

  /* Garde-fou : si une arête arrive avant ses extrémités (delta de nœud
   * sauté par lag), on crée le nœud — l'upsert suivant le complétera. */
  ensureEndpoint(id) {
    if (this.graph.hasNode(id)) return;
    this.upsertNode(id, id, 0, 0, "?");
  }

  upsertEdge(id, source, target, bytes, packets, proto) {
    registerProto(proto);
    this.ensureEndpoint(source);
    this.ensureEndpoint(target);
    this.graph.mergeEdgeWithKey(id, source, target, {
      size: edgeSize(bytes),
      color: edgeColor(proto),
      bytes,
      packets,
      proto,
    });
  }

  removeNode(id) {
    if (this.graph.hasNode(id)) this.graph.dropNode(id);
    if (this.graph.order === 0) this.resetLayout();
  }

  removeEdge(id) {
    if (this.graph.hasEdge(id)) this.graph.dropEdge(id);
  }

  resetLayout() {
    if (this.layout) {
      this.layout.kill(); /* kill est définitif : on recréera au besoin */
      this.layout = null;
    }
  }

  clear() {
    this.resetLayout();
    this.graph.clear();
  }
}

const views = {
  ether: new GraphView("graph-ether"),
  inter: new GraphView("graph-inter"),
};

/* --- Application des deltas. */

function applyDelta(delta) {
  const view = views[delta.view];
  if (!view) return;
  switch (delta.type) {
    case "upsert_node":
      view.upsertNode(delta.id, delta.label, delta.bytes, delta.packets, delta.proto);
      break;
    case "upsert_edge":
      view.upsertEdge(delta.id, delta.source, delta.target, delta.bytes, delta.packets, delta.proto);
      break;
    case "remove_node":
      view.removeNode(delta.id);
      break;
    case "remove_edge":
      view.removeEdge(delta.id);
      break;
    default:
      console.warn("unknown message type", delta);
  }
}

/* --- Contrôles. */

const statusEl = document.getElementById("status");
const pauseEl = document.getElementById("pause");
const resetEl = document.getElementById("reset");
const filterEl = document.getElementById("filter");
const fadeEl = document.getElementById("fade");
const fadeValueEl = document.getElementById("fade-value");
let socket = null;
let paused = false;

/* Pause : gèle les deux vues (les deltas sont ignorés). La reprise force une
 * reconnexion → le snapshot serveur remet les vues exactement à jour. */
pauseEl.addEventListener("click", () => {
  paused = !paused;
  pauseEl.textContent = paused ? "Resume" : "Pause";
  pauseEl.classList.toggle("active", paused);
  if (!paused && socket) socket.close();
});

/* Reset : repart de zéro à partir du snapshot serveur. */
resetEl.addEventListener("click", () => {
  if (socket) socket.close();
});

/* Filtre protocole : la liste se remplit au fil des protocoles rencontrés. */
const seenProtos = new Set();

function registerProto(proto) {
  if (!proto || proto === "?" || seenProtos.has(proto)) return;
  seenProtos.add(proto);
  const option = document.createElement("option");
  option.value = proto;
  option.textContent = proto;
  filterEl.appendChild(option);
}

filterEl.addEventListener("change", () => {
  protoFilter = filterEl.value;
  for (const view of Object.values(views)) {
    view.renderer.refresh({ skipIndexation: true });
  }
});

/* Réglage du fade : slider → serveur ; le serveur renvoie {type:"config"} à
 * tous les clients (y compris l'émetteur), qui fait foi. */

function fadeLabel(seconds) {
  return seconds >= 60 && seconds % 60 === 0 ? `${seconds / 60} min` : `${seconds} s`;
}

fadeEl.addEventListener("input", () => {
  fadeValueEl.textContent = fadeLabel(Number(fadeEl.value));
});

fadeEl.addEventListener("change", () => {
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify({ type: "set_fade", seconds: Number(fadeEl.value) }));
  }
});

function applyConfig(config) {
  fadeEl.value = config.fade_secs;
  fadeValueEl.textContent = fadeLabel(config.fade_secs);
}

/* --- Légende. */

{
  const legend = document.getElementById("legend");
  const entries = { ...PROTO_COLORS, other: OTHER_COLOR };
  for (const [proto, color] of Object.entries(entries)) {
    const item = document.createElement("span");
    item.className = "legend-item";
    const dot = document.createElement("span");
    dot.className = "legend-dot";
    dot.style.background = color;
    item.append(dot, proto);
    legend.appendChild(item);
  }
}

/* --- Connexion WebSocket avec reconnexion (backoff progressif).
 * À chaque (re)connexion le serveur envoie config + snapshot complet : on
 * repart de graphes vides pour éliminer toute entrée périmée. */

let reconnectDelay = 500;

function connect() {
  const ws = new WebSocket(`ws://${location.host}/ws`);
  socket = ws;

  ws.onopen = () => {
    reconnectDelay = 500;
    statusEl.textContent = paused ? "paused" : "live";
    statusEl.className = paused ? "disconnected" : "connected";
    /* En pause, on garde la vue gelée : le clear + snapshot se feront à la
     * reprise (Resume ferme la socket → reconnexion propre). */
    if (!paused) {
      for (const view of Object.values(views)) view.clear();
    }
  };

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);
      if (msg.type === "config") {
        applyConfig(msg);
      } else if (!paused) {
        applyDelta(msg);
      }
    } catch (e) {
      console.error("bad message", e, event.data);
    }
  };

  ws.onclose = () => {
    statusEl.textContent = paused
      ? "paused"
      : `disconnected — retrying in ${Math.round(reconnectDelay / 1000)}s`;
    statusEl.className = "disconnected";
    setTimeout(connect, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 2, 10000);
  };

  ws.onerror = () => ws.close();
}

connect();
