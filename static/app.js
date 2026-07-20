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
 *   - taille de nœud    ∝ log2(octets cumulés)  [2 .. 18]
 *   - épaisseur d'arête ∝ log2(débit observé)   [0.4 .. 12], amplification
 *     réglable par vue (slider « Link width » de chaque panneau)
 *   - couleur = protocole dominant (palette PROTO_COLORS)
 *
 * Débit : les upserts portent des cumuls absolus ; le client en dérive un
 * débit lissé (EWMA, constante RATE_TAU) et le fait décroître vers zéro
 * quand une arête ne reçoit plus de mises à jour.
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

/* Constante de temps (s) du lissage/décroissance du débit des arêtes. */
const RATE_TAU = 3;
const RATE_DECAY = Math.exp(-1 / RATE_TAU);

/* Épaisseur ∝ log2 du débit (octets/s), amplifiée par le slider de la vue :
 * ~1 kB/s → 1.6 px, ~1 MB/s → 5 px, ~100 MB/s → 8 px (à scale 1). */
function edgeWidth(rate, scale) {
  return Math.min(12, 0.4 + 0.35 * scale * Math.log2(1 + rate / 100));
}

/* Débit en bit/s, unité adaptée : bit/s < 1 kbit/s < 1 Mbit/s < 1 Gbit/s. */
function formatRate(bytesPerSec) {
  const bps = bytesPerSec * 8;
  if (bps < 1000) return `${Math.round(bps)} bit/s`;
  if (bps < 1e6) return `${(bps / 1000).toFixed(1)} kbit/s`;
  if (bps < 1e9) return `${(bps / 1e6).toFixed(1)} Mbit/s`;
  return `${(bps / 1e9).toFixed(2)} Gbit/s`;
}

/* Débit moyen entre le PREMIER et le DERNIER paquet observés depuis que
 * l'élément est affiché en continu : la fenêtre s'arrête au dernier paquet
 * (pas de dilution quand le trafic cesse). Aucune mémoire pour les éléments
 * disparus par fade : la base repart de zéro à leur réapparition (leurs
 * attributs client ET leurs compteurs serveur sont recréés). */
function avgRate(currentBytes, firstBytes, firstTime, lastTime) {
  const span = Math.max(lastTime - firstTime, 0.5);
  return Math.max(0, currentBytes - firstBytes) / span;
}

function escapeHtml(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* --- Filtre protocole (piloté par le <select>, appliqué via les reducers
 * sigma : les arêtes d'un autre protocole sont masquées, leurs nœuds
 * estompés — aucune mutation des graphes, purement visuel). */

let protoFilter = "";

const SIGMA_BASE_SETTINGS = {
  labelColor: { color: "#aeb6c4" },
  labelSize: 11,
  labelRenderedSizeThreshold: 5,
  edgeLabelColor: { color: "#aeb6c4" },
  edgeLabelSize: 10,
  renderEdgeLabels: true, /* « Rates » est actif par défaut */
  defaultNodeColor: OTHER_COLOR,
  defaultEdgeColor: "#333a48",
  minCameraRatio: 0.05,
  maxCameraRatio: 20,
};

/* --- Regroupement Interman par réseau.
 * IPv4 : réseau classful — classe A → /8, classe B → /16, classe C → /24,
 * classes D/E (multicast & réservé) dans un groupe à part.
 * IPv6 : préfixe /64 (l'équivalent moderne du « réseau » local). */

function expandIpv6(ip) {
  const [head, tail = ""] = ip.split("::");
  const headParts = head ? head.split(":") : [];
  const tailParts = tail ? tail.split(":") : [];
  const missing = Math.max(8 - headParts.length - tailParts.length, 0);
  return [...headParts, ...Array(missing).fill("0"), ...tailParts];
}

function networkKey(id) {
  if (id.includes(":")) {
    return "v6 " + expandIpv6(id).slice(0, 4).join(":") + "::/64";
  }
  const o = id.split(".").map(Number);
  if (o[0] < 128) return `${o[0]}.0.0.0/8`;
  if (o[0] < 192) return `${o[0]}.${o[1]}.0.0/16`;
  if (o[0] < 224) return `${o[0]}.${o[1]}.${o[2]}.0/24`;
  return "multicast & reserved";
}

/* Tri : IPv4 par octets (10.0.0.2 avant 10.0.0.10), le reste lexicographique. */
function compareNodeIds(a, b) {
  if (!a.includes(":") && !b.includes(":")) {
    const ao = a.split(".").map(Number);
    const bo = b.split(".").map(Number);
    for (let i = 0; i < 4; i++) {
      if (ao[i] !== bo[i]) return ao[i] - bo[i];
    }
    return 0;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

/* --- Deux vues indépendantes : graphe graphology + sigma + supervisor FA2. */

class GraphView {
  /* mode "circle"   : nœuds répartis sur un grand cercle (Etherman — un
   *                    réseau L2 est plat, toutes les stations sont sur le
   *                    même segment ; les conversations traversent le cercle,
   *                    comme dans l'Etherman de 1993) ;
   * mode "networks" : un cercle par réseau (Interman — les hôtes d'un même
   *                    réseau classful A/B/C, ou /64 en IPv6, forment un
   *                    cercle ; les réseaux se répartissent sur un anneau) ;
   * mode "force"    : ForceAtlas2 continu (non utilisé actuellement). */
  constructor(containerId, mode = "force") {
    this.mode = mode;
    this.graph = new graphology.Graph();
    /* Amplification de « épaisseur ∝ débit », pilotée par le slider du
     * panneau. Appliquée dans l'edgeReducer : purement visuel, aucun
     * recalcul d'attributs au changement de slider. */
    this.widthScale = 1;
    this.animFrame = null; /* animation de re-layout en cours */
    this.renderer = new Sigma(this.graph, document.getElementById(containerId), {
      ...SIGMA_BASE_SETTINGS,
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
        return { ...data, size: edgeWidth(data.rate || 0, this.widthScale) };
      },
    });
    this.layout = null;
  }

  /* FA2 refuse un graphe vide : démarrage paresseux au premier nœud.
   * Le supervisor tolère les mutations à chaud (respawn debouncé du worker). */
  ensureLayout() {
    if (this.mode !== "force" || this.layout || this.graph.order === 0) return;
    const settings = graphologyLibrary.layoutForceAtlas2.inferSettings(this.graph);
    settings.slowDown = 5; /* placement plus stable pour un graphe vivant */
    this.layout = new graphologyLibrary.FA2Layout(this.graph, { settings });
    this.layout.start();
  }

  /* Déplacement fluide vers des positions cibles (ease-out cubic, ~600 ms).
   * Les nœuds encore jamais placés (fraîchement apparus) vont directement à
   * leur cible — pas de traversée d'écran ; les autres glissent. Un nouveau
   * re-layout pendant l'animation repart des positions courantes : pas
   * d'à-coup. */
  animateTo(targets, duration = 600) {
    if (this.animFrame) cancelAnimationFrame(this.animFrame);
    const from = {};
    for (const [id, target] of Object.entries(targets)) {
      if (!this.graph.hasNode(id)) continue;
      const attrs = this.graph.getNodeAttributes(id);
      if (!attrs.placed) {
        this.graph.mergeNode(id, { x: target.x, y: target.y, placed: true });
      } else {
        from[id] = { x: attrs.x, y: attrs.y };
      }
    }
    const start = performance.now();
    const step = (nowMs) => {
      const t = Math.min((nowMs - start) / duration, 1);
      const eased = 1 - Math.pow(1 - t, 3);
      for (const [id, origin] of Object.entries(from)) {
        if (!this.graph.hasNode(id)) continue;
        const target = targets[id];
        this.graph.mergeNode(id, {
          x: origin.x + (target.x - origin.x) * eased,
          y: origin.y + (target.y - origin.y) * eased,
        });
      }
      this.animFrame = t < 1 ? requestAnimationFrame(step) : null;
    };
    this.animFrame = requestAnimationFrame(step);
  }

  /* Redistribue tous les nœuds uniformément sur le cercle. Tri par id (MAC) :
   * placement déterministe et stable, et les préfixes constructeurs voisins
   * se retrouvent naturellement côte à côte. */
  circleLayout() {
    const ids = this.graph.nodes().sort();
    const radius = 100;
    const count = ids.length;
    const targets = {};
    ids.forEach((id, i) => {
      const angle = (2 * Math.PI * i) / count - Math.PI / 2;
      targets[id] = { x: radius * Math.cos(angle), y: radius * Math.sin(angle) };
    });
    this.animateTo(targets);
  }

  /* Un cercle par réseau, les centres des réseaux répartis sur un anneau
   * dont le rayon s'adapte pour que les cercles ne se chevauchent pas.
   * Tout est trié → placement déterministe et stable. */
  networksLayout() {
    const groups = new Map();
    this.graph.forEachNode((id) => {
      const key = networkKey(id);
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(id);
    });
    const keys = [...groups.keys()].sort();
    const clusterRadius = (count) =>
      count === 1 ? 0 : Math.max(16, (count * 10) / (2 * Math.PI));
    let maxRadius = 0;
    for (const key of keys) {
      maxRadius = Math.max(maxRadius, clusterRadius(groups.get(key).length));
    }
    const networkCount = keys.length;
    const ringRadius =
      networkCount === 1
        ? 0
        : Math.max(150, (networkCount * (2 * maxRadius + 50)) / (2 * Math.PI));
    const targets = {};
    keys.forEach((key, ki) => {
      const centerAngle = (2 * Math.PI * ki) / networkCount - Math.PI / 2;
      const cx = ringRadius * Math.cos(centerAngle);
      const cy = ringRadius * Math.sin(centerAngle);
      const members = groups.get(key).sort(compareNodeIds);
      const radius = clusterRadius(members.length);
      members.forEach((id, i) => {
        const angle = (2 * Math.PI * i) / members.length - Math.PI / 2;
        targets[id] = {
          x: cx + radius * Math.cos(angle),
          y: cy + radius * Math.sin(angle),
        };
      });
    });
    this.animateTo(targets);
  }

  /* Applique le layout du mode courant après une mutation de topologie. */
  relayout() {
    if (this.mode === "circle") this.circleLayout();
    else if (this.mode === "networks") this.networksLayout();
    else this.ensureLayout();
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

  upsertNode(id, label, bytes, packets, proto, bytesIn = 0, bytesOut = 0) {
    registerProto(proto);
    const attrs = {
      label,
      size: nodeSize(bytes),
      color: protoColor(proto),
      bytes,
      packets,
      proto,
      bytesIn,
      bytesOut,
    };
    /* sigma v3 exige x/y AU MOMENT de l'ajout : la position fait partie des
     * attributs du merge. En mode force, jamais écrasée ensuite (FA2 la fait
     * vivre) ; en mode cercle, le layout redistribue tout de suite. */
    const isNew = !this.graph.hasNode(id);
    const now = performance.now() / 1000;
    if (isNew) {
      const pos = this.mode === "circle" ? { x: 0, y: 0 } : this.spawnPosition();
      attrs.x = pos.x;
      attrs.y = pos.y;
      /* Fenêtre des débits moyens (survol) : [premier, dernier] paquet. */
      attrs.firstIn = bytesIn;
      attrs.firstOut = bytesOut;
      attrs.firstTime = now;
      attrs.lastTime = now;
    } else if (bytes !== this.graph.getNodeAttribute(id, "bytes")) {
      /* N'avance la fin de fenêtre que si des paquets sont arrivés (un
       * upsert peut ne porter qu'un changement de label, ex. PTR résolu). */
      attrs.lastTime = now;
    }
    this.graph.mergeNode(id, attrs);
    if (isNew) this.relayout();
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
    /* Débit lissé (EWMA) dérivé des cumuls absolus successifs. */
    const now = performance.now() / 1000;
    let rate = 0;
    let prevBytes = bytes;
    let prevTime = now;
    let firstBytes = bytes;
    let firstTime = now;
    if (this.graph.hasEdge(id)) {
      const prev = this.graph.getEdgeAttributes(id);
      firstBytes = prev.firstBytes ?? bytes;
      firstTime = prev.firstTime ?? now;
      const dt = now - (prev.prevTime ?? now);
      if (dt >= 0.05) {
        const inst = Math.max(0, bytes - (prev.prevBytes ?? bytes)) / dt;
        const alpha = 1 - Math.exp(-dt / RATE_TAU);
        rate = (prev.rate || 0) + alpha * (inst - (prev.rate || 0));
      } else {
        /* Mise à jour trop rapprochée : on conserve l'état précédent. */
        rate = prev.rate || 0;
        prevBytes = prev.prevBytes ?? bytes;
        prevTime = prev.prevTime ?? now;
      }
    }
    this.graph.mergeEdgeWithKey(id, source, target, {
      color: edgeColor(proto),
      bytes,
      packets,
      proto,
      rate,
      prevBytes,
      prevTime,
      firstBytes,
      firstTime,
    });
    if (ratesOn) this.updateEdgeLabel(id);
  }

  /* Label d'arête (bouton « Rates ») : débit moyen bidirectionnel entre le
   * premier et le dernier paquet observés depuis l'affichage du lien
   * (prevTime = dernière mise à jour réelle, les arêtes n'étant re-diffusées
   * que quand du trafic passe). */
  updateEdgeLabel(edge) {
    const attrs = this.graph.getEdgeAttributes(edge);
    const now = performance.now() / 1000;
    const avg = avgRate(
      attrs.bytes,
      attrs.firstBytes ?? attrs.bytes,
      attrs.firstTime ?? now,
      attrs.prevTime ?? now,
    );
    this.graph.setEdgeAttribute(edge, "label", formatRate(avg));
  }

  updateAllEdgeLabels() {
    this.graph.forEachEdge((edge) => this.updateEdgeLabel(edge));
  }

  removeNode(id) {
    if (this.graph.hasNode(id)) this.graph.dropNode(id);
    if (this.mode !== "force") this.relayout();
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
    if (this.animFrame) {
      cancelAnimationFrame(this.animFrame);
      this.animFrame = null;
    }
    this.resetLayout();
    this.graph.clear();
  }
}

const views = {
  ether: new GraphView("graph-ether", "circle"),
  inter: new GraphView("graph-inter", "networks"),
};

/* Ticker 1 Hz :
 * - décroissance du débit lissé des arêtes muettes (le serveur n'envoie
 *   d'upsert que quand une conversation change) ;
 * - rafraîchissement des labels de débit moyen (bouton « Rates ») ;
 * - rafraîchissement du tooltip de survol (les moyennes évoluent). */
setInterval(() => {
  const now = performance.now() / 1000;
  for (const view of Object.values(views)) {
    view.graph.forEachEdge((edge, attrs) => {
      if ((attrs.rate || 0) > 1 && now - (attrs.prevTime ?? now) > 2) {
        view.graph.setEdgeAttribute(edge, "rate", attrs.rate * RATE_DECAY);
      }
    });
    if (ratesOn) view.updateAllEdgeLabels();
  }
  refreshTooltip();
}, 1000);

/* --- Application des deltas. */

function applyDelta(delta) {
  const view = views[delta.view];
  if (!view) return;
  switch (delta.type) {
    case "upsert_node":
      view.upsertNode(
        delta.id,
        delta.label,
        delta.bytes,
        delta.packets,
        delta.proto,
        delta.bytes_in,
        delta.bytes_out,
      );
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

/* Sliders « Link width » : un par vue, amplifie/réduit épaisseur ∝ débit. */
for (const [key, view] of Object.entries(views)) {
  const slider = document.getElementById(`width-${key}`);
  slider.addEventListener("input", () => {
    view.widthScale = Number(slider.value);
    view.renderer.refresh({ skipIndexation: true });
  });
}

/* Bouton « Rates » : affiche sur chaque lien le débit moyen bidirectionnel
 * (depuis que le lien est affiché), avec son unité. */
const ratesEl = document.getElementById("rates");
let ratesOn = true;

ratesEl.addEventListener("click", () => {
  ratesOn = !ratesOn;
  ratesEl.classList.toggle("active", ratesOn);
  for (const view of Object.values(views)) {
    if (ratesOn) view.updateAllEdgeLabels();
    view.renderer.setSetting("renderEdgeLabels", ratesOn);
  }
});

/* --- Tooltip de survol des nœuds : identité + débits moyens in/out
 * (moyennés depuis que l'hôte est affiché). */

const tooltipEl = document.getElementById("tooltip");
let hovered = null; /* { view, node } */

function refreshTooltip() {
  if (!hovered) return;
  const { view, node } = hovered;
  if (!view.graph.hasNode(node)) {
    hovered = null;
    tooltipEl.hidden = true;
    return;
  }
  const attrs = view.graph.getNodeAttributes(node);
  const now = performance.now() / 1000;
  const first = attrs.firstTime ?? now;
  const last = attrs.lastTime ?? now;
  const outRate = avgRate(attrs.bytesOut || 0, attrs.firstOut || 0, first, last);
  const inRate = avgRate(attrs.bytesIn || 0, attrs.firstIn || 0, first, last);
  const lines = [`<strong>${escapeHtml(node)}</strong>`];
  /* Etherman : MAC complète + version OUI ; Interman : IP + nom résolu. */
  if (attrs.label && attrs.label !== node) {
    lines.push(escapeHtml(attrs.label));
  }
  lines.push(`out: ${formatRate(outRate)}`, `in: ${formatRate(inRate)}`);
  tooltipEl.innerHTML = lines.join("<br>");
  tooltipEl.hidden = false;
}

for (const view of Object.values(views)) {
  view.renderer.on("enterNode", ({ node }) => {
    hovered = { view, node };
    refreshTooltip();
  });
  view.renderer.on("leaveNode", () => {
    hovered = null;
    tooltipEl.hidden = true;
  });
}

document.addEventListener("mousemove", (e) => {
  if (tooltipEl.hidden) return;
  const pad = 14;
  const x = Math.min(e.clientX + pad, window.innerWidth - tooltipEl.offsetWidth - 8);
  const y = Math.min(e.clientY + pad, window.innerHeight - tooltipEl.offsetHeight - 8);
  tooltipEl.style.left = `${x}px`;
  tooltipEl.style.top = `${y}px`;
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
