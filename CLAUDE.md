# CLAUDE.md — Netman Reborn (Etherman + Interman)

Ce fichier cadre le travail de Claude Code sur ce projet. Lis-le avant toute
tâche. En cas de conflit entre une demande ponctuelle et un **invariant** listé
ici, signale le conflit avant d'agir.

## 1. Objectif

Recréer en version moderne deux outils de la suite **Netman** (Curtin
University, 1993) :

- **Etherman** — vue couche 2 : conversations entre adresses **MAC**.
- **Interman** — vue couche 3 : conversations entre adresses **IP** (v4 + v6),
  y compris réseaux distants.

Backend **Rust** (capture + agrégation + serveur), frontend **navigateur**
(sigma.js). Les deux vues s'affichent **simultanément, côte à côte**, dans une
seule page, alimentées par **une seule capture réseau**.

L'outil est un **moniteur passif**. Voir §3.

## 2. Invariants (ne jamais violer sans validation explicite)

1. **Une capture, deux agrégations.** Etherman et Interman ne sont PAS deux
   sniffers. Ce sont deux projections (MAC vs IP) du *même* flux de trames. La
   carte n'est mise en promiscuous **qu'une seule fois**. Toute proposition de
   double capture est une régression.
2. **La capture ne bloque jamais sur l'UI.** Un thread OS dédié exécute la
   boucle pcap (bloquante). Il communique avec le reste via un channel. Aucune
   opération réseau/DNS/rendu ne s'exécute dans ce thread.
3. **Capture native Windows uniquement, via Npcap.** Ne JAMAIS capturer depuis
   WSL2 : son namespace réseau virtualisé ne voit pas le trafic promiscuous de
   la carte physique. Le binaire de capture se compile et tourne côté hôte
   Windows. Le dev peut vivre dans WSL, mais l'exécutable de capture est natif.
4. **Aucune résolution bloquante dans le chemin de capture.** OUI (MAC→vendeur)
   et hostnames sont best-effort, asynchrones, jamais sur le trajet critique du
   paquet.
5. **La capture prime sur l'affichage.** Sous charge, on peut sauter des frames
   d'UI ou coalescer des deltas ; on ne perd pas de paquets à cause d'un
   consommateur lent. Le découplage capture/UI doit rendre ça vrai par
   construction.
6. **Deltas atomiques.** Le protocole WebSocket transporte des mutations de
   graphe atomiques (upsert/remove nœud/arête). Le frontend applique, il ne
   recalcule pas. Le schéma WebSocket est un **contrat** : toute modification
   met à jour backend ET frontend dans le même commit.
7. **Le fade émet des suppressions.** Le vieillissement (nœuds/arêtes non revus
   depuis N s) produit des messages `remove_*` explicites, pas un silence.

## 3. Périmètre & éthique (strict)

- Outil **strictement passif** : capture et affichage. **Aucune** injection de
  trames, **aucune** manipulation de table CAM, **aucun** ARP spoofing, **aucun**
  MAC flooding. Ces techniques sont hors périmètre et ne doivent jamais être
  ajoutées, même « en option ».
- La visibilité se règle en amont (port SPAN/miroir ou TAP), pas dans le code.
  Si une fonctionnalité suppose de « forcer » le switch à envoyer plus de
  trafic, elle est refusée : ce n'est pas le rôle de cet outil.

## 4. Stack & versions

Renseigner les **versions résolues exactes** ici après la Phase 0, puis les
figer dans `Cargo.toml` / `package.json`. Les majeures ci-dessous sont un point
de départ **à confirmer**, pas une autorité.

### Rust (backend)
- `pcap` — capture via Npcap sous Windows. _(version : à figer en Phase 0)_
- `etherparse` — décodage Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP / ARP.
- `tokio` (1.x) + `axum` — serveur statique + WebSocket.
- `tokio::sync::broadcast` — diffusion des deltas aux clients WS.
- `serde` + `serde_json` — sérialisation du protocole.
- `tracing` + `tracing-subscriber` — logs structurés.
- `anyhow` (frontières) + `thiserror` (erreurs typées des modules).
- `clap` — CLI (choix d'interface, port, timers).

### Frontend
- **sigma.js v3** + **graphology** + **graphology-layout-forceatlas2**
  (supervisor `FA2Layout` en web worker, layout **continu**).
- Vanilla JS/TS. Pas de framework lourd sans raison — garder les dépendances
  minimales. Bundler léger (esbuild/vite) acceptable.

## 5. Architecture

```
[thread pcap natif] --trames--> parse --> MAJ 2 tables (L2, L3) en mémoire
        |                                          |
        | (channel)                                | tick 200–500 ms : deltas
        v                                          v
   [runtime tokio] <---- broadcast des deltas ----+
        |
   axum: sert static/  +  WebSocket /ws
        |
   navigateur: 2 graphes graphology + 2 sigma + 2 supervisors FA2
```

- Un binaire, un dossier `static/`. `cargo build --release` → lancer l'exe,
  ouvrir `http://localhost:PORT`.
- Table Etherman : clé `(src_mac, dst_mac)` → octets, paquets, EtherType/proto
  dominant, last-seen.
- Table Interman : clé `(src_ip, dst_ip)` v4+v6 → octets, paquets, proto L4 (ou
  applicatif déduit du port) dominant, last-seen.

## 6. Protocole WebSocket (contrat)

Enum serde **tagué** sur `type`. Champ `view` ∈ `{ "ether", "inter" }` route le
message vers le bon graphe. Une mutation = un message.

```json
{ "type": "upsert_node", "view": "ether", "id": "...", "label": "...",
  "bytes": 0, "packets": 0, "proto": "..." }
{ "type": "upsert_edge", "view": "inter", "id": "...", "source": "...",
  "target": "...", "bytes": 0, "packets": 0, "proto": "..." }
{ "type": "remove_node", "view": "ether", "id": "..." }
{ "type": "remove_edge", "view": "inter", "id": "..." }
```

Tout changement de ce schéma touche `model/`, la sérialisation backend et le
client frontend **dans le même commit**.

## 7. Conventions de code

- Rust edition 2021. `cargo fmt` + `cargo clippy` propres avant chaque commit
  (viser `-D warnings`).
- **Pas de `unwrap()`/`expect()`** dans les chemins capture et serveur. Toléré
  au démarrage/parse CLI uniquement, avec message clair.
- Erreurs : `thiserror` pour les types de modules, `anyhow` aux frontières.
- Modules suggérés : `capture/`, `model/` (tables + agrégation), `wsproto/`
  (schéma), `server/`, `resolve/` (OUI + hostnames), `main.rs`.
- Frontend : mapping visuel **fixe et documenté** — taille nœud ∝ trafic cumulé,
  épaisseur arête ∝ octets, couleur ∝ protocole dominant. Légende des couleurs
  obligatoire.

## 8. Tests

- **Mode offline** : pouvoir rejouer un fichier `.pcap` en entrée (capture depuis
  fichier) pour des tests déterministes, sans carte réseau.
- Tests unitaires de parsing et d'agrégation sur trames-échantillons (y compris
  IPv6, ARP, VLAN tagué le cas échéant).
- Un fixture `.pcap` de référence dans `tests/fixtures/`.

## 9. Définition de « terminé » par jalon

1. Liste des interfaces + capture promiscuous + compteur trames/s en console.
2. Parsing + double agrégation L2/L3 + dump texte périodique des top talkers.
3. axum + WebSocket diffusant des deltas ; validé avec un client minimal.
4. Deux panneaux sigma.js + FA2 continu ; deltas appliqués en live.
5. Fade, résolution OUI/hostname, contrôles (pause/filtre/reset/timer), légende,
   packaging + README (install Npcap, build, exécution, choix d'interface).

## 10. Méthode

Procéder jalon par jalon, chacun validé avant le suivant. Expliquer les choix
d'API au fur et à mesure. Consigner les décisions et versions résolues dans
`RESEARCH.md`. Ne pas anticiper les jalons suivants dans le code d'un jalon en
cours.
