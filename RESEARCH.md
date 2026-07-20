# RESEARCH.md — Phase 0 : versions résolues & décisions d'API

Recherche effectuée le **2026-07-20** (crates.io, docs.rs, npm, sources GitHub).
Ces versions sont **figées** ; toute montée de version passe par une mise à jour
de ce fichier.

## Environnement constaté

- Windows 11 Pro for Workstations, hôte x86_64-pc-windows-msvc.
- **Npcap 1.10.4** installé, DLLs dans `C:\Windows\System32\Npcap` **uniquement**
  (mode « WinPcap API-compatible » NON activé → wpcap.dll absent de System32).
- Rust **1.97.1** (rustup, stable-msvc), VS 2022 Community (linker MSVC).
- Node.js absent — et finalement **non requis** (voir Frontend).
- Npcap SDK **1.16** vendorisé dans `third_party/npcap-sdk-1.16/`.

## Backend Rust — versions figées

| Crate | Version | Rôle |
|---|---|---|
| `pcap` | 2.4.0 | capture Npcap (aucune feature ; boucle bloquante sur thread OS) |
| `etherparse` | 0.20.3 | décodage Ethernet/IPv4/IPv6/TCP/UDP/ICMP/**ARP**/VLAN |
| `tokio` | 1.53.0 | runtime (features rt-multi-thread, net, sync, time, signal, macros) |
| `axum` | 0.8.9 | HTTP + WebSocket (feature `ws`) |
| `tower-http` | 0.7.0 | `ServeDir` (feature `fs`) |
| `serde` / `serde_json` | 1.0.229 / 1.0.151 | protocole WS |
| `clap` | 4.6.3 | CLI (derive) |
| `tracing` / `tracing-subscriber` | 0.1.44 / 0.3.23 | logs |
| `thiserror` / `anyhow` | (dernières 2.x / 1.x au lock) | erreurs modules / frontières |
| `windows-sys` | (dernière au lock) | `SetDllDirectoryW` |

## `pcap` 2.4.0 — API et spécificités Windows

- Énumération : `Device::list()` → `Vec<Device>` ; sous Windows `name` est le
  GUID NPF (`\Device\NPF_{...}`), `desc` le nom convivial → **afficher `desc`**
  dans le sélecteur d'interface.
- Ouverture : `Capture::from_device(dev)?.promisc(true).immediate_mode(true)
  .snaplen(65535).timeout(500).open()?` (typestate `Inactive` → `Active`).
  - `immediate_mode(true)` **indispensable** sous Npcap : sans lui le buffering
    kernel (`min_to_copy`) retient les paquets → latence de visualisation.
  - `.timeout(500)` : `next_packet()` rend `Err(Error::TimeoutExpired)`
    périodiquement → **non fatal**, c'est notre point de contrôle du flag
    d'arrêt (`AtomicBool`), car `next_packet()` n'est pas interruptible.
- Mode offline (tests, §8 CLAUDE.md) : `Capture::from_file(path)` → même boucle,
  EOF = `Error::NoMorePackets`.
- Comptage : utiliser `PacketHeader::len` (longueur fil), pas `caplen`.
  Timestamps pcap = `libc::timeval` → horloge monotone locale pour les taux.
- **Link time** : le crate lie dynamiquement `wpcap.lib` → Npcap SDK requis ;
  on passe `third_party/npcap-sdk-1.16/Lib/x64` via `cargo:rustc-link-search`
  dans `build.rs` (pas besoin de toucher la var d'env `LIB` globale).
- **Runtime** : notre Npcap est sans mode compat WinPcap → le loader Windows ne
  trouve pas `wpcap.dll` au démarrage du process. Solution retenue :
  1. `build.rs` : `cargo:rustc-link-arg=/DELAYLOAD:wpcap.dll` + link
     `delayimp.lib` (import résolu au premier appel, pas au lancement) ;
  2. tout début de `main()` : `SetDllDirectoryW("C:\\Windows\\System32\\Npcap")`
     (pattern documenté par le SDK Npcap). Permet aussi un message d'erreur
     propre si Npcap n'est pas installé.
- **Droits** : install Npcap par défaut = capture possible sans élévation ;
  si l'option « Restrict Npcap driver's access to Administrators only » est
  cochée, il faut lancer en admin. Documenté dans le README.
- Alternatives écartées : `pnet` (orienté forge/injection — hors mission d'un
  moniteur passif), `rawsock` (chargement runtime séduisant mais peu maintenu).

## `etherparse` 0.20.3 — extraction

API 0.20 (renommages vs anciennes versions : `NetSlice`, plus `InternetSlice`) :

```rust
let s = SlicedPacket::from_ethernet(data)?; // fallback: LaxSlicedPacket
// L2 : LinkSlice::Ethernet2(e) → e.source(), e.destination(), e.ether_type()
// VLAN 802.1Q : s.link_exts / s.vlan_ids() ; net/transport restent peuplés
// IPv4 : Ipv4Slice::header().source_addr()/.destination_addr()
//        proto L4 = ipv4.payload_ip_number()
// IPv6 : Ipv6Slice::header().source_addr()/.destination_addr()
//        proto réel = ipv6.payload().ip_number  // PAS next_header() (extensions !)
// L4 : TcpSlice/UdpSlice::source_port()/destination_port()
// ARP : NetSlice::Arp(a) → a.sender_hw_addr(), a.sender_protocol_addr(), ...
```

- **ARP est parsé nativement** en 0.20 (`ArpPacketSlice`) → alimente la
  résolution passive IP↔MAC sans parsing manuel (les anciennes versions ne
  donnaient que le payload brut).
- `LaxSlicedPacket::from_ethernet` : parsing partiel des trames tronquées.

## Serveur — décisions

- **axum 0.8.9 WS** : `Message::Text(Utf8Bytes)` (tungstenite re-exporté).
  `Utf8Bytes` = wrapper UTF-8 ref-compté sur `Bytes`, `From<String>`.
- **Diffusion** : sérialiser chaque delta **une seule fois**
  (`serde_json::to_string` → `Utf8Bytes`), puis
  `broadcast::channel::<Utf8Bytes>(4096)` — le clone par récepteur est un
  bump de refcount, `Message::Text(txt)` est zéro-copie.
  - Client lent ⇒ `RecvError::Lagged(n)` → on continue (le flux d'upserts se
    répare au tick suivant). **Limite connue** : un `remove_*` manqué n'est pas
    rejoué — mitigé par la capacité généreuse ; si besoin, keyframe périodique
    (non implémenté pour l'instant).
  - `subscribe()` ne voit que les messages postérieurs → **snapshot complet**
    envoyé à chaque nouvelle connexion WS avant l'abonnement au flux.
- **Pont capture→tokio** : `tokio::sync::mpsc::channel::<PacketMeta>(65536)` ;
  côté capture **`try_send`** + compteur atomique de drops (invariant 5 : la
  capture ne bloque jamais sur un consommateur lent) ; côté tokio
  `recv_many` (batch) + `tokio::time::interval(250 ms)` dans un `select!`.
- **Static** : `ServeDir::new("static")` en `fallback_service` (livrable
  « binaire + static/ » du CLAUDE.md §5). `rust-embed` 8.12 possible au jalon 5
  pour un exe autonome (charge depuis le disque en debug).
- **Protocole** : enum interne serde `#[serde(tag = "type",
  rename_all = "snake_case")]` — supporte les struct variants (pas les tuple
  variants : c'est le seul piège). Champ `view` = champ ordinaire de chaque
  variante.
- **Arrêt** : `axum::serve(...).with_graceful_shutdown(async { let _ =
  tokio::signal::ctrl_c().await; })` ; côté capture, flag + timeout pcap ;
  join du thread après la sortie du runtime.

## Frontend — versions figées

| Lib | Version | Distribution (vendorisée dans `static/vendor/`) |
|---|---|---|
| sigma | 3.0.3 (pas la v4 alpha) | `sigma.min.js` (UMD) → global `Sigma` |
| graphology | 0.26.0 | `graphology.umd.min.js` → global `graphology` |
| graphology-layout-forceatlas2 | 0.10.1 | via `graphology-library` 0.8.0 `graphology-library.min.js` → `graphologyLibrary.FA2Layout`, `graphologyLibrary.layoutForceAtlas2.inferSettings` |

- **Aucun bundler / Node requis** : les trois UMD sont autonomes ; le worker du
  supervisor FA2 est instancié depuis un **Blob inline** (fonction stringifiée)
  → pas de fichier worker séparé, pas de CORS, fonctionne servi par axum.
  (`graphology-layout-forceatlas2` seul ne publie pas d'UMD, d'où le bundle
  `graphology-library`, qui épingle bien la 0.10.1 courante.)
- **sigma v3 est réactif** : il s'abonne aux événements graphology
  (`nodeAdded`, `edgeAdded`, `*AttributesUpdated`, `nodeDropped`, …) et se
  rafraîchit au frame suivant — aucun `refresh()` manuel après mutation.
- Upserts : `graph.mergeNode(id, attrs)` → `[key, wasAdded]` ;
  `graph.mergeEdgeWithKey(id, src, tgt, attrs)` (auto-crée les extrémités
  manquantes). Suppressions : `dropNode` (retire les arêtes incidentes),
  `dropEdge`.
- **FA2Layout (worker)** : `new FA2Layout(graph, {settings})`, `.start()`,
  `.stop()`, `.kill()`, `.isRunning()` ; settings via
  `layoutForceAtlas2.inferSettings(graph)`.
  - **Mutations à chaud supportées** : le supervisor écoute les événements de
    topologie et respawne le worker (débouncé), positions conservées.
  - Ne pas démarrer sur graphe vide (refusé) → démarrage paresseux au premier
    delta.
  - `.kill()` est définitif → « reset » = recréer un FA2Layout ; « pause » =
    `.stop()`.
  - **x/y obligatoires sur tout nouveau nœud** (sinon NaN se propage dans tout
    le layout) : poser des positions aléatoires uniquement quand
    `wasAdded === true`.

## OUI (MAC → fabricant)

- Décision : **vendoriser le fichier Wireshark `manuf`**
  (<https://www.wireshark.org/download/automated/data/manuf> — build automatisé
  canonique ; le fichier a quitté le dépôt git Wireshark en 2023), `include_str!`,
  parsé au démarrage en trois maps (/24, /28 MA-M, /36 MA-S), lookup
  /36 → /28 → /24 en O(1). Coût ≈ 3 Mo dans le binaire ; données rafraîchies
  par simple re-téléchargement.
- Alternatives écartées : crate `oui` 0.8.1 (2021, mort), `mac_oui` 0.4.11
  (données figées à la publication, ~2024).

## Compléments (jalon 5)

- **Reverse-DNS (PTR)** : crate `dns-lookup` 2.x (`lookup_addr` =
  `getnameinfo`, résolveur système Windows) sur le pool bloquant tokio,
  concurrence bornée (8), plutôt que `hickory-resolver` (API async complète
  mais dépendance lourde pour un simple PTR best-effort). Détection du
  négatif : `getnameinfo` renvoie la forme numérique quand il n'y a pas de
  PTR. Cache de session : une tentative par IP (succès et échecs), noms
  conservés dans `Tables::l3_labels` (survivent au fade).
- **Contrat WS étendu** (backend + frontend même commit) :
  `{"type":"set_fade","seconds":N}` (client→serveur) et
  `{"type":"config","fade_secs":N}` (serveur→client, à la connexion et à
  chaque changement — le serveur fait foi, tous les onglets se synchronisent).
- **OUI embarqué** : `manuf` Wireshark du 2026-07-20 (3,1 Mo), parse paresseux
  (`OnceLock`) en trois maps /24 (MA-L), /28 (MA-M), /36 (MA-S), lookup
  /36→/28→/24. Les MAC localement administrées (bit U/L) sont exclues par
  construction. Étiquette Etherman : `Fabricant xx:yy:zz`.
- **Piège sigma v3 rencontré** : un nœud DOIT avoir `x`/`y` dans les attributs
  passés à `mergeNode` — les poser après coup via `setNodeAttribute` lève
  `Sigma: could not find a valid position`. (Consigné aussi dans app.js.)

## Décisions transverses

- Une seule capture, deux projections (invariant 1) : le thread pcap produit un
  `PacketMeta` unique consommé par l'agrégateur qui maintient les DEUX tables.
- Clés de conversation : paire **ordonnée canoniquement** (min, max) pour
  agréger les deux sens dans une seule arête.
- UI en **anglais** (décision utilisateur). Port par défaut **8080**,
  fade par défaut **60 s** (CLI `--fade`).
