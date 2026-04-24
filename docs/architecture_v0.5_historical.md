# WardSOAR — Architecture v0.5

> Document de référence décrivant l'architecture cible de WardSOAR.
> Rédigé le 2026-04-19 après une session de revue architecturale.
> Remplace progressivement l'état actuel v0.4.4.

---

## 1. Contexte et vision

### 1.1 Rappel du projet

WardSOAR est un SOAR (Security Orchestration, Automation & Response)
qui orchestre **Suricata + pfSense + Claude API** pour bloquer automatiquement
des IPs malveillantes, avec une UI Windows Fluent Design.

Topologie :

```
[Netgate 4200 + pfSense + Suricata]  ──SSH──▶  [PC Windows + WardSOAR]
            │                                          │
            │  EVE JSON stream                         │
            │  Règles de blocage pfctl                 │
            └──────────────────────────────────────────┘
```

### 1.2 Pourquoi v0.5

La v0.4.4 a révélé des limitations structurelles après observation de 3 semaines
de trafic réel + simulation :

- **Sonnet** (LLM tri) n'est jamais sollicité — Filter + Deduplicator absorbent 100% du trafic
- **VirusTotal** est surexploité (hash de milliers de fichiers par alerte)
- **VirusTotal** fuite des données chez Google (problème privacy)
- Pas de **rollback** utilisateur en cas de faux positif
- Pas de **forensic profond** après un block
- Pas d'**export** pour partage avec expert/autorité

### 1.3 Principes directeurs

1. **Privacy first** — pas de fuite de données vers tiers sans nécessité
2. **Fail-safe** — une erreur technique ne doit jamais bloquer du trafic légitime
3. **Reversibilité** — toute action doit pouvoir être annulée
4. **Preuves intègres** — capture avant analyse, chaîne de custody stricte
5. **Simplicité utilisateur** — pas de jargon, pas de choix techniques exposés
6. **Transparence** — tout verdict LLM accompagné d'un reasoning auditable

---

## 2. Pipeline principal

### 2.1 Diagramme d'ensemble

```
┌─────────────────────────────────────────────────────────────┐
│                    ALERTE SURICATA                          │
│              (via SSH stream depuis pfSense)                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  [1] FILTER (Python)                                        │
│      Suppression des faux positifs connus (SIDs/pairs)      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  [2] DEDUPLICATOR (Python)                                  │
│      Groupage des rafales d'alertes identiques              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  [3] DECISION CACHE LOOKUP (Python)                         │
│      Même signature+IP récemment jugée ? → réutilise verdict│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  [4] PRESCORER (Python, mode ACTIVE, seuil 40)              │
│      Scoring pondéré : signature + severity + reputation    │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
          score < 40                  score ≥ 40
              │                           │
              ▼                           ▼
         ┌─────────┐     ┌───────────────────────────────────┐
         │  DROP   │     │  [5] ENRICHISSEMENT (parallèle)   │
         │  + log  │     │                                   │
         │  FIN    │     │   ├─ Collector (network)          │
         └─────────┘     │   ├─ Reputation (AbuseIPDB, OTX)  │
                         │   └─ Forensics :                  │
                         │        find_suspicious_files      │
                         │        (filtres stricts) :        │
                         │        • < 5 min de l'alerte      │
                         │        • 1 KB–32 MB               │
                         │        • extensions exécutables   │
                         │        • exclusions apps legit    │
                         └───────────────────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────┐
                  │  [6] CASCADE PRIVACY-FIRST (par fichier) │
                  │                                          │
                  │     Windows Defender (local)             │
                  │       detection → MALICIOUS (stop)       │
                  │       clean →                            │
                  │                                          │
                  │     YARA rules (local)                   │
                  │       match → SUSPICIOUS (stop)          │
                  │       no match →                         │
                  │                                          │
                  │     Cache VT local (SQLite, TTL 7j)      │
                  │       hit → verdict caché                │
                  │       miss →                             │
                  │                                          │
                  │     VirusTotal API (rate-limited 4/min)  │
                  └──────────────────────────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────┐
                  │  [7] OPUS — décision finale              │
                  │                                          │
                  │     Input : alerte + tout l'enrichi      │
                  │     Output : verdict + reasoning         │
                  │              (auditable pour forensic)   │
                  │                                          │
                  │     Timeout 30s → fail-safe INCONCLUSIVE │
                  └──────────────────────────────────────────┘
                                         │
                                         ▼
                  ┌──────────────────────────────────────────┐
                  │  [8] RESPONDER (Python, garde-fous)      │
                  │                                          │
                  │     Checks : whitelist, rate limit,      │
                  │              business hours, cooldown    │
                  └──────────────────────────────────────────┘
                                         │
                       ┌─────────────────┴─────────────────┐
                       │                                   │
              MALICIOUS + conf > 0.8                  Autre cas
                 + non whitelisté                         │
                 + pas rate-limited                       ▼
                       │                            ┌──────────┐
                       ▼                            │  Log +   │
              ┌────────────────┐                    │  notif   │
              │  BLOCK pfSense │                    │  no block│
              │  (via SSH)     │                    └──────────┘
              └────────┬───────┘
                       │
                       ▼
          ┌─────────────────────────────────────────────┐
          │  PHASE FORENSIC (voir section 3)            │
          │   [8.1] Quick acquisition (< 1 min)         │
          │   [8.2] Tray notification                   │
          │   [8.3] Deep acquisition (2-5 min)          │
          │   [8.4] Deep analysis (3-10 min)            │
          └─────────────────────────────────────────────┘
                       │
                       ▼
              ┌─────────────────────────────────────┐
              │  [9] LOGGER + CACHE STORE           │
              │                                     │
              │   • decisions.jsonl                 │
              │   • alerts_history.jsonl            │
              │   • DecisionCache (pour étape [3])  │
              └─────────────────────────────────────┘
```

### 2.2 Justification des choix majeurs

#### Retrait de Sonnet (Analyzer actuel)

**Observation empirique** (49 alertes sur 3 semaines + simulation de 15 tests) :
zéro alerte n'a atteint l'Analyzer. Filter + Deduplicator absorbent 100% du trafic.

**Conséquence** : Sonnet est un coût sans valeur sur le profil d'usage SOHO.

**Décision** : Opus devient le LLM unique. Un seul appel par alerte qui l'atteint.

#### Retrait du Confirmer

Sans Sonnet en amont, le Confirmer (qui était un "counter-argument Opus")
n'a plus de sens. Supprimé complètement.

#### Cascade privacy-first avant VirusTotal

**Problème identifié** : `find_suspicious_files` retourne tout le TEMP + APPDATA
sans filtre (potentiellement 1000-8000 fichiers par alerte), et chaque fichier
est hashé puis envoyé à VT. Double problème :

- Saturation du quota VT (500/jour sauté en 1-2 alertes)
- Fuite massive de hashs chez Google (fingerprinting de tous les fichiers du PC)

**Solution** : cascade locale avant VT

```
Défender (local) → YARA (local) → Cache VT (SQLite) → VT API (en dernier recours)
```

Gain : VT n'est sollicité que pour les fichiers **incertains après analyse locale**.
Fuite résiduelle minime, couverture maintenue.

#### PreScorer en mode ACTIVE

En mode `learning` (actuel), le PreScorer calcule les scores mais ne filtre rien.
Passer en `active` avec seuil 40 :

- Score < 40 → DROP (pas d'enrichissement, pas d'Opus, pas de VT)
- Score ≥ 40 → pipeline complet d'analyse

Seuil calibré à démarrer à 40 (ajustable après data réelle).

---

## 3. Phase forensic

### 3.1 Principe fondamental

**Capture d'abord, analyse ensuite.**

Conformément au principe forensique (RFC 3227, NIST 800-86), les preuves
volatiles (process, mémoire, connexions) doivent être figées **avant toute
analyse**, sinon elles se transforment ou disparaissent.

### 3.2 Les 3 phases post-block

#### Phase [8.1] — QUICK ACQUISITION (< 1 min, priorité MAX)

**Objectif** : figer les preuves volatiles avant qu'elles disparaissent.

**Pas d'analyse. Pas d'appel LLM. Pure capture.**

Ordre de volatilité strict :

1. **Priorité 1 — disparaît en secondes** :
   - Process list instantanée (snapshot atomique)
   - Memory dumps des PIDs suspects (minidump)
   - Connexions actives + handles
   - DLLs chargées
   - Thread states

2. **Priorité 2 — disparaît en minutes** :
   - Clipboard
   - Session tokens en mémoire
   - Temp files (copies binaires + hash)
   - Network state (TIME_WAIT, sockets)

3. **Priorité 3 — stable quelques heures** :
   - DNS cache, ARP cache, routing table

**Storage** : `C:\ProgramData\WardSOAR\evidence\{alert_id}\volatile\`
- Chaque artefact hashé SHA-256 immédiatement
- Manifest + timestamp UTC
- Read-only immédiatement après écriture

#### Phase [8.2] — TRAY NOTIFICATION (immédiate)

Notification minimaliste dans le system tray :

```
┌──────────────────────────────────────────┐
│ 🛡️ Ward a bloqué 52.85.47.4              │
│                                           │
│ ✓ Preuves conservées (27 artefacts)       │
│ ⏳ Analyse approfondie en cours…          │
│                                           │
│ [Rollback]  [Détails]                     │
└──────────────────────────────────────────┘
```

Pas de pseudo-résumé bâclé. Message honnête : "bloqué, preuves sauvées, analyse à venir".

#### Phase [8.3] — DEEP ACQUISITION (2-5 min, priorité normale)

Artefacts plus durables mais longs à collecter :

- Event Logs (Security, Sysmon, PowerShell)
- Registry hives via VSS (Volume Shadow Copy)
- Prefetch, Amcache, ShimCache
- MFT entries (fichiers récents)
- LNK files, Jump Lists
- Browser artifacts (24h)
- Scheduled Tasks, Services, WMI persistence

**Storage** : `C:\ProgramData\WardSOAR\evidence\{alert_id}\durable\`

#### Phase [8.4] — DEEP ANALYSIS (3-10 min, priorité basse, async)

**Travaille sur les preuves figées** (idempotent, rejouable plus tard).

- Super timeline (Plaso-style)
- IOC extraction (IPs, domains, hashes, URLs)
- MITRE ATT&CK mapping
- YARA scan sur tous les artefacts
- Corrélation cross-sources
- **1 appel Opus** avec contexte massif → rapport d'incident complet

**Output** : `deep_report.zip` avec rapport PDF + preuves structurées.

### 3.3 Budget LLM

| Phase | Opus ? | Tokens approx |
|-------|:-----:|:-------------:|
| Pipeline [7] | ✅ | 2K in / 500 out |
| Quick [8.1] | ❌ | — |
| Deep [8.4] | ✅ | 30-100K in / 3K out |
| **Total par incident avec block** | 2 appels | ~35-100K in / 3.5K out |

Coût estimé : ~0.50-1.50 € par incident avec block.

---

## 4. Rollback 1-clic

### 4.1 Principe

Tout block doit pouvoir être annulé rapidement par l'utilisateur en cas de
faux positif. La reversibilité est **la condition** pour accepter l'automatisation
agressive du blocage.

### 4.2 Workflow

```
User clique [Rollback] dans la tray notification
    ↓
1. Retrait de la règle pfSense via SSH
2. Marque verdict comme "user_rollback" dans decisions.jsonl
3. Ajoute IP à trusted_temp (30 min) — évite re-block immédiat
4. Feedback PreScorer : -20 points sur cette signature
5. Propose à l'utilisateur : "Ajouter SID à known_false_positives.yaml ?"
6. Continue le deep forensic (tagué "user_rollback")
7. Notification : "Block retiré. IP en quarantaine 30 min."
```

### 4.3 Règles

| Paramètre | Valeur |
|-----------|--------|
| Fenêtre de rollback | 24h |
| Après rollback, IP en trusted_temp | 30 min |
| Feedback PreScorer | -20 points (auto) |
| Proposition FP-whitelist | Explicite (user décide) |
| Deep analysis post-rollback | Continue, tag dans rapport |

---

## 5. Export forensic

### 5.1 Principe

L'utilisateur doit pouvoir partager un dossier d'incident avec **1 seul clic**,
sans choix techniques, vers un destinataire qui **peut** être non-technique.

### 5.2 Format — UN seul ZIP

```
WardSOAR_Incident_2026-04-19_52.85.47.4.zip
│
├── 📄 RAPPORT.pdf              ← Pour utilisateur non-technique
│                                   (résumé + timeline + conclusions)
│
├── 📁 preuves/                 ← Pour expert
│   ├── processus.json
│   ├── connexions.json
│   ├── memoire/*.dmp           (Volatility-compatible)
│   ├── journaux/*.evtx         (Windows Event Viewer natif)
│   ├── registre/*.reg          (RegEdit natif)
│   ├── timeline.csv            (Excel ou Timesketch)
│   ├── iocs.json               (STIX 2.1 — standard mondial)
│   └── fichiers_suspects/*.bin
│
├── 📄 MANIFEST.txt             ← Liste + signatures SHA-256
└── 📄 README.txt               ← "Que faire avec ce dossier"
```

### 5.3 UX — bouton unique

```
┌─────────────────────────────────────────────┐
│  🛡️ Incident du 19/04/2026 — 52.85.47.4     │
├─────────────────────────────────────────────┤
│                                              │
│  [ Voir le rapport ]                         │
│                                              │
│  [ 📦 Partager ce dossier ]                  │
│                                              │
│  ▸ Options avancées                          │
│                                              │
└─────────────────────────────────────────────┘
```

Au clic sur "Partager" :

```
┌──────────────────────────────────────────────┐
│  Où voulez-vous enregistrer le dossier ?     │
│                                               │
│   💾  Sur mon ordinateur                     │
│   🔑  Sur ma clé USB (E:)                    │
│                                               │
│   ☑ Protéger avec un mot de passe            │
│     (recommandé si vous l'envoyez)           │
│                                               │
│              [ Enregistrer ]                  │
└──────────────────────────────────────────────┘
```

### 5.4 Option avancée — E01

Sous "Options avancées", bouton optionnel pour créer une image disque E01 :

- Implémenté via **lancement de FTK Imager externe** (Exterro, gratuit)
- Si FTK Imager absent : bouton "Télécharger FTK Imager"
- Usage réservé aux cas exceptionnels (image complète du disque, 6-12h)
- **Pas de bundling** dans le MSI (licence propriétaire d'Exterro)

### 5.5 Formats utilisés — choix et justifications

| Format | Raison |
|--------|--------|
| **ZIP** conteneur | Ouvert nativement par Windows/Mac/Linux |
| **PDF** pour rapport | Lisible partout, non modifiable accidentellement |
| **.evtx** pour logs | Format Microsoft natif, lu par Event Viewer |
| **.reg** pour registre | Format Microsoft natif |
| **.dmp** minidump | Volatility 3 compatible |
| **CSV** pour timeline | Ouvrable dans Excel |
| **STIX 2.1 JSON** pour IOCs | Standard mondial (MISP, TAXII, SOC) |

---

## 6. Anti-ransomware

### 6.1 Stratégie en 4 couches

#### Couche 1 — Protection système (obligatoire)

- Stockage : `C:\ProgramData\WardSOAR\evidence\`
- ACL : `SYSTEM:Full`, `Administrators:Read`, `Users:None`
- Attribut read-only après écriture
- Windows Controlled Folder Access (si disponible) ajouté au whitelist

#### Couche 2 — Sync externe asynchrone (configurable)

- Détection USB clé dédiée (VolumeLabel = `WARDSOAR-EVIDENCE`)
  → Copy auto dès branchement
- Sync NAS via SSH/SFTP (si configuré)
- Sync cloud (option, chiffré)

Le PC devient **stateless** pour les preuves critiques.

#### Couche 3 — Preuve d'existence externalisée

- Envoi automatique du **hash SHA-256 du manifest** par email à l'utilisateur
  (pièce jointe 64 bytes)
- Option : timestamp RFC 3161 (TSA tiers)
- Permet de prouver qu'un rapport existait **avant** une compromission

#### Couche 4 — Détection de tamper

- Watcher inotify sur `evidence/` → alerte tray si modification
- Hash re-check quotidien → détecte corruption
- Logs d'intégrité append-only

### 6.2 Mode "emergency lockdown"

Déclenchable manuellement ou auto-détecté (ex: plusieurs blocks en cascade) :

- Evidence switch en read-only absolu
- Clé DPAPI remplacée par passphrase user-fournie
- Sync externe forcée immédiatement
- WardSOAR passe en mode observe-only

---

## 7. Chiffrement et stockage

### 7.1 Chiffrement local

- **DPAPI Windows** (Data Protection API) par défaut
- Transparent pour l'utilisateur
- Clé liée au compte utilisateur Windows
- Survie au vol de disque (clé hors disque)

### 7.2 Chiffrement pour export

- Export ZIP optionnellement chiffré par **passphrase utilisateur**
- AES-256
- Permet le partage sécurisé (email, USB perdue, etc.)

### 7.3 Stockage des preuves

- **Emplacement** : `C:\ProgramData\WardSOAR\evidence\`
- **Structure** : `evidence/{alert_id}/{volatile|durable}/...`
- **Permissions** : SYSTEM:Full, Administrators:Read, Users:None
- **Rétention** :
  - 30 jours si alerte sans block
  - 90 jours si block effectué
  - Purge auto après, sauf marqué "archive" par l'utilisateur

---

## 8. Modules — ajouts, modifications, suppressions

### 8.1 Modules à supprimer

| Module | LOC supprimés | Raison |
|--------|:-----:|--------|
| `src/analyzer.py` (Sonnet) | ~211 | Remplacé par nouvel analyzer Opus |
| `src/confirmer.py` | ~235 | Plus de double-avis nécessaire |
| `tests/test_analyzer.py` | ~300 | Remplacé |
| `tests/test_confirmer.py` | ~250 | Supprimé |

### 8.2 Modules à modifier

| Module | Changements |
|--------|-------------|
| `src/forensics.py` | Fix `find_suspicious_files` : filtres fraîcheur/taille/extension/exclusions |
| `src/virustotal.py` | Intégrer cache SQLite + rate limit strict |
| `src/main.py` | Réordonner pipeline : cascade locale avant VT, VT avant Opus uniquement |
| `src/prescorer.py` | Support mode `active` + feedback loop rollback |
| `src/rule_manager.py` | Ajouter méthode `rollback_block()` |
| `src/notifier.py` | Ajouter CTAs "Rollback" + "Deep report ready" |
| `src/decision_cache.py` | Support trusted_temp IPs (TTL 30 min) |
| `src/forensic_report.py` | Refondre en acquisition ciblée + export ZIP |
| `config/config.yaml` | PreScorer `mode: active`, seuil 40, VT cascade |

### 8.3 Modules à créer

#### Analyseur unique (Opus)

```
src/analyzer_opus.py        # Remplace analyzer.py + confirmer.py
```

#### Cascade locale privacy-first

```
src/local_av/
├── defender.py             # Wrap MpCmdRun.exe
├── yara_scanner.py         # yara-python + rules locales
└── hash_cache.py           # Cache SQLite des verdicts
```

#### Module forensic v2

```
src/forensic/
├── acquisition/
│   ├── volatile.py         # Quick phase < 1 min
│   ├── durable.py          # Deep acquisition 2-5 min
│   ├── registry.py
│   ├── event_logs.py
│   ├── memory.py           # Process dumps via minidump
│   └── orchestrator.py
│
├── analysis/
│   ├── timeline.py         # Super timeline Plaso-compatible
│   ├── ioc_extractor.py    # STIX 2.1
│   ├── attack_mapper.py    # MITRE ATT&CK
│   ├── correlator.py
│   └── yara_runner.py
│
├── storage/
│   ├── encryption.py       # DPAPI wrapper
│   ├── acl_protection.py   # Windows ACLs
│   ├── integrity_monitor.py
│   └── anti_ransomware.py
│
├── chain_of_custody/
│   ├── hasher.py
│   ├── manifest.py
│   ├── audit_log.py
│   └── receipt.py
│
├── export/
│   ├── bundler.py          # ZIP builder
│   ├── pdf_builder.py      # RAPPORT.pdf
│   ├── manifest.py
│   ├── readme_writer.py    # README multilingue
│   ├── encryption.py       # Passphrase AES-256
│   └── e01_launcher.py     # Lancement FTK Imager externe
│
├── sync/
│   ├── usb_watcher.py
│   ├── nas_sync.py
│   └── hash_external.py    # Email hash manifest
│
├── reporting/
│   ├── executive.py
│   ├── technical.py
│   └── timeline_viz.py
│
└── orchestrator.py         # Chef d'orchestre global
```

#### Rollback

```
src/rollback/
├── rollback.py             # Orchestrateur
└── feedback_loop.py        # Feedback PreScorer
```

### 8.4 Impact quantitatif

| | v0.4.4 | v0.5 cible |
|---|:-----:|:----------:|
| Total LOC source | 9714 | ~15000 |
| Modules | 27 | ~50 |
| Fichiers test | 27 | ~50 |
| Dépendances nouvelles | — | yara-python, python-evtx, pyzstd, reportlab, LnkParse3 |

---

## 9. Dépendances nouvelles

### 9.1 Sécurité & forensic

- **yara-python** (≥ 4.5) — YARA scanner
- **python-evtx** — lecture fichiers .evtx natifs
- **Registry** (python-registry) — parsing hives Windows
- **LnkParse3** — parsing LNK files
- **windowsprefetch** — parsing .pf files

### 9.2 Mémoire

- **minidump** — création process dumps via Windows API
- (optionnel v2) **pyewf** + libewf pour création E01 native

### 9.3 Reporting & export

- **reportlab** (PDF generation) ou **weasyprint**
- **pyzstd** ou **zstandard** (compression moderne)

### 9.4 Sécurité

- **bandit** (déjà ajouté)
- **pip-audit** (déjà ajouté)

---

## 10. Phasage d'implémentation

### Phase 1 — Urgent (2-3 jours)

**Objectif** : stopper la fuite VT et activer le PreScorer.

- Fix `find_suspicious_files` (filtres stricts)
- Passer PreScorer en mode `active`, seuil 40
- Ajouter cache VT basique (SQLite)
- Tests unitaires

### Phase 2 — Simplification (2-3 jours)

**Objectif** : retirer Sonnet, garder Opus.

- Créer `src/analyzer_opus.py`
- Supprimer `src/analyzer.py`, `src/confirmer.py` + tests
- Migrer les appels dans `main.py`
- Ajuster config.yaml
- Tests

### Phase 3 — Privacy cascade (4-5 jours)

**Objectif** : minimiser les appels VT.

- Module `src/local_av/` (Defender, YARA, hash_cache)
- Intégration cascade dans pipeline
- Rate limit strict VT
- Tests

### Phase 4 — Rollback 1-clic (3-4 jours)

**Objectif** : reversibilité utilisateur.

- Module `src/rollback/`
- UI : bouton rollback dans tray
- Feedback PreScorer
- Proposition FP-whitelist
- Tests

### Phase 5 — Forensic quick (7-10 jours)

**Objectif** : capture fiable des preuves volatiles.

- Module `src/forensic/acquisition/volatile.py`
- Storage chiffré (DPAPI) + ACL
- Manifest + chain of custody
- UI notification après block
- Tests

### Phase 6 — Deep analysis (5-7 jours)

**Objectif** : rapport d'incident complet.

- Module `src/forensic/analysis/` (timeline, IOC, ATT&CK)
- Deep acquisition (durable)
- Appel Opus deep
- Export ZIP + PDF
- Tests

### Phase 7 — Anti-ransomware (3-5 jours)

**Objectif** : résilience face à attaque active.

- Sync USB auto
- Sync NAS (optionnel)
- Hash externalisé par email
- Tamper detection
- Mode emergency lockdown
- Tests

### Phase 8 — Export E01 (1 jour)

**Objectif** : extension pour cas exceptionnels.

- Launcher FTK Imager externe
- Détection install / bouton download
- UI intégrée dans "Options avancées"

### Total estimé

**~30-40 jours de développement**.

---

## 11. Métriques cibles

### 11.1 Pipeline

| Métrique | v0.4.4 | v0.5 cible |
|----------|:-----:|:----------:|
| Appels Opus par alerte (cas normal) | 0-2 | 0-1 |
| Appels Opus par incident avec block | 0-2 | 2 |
| Queries VT par alerte | 0 à 8000+ | 0 à 3 |
| Fichiers hashés par alerte | Jusqu'à milliers | 0 à 10 |
| Fuite hash vers Google | Massive | Résiduelle |
| Latence pipeline (alerte→block) | Variable | < 5s |

### 11.2 Forensic

| Métrique | Cible |
|----------|:-----:|
| Durée quick acquisition | < 1 min |
| Durée deep analysis | < 10 min |
| Taille ZIP export typique | 50-500 MB |
| Rétention preuves (block) | 90 jours |
| Conformité chain of custody | NIST 800-86, RFC 3227 |

### 11.3 Coûts

| | v0.4.4 estimé | v0.5 estimé |
|---|:-------------:|:-----------:|
| Coût LLM / mois | Variable (dépend Sonnet) | ~5-30 € (Opus ciblé) |
| Coût VT | Free tier saturé | Free tier largement suffisant |

---

## 12. Risques et mitigations

| Risque | Mitigation |
|--------|-----------|
| Opus API down pendant pipeline | Fail-safe INCONCLUSIVE, pas de block |
| Deep analysis crash au milieu | Tag "deep_incomplete", preuves conservées, re-run manuel possible |
| Saturation disque `evidence/` | Rotation automatique + alerte tray |
| Fichier evidence volé (exfil) | DPAPI limite la portée (clé liée compte Windows) |
| Ransomware compromet WardSOAR | Couches anti-ransomware (ACL, sync USB, hash externe) |
| User décide de rollback trop vite | Deep analysis continue, rapport reste accessible |

---

## 13. Standards et conformité

### 13.1 Forensic

- **NIST SP 800-86** — Guide to Integrating Forensic Techniques into Incident Response
- **RFC 3227** — Guidelines for Evidence Collection and Archiving
- **ISO/IEC 27037** — Guidelines for identification, collection, acquisition and preservation of digital evidence

### 13.2 Sécurité

- **bandit** — static security analysis (0 findings MEDIUM+)
- **pip-audit** — dependency CVE check (0 CVE)
- Hook build.ps1 — fail-fast sur régression

### 13.3 Qualité

- **black** (line-length 100)
- **ruff**
- **mypy --strict**
- Couverture test ≥ 85%

---

## 14. Glossaire

| Terme | Définition |
|-------|-----------|
| **SOAR** | Security Orchestration, Automation & Response |
| **IDS/IPS** | Intrusion Detection/Prevention System |
| **IOC** | Indicator of Compromise |
| **STIX 2.1** | Structured Threat Information eXpression (format IOCs) |
| **ATT&CK** | MITRE framework de tactiques/techniques adversaires |
| **DPAPI** | Windows Data Protection API |
| **VSS** | Volume Shadow Copy Service |
| **MFT** | Master File Table (NTFS) |
| **evtx** | Event Log format Windows |
| **E01** | EnCase Expert Witness Format (image forensique) |
| **Plaso** | Outil de super-timeline forensic |
| **YARA** | Pattern matching pour malware detection |

---

## 15. Historique des décisions

| Date | Décision | Raison |
|------|----------|--------|
| 2026-04-19 | Retrait Sonnet | 0 appels observés sur 49 alertes |
| 2026-04-19 | Retrait Confirmer | Sans Sonnet, plus de rôle |
| 2026-04-19 | Cascade locale avant VT | Privacy + économie quota |
| 2026-04-19 | Rollback 1-clic | Reversibilité = condition du blocage auto |
| 2026-04-19 | Deep analysis systématique | Chaque block mérite une enquête complète |
| 2026-04-19 | Quick = pure acquisition | Principe forensique capture-first |
| 2026-04-19 | Export ZIP + PDF simple | UX non-technique |
| 2026-04-19 | E01 via FTK externe | Simplicité + outil standard |

---

*Document vivant — à maintenir au fil des décisions architecturales futures.*
