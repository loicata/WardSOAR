# WardSOAR v0.5.0 — Rapport de session de nuit

**Session :** 19 avril 2026, ~20h00 → ~23h30 (Paris)
**Objectif :** implémenter Phases 5 + 6, builder le MSI, laisser l'app tourner.

---

## Ce qui a été fait ce soir

### Phase 5 — Forensic quick acquisition (post-block)

Package `src/forensic/` (6 modules) qui démarre automatiquement après
chaque block pfSense réussi et capture l'état volatile du système.

| Module | Rôle |
|--------|------|
| `storage.py` | Écriture dans `evidence/{alert_id}/volatile/` avec ACL Windows + attribut read-only |
| `encryption.py` | Wrapping DPAPI (`win32crypt.CryptProtectData`), scope `user` ou `machine` |
| `manifest.py` | JSON `MANIFEST.json` avec SHA-256 de chaque artefact + vérif d'intégrité |
| `memory.py` | `MiniDumpWriteDump` via ctypes — dumps mémoire des PIDs suspects |
| `acquisition.py` | Capture processes / net / DNS / ARP / routing / DLLs loaded |
| `orchestrator.py` | Chaîne le tout, callable via `QuickAcquisitionManager.quick_acquire()` |

**Intégré dans `src/main.py`** : `_schedule_quick_acquisition` fire-and-forget
après chaque block effectif (non-bloquant, priorité asyncio).

### Phase 6 — Deep forensic analysis + export

Package `src/forensic/` étendu (5 modules supplémentaires) qui, après la
Phase 5, produit le rapport d'incident complet.

| Module | Rôle |
|--------|------|
| `ioc_extractor.py` | Observables STIX 2.1 + CSV depuis alerte/forensic/VT |
| `timeline.py` | Super timeline Plaso-compatible (CSV + JSON) |
| `attack_mapper.py` | 14 règles curatées → IDs MITRE ATT&CK |
| `report_pdf.py` | RAPPORT.pdf via reportlab (markdown → PDF) |
| `export.py` | Bundle ZIP `WardSOAR_Incident_<date>_<ip>.zip` |
| `deep_orchestrator.py` | Chaîne Opus deep_analyze + les 4 producers + export |

`ThreatAnalyzer` étendu avec `deep_analyze()` : freeform markdown pour le
rapport, prompt qui embed timeline + IOCs + ATT&CK pour raisonnement
contextuel.

### Logging overnight

`src/logger.py` ajoute :
- **`trace_debug.log`** (25 MB x 5 rotation) : DEBUG+ toujours écrit,
  indépendamment de `level` configuré.
- **Banner de boot** visible dans les logs — confirme les settings actifs
  (prescorer mode, analyzer model, encryption scope, dry_run status…).

### Sécurité + qualité

- **bandit** : 0 findings (LOW/MED/HIGH)
- **pip-audit** : 0 CVE
- **black** : 94 files OK
- **ruff** : All checks passed
- **mypy --strict** : 0 issues in 59 source files
- **pytest** : **565 tests verts** (+41 nouveaux sur les Phases 5/6)

### Build MSI

Version bumpée à **0.5.0** dans :
- `src/__init__.py`
- `installer/ward.wxs`

`installer/ward.spec` mis à jour pour inclure :
- Nouveaux modules Python (local_av/, forensic/, rollback, trusted_temp, vt_cache, etc.)
- Nouvelles deps runtime (yara, reportlab, win32crypt)
- `config/yara_rules/` dans les datas PyInstaller

---

## Comment consulter les logs demain matin

### Emplacement
Toutes les traces vont dans `%APPDATA%/WardSOAR/logs/` (frozen app) ou
`data/logs/` en dev :

| Fichier | Contenu | Rotation |
|---------|---------|----------|
| `ward_soar.log` | Log principal JSON (INFO+) | 10 MB x 5 |
| `trace_debug.log` | **DEBUG+ textual, overnight** | 25 MB x 5 |
| `decisions.jsonl` | Decision records structurés | append-only |
| `alerts_history.jsonl` | Historique des alertes UI | append-only |
| `rollback_audit.jsonl` | Audit des rollbacks utilisateur | append-only |

### Commandes utiles

```powershell
# Dernière fenêtre de 10 min
Get-Content "$env:APPDATA\WardSOAR\logs\trace_debug.log" -Tail 200

# Tous les blocks de la nuit
Get-Content "$env:APPDATA\WardSOAR\logs\ward_soar.log" | Select-String '"BLOCK"'

# Deep analyses terminées
Get-Content "$env:APPDATA\WardSOAR\logs\trace_debug.log" | Select-String 'deep analysis done'
```

### Where to look for each feature

| Feature | Trace | Comment |
|---------|-------|---------|
| Boot config | `ward_soar.log` au démarrage | Cherche "Pipeline initialised" |
| Filter/dedup | `trace_debug.log` | Tag `ward_soar.filter` ou `ward_soar.deduplicator` |
| PreScorer | `trace_debug.log` | "PreScore: SID %d from %s" |
| Cascade Defender/YARA | `trace_debug.log` | `ward_soar.defender`, `ward_soar.yara`, `ward_soar.local_av` |
| VT cache hit/miss | `trace_debug.log` | `ward_soar.vt_cache` |
| Block pfSense | `ward_soar.log` | "Blocked IP %s on pfSense blocklist" |
| Quick acquisition | `trace_debug.log` | `ward_soar.forensic.orchestrator` |
| Deep analysis | `trace_debug.log` | `ward_soar.forensic.deep` |
| ZIP export | `trace_debug.log` | "DeepReport exported" |
| Rollbacks UI | `rollback_audit.jsonl` | 1 JSON par rollback |

---

## État attendu au matin

Si WardSOAR a tourné toute la nuit (build MSI → install → start) :
- `evidence/` : 0 à N dossiers selon les alertes. Chaque alerte bloquée
  crée `evidence/<uuid>/volatile/` avec `MANIFEST.json` + artefacts.
- `reports/` : 0 à N ZIP `WardSOAR_Incident_<date>_<ip>.zip` (1 par block).
- `alerts_history.jsonl` : devrait grandir au rythme des alertes Suricata
  (profil historique ~6/jour sur ton setup).

**Ce qui devrait apparaître en premier le matin si tout va bien :**
- Banner "Pipeline initialised" au premier boot après install.
- PreScorer en mode `active` seuil 30 (passe uniquement alertes severity_1
  ou severity_2+rep malicious).
- Analyzer pointant sur `claude-opus-4-7`.

**Ce qui mérite attention si vu :**
- Log "FALLBACK to plaintext" → DPAPI n'a pas pu chiffrer (rare).
- Log "icacls returned N" → ACL hardening a raté (besoin admin).
- Log "Deep analysis crashed" → exception dans deep_orchestrator, voir
  stack trace dans `trace_debug.log`.
- Log "Opus unavailable" → API key manquante ou timeout ; le rapport
  contient un texte fallback.

---

## Décisions architecturales majeures prises ce soir

1. **DPAPI + memory dumps inclus en v0.5** (pas reportés v2). L'utilisateur
   a demandé "à fond pas de compromis", ce qui correspond au design
   original de `docs/architecture.md` §3 + §7.
2. **Opus 4.7 unique** pour les deux appels LLM (verdict + deep report) —
   plus de Sonnet, plus de Confirmer counter-argument.
3. **Cascade privacy-first** : Defender → YARA → VT. VT n'est hit que sur
   les cas où Defender ET YARA sont silencieux.
4. **Rollback 1-clic** via bouton Unblock IP déjà présent dans UI
   (AlertDetailPanel) — câblé au RollbackManager (trusted_temp 30 min +
   feedback -20 pts PreScorer pour la signature).
5. **trace_debug.log** DEBUG+ toujours écrit, indépendant du niveau
   configuré. À **retirer quand v0.5 passe en prod stable** (voir commentaire
   dans `src/logger.py`).

---

## Si tu vois quelque chose qui cloche

Ordre de diagnostic :

1. `trace_debug.log` — 95% des problèmes visibles ici.
2. `decisions.jsonl` — vérifier que les verdicts arrivent bien.
3. `rollback_audit.jsonl` — vérifier que les rollbacks s'inscrivent.
4. Contenu d'un `evidence/<uuid>/volatile/` — `MANIFEST.json` doit lister
   6 artefacts minimum ; présence de `.dpapi` indique que l'encryption est
   active.
5. Contenu d'un `reports/WardSOAR_Incident_*.zip` — doit contenir au
   minimum : README.txt, RAPPORT.pdf, MANIFEST.json, iocs.stix21.json,
   timeline.csv, attack_mapping.json, opus_report.md, evidence/.

Si un bug empêche le blocking :
- `ward_soar.log` au niveau ERROR : chercher "Pipeline error", "pfSense
  SSH", "OpenProcess failed".
- Le pipeline est **fail-safe** : aucune erreur ne doit bloquer du
  trafic légitime ; au pire le verdict devient INCONCLUSIVE et pas de
  block.

Bonne nuit, bon matin.
