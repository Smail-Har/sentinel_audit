# SentinelAudit

Outil professionnel d'audit de sécurité Linux en **lecture seule**. SentinelAudit se connecte à un ou plusieurs serveurs via SSH, exécute des vérifications de sécurité sans laisser de trace, calcule un score et génère des rapports exploitables (JSON, Markdown, HTML, PDF, console).

Conçu pour les consultants en cybersécurité qui présentent des rapports à des DSI et RSSI.

## Caractéristiques

- **13 modules d'audit** : SSH, firewall, users, permissions, services, packages, kernel, cron, network, filesystem, containers, compliance (CIS)
- **Lecture seule** : aucune modification sur la cible, zéro trace
- **Multi-cible** : inventaire YAML pour auditer une flotte entière
- **Scoring intelligent** : rendements décroissants + plafonds par sévérité (pas de score détruit par du bruit)
- **Séparation inventaire/findings** : les services et packages sont collectés en inventaire, pas en findings
- **5 formats de rapport** : JSON, Markdown, HTML (Jinja2), PDF (weasyprint), console (rich)
- **Rapport consolidé** : vue multi-serveur en un seul HTML
- **Sécurité SSH** : `RejectPolicy` (pas d'`AutoAddPolicy`), vérification `known_hosts`
- **Sanitisation** : les hash de mots de passe et clés privées sont masqués dans les rapports

## Structure du projet

```
sentinel_audit/
├── sentinel_audit/
│   ├── __init__.py
│   ├── cli.py                 # CLI (argparse)
│   ├── main.py                # Entrypoint module
│   ├── orchestrator.py        # Pipeline: connect → audit → score → report
│   ├── inventory.py           # Parser inventaire YAML multi-cible
│   ├── core/
│   │   ├── constants.py       # Severity, scoring penalties, thresholds
│   │   ├── models.py          # Finding, AuditResult, SystemInfo, etc.
│   │   ├── scoring.py         # Scoring engine (diminishing returns)
│   │   ├── ssh_client.py      # SSH client (paramiko + RejectPolicy)
│   │   ├── executor.py        # Local/Remote command execution
│   │   ├── utils.py           # Helpers (parse sshd, sanitise, etc.)
│   │   └── exceptions.py      # Custom exceptions
│   ├── audit/                 # 13 audit modules
│   ├── config/
│   │   └── default_rules.yaml # SSH, sysctl, permissions, compliance rules
│   ├── reporting/
│   │   ├── base.py            # Shared helpers (DRY)
│   │   ├── json_report.py
│   │   ├── markdown_report.py
│   │   ├── html_report.py     # Jinja2 template
│   │   ├── pdf_report.py      # weasyprint
│   │   ├── console_report.py  # rich
│   │   └── consolidated_report.py
│   └── templates/
│       ├── html_report.jinja2
│       └── consolidated_report.jinja2
├── tests/                     # 75 tests (pytest)
├── pyproject.toml
├── Dockerfile
└── .github/workflows/ci.yml
```

## Installation

Prérequis : Python 3.11+

```bash
git clone https://github.com/Smail-Har/sentinel_audit.git
cd sentinel_audit
python3 -m venv .venv && source .venv/bin/activate

# Installation standard
pip install -e .

# Avec support PDF
pip install -e ".[pdf]"

# Avec outils de développement
pip install -e ".[dev]"
```

## Utilisation

### Audit d'un serveur unique

```bash
# Audit distant via SSH (mode par défaut)
sentinel-audit audit --target 192.168.1.10 --ssh-user root --ssh-key ~/.ssh/id_ed25519

# Audit local
sentinel-audit audit --target localhost --mode local

# Sélection de modules et format
sentinel-audit audit --target 192.168.1.10 --include ssh,permissions,users --format html,pdf
```

### Audit multi-cible avec inventaire

```bash
sentinel-audit audit --inventory inventory.yaml --output reports/
```

Exemple d'inventaire (`inventory.yaml`) :

```yaml
defaults:
  ssh_user: auditor
  ssh_key: ~/.ssh/id_ed25519
  ssh_port: 22

targets:
  - host: 192.168.1.10
    label: Web Server (Production)
  - host: 192.168.1.20
    label: Database Server
    ssh_user: admin
    exclude_modules: [container]
  - host: 192.168.1.30
    label: CI/CD Runner
    modules: [ssh, firewall, users, permissions]
```

### Lister les modules disponibles

```bash
sentinel-audit modules
```

### Options CLI

| Option | Description |
|---|---|
| `--target` | Cible (IP ou hostname) |
| `--inventory` | Fichier YAML inventaire multi-cible |
| `--mode` | `local` ou `remote` (défaut: `remote`) |
| `--ssh-user` | Utilisateur SSH (défaut: `root`) |
| `--ssh-key` | Chemin vers la clé privée SSH |
| `--ssh-port` | Port SSH (défaut: `22`) |
| `--label` | Libellé pour le rapport |
| `--output` | Dossier de sortie (défaut: `reports`) |
| `--include` | Modules à inclure (CSV) |
| `--exclude` | Modules à exclure (CSV) |
| `--format` | `json,md,html,pdf,console,all` |
| `--verbose` | Logs détaillés (DEBUG) |

## Scoring

Le score commence à 100 et diminue selon les findings :

| Sévérité | 1er finding | Suivants | Plafond |
|---|---:|---:|---:|
| CRITICAL | -15 | -10 | 40 |
| HIGH | -8 | -5 | 30 |
| MEDIUM | -3 | -2 | 20 |
| LOW | -1 | -1 | 10 |
| INFO | 0 | 0 | 0 |

- **Rendements décroissants** : le 1er finding coûte plus que les suivants
- **Plafonds** : 100 LOWs ne détruisent pas le score (plafonné à -10)
- **Plancher** : le score minimum est 5 (pas 0)
- **Grades** : A (≥90), B (≥75), C (≥60), D (≥45), F (<45)

## Modules d'audit

| Module | Description |
|---|---|
| `system_info` | Collecte des infos système (inventaire) |
| `ssh` | Vérification sshd_config vs règles YAML |
| `firewall` | Détection firewall actif, politique INPUT |
| `users` | UID 0, NOPASSWD sudo, mots de passe vides |
| `permissions` | Permissions fichiers sensibles vs règles YAML |
| `services` | Services dangereux (telnet, rsh, etc.) |
| `packages` | Mises à jour de sécurité en attente |
| `kernel` | Paramètres sysctl vs CIS benchmarks |
| `cron` | Patterns suspects dans les cron jobs |
| `network` | Ports sensibles exposés (Redis, MySQL, etc.) |
| `filesystem` | SUID/SGID inattendus, /tmp sans noexec |
| `container` | Conteneurs Docker privilégiés, socket |
| `compliance` | Vérifications CIS depuis le YAML |

## Exécution des tests

```bash
python3 -m pytest tests/ -v
```

75 tests couvrant : scoring, SSH, permissions, firewall, users, services, network, cron, filesystem, containers, inventaire, reporters, CLI, utilitaires.

## Docker

```bash
docker build -t sentinel-audit .
docker run --rm -v $(pwd)/reports:/app/reports sentinel-audit audit --target 192.168.1.10 --ssh-key /app/keys/id_ed25519
```

## Licence

MIT (voir `LICENSE`).
