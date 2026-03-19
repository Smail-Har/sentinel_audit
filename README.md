# SentinelAudit

SentinelAudit est un outil d’audit de sécurité Linux en lecture seule. Il analyse la configuration système, la posture de sécurité et l’exposition réseau, puis produit des rapports exploitables en JSON, Markdown, HTML et console.

## Présentation du projet

Objectifs principaux :
- auditer un hôte Linux local ou distant (SSH)
- agréger les findings des modules d’audit
- calculer un score global de sécurité (0 à 100)
- générer des rapports lisibles et structurés

Le projet est modulaire : chaque audit est indépendant, les erreurs sont capturées sans arrêter tout le run, et les reporters sont découplés du moteur d’audit.

## Project Structure

```
sentinel_audit/
├── sentinel_audit/
│   ├── main.py
│   ├── cli.py
│   ├── core/
│   │   ├── models.py
│   │   ├── executor.py
│   │   ├── ssh_client.py
│   │   ├── scoring.py
│   │   ├── utils.py
│   │   └── exceptions.py
│   ├── audit/
│   │   ├── base.py
│   │   ├── system_info.py
│   │   ├── ssh_audit.py
│   │   ├── firewall_audit.py
│   │   ├── users_audit.py
│   │   ├── permissions_audit.py
│   │   ├── services_audit.py
│   │   ├── packages_audit.py
│   │   ├── kernel_audit.py
│   │   ├── sysctl_audit.py
│   │   ├── cron_audit.py
│   │   ├── network_audit.py
│   │   ├── process_audit.py
│   │   ├── filesystem_audit.py
│   │   ├── container_audit.py
│   │   ├── compliance_audit.py
│   │   └── lynis_adapter.py
│   ├── reporting/
│   │   ├── json_report.py
│   │   ├── markdown_report.py
│   │   ├── html_report.py
│   │   └── console_report.py
│   └── config/
│       └── default_rules.yaml
├── tests/
│   ├── test_scoring.py
│   ├── test_ssh_audit.py
│   └── test_permissions.py
├── examples/
│   └── sample_audit_report.md
└── README.md
```

## Architecture

Le flux d’exécution suit ce pipeline:

1. Chargement des modules d’audit (registre modulaire)
2. Exécution des checks en mode local ou remote
3. Agrégation des findings dans `AuditResult`
4. Calcul du score via `core/scoring.py`
5. Génération des rapports (JSON / Markdown / HTML / Console)
6. Affichage du résumé terminal

## Installation

Prérequis : Python 3.11+

```bash
git clone https://github.com/Smail-Har/sentinel_audit.git
cd sentinel_audit

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## Utilisation

### Commande principale

```bash
python -m sentinel_audit.main audit --target <target>
```

### Options CLI

- `--target` : cible (`localhost`, IP, hostname)
- `--mode local|remote` : mode d’exécution
- `--ssh-user` : utilisateur SSH (mode remote)
- `--ssh-key` : clé privée SSH (mode remote)
- `--output` : dossier de sortie des rapports
- `--include` : modules à inclure (liste CSV)
- `--exclude` : modules à exclure (liste CSV)
- `--format` : `json,md,html,console,all` (CSV autorisé)
- `--verbose` : logs détaillés

### Exemples de commande

```bash
python -m sentinel_audit.main audit --target localhost --output reports
python -m sentinel_audit.main audit --target 192.168.1.10 --mode remote --ssh-user admin --ssh-key ~/.ssh/id_rsa --output reports
python -m sentinel_audit.main audit --target localhost --include ssh,permissions,users
python -m sentinel_audit.main audit --target localhost --format all
```

## Flux d’exécution

1. chargement des modules d’audit
2. exécution des audits sélectionnés
3. agrégation des findings
4. calcul du score (`core/scoring.py`)
5. génération des rapports
6. affichage du résumé console

Si un module d’audit échoue, l’erreur est enregistrée et le flux continue.
Si un reporter échoue, les autres rapports sont quand même générés.

## Formats de rapport

- **JSON (`json_report.py`)**
    - structure sérialisable
    - metadata, system info, score, findings, regroupements, recommandations

- **Markdown (`markdown_report.py`)**
    - lisible sur GitHub
    - résumé, score, tableau par gravité, détails des findings, recommandations

- **HTML (`html_report.py`)**
    - simple, propre, autonome
    - sans dépendances frontend

- **Console (`console_report.py`)**
    - score global
    - nombre de findings par gravité
    - top findings critiques et élevés

## Example Output

Un exemple réaliste de rapport est disponible dans:

- `examples/sample_audit_report.md`

Extrait de résumé console:

```text
SentinelAudit | Target: localhost
========================================================================
Score: 55/100 (D) | Risk: Critical risk posture: 1 critical finding(s) require immediate remediation.
Findings by severity:
    - INFO    : 2
    - LOW     : 0
    - MEDIUM  : 3
    - HIGH    : 1
    - CRITICAL: 1
Top critical/high findings:
    - [CRITICAL] USR-001 | Compte UID 0: deploy
    - [HIGH] SSH-002 | SSH: PasswordAuthentication activé
```

## Exécution des tests

Le framework cible est **pytest**.

```bash
pytest tests -v
```

Tests unitaires inclus :
- scoring
- audit SSH
- audit permissions

## Roadmap

- amélioration du filtrage et du tri des findings
- enrichissement des règles de conformité
- export PDF
- intégration CI/CD (GitHub Actions)
- extension des audits containers et cloud

## Licence

MIT (voir `LICENSE`).
