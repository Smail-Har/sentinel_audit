# SentinelAudit - Sample Audit Report

## Target

- Host: `prod-web-01`
- IP: `192.168.10.24`
- Audit date: `2026-03-16T11:30:00Z`
- Mode: `remote`

## System Information

- Hostname: `prod-web-01`
- OS: `Ubuntu 24.04 LTS`
- Kernel: `6.8.0-45-generic`
- Uptime: `up 19 days, 4 hours`
- IP addresses: `192.168.10.24`, `10.10.2.8`

## Security Score

- Score: **68 / 100**
- Grade: **C**
- Risk summary: **Elevated risk posture: prioritize high and medium findings.**

## Findings by Severity

| Severity | Count |
|---|---:|
| CRITICAL | 1 |
| HIGH | 3 |
| MEDIUM | 5 |
| LOW | 4 |
| INFO | 12 |

## Key Findings

### [CRITICAL] SSH: PermitRootLogin activé (SSH-001)
- Description: L'accès root SSH est autorisé.
- Evidence: `PermitRootLogin yes`
- Recommendation: Set `PermitRootLogin no` or `prohibit-password`.

### [HIGH] Aucun firewall actif (FW-001)
- Description: Aucun firewall actif détecté (ufw, firewalld, iptables, nftables).
- Evidence: `none active`
- Recommendation: Activer un firewall et appliquer une politique par défaut restrictive.

### [HIGH] Membre du groupe sudo: deploy (USR-002)
- Description: Ce compte peut utiliser sudo.
- Evidence: `deploy`
- Recommendation: Limiter les comptes membres du groupe sudo.

### [MEDIUM] SSH: MaxAuthTries trop élevé (SSH-004)
- Description: MaxAuthTries autorise trop d'essais d'authentification.
- Evidence: `MaxAuthTries 6`
- Recommendation: Réduire `MaxAuthTries` à `3`.

### [MEDIUM] Permissions incorrectes: /etc/passwd (PERM-_etc_passwd)
- Description: `/etc/passwd` est plus permissif que la valeur attendue.
- Evidence: `/etc/passwd: 666`
- Recommendation: `chmod 644 /etc/passwd`

## Recommendations

1. Durcir la configuration SSH (root login, password auth, MaxAuthTries).
2. Activer un firewall hôte (UFW/firewalld) et fermer les ports inutiles.
3. Revoir les privilèges sudo et supprimer les accès excessifs.
4. Corriger les permissions des fichiers sensibles (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`).
5. Prioriser les findings CRITICAL et HIGH avant le prochain cycle d’audit.

## Notes

- SentinelAudit fonctionne en lecture seule: aucune modification système n'est appliquée.
- Cet exemple illustre la structure attendue des rapports Markdown générés.
