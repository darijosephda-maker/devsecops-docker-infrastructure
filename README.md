# Infrastructure DevSecOps Docker – Université Thomas Sankara

Infrastructure conteneurisée conçue et déployée lors de mon stage DevSecOps à la Direction des Systèmes d'Information de l'Université Thomas Sankara (2025-2026), sur Ubuntu Server 22.04 LTS.

## Résultats

- **26 conteneurs** répartis en **5 stacks** Docker Compose
- **11 domaines** exposés en HTTPS via Traefik
- **Score CIS Benchmark : 66/100**, **zéro CVE critique** (analyse des images avec Trivy)
- Supervision en temps réel et alertes par e-mail
- Rapport de stage (~45 pages), schéma d'architecture et planning sur 13 semaines

## Architecture

| Stack | Rôle | Technologies |
|---|---|---|
| `traefik` | Reverse proxy, routage HTTPS des domaines | Traefik |
| `monitoring` | Supervision et alertes | Prometheus, Grafana, Alertmanager |
| `harbor` | Registre privé d'images avec analyse des vulnérabilités | Harbor v2.11, Trivy |
| `production` | Services universitaires : portail, inscription, API, base de données, cache | Docker, PostgreSQL |
| `portail` | Portail d'administration et API de pilotage de l'infrastructure | Flask (Python), Nginx |

## Sécurité

- **Zero Trust et micro-segmentation** : réseaux Docker isolés (`dmz_net`, `backend_net`, `database_net`) pour cloisonner les services selon leur sensibilité.
- **Docker Secrets** pour les identifiants PostgreSQL : aucun mot de passe dans les fichiers compose.
- **Analyse des images** (Trivy via Harbor) avant déploiement.
- **Trois scénarios de type Red Team** : déni de service (SYN Flood), audit de la chaîne d'approvisionnement logicielle (CVE), prévention des mouvements latéraux.
- **Audit CIS Benchmark** pour mesurer et améliorer la configuration.

## Structure du dépôt

- `traefik/` : reverse proxy et routage dynamique
- `monitoring/` : Prometheus, Alertmanager, règles d'alerte
- `harbor/` : configuration modèle de Harbor
- `production/` : stack des services universitaires
- `portail/` : portail d'administration (Flask + Nginx)

## Configuration

Tous les secrets ont été retirés de ce dépôt. Les fichiers `.env.example` et les valeurs `CHANGE_ME` indiquent ce qu'il faut renseigner :

- `monitoring/.env.example` : mot de passe administrateur Grafana
- `portail/.env.example` : identifiants du registre Harbor (`HARBOR_CREDENTIALS`)
- `harbor/harbor.yml.example` : mots de passe Harbor et de sa base
- `monitoring/alertmanager/alertmanager.yml` : compte SMTP des alertes
- `production/` : créer `secrets/postgres_user` et `secrets/postgres_password`

Les adresses IP (192.168.122.x et 172.x) correspondent au réseau interne du laboratoire.

## Auteur

**DA Dari Joseph** – Licence en Système d'Information et Réseau, Université Thomas Sankara.
Fondateur & PDG d'[INSIGN Digital Services](https://insigndigitalservices.com).
