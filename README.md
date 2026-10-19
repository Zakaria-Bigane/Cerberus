# Cerberus

**Outil d'audit automatisé du contrôle d'accès des API modernes (REST/OpenAPI & GraphQL).**

Cerberus détecte les vulnérabilités de contrôle d'accès les plus critiques du
référentiel OWASP API Security — **BOLA** (*Broken Object Level Authorization*,
API1:2023) et **BFLA** (*Broken Function Level Authorization*, API5:2023) — en
s'appuyant sur le schéma de l'API et sur un test différentiel entre identités.

> *« Les trois têtes veillent : admin · user · anonyme. »*

---

## Pourquoi Cerberus ?

Le schéma d'une API (OpenAPI, introspection GraphQL) déclare les besoins
**d'authentification**, mais **jamais les règles d'autorisation**. Il n'existe
donc aucun oracle déclaratif permettant de savoir, par simple lecture, si un
accès devrait être autorisé ou refusé.

Cerberus **fabrique cet oracle dynamiquement** : il rejoue chaque opération avec
plusieurs identités (un rôle privilégié, un utilisateur standard, un accès
anonyme) et compare les résultats, en vérifiant systématiquement l'**effet réel**
de l'opération plutôt que le seul code de statut renvoyé.

## Fonctionnalités

- **Deux protocoles** : API REST décrites en OpenAPI, et API GraphQL via
  introspection.
- **Deux vulnérabilités** : BOLA et BFLA.
- **Plusieurs oracles complémentaires** :
  - *contre-test anonyme* — la ressource est-elle simplement publique ?
  - *oracle de propriété* — la ressource obtenue appartient-elle à un tiers ?
  - *oracle d'effet* — la ressource d'autrui a-t-elle réellement été modifiée
    ou supprimée ? (lecture avant/après)
  - *différentiel de rôle* — un rôle inférieur accède-t-il à une fonction
    réservée ?
- **Générique** : aucun nom de cible codé en dur, piloté par un fichier de
  configuration.
- **Rapports** : sortie console colorée, plus rapports **JSON** et **HTML** avec
  preuves et recommandations, classés par gravité.
- **Classification à deux niveaux** : failles confirmées vs points à examiner,
  pour limiter les faux positifs.

## Installation

Prérequis : **Python 3.9+**.

```bash
git clone https://github.com/VOTRE-PSEUDO/cerberus.git
cd cerberus
python -m venv venv
source venv/bin/activate        # Windows : venv\Scripts\activate
pip install -r requirements.txt
```

## Utilisation

### API REST (OpenAPI)

```bash
python main.py \
  --target http://localhost:5002 \
  --type rest \
  --schema vampi_openapi.json \
  --victim-id name2 \
  --config config/vampi_config.yaml
```

### API GraphQL

```bash
python main.py \
  --target http://localhost:5013/graphql \
  --type graphql \
  --victim-id 1 \
  --config config/dvga_config.yaml
```

### Options

| Option | Description |
|---|---|
| `-t`, `--target` | URL de base de l'API ciblée (obligatoire) |
| `--type` | `rest` ou `graphql` (obligatoire) |
| `-s`, `--schema` | Chemin du fichier OpenAPI (obligatoire pour REST) |
| `-v`, `--victim-id` | Identifiant de la ressource victime pour le test BOLA |
| `-c`, `--config` | Chemin du fichier de configuration YAML |

## Configuration

Chaque cible est décrite par un fichier YAML qui isole les paramètres variables
du code. Exemple pour une API REST :

```yaml
auth:
  type: "rest"
  login_path: "/users/v1/login"
  token_response_key: "auth_token"
  accounts:
    admin:
      username: "admin"
      password: "pass1"
    user_a:
      username: "name1"
      password: "pass1"
    user_b:
      username: "name2"
      password: "pass2"
```

## Architecture

```
cerberus/
├── main.py                 # point d'entrée (CLI)
├── config/                 # configurations YAML par cible
├── core/                   # auth, requêtes HTTP, affichage
├── parsers/                # analyseurs OpenAPI et GraphQL
├── engines/                # moteurs BOLA et BFLA
├── models/                 # modèle unifié d'opération
└── reporters/              # générateurs de rapports JSON / HTML
```

Le flux d'exécution : **analyse du schéma → authentification multi-rôles →
moteurs BOLA/BFLA → oracles → rapports**.

## Exemple de sortie

```
[+] 44 opérations cibles chargées avec succès.
[*] Test BOLA sur : GET /workshop/api/mechanic/mechanic_report
[!!!] FAILLE BOLA CONFIRMÉE ! (Statut: 200)
...
[+] Rapport JSON généré : rapport_audit.json
[+] 1 faille(s) — 0 critique(s), 1 haute(s), 13 à examiner
```

## Environnement de test

Cerberus a été validé sur trois applications volontairement vulnérables,
déployables via Docker :

- [**VAmPI**](https://github.com/erev0s/VAmPI) — API REST de laboratoire
- [**DVGA**](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) — application GraphQL vulnérable
- [**crAPI**](https://github.com/OWASP/crAPI) — API réaliste conçue par l'OWASP

## Avertissement

Cet outil est destiné à des fins **éducatives** et à des tests autorisés
uniquement. N'auditez que des systèmes pour lesquels vous disposez d'une
autorisation explicite. L'auteur décline toute responsabilité en cas d'usage
abusif.

## Licence

Distribué sous licence MIT. Voir le fichier [`LICENSE`](LICENSE).

## Auteur

**Zakaria Bigane** — élève ingénieur en cybersécurité (INPT).
Projet développé dans le cadre d'un stage chez DATAPROTECT.