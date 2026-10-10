# TP1 — Analyse statique (SAST) et sécurité des dépendances (SCA)

| | |
|---|---|
| **Étudiant** | Yassine Dahmoul — GRP1 |
| **Encadrante** | Saloua BEN YAHIA |
| **Date** | 10 octobre 2026 |
| **Projet analysé** | *Notes App* — application web Python/Flask (ce dépôt) |
| **Outils** | Docker 29.6.1 · Bandit 1.9.4 (SAST) · OWASP Dependency-Check 13.0.0 (SCA) · pip-audit 2.10.1 (SCA, contre-vérification) |

---

## Sommaire

1. [Objectifs et approche « shift-left »](#1-objectifs-et-approche-shift-left)
2. [Mise en place de l'environnement](#2-mise-en-place-de-lenvironnement)
3. [Analyse statique (SAST) avec Bandit](#3-analyse-statique-sast-avec-bandit)
4. [Analyse des dépendances (SCA) avec OWASP Dependency-Check et pip-audit](#4-analyse-des-dépendances-sca)
5. [Démonstration](#5-démonstration)
6. [Aller plus loin : intégration continue](#6-aller-plus-loin--intégration-continue-shift-left-automatisé)
7. [Bilan](#7-bilan)
8. [Annexes](#8-annexes)

---

## 1. Objectifs et approche « shift-left »

Le **shift-left** consiste à déplacer la sécurité « vers la gauche » du cycle de développement, c'est-à-dire le plus tôt possible : dès l'écriture du code et le choix des bibliothèques, plutôt qu'au moment d'un audit ou d'un test d'intrusion juste avant la mise en production. Plus une vulnérabilité est détectée tard, plus elle coûte cher à corriger (code déjà intégré, déployé, parfois déjà exploité).

Deux familles d'outils automatisables permettent de le faire :

| Approche | Ce qui est analysé | Quand | Exemple de problème trouvé | Outil utilisé ici |
|---|---|---|---|---|
| **SAST** (*Static Application Security Testing*) | **Notre code source**, sans l'exécuter | À chaque commit / PR | Injection SQL, injection de commande, secret en dur | **Bandit** |
| **SCA** (*Software Composition Analysis*) | **Les bibliothèques tierces** (dépendances directes et transitives) | À chaque commit + en continu (nouvelles CVE publiées chaque jour) | Version de PyYAML vulnérable à une exécution de code (CVE-2020-1747) | **OWASP Dependency-Check** (+ pip-audit) |

Les deux sont complémentaires : un code parfaitement écrit reste vulnérable s'il s'appuie sur une bibliothèque vulnérable, et inversement.

---

## 2. Mise en place de l'environnement

### 2.1 Le projet

*Notes App* est une petite application Flask de prise de notes, écrite pour ce TP, avec des fonctionnalités réalistes : inscription/connexion, création et recherche de notes, import de notes au format YAML, préférences utilisateur, et deux outils réseau (ping, récupération d'une URL).

La **version initiale** (tag Git `v1.0-vulnerable`) reproduit des erreurs de développement courantes et utilise des dépendances anciennes, comme on en trouve dans une application « legacy ».

```
.
├── app/
│   ├── app.py                 # application Flask
│   └── templates/             # vues Jinja2
├── requirements.txt           # dépendances figées (directes + transitives)
├── Dockerfile                 # image de l'application
├── scripts/scan.ps1           # lance SAST + SCA sur n'importe quelle version Git
├── .github/workflows/security.yml   # scans automatiques en CI (bonus)
├── reports/
│   ├── sast/                  # rapports Bandit avant / après (txt, json, html)
│   └── sca/                   # rapports Dependency-Check et pip-audit avant / après
└── RAPPORT.md                 # ce rapport
```

### 2.2 Historique Git

L'historique est découpé pour que chaque étape du TP soit visible et comparable :

| Commit / tag | Contenu |
|---|---|
| `v1.0-vulnerable` | Application initiale vulnérable |
| `SAST : correction…` | Corrections des vulnérabilités signalées par Bandit + rapports Bandit |
| `v2.0-secure` | Mise à jour des dépendances + image Docker durcie + rapports SCA |
| *(commits suivants)* | Script de scan, CI, rapport |

```bash
git log --oneline --decorate
git diff v1.0-vulnerable v2.0-secure -- app/app.py requirements.txt Dockerfile
```

### 2.3 Image Docker

**Dockerfile initial** (`v1.0-vulnerable`) : volontairement naïf.

```dockerfile
FROM python:3.7-slim                 # Python 3.7 : fin de support en juin 2023
WORKDIR /app
RUN apt-get update && apt-get install -y iputils-ping && rm -rf /var/lib/apt/lists/*
COPY . .
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "app/app.py"]         # serveur de développement Flask, en root
```

Construction et lancement :

```bash
docker build -t notes-app:vulnerable .
docker run -d --name notes-vuln -p 5001:5000 notes-app:vulnerable
```

Au démarrage, les journaux du conteneur affichent déjà un signal d'alarme : `Debugger is active!` (le débogueur Werkzeug est exposé sur toutes les interfaces).

Le **Dockerfile final** (`v2.0-secure`) est décrit au [§4.5](#45-durcissement-de-limage-docker).

### 2.4 Outils, tous lancés via Docker

Aucun outil n'est installé sur la machine : tout tourne dans des conteneurs, ce qui rend les résultats reproductibles.

| Outil | Image Docker | Rôle |
|---|---|---|
| Bandit 1.9.4 | `ghcr.io/pycqa/bandit/bandit` (image officielle PyCQA) | SAST Python |
| OWASP Dependency-Check 13.0.0 | `owasp/dependency-check` | SCA, base NVD (CVE/CPE) |
| pip-audit 2.10.1 | `python:3.13-slim` + `pip install pip-audit` | SCA Python, base PyPA/OSV |

---

## 3. Analyse statique (SAST) avec Bandit

### 3.1 Lancement du scan

Bandit parcourt l'arbre syntaxique (AST) de chaque fichier Python et applique des règles (`B1xx` à `B7xx`). Chaque problème reçoit une **sévérité** (impact si c'est exploitable) et un **niveau de confiance** (probabilité que ce soit un vrai problème).

```bash
# depuis la racine du projet (sous Git Bash : préfixer avec MSYS_NO_PATHCONV=1)
docker run --rm -v "$PWD:/src" -w /src --entrypoint bandit ghcr.io/pycqa/bandit/bandit \
    -r app -f html -o reports/sast/bandit-before.html
```

Les rapports sont générés en trois formats : texte (lecture), JSON (traitement automatique), HTML (présentation).

### 3.2 Résultats initiaux : 15 problèmes

Rapport complet : [`reports/sast/bandit-before.txt`](reports/sast/bandit-before.txt) / [`.html`](reports/sast/bandit-before.html)

| # | Règle Bandit | Sévérité / Confiance | CWE | Ligne | Problème |
|---|---|---|---|---|---|
| 1 | B608 hardcoded_sql_expressions | Medium / Low | CWE-89 | 102 | **Injection SQL** dans `/login` (requête construite avec `%`) |
| 2 | B608 hardcoded_sql_expressions | Medium / Low | CWE-89 | 152 | **Injection SQL** dans `/search` |
| 3 | B602 subprocess_popen_with_shell_equals_true | **High** / High | CWE-78 | 199 | **Injection de commande** OS dans `/tools/ping` |
| 4 | B704 markupsafe_markup_xss | Medium / High | CWE-79 | 157 | **XSS réfléchi** : `Markup()` sur la saisie de recherche |
| 5 | B301 pickle | Medium / High | CWE-502 | 189 | **Désérialisation non sûre** d'un cookie avec `pickle` |
| 6 | B403 import pickle | Low / High | CWE-502 | 11 | Import du module `pickle` |
| 7 | B506 yaml_load | Medium / High | CWE-20 | 166 | `yaml.load()` sur un fichier envoyé par l'utilisateur |
| 8 | B324 hashlib | **High** / High | CWE-327 | 47 | Mots de passe hachés en **MD5** |
| 9 | B105 hardcoded_password_string | Low / Medium | CWE-259 | 24 | `secret_key` Flask **en dur** dans le code |
| 10 | B105 hardcoded_password_string | Low / Medium | CWE-259 | 26 | Mot de passe admin **en dur** (`admin123`) |
| 11 | B501 request_with_no_cert_validation | **High** / High | CWE-295 | 206 | `requests.get(..., verify=False)` : TLS non vérifié |
| 12 | B113 request_without_timeout | Medium / Low | CWE-400 | 206 | Requête HTTP sans timeout |
| 13 | B201 flask_debug_true | **High** / Medium | CWE-94 | 213 | `app.run(debug=True)` : débogueur Werkzeug exposé |
| 14 | B104 hardcoded_bind_all_interfaces | Medium / Medium | CWE-605 | 213 | Écoute sur `0.0.0.0` |
| 15 | B404 import subprocess | Low / High | CWE-78 | 13 | Import du module `subprocess` |

**Bilan initial : 4 High, 7 Medium, 4 Low.**

### 3.3 Analyse et correction des vulnérabilités

Le TP demandait d'en corriger au moins deux. **Toutes les vulnérabilités High et Medium ont été corrigées.** Les deux premières sont détaillées, les autres plus brièvement. Dans le code corrigé, chaque correction est repérée par un commentaire `[SAST Bxxx]`.

#### Vulnérabilité 1 : injection SQL (B608, CWE-89, OWASP A03:2021)

**Code vulnérable** (`/login`) :

```python
query = "SELECT id, username FROM users WHERE username = '%s' AND password = '%s'" % (
    username,
    hash_password(password),
)
user = get_db().execute(query).fetchone()
```

**Pourquoi c'est dangereux.** La saisie de l'utilisateur est collée directement dans le texte de la requête SQL. Un attaquant peut donc y insérer des caractères SQL (apostrophe, commentaire…) qui **changent la structure de la requête** au lieu d'être traités comme des données. Sur `/login`, cela permet de se connecter sous l'identité d'un autre utilisateur (par exemple `admin`) sans connaître son mot de passe. Sur `/search`, un `UNION SELECT` permet de lire d'autres tables, par exemple les hachés de mots de passe de la table `users`.

**Correction : requêtes paramétrées.** La requête et les données sont envoyées séparément au moteur SQLite. La saisie est toujours traitée comme une valeur, jamais comme du code SQL.

```python
# [SAST B608] Requete parametree : la saisie n'est jamais concatenee au SQL.
user = get_db().execute(
    "SELECT id, username, password FROM users WHERE username = ?",
    (request.form["username"],),
).fetchone()
if user and check_password_hash(user["password"], request.form["password"]):
    ...
```

```python
# /search : le motif LIKE est lui aussi passe en parametre
notes = get_db().execute(
    "SELECT id, title, content FROM notes WHERE owner_id = ? AND title LIKE ?",
    (session["user_id"], "%" + q + "%"),
).fetchall()
```

> Remarque : Bandit attribue à B608 une confiance *Low*, parce qu'il repère un motif (une chaîne SQL formatée) sans pouvoir prouver que la variable vient de l'utilisateur. Ici, c'est un **vrai positif** : `username` provient directement de `request.form`. L'analyse SAST demande donc toujours une vérification humaine (triage).

#### Vulnérabilité 2 : injection de commande OS (B602, CWE-78, OWASP A03:2021)

**Code vulnérable** (`/tools/ping`) :

```python
host = request.args.get("host", "127.0.0.1")
output = subprocess.check_output("ping -c 1 " + host, shell=True, stderr=subprocess.STDOUT)
```

**Pourquoi c'est dangereux.** Avec `shell=True`, la chaîne est interprétée par `/bin/sh`. Les métacaractères du shell (`;`, `&&`, `|`, `$( )`…) présents dans `host` permettent donc d'enchaîner **n'importe quelle commande** sur le serveur, avec les droits du processus. Dans l'image initiale, ce processus tourne en **root**. C'est une exécution de code à distance (RCE), sans authentification, puisque la route n'était pas protégée.

**Correction : validation stricte + suppression du shell** (défense en profondeur) :

```python
@app.route("/tools/ping")
@login_required
def ping():
    # [SAST B602] Validation stricte de l'entree (adresse IP uniquement) et
    # appel sans shell, avec une liste d'arguments et un chemin absolu.
    try:
        ip = ipaddress.ip_address(request.args.get("host", "127.0.0.1"))
    except ValueError:
        abort(400, "Adresse IP invalide")
    result = subprocess.run(
        ["/bin/ping", "-c", "1", str(ip)], capture_output=True, timeout=5, check=False
    )
```

1. **Validation par liste blanche** : seule une adresse IPv4/IPv6 valide est acceptée (`ipaddress.ip_address`). Tout le reste renvoie une erreur 400.
2. **Pas de shell** : la commande est passée sous forme de liste d'arguments, si bien qu'aucun métacaractère ne peut être interprété.
3. **Chemin absolu** (`/bin/ping`) : évite le détournement via le `PATH` (règle B607).
4. **Timeout**, **authentification obligatoire** et, au niveau de l'image, **utilisateur non-root**.

#### Vulnérabilité 3 : Cross-Site Scripting réfléchi (B704, CWE-79)

```python
# Avant : Markup() declare la chaine "sure" et desactive l'echappement de Jinja2
message = Markup("Resultats pour : <b>%s</b>" % q)
```

Le texte recherché était renvoyé dans la page sans être échappé. Un lien piégé pouvait donc exécuter du JavaScript dans le navigateur de la victime (vol de session, actions à sa place).

**Correction** : `Markup()` est supprimé et la valeur brute est transmise au template, où l'**auto-échappement de Jinja2** la convertit en texte inoffensif (`<` devient `&lt;`) :

```html
{% if query %}<p>Resultats pour : <b>{{ query }}</b></p>{% endif %}
```

Un en-tête `Content-Security-Policy` a aussi été ajouté en défense en profondeur.

#### Vulnérabilité 4 : désérialisation non sûre avec pickle (B301/B403, CWE-502, OWASP A08:2021)

Les préférences étaient stockées dans un cookie `base64(pickle(...))` puis relues avec `pickle.loads()`. Or le cookie est entièrement contrôlé par le client, et **désérialiser un pickle arbitraire revient à exécuter du code arbitraire** : le format permet d'appeler n'importe quelle fonction pendant le chargement.

**Correction** : `pickle` est supprimé. La préférence est stockée dans la **session Flask**, un cookie sérialisé en JSON et **signé par HMAC** avec `SECRET_KEY` donc infalsifiable, puis validée par liste blanche (`ALLOWED_THEMES = {"light", "dark"}`).

#### Vulnérabilité 5 : `yaml.load()` sur un fichier utilisateur (B506, CWE-20)

```python
data = yaml.load(request.files["file"].read())        # avant
data = yaml.safe_load(request.files["file"].read())   # apres
```

`yaml.load()` sans `SafeLoader` peut instancier des objets Python arbitraires à partir du YAML. Combiné à la version **PyYAML 5.3** utilisée (CVE-2020-1747, voir §4.3), cela permettait une exécution de code sur le serveur via un simple import de fichier. `yaml.safe_load()` ne construit que des types simples (dict, list, str, int…). La structure est en plus validée (liste de `{title: str, content: str}`), et la taille d'upload est limitée (`MAX_CONTENT_LENGTH` = 1 Mo).

> Ce cas montre bien la complémentarité SAST/SCA : **Bandit** signale le mauvais *usage* de la bibliothèque, **Dependency-Check** signale la *version* vulnérable de cette même bibliothèque.

#### Vulnérabilité 6 : mots de passe hachés en MD5 (B324, CWE-327/CWE-916)

MD5 est extrêmement rapide (des milliards de hachés par seconde sur un GPU) et était utilisé sans sel. En cas de fuite de la base, les mots de passe se retrouvent en quelques secondes par force brute ou tables précalculées. **Correction** : `werkzeug.security.generate_password_hash()` / `check_password_hash()`, qui utilise **scrypt** (lent, coûteux en mémoire) avec un **sel aléatoire** par utilisateur.

#### Vulnérabilité 7 : secrets en dur (B105, CWE-259/CWE-798)

`app.secret_key = "s3cr3t-k3y-tp1-devsecops"` et `ADMIN_PASSWORD = "admin123"` étaient écrits dans le code, donc visibles dans tout l'historique Git. Avec la `secret_key`, n'importe qui peut **forger une session valide**. **Correction** : les deux valeurs viennent de variables d'environnement (`SECRET_KEY`, `ADMIN_PASSWORD`). À défaut de `SECRET_KEY`, une clé aléatoire est générée au démarrage avec `secrets.token_hex(32)`. Le compte admin n'est créé que si `ADMIN_PASSWORD` est fourni.

> Un secret qui a été commité doit être considéré comme **compromis** : le retirer du code ne suffit pas, il faut le **changer** (rotation).

#### Vulnérabilité 8 : TLS non vérifié, pas de timeout, SSRF (B501, B113, CWE-295/CWE-400/CWE-918)

`requests.get(url, verify=False)` désactivait la vérification du certificat (interception de type *man-in-the-middle* possible) et n'avait pas de timeout (un serveur lent pouvait bloquer les workers, donc déni de service). Au-delà de ce que Bandit détecte, la route permettait aussi une **SSRF** : faire envoyer par le serveur des requêtes vers le réseau interne.

**Correction** : `verify=True` (valeur par défaut), `timeout=5`, `allow_redirects=False`, et une fonction `is_public_http_url()` qui n'accepte que `http`/`https` vers des adresses **publiques** (refus de `127.0.0.1`, `10.x`, `169.254.169.254`…).

#### Vulnérabilité 9 : mode debug et écoute sur toutes les interfaces (B201, B104, CWE-94)

`app.run(host="0.0.0.0", debug=True)` expose le **débogueur interactif Werkzeug**, qui permet d'exécuter du Python dans le navigateur dès qu'il est déverrouillé. Son code PIN est en plus prévisible dans Docker (CVE-2019-14806, voir §4). **Correction** : `debug` n'est activé que si `FLASK_DEBUG=1`, l'écoute par défaut se fait sur `127.0.0.1`, et en production (Docker) l'application est servie par **gunicorn**, qui ne contient pas de débogueur.

### 3.4 Résultats après correction

Rapport complet : [`reports/sast/bandit-after.txt`](reports/sast/bandit-after.txt) / [`.html`](reports/sast/bandit-after.html)

| Sévérité | Avant | Après |
|---|:---:|:---:|
| **High** | 4 | **0** |
| **Medium** | 7 | **0** |
| **Low** | 4 | 2 |
| **Total** | 15 | 2 |

Les **2 problèmes Low restants** ont été analysés (triage) et sont **acceptés** :

| Règle | Ligne | Pourquoi il est accepté |
|---|---|---|
| B404 import subprocess | 14 | Avertissement générique : le simple fait d'importer `subprocess` est signalé. Le module est nécessaire pour la fonctionnalité ping. |
| B603 subprocess_without_shell_equals_true | 241 | Bandit rappelle de vérifier les entrées. C'est fait : pas de shell, chemin absolu, argument validé comme adresse IP par `ipaddress`. Aucune injection n'est possible. |

Ces deux lignes n'ont volontairement **pas** été masquées avec `# nosec`, pour rester transparent dans le rapport. En CI, le seuil de blocage est fixé à *Medium* (§6).

### 3.5 Limites du SAST observées

- **Faux positifs / confiance faible** : B608 a une confiance *Low*. Un humain doit confirmer.
- **Faux négatifs** : Bandit ne raisonne pas sur la logique applicative. Il n'a pas détecté la **SSRF** de `/tools/fetch`, l'**absence d'authentification** sur les outils réseau, ni l'absence de protection **CSRF** sur les formulaires. Ces points ont été vus à la relecture du code.
- Bandit n'analyse ni les templates HTML, ni le Dockerfile, ni les dépendances : c'est le rôle de la SCA.

---

## 4. Analyse des dépendances (SCA)

### 4.1 Outils et lancement

**OWASP Dependency-Check** (outil demandé) identifie chaque composant, lui associe un identifiant **CPE** (*Common Platform Enumeration*), puis recherche les **CVE** correspondantes dans la base **NVD** du NIST.

```bash
docker run --rm -v "$PWD:/src" -v dc-data:/usr/share/dependency-check/data \
  owasp/dependency-check:latest \
  --project "TP1 Notes App" --scan /src --exclude "**/reports/**" --exclude "**/.git/**" \
  --enableExperimental --disableOssIndex \
  --nvdDatafeed "https://dependency-check.github.io/DependencyCheck_Builder/nvd_cache/" \
  --format HTML --format JSON --out /src/reports/sca
```

Explication des options :

- `--enableExperimental` : l'analyseur de `requirements.txt` (pip) est classé « expérimental ». Sans cette option, aucune dépendance Python n'est détectée.
- `--nvdDatafeed` : sans clé d'API NVD, le téléchargement de la base via l'API est fortement limité (plusieurs dizaines de minutes à plusieurs heures). On utilise donc le miroir officiel du projet Dependency-Check (≈ 100 s au premier lancement). La base est conservée dans le volume Docker `dc-data`, ce qui accélère les lancements suivants. En production, on demanderait une clé gratuite (`--nvdApiKey`).
- `--disableOssIndex` : l'analyseur Sonatype OSS Index demande désormais un jeton d'accès personnel.

**pip-audit** (outil de la PyPA, fondation Python) est utilisé en **contre-vérification**. Il interroge la base **OSV / PyPI Advisory** et identifie les paquets par leur nom PyPI exact (*purl*), sans passer par les CPE :

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.13-slim sh -c \
  "pip install -q pip-audit && pip-audit -r requirements.txt --no-deps --disable-pip"
```

### 4.2 Résultats initiaux

Trois analyses ont été menées sur la version initiale :

| Analyse | Cible | Résultat |
|---|---|---|
| Dependency-Check (projet) | `requirements.txt` | **4 CVE** : 3 Critical, 1 High (PyYAML, certifi) |
| Dependency-Check (image) | paquets installés dans l'image Docker (`site-packages`) | **44 alertes** : 7 Critical, 12 High, 20 Medium, 5 Low |
| pip-audit | `requirements.txt` | **47 vulnérabilités distinctes dans 9 paquets** |

Rapports : [`dependency-check-before.html`](reports/sca/dependency-check-before.html), [`dependency-check-image-before.html`](reports/sca/dependency-check-image-before.html), [`pip-audit-before.txt`](reports/sca/pip-audit-before.txt).

Synthèse par paquet (détail des 47 vulnérabilités en [annexe A](#annexe-a--détail-des-vulnérabilités-des-dépendances-avant-mise-à-jour)) :

| Paquet | Version initiale | Nb vuln. | Plus grave (CVSS NVD) | Version retenue |
|---|---|:---:|---|---|
| **PyYAML** | 5.3 | 2 | **CVE-2020-1747 / CVE-2020-14343 : 9.8 Critical**, exécution de code | **6.0.3** |
| **Werkzeug** | 0.14.1 | 12 | CVE-2022-29361 : 9.8 Critical (*request smuggling*) ; CVE-2019-14806 / CVE-2024-34069 : 7.5 (débogueur) | **3.1.9** |
| **certifi** | 2018.4.16 | 2 | CVE-2023-37920 : 9.8 Critical (racines e-Tugra non fiables) | **2026.7.22** |
| **requests** | 2.19.1 | 5 | CVE-2018-18074 : 7.5 High (fuite de l'en-tête `Authorization`) | **2.34.2** |
| **urllib3** | 1.23 | 12 | CVE-2023-43804 (fuite de cookies sur redirection)… | **2.8.0** |
| **Jinja2** | 2.10 | 6 | CVE-2019-10906, CVE-2024-56326, CVE-2025-27516 (évasions du *sandbox*) | **3.1.6** |
| **Flask** | 0.12.2 | 4 | CVE-2018-1000656 (DoS), CVE-2023-30861 (cookie de session mis en cache) | **3.1.3** |
| **gunicorn** | 19.9.0 | 2 | CVE-2024-1135 (*HTTP request smuggling*) | **26.2.0** |
| **idna** | 2.7 | 2 | CVE-2024-3651 (DoS) | **3.20** |

### 4.3 Dépendance vulnérable choisie : PyYAML 5.3 → 6.0.3

**Les vulnérabilités.**

- **CVE-2020-1747** (CVSS 9.8, **Critical**) : dans PyYAML < 5.3.1, le chargement d'un YAML non fiable avec `full_load()` ou le `FullLoader` permet une **exécution de code arbitraire**, en abusant du constructeur `python/object/new`.
- **CVE-2020-14343** (CVSS 9.8, **Critical**) : le correctif de 5.3.1 était **incomplet**. La même attaque restait possible jusqu'à la version 5.4.

**Pourquoi la mise à jour est nécessaire dans notre cas.**

1. **La faille était directement exploitable dans l'application.** La route `/import` passait un fichier fourni par l'utilisateur à `yaml.load()` sans `Loader`. Dans PyYAML 5.x, ce cas utilise par défaut le `FullLoader`, précisément celui concerné par les deux CVE. C'est une **exécution de code à distance** de gravité maximale (CVSS 9.8 : exploitable à distance, sans privilège, sans interaction).
2. **La correction du code (`safe_load`) ne suffit pas.** C'est une **défense en profondeur** : si un autre développeur réintroduit plus tard un `full_load()`, ou si une autre bibliothèque utilise PyYAML, la version corrigée protège encore. On ne doit pas compter sur le fait que « le code n'utilise pas la fonction vulnérable ».
3. **PyYAML 6.0 est plus sûr par conception** : `yaml.load()` sans `Loader` explicite lève désormais une erreur. Le piège qui a causé la vulnérabilité n'existe plus.
4. **Choix de la version** : la version minimale corrigée est 5.4. On prend la **dernière version stable (6.0.3)**, qui supporte Python 3.13 et ne comporte aucune vulnérabilité connue (vérifié avec les deux outils).

### 4.4 Autres mises à jour et justification

Toutes les dépendances ont été mises à jour, pas seulement la plus grave. Une dépendance vulnérable non exploitée aujourd'hui peut l'être demain, si le code évolue.

| Paquet | Justification principale |
|---|---|
| **Werkzeug 3.1.9** | Les CVE du **débogueur** (CVE-2019-14806 : PIN prévisible *dans Docker* ; CVE-2024-34069 : exécution de code) aggravaient directement la vulnérabilité B201 (`debug=True`). S'y ajoutent des failles de *request smuggling* et de DoS sur les formulaires multipart (CVE-2023-25577, CVE-2023-46136). |
| **Flask 3.1.3** | DoS par JSON mal encodé (CVE-2018-1000656) ; possible fuite du cookie de session via un proxy cache (CVE-2023-30861). Flask 3 impose aussi Werkzeug ≥ 3. |
| **requests 2.34.2 / urllib3 2.8.0** | Fuite d'en-têtes `Authorization` / `Proxy-Authorization` / `Cookie` lors de redirections (CVE-2018-18074, CVE-2023-32681, CVE-2023-43804…). À noter, **CVE-2024-35195** : dans une `Session`, une première requête en `verify=False` pouvait désactiver la vérification TLS pour les suivantes, en lien direct avec la faille B501 corrigée. |
| **certifi 2026.7.22** | Le magasin de certificats racines datait de 2018. Il contenait encore des autorités retirées par Mozilla pour manque de fiabilité (TrustCor : CVE-2022-23491 ; e-Tugra : CVE-2023-37920). La vérification TLS n'a de valeur que si la liste des autorités de confiance est à jour. |
| **gunicorn 26.2.0** | *HTTP request smuggling* via des en-têtes `Transfer-Encoding` contradictoires (CVE-2024-1135, CVE-2024-6827), qui permet de contourner des restrictions d'accès. |
| **Jinja2 3.1.6 / MarkupSafe 3.0.4** | Évasions du *sandbox* Jinja2, ReDoS (CVE-2020-28493), injection d'attributs via `xmlattr`. |
| **idna 3.20, click, itsdangerous, blinker, charset-normalizer** | Alignement sur les versions requises par Flask 3 / requests 2.34. `chardet` est remplacé par `charset-normalizer`. |

Toutes les versions restent **figées** (`==`) dans `requirements.txt`, y compris les dépendances transitives. Le build est ainsi reproductible et l'analyse SCA porte exactement sur ce qui est déployé.

### 4.5 Durcissement de l'image Docker

L'analyse de l'image a aussi révélé des vulnérabilités dans les outils de la **base Python 3.7** elle-même (`pip 23.0.1`, `setuptools 57.5.0`, `wheel 0.41.2`). Python 3.7 n'est plus maintenu depuis juin 2023. Nouveau `Dockerfile` :

```dockerfile
FROM python:3.13-slim                         # version maintenue, sans setuptools/wheel
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 ...
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/* && useradd --create-home --uid 10001 appuser
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY app/ ./app/                              # seulement le code (plus de "COPY . .")
USER appuser                                  # plus de root
HEALTHCHECK ... 
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--preload", "--chdir", "app", "app:app"]
```

| Avant | Après |
|---|---|
| Python 3.7 (fin de vie) | Python 3.13 (maintenu) |
| Conteneur exécuté en **root** | Utilisateur **`appuser`** (uid 10001) |
| Serveur de dev Flask + débogueur | **gunicorn** (serveur WSGI de production) |
| `COPY . .` (tout le dépôt) | Copie de `requirements.txt` et `app/` uniquement + `.dockerignore` |
| Pas de supervision | `HEALTHCHECK` |

Test fonctionnel de l'image corrigée : conteneur `healthy`, processus exécuté par `appuser`. Inscription, connexion, ajout et recherche de notes, préférences et ping d'une IP fonctionnent. Un hôte non-IP et une URL interne sont refusés (HTTP 400), et une recherche contenant du HTML est affichée échappée (`&lt;i&gt;`).

### 4.6 Résultats après mise à jour

| Analyse | Avant | Après |
|---|:---:|:---:|
| Dependency-Check, `requirements.txt` | 4 CVE (3 Critical, 1 High) | **0** |
| Dependency-Check, image Docker | 44 alertes (7 Critical, 12 High) | **0** |
| pip-audit | 47 vulnérabilités / 9 paquets | **0** (« No known vulnerabilities found ») |

Rapports : [`dependency-check-after.html`](reports/sca/dependency-check-after.html), [`dependency-check-image-after.html`](reports/sca/dependency-check-image-after.html), [`pip-audit-after.txt`](reports/sca/pip-audit-after.txt).

### 4.7 Comparaison des outils SCA : ce que montre le TP

Le résultat le plus instructif de cette partie est l'**écart entre les outils** :

- **Dependency-Check sur `requirements.txt` n'a trouvé que 4 CVE sur 2 paquets**, alors que pip-audit en trouve 47 sur 9. Dependency-Check doit deviner l'identifiant **CPE** du paquet (par exemple `cpe:2.3:a:palletsprojects:werkzeug`). Or une ligne `Werkzeug==0.14.1` ne lui donne qu'un nom et une version, sans éditeur : la correspondance échoue pour Flask, Werkzeug, requests, urllib3, gunicorn… Ce sont des **faux négatifs**.
- **Sur l'image Docker**, les métadonnées des paquets installés (`*.dist-info/METADATA` : auteur, page d'accueil…) apportent plus d'indices. Dependency-Check trouve alors Werkzeug (12), requests (3), Jinja2… mais il manque toujours Flask, urllib3 et gunicorn. Il génère aussi :
  - des **doublons** : copies de `requests`, `certifi`… *embarquées* (*vendored*) dans `pip` ;
  - des **faux positifs** : `cli-32.exe` de setuptools associé à tort à la CVE-2016-10538 du paquet npm `node-cli` ;
  - des vulnérabilités réelles mais **hors du code applicatif** : `jquery 1.11.3` embarqué dans le débogueur de Werkzeug 0.14, ainsi que `pip`, `setuptools` et `wheel` de l'image de base.
- **pip-audit** identifie les paquets par leur **nom PyPI exact** et interroge une base dédiée à l'écosystème Python (PyPA/OSV) : il est plus précis pour Python, et indique directement la **version corrigée**. Il ne voit cependant ni l'image, ni les composants non-Python.

**Conclusion** : aucun outil SCA n'est exhaustif. Il faut **croiser les sources** (NVD, OSV, GitHub Advisories), analyser **aussi l'artefact livré** (l'image) et pas seulement le fichier de dépendances, et **trier** les résultats (doublons, faux positifs).

---

## 5. Démonstration

### 5.1 Scénario (≈ 5 minutes)

Le script [`scripts/scan.ps1`](scripts/scan.ps1) extrait une version Git (`git archive`, sans toucher à la copie de travail), puis lance **Bandit + pip-audit + Dependency-Check** dans Docker. Il affiche une synthèse et écrit les rapports dans `reports/demo/<version>/`.

**Étape 1 : la version initiale et ses vulnérabilités**

```powershell
git log --oneline --decorate
.\scripts\scan.ps1 -Ref v1.0-vulnerable
```

Sortie obtenue :

```
================ SYNTHESE : v1.0-vulnerable ================
Bandit (SAST)            : High=4  Medium=7  Low=4
pip-audit (SCA)          : 47 vulnerabilite(s) dans 9 paquet(s)
Dependency-Check (SCA)   : 4 CVE (Critical=3 High=1)
```

On ouvre ensuite `reports/demo/v1.0-vulnerable/bandit.html` et `dependency-check-report.html` pour montrer l'injection SQL (B608), l'injection de commande (B602) et PyYAML (CVE-2020-1747).

**Étape 2 : les correctifs**

```powershell
git diff v1.0-vulnerable v2.0-secure -- app/app.py requirements.txt Dockerfile
```

**Étape 3 : les scanners ne signalent plus les problèmes corrigés**

```powershell
.\scripts\scan.ps1 -Ref v2.0-secure
```

```
================ SYNTHESE : v2.0-secure ================
Bandit (SAST)            : High=0  Medium=0  Low=2
pip-audit (SCA)          : 0 vulnerabilite(s) dans 0 paquet(s)
Dependency-Check (SCA)   : 0 CVE (Critical=0 High=0)
```

**Étape 4 : l'application corrigée fonctionne**

```powershell
docker build -t notes-app:secure .
$key = python -c "import secrets; print(secrets.token_hex(32))"
docker run -d --name notes-secure -p 5000:5000 -e SECRET_KEY=$key -e ADMIN_PASSWORD="UnMotDePasseRobuste!" notes-app:secure
docker exec notes-secure id -un          # -> appuser (non-root)
```

Puis, sur http://localhost:5000 : création d'un compte, d'une note, recherche, et ping de `127.0.0.1`. Un ping vers un hôte qui n'est pas une adresse IP est refusé (HTTP 400).

Pour reconstruire l'image **initiale** à des fins de comparaison :

```powershell
git worktree add ..\tp1-v1 v1.0-vulnerable
docker build -t notes-app:vulnerable ..\tp1-v1
git worktree remove ..\tp1-v1
```

### 5.2 Tableau récapitulatif avant / après

| | Version initiale (`v1.0-vulnerable`) | Version corrigée (`v2.0-secure`) |
|---|:---:|:---:|
| Bandit, High | 4 | **0** |
| Bandit, Medium | 7 | **0** |
| Bandit, Low | 4 | 2 (acceptés, cf. §3.4) |
| pip-audit | 47 vulnérabilités (9 paquets) | **0** |
| Dependency-Check, projet | 4 CVE (3 Critical) | **0** |
| Dependency-Check, image | 44 alertes (7 Critical) | **0** |
| Image de base | Python 3.7 (EOL), root | Python 3.13, non-root |

---

## 6. Aller plus loin : intégration continue (shift-left automatisé)

Lancer les scans à la main une fois ne suffit pas : de nouvelles CVE sont publiées chaque jour et chaque commit peut introduire une faille. Le workflow [`.github/workflows/security.yml`](.github/workflows/security.yml) exécute automatiquement les contrôles à chaque *push* et *pull request* :

| Job | Condition d'échec du pipeline |
|---|---|
| SAST : Bandit | Un problème de sévérité ≥ **Medium** |
| SCA : pip-audit | Une vulnérabilité connue dans `requirements.txt` |
| SCA : OWASP Dependency-Check | Une CVE de score **CVSS ≥ 7** (`--failOnCVSS 7`) ; base NVD mise en cache |
| Build Docker | L'image ne se construit pas |

Une pull request qui réintroduirait `shell=True` ou une version vulnérable de PyYAML serait donc **bloquée avant la fusion**. C'est l'application concrète du shift-left.

---

## 7. Bilan

**Travail réalisé**

- **SAST** : 15 problèmes détectés par Bandit, dont 4 High et 7 Medium. **11 vulnérabilités High/Medium corrigées** : injection SQL, injection de commande, XSS, désérialisation pickle, `yaml.load`, MD5, TLS non vérifié, absence de timeout, mode debug… ainsi que les secrets en dur. Il reste 2 alertes Low, analysées et justifiées.
- **SCA** : 47 vulnérabilités connues dans 9 dépendances, dont plusieurs **Critical (CVSS 9.8)**. **Toutes les dépendances ont été mises à jour**, avec une justification détaillée pour PyYAML (exécution de code à distance directement exploitable via `/import`). Il reste 0 vulnérabilité selon les deux outils.
- **Image Docker** reconstruite sur une base maintenue, sans root, avec un serveur de production.
- **Démonstration reproductible** (`scripts/scan.ps1` sur les tags Git) et **pipeline CI**.

**Enseignements**

1. Le SAST trouve vite les erreurs de codage classiques, mais produit des alertes à **trier** (confiance *Low*, alertes génériques). Il ne voit pas les failles de logique (SSRF, contrôle d'accès, CSRF).
2. La SCA est indispensable : **la majorité des vulnérabilités du projet venaient du code des autres** (47 contre 15).
3. Les outils SCA ne trouvent pas tous la même chose. Dependency-Check, basé sur les CPE, rate beaucoup de paquets Python ; il faut **combiner plusieurs sources** et scanner l'image livrée.
4. SAST et SCA se renforcent mutuellement : `yaml.load` (Bandit) + PyYAML 5.3 (Dependency-Check) = RCE ; `debug=True` (Bandit) + Werkzeug 0.14 (PIN prévisible dans Docker) = RCE.

**Pistes d'amélioration** (hors périmètre de ce TP)

- Protection **CSRF** des formulaires (Flask-WTF).
- `requirements.txt` avec **empreintes** (`pip-compile --generate-hashes`) contre la substitution de paquets.
- **Dependabot / Renovate** pour proposer automatiquement les mises à jour.
- Scan de l'image complète, paquets Debian compris (**Trivy**, Grype), et image de base épinglée par **digest**.
- Détection de secrets dans l'historique Git (**gitleaks**). Les anciens secrets, présents dans l'historique de `v1.0-vulnerable`, doivent être considérés comme compromis.
- Tests dynamiques (**DAST**, par exemple OWASP ZAP) sur l'application déployée.

---

## 8. Annexes

### Annexe A : détail des vulnérabilités des dépendances (avant mise à jour)

Source : `pip-audit` (identifiants et versions corrigées) croisé avec Dependency-Check (scores CVSS de la NVD). « non vu par DC » signifie que Dependency-Check n'a pas détecté la vulnérabilité (cf. §4.7).

| Paquet | Version initiale | Identifiant | CVE | CVSS (NVD, via Dependency-Check) | Corrige en | Version retenue |
|---|---|---|---|---|---|---|
| flask | 0.12.2 | PYSEC-2019-179 | CVE-2019-1010083 | *non vu par DC* | 1.0 | 3.1.3 |
| flask | 0.12.2 | PYSEC-2018-66 | CVE-2018-1000656 | *non vu par DC* | 0.12.3 | 3.1.3 |
| flask | 0.12.2 | PYSEC-2023-62 | CVE-2023-30861 | *non vu par DC* | 2.2.5, 2.3.2 | 3.1.3 |
| flask | 0.12.2 | PYSEC-2026-2151 | CVE-2026-27205 | *non vu par DC* | 3.1.3 | 3.1.3 |
| werkzeug | 0.14.1 | PYSEC-2019-140 | CVE-2019-14806 | 7.5 (High) | 0.15.3 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2022-203 | CVE-2022-29361 | 9.8 (Critical) | 2.1.1 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-1065 | CVE-2019-14322 | 7.5 (High) | 0.15.5 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2023-57 | CVE-2023-23934 | 3.5 (Low) | 2.2.3 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2023-58 | CVE-2023-25577 | 7.5 (High) | 2.2.3 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2023-221 | CVE-2023-46136 | 7.5 (High) | 2.3.8, 3.0.1 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-2043 | CVE-2024-34069 | 7.5 (High) | 3.0.3 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-2045 | CVE-2024-49766 | 5.3 (Medium) | 3.0.6 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-2046 | CVE-2025-66221 | 5.3 (Medium) | 3.1.4 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-2044 | CVE-2026-21860 | 5.3 (Medium) | 3.1.5 | 3.1.9 |
| werkzeug | 0.14.1 | PYSEC-2026-2320 | CVE-2026-27199 | 5.3 (Medium) | 3.1.6 | 3.1.9 |
| werkzeug | 0.14.1 | CVE-2026-102598 | CVE-2026-102598 | *non vu par DC* | 3.1.9 | 3.1.9 |
| jinja2 | 2.10 | PYSEC-2021-66 | CVE-2020-28493 | *non vu par DC* | 2.11.3 | 3.1.6 |
| jinja2 | 2.10 | PYSEC-2019-217 | CVE-2019-10906 | *non vu par DC* | 2.10.1 | 3.1.6 |
| jinja2 | 2.10 | PYSEC-2026-1473 | CVE-2024-22195 | *non vu par DC* | 3.1.3 | 3.1.6 |
| jinja2 | 2.10 | PYSEC-2026-1474 | CVE-2024-34064 | *non vu par DC* | 3.1.4 | 3.1.6 |
| jinja2 | 2.10 | PYSEC-2026-1475 | CVE-2024-56326 | *non vu par DC* | 3.1.5 | 3.1.6 |
| jinja2 | 2.10 | PYSEC-2026-1471 | CVE-2025-27516 | *non vu par DC* | 3.1.6 | 3.1.6 |
| pyyaml | 5.3 | PYSEC-2020-96 | CVE-2020-1747 | 9.8 (Critical) | 5.3.1 | 6.0.3 |
| pyyaml | 5.3 | PYSEC-2021-142 | CVE-2020-14343 | 9.8 (Critical) | 5.4 | 6.0.3 |
| requests | 2.19.1 | PYSEC-2018-28 | CVE-2018-18074 | 7.5 (High) | 2.20.0 | 2.34.2 |
| requests | 2.19.1 | PYSEC-2023-74 | CVE-2023-32681 | 6.1 (Medium) | 2.31.0 | 2.34.2 |
| requests | 2.19.1 | PYSEC-2026-1873 | CVE-2024-35195 | *non vu par DC* | 2.32.0 | 2.34.2 |
| requests | 2.19.1 | PYSEC-2026-1872 | CVE-2024-47081 | *non vu par DC* | 2.32.4 | 2.34.2 |
| requests | 2.19.1 | PYSEC-2026-2275 | CVE-2026-25645 | 5.5 (Medium) | 2.33.0 | 2.34.2 |
| urllib3 | 1.23 | PYSEC-2019-133 | CVE-2019-11324 | *non vu par DC* | 1.24.2 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2019-132 | CVE-2019-11236 | *non vu par DC* | 1.24.3 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2020-148 | CVE-2020-26137 | *non vu par DC* | 1.25.9 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-1995 | CVE-2024-37891 | *non vu par DC* | 1.26.19, 2.2.2 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2023-192 | CVE-2023-43804 | *non vu par DC* | 1.26.17, 2.0.6 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2023-207 | CVE-2018-25091 | *non vu par DC* | 1.24.2 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2023-212 | CVE-2023-45803 | *non vu par DC* | 1.26.18, 2.0.7 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-1999 | CVE-2025-50181 | *non vu par DC* | 2.5.0 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-1994 | CVE-2025-66471 | *non vu par DC* | 2.6.0 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-1996 | CVE-2026-21441 | *non vu par DC* | 2.6.3 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-141 | CVE-2026-44431 | *non vu par DC* | 2.7.0 | 2.8.0 |
| urllib3 | 1.23 | PYSEC-2026-4177 | CVE-2026-97689 | *non vu par DC* | 2.8.0 | 2.8.0 |
| idna | 2.7 | PYSEC-2024-60 | CVE-2024-3651 | *non vu par DC* | 3.7 | 3.20 |
| idna | 2.7 | PYSEC-2026-215 | CVE-2026-45409 | *non vu par DC* | 3.15 | 3.20 |
| certifi | 2018.4.16 | PYSEC-2022-42986 | CVE-2022-23491 | 7.5 (High) | 2022.12.7 | 2026.7.22 |
| certifi | 2018.4.16 | PYSEC-2023-135 | CVE-2023-37920 | 9.8 (Critical) | 2023.7.22 | 2026.7.22 |
| gunicorn | 19.9.0 | PYSEC-2026-1434 | CVE-2024-1135 | *non vu par DC* | 22.0.0 | 26.2.0 |
| gunicorn | 19.9.0 | PYSEC-2026-1433 | CVE-2024-6827 | *non vu par DC* | 22.0.0 | 26.2.0 |

### Annexe B : fichiers de rapport

| Fichier | Contenu |
|---|---|
| `reports/sast/bandit-before.{txt,json,html}` | Bandit, version initiale |
| `reports/sast/bandit-after.{txt,json,html}` | Bandit, version corrigée |
| `reports/sca/dependency-check-before.{html,json}` | Dependency-Check sur le projet, version initiale |
| `reports/sca/dependency-check-image-before.{html,json}` | Dependency-Check sur les paquets de l'image, version initiale |
| `reports/sca/dependency-check-after.{html,json}` / `-image-after` | Idem, version corrigée |
| `reports/sca/pip-audit-before.{txt,json}` / `-after` | pip-audit avant / après |

### Annexe C : correspondance avec l'OWASP Top 10 (2021)

| Catégorie OWASP | Vulnérabilités du projet |
|---|---|
| A01 Broken Access Control | Outils réseau accessibles sans authentification |
| A02 Cryptographic Failures | MD5 (B324), TLS non vérifié (B501), magasin `certifi` obsolète |
| A03 Injection | Injection SQL (B608), injection de commande (B602), XSS (B704) |
| A05 Security Misconfiguration | `debug=True` (B201), écoute `0.0.0.0` (B104), conteneur root |
| A06 Vulnerable and Outdated Components | 47 CVE dans les dépendances, Python 3.7 en fin de vie |
| A07 Identification and Authentication Failures | Secrets et mot de passe admin en dur (B105) |
| A08 Software and Data Integrity Failures | Désérialisation pickle (B301), `yaml.load` (B506) |
| A10 Server-Side Request Forgery | `/tools/fetch` |
