# TP1 DevSecOps : SAST & SCA sur une application Flask

Application de prise de notes (Python/Flask) utilisée pour le TP1 *Analyse statique (SAST) et sécurité des dépendances (SCA)*.

Le rapport complet, avec les explications, les résultats et la démonstration, se trouve dans **[RAPPORT.md](RAPPORT.md)**.

| Version | Tag Git | Bandit (High/Med/Low) | Vulnérabilités des dépendances |
|---|---|---|---|
| Initiale (vulnérable) | `v1.0-vulnerable` | 4 / 7 / 4 | 47 (pip-audit), 4 CVE (Dependency-Check) |
| Corrigée | `v2.0-secure` | 0 / 0 / 2 | 0 |

## Lancer l'application

```powershell
docker build -t notes-app:secure .
docker run -d -p 5000:5000 -e SECRET_KEY=remplacer-par-une-valeur-aleatoire -e ADMIN_PASSWORD=remplacer-par-un-mot-de-passe notes-app:secure
```

Puis ouvrir http://localhost:5000.

## Lancer les scans (Docker requis)

```powershell
.\scripts\scan.ps1 -Ref v1.0-vulnerable   # avant
.\scripts\scan.ps1 -Ref v2.0-secure       # après
```

Le script lance Bandit (SAST), pip-audit et OWASP Dependency-Check (SCA) sur la version Git demandée. Les rapports sont écrits dans `reports/demo/<version>/`.

Les rapports de référence se trouvent dans `reports/sast/` et `reports/sca/`.
