# Détecteur de phishing

Outil en ligne de commande qui analyse des URL et donne un **score de risque (0–100)** avec les raisons détaillées.
Analyse **statique** : aucune requête n'est envoyée vers le site testé.

## Indices détectés
- adresse IP au lieu d'un nom de domaine, `@` dans l'URL, domaine punycode (`xn--`)
- usurpation de marque (`paypal.com.verification.xyz`) et fautes de frappe volontaires (`paypa1.com`, distance de Levenshtein)
- extensions à risque, trop de sous-domaines ou de tirets, URL très longue, liens raccourcis
- mots sensibles (`login`, `verify`, `password`…), connexion non chiffrée (http)

## Utilisation
```bash
python phishing.py http://paypa1-secure-login.xyz/verify https://www.google.com
python phishing.py -f liste_urls.txt
```
Code de sortie : `2` si une URL est « PHISHING PROBABLE », sinon `0` (pratique dans un script).

Exemple :
```
http://paypa1-secure-login.xyz/verify
  -> PHISHING PROBABLE (score 85/100)
```

## Tests
```bash
pip install pytest && pytest
```

## Limites
Heuristiques : possibles faux positifs/négatifs. À compléter par des listes de réputation (ex. PhishTank) dans une version future.
