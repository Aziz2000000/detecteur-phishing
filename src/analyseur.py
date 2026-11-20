"""Détection heuristique d'URL de phishing (analyse statique, sans accès réseau)."""
import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

MARQUES = {  # marque -> domaine légitime
    "paypal": "paypal.com", "google": "google.com", "facebook": "facebook.com",
    "microsoft": "microsoft.com", "apple": "apple.com", "amazon": "amazon.com",
    "orange": "orange.com", "wave": "wave.com", "whatsapp": "whatsapp.com",
}
MOTS_SUSPECTS = ("login", "signin", "verify", "verification", "secure", "account", "update",
                 "confirm", "password", "banking", "wallet", "connexion", "compte")
TLD_RISQUES = {"zip", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "country"}
RACCOURCISSEURS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly"}


@dataclass
class Resultat:
    url: str
    score: int = 0
    raisons: list = field(default_factory=list)

    @property
    def verdict(self):
        return "PHISHING PROBABLE" if self.score >= 60 else "SUSPECT" if self.score >= 30 else "SAIN"

    def ajouter(self, points, raison):
        self.score = min(100, self.score + points)
        self.raisons.append(f"+{points} {raison}")


def distance(a, b):
    """Distance de Levenshtein."""
    prec = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cour = [i]
        for j, cb in enumerate(b, 1):
            cour.append(min(prec[j] + 1, cour[j - 1] + 1, prec[j - 1] + (ca != cb)))
        prec = cour
    return prec[-1]


def domaine_enregistre(hote):
    p = hote.split(".")
    if len(p) >= 3 and p[-2] in ("co", "com", "org", "gov", "ac") and len(p[-1]) == 2:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def analyser(url):
    r = Resultat(url)
    brut = url if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I) else "http://" + url
    u = urlparse(brut)
    hote = (u.hostname or "").lower()
    if not hote:
        r.ajouter(100, "URL illisible")
        return r

    try:
        ipaddress.ip_address(hote)
        r.ajouter(40, "adresse IP à la place d'un nom de domaine")
    except ValueError:
        pass
    if u.scheme == "http":
        r.ajouter(10, "connexion non chiffrée (http)")
    if "@" in u.netloc:
        r.ajouter(35, "caractère « @ » dans l'adresse (masque la vraie destination)")
    if hote.startswith("xn--") or ".xn--" in hote:
        r.ajouter(30, "domaine en punycode (caractères imitant d'autres lettres)")
    if hote in RACCOURCISSEURS:
        r.ajouter(20, "lien raccourci : destination cachée")
    if len(url) > 75:
        r.ajouter(10, "URL très longue")
    sous = max(hote.count(".") - 1, 0)
    if sous >= 3:
        r.ajouter(15, f"{sous} niveaux de sous-domaines")
    if hote.count("-") >= 3:
        r.ajouter(10, "nombreux tirets dans le domaine")
    tld = hote.rsplit(".", 1)[-1]
    if tld in TLD_RISQUES:
        r.ajouter(15, f"extension « .{tld} » souvent utilisée pour des abus")
    chemin = (u.path + "?" + u.query).lower()
    trouves = [m for m in MOTS_SUSPECTS if m in hote or m in chemin]
    if trouves:
        r.ajouter(min(10 * len(trouves), 20), "mots sensibles : " + ", ".join(trouves[:3]))

    reg = domaine_enregistre(hote)
    nom = reg.split(".")[0]
    for marque, legit in MARQUES.items():
        if reg == legit:
            break
        if marque in hote:
            r.ajouter(35, f"cite « {marque} » mais le domaine réel est {reg}")
            break
        jetons = [nom] + nom.split("-")
        if any(j != marque and len(j) >= 5 and 0 < distance(j, marque) <= 2 for j in jetons):
            r.ajouter(40, f"ressemble à « {marque} » (faute de frappe volontaire ?)")
            break
    return r
