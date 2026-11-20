from src.analyseur import analyser, distance, domaine_enregistre


def test_distance():
    assert distance("paypal", "paypa1") == 1 and distance("a", "a") == 0


def test_domaine_enregistre():
    assert domaine_enregistre("www.google.com") == "google.com"
    assert domaine_enregistre("shop.example.co.uk") == "example.co.uk"


def test_sites_legitimes_sains():
    for u in ("https://www.google.com", "https://accounts.google.com/signin", "https://fr.wikipedia.org/wiki/Python"):
        assert analyser(u).verdict == "SAIN", u


def test_phishing_detecte():
    for u in ("http://paypa1-secure-login.xyz/verify", "http://192.168.1.5/login", "https://google.com@evil.top/"):
        assert analyser(u).verdict != "SAIN", u
    assert analyser("http://paypa1.com/login/verify").verdict == "PHISHING PROBABLE"


def test_marque_dans_sous_domaine():
    r = analyser("https://paypal.com.verification-compte.xyz")
    assert r.verdict == "PHISHING PROBABLE"
