"""Usage : python phishing.py <url> [<url> ...]   |   python phishing.py -f liste.txt"""
import sys

from src.analyseur import analyser


def main(args):
    if not args:
        print(__doc__)
        return 1
    urls = open(args[1], encoding="utf-8").read().split() if args[0] == "-f" and len(args) > 1 else args
    pire = 0
    for url in urls:
        r = analyser(url)
        pire = max(pire, r.score)
        print(f"\n{r.url}\n  -> {r.verdict} (score {r.score}/100)")
        for raison in r.raisons:
            print("     ", raison)
    return 2 if pire >= 60 else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
