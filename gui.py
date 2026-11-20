"""Interface graphique du détecteur de phishing (tkinter, inclus avec Python sous Windows).

Lancer :  python gui.py
"""
import csv
import re
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from src.analyseur import analyser

COULEURS = {"SAIN": "#2e7d32", "SUSPECT": "#ef6c00", "PHISHING PROBABLE": "#c62828"}
FONDS = {"SAIN": "#e8f5e9", "SUSPECT": "#fff3e0", "PHISHING PROBABLE": "#ffebee"}
ETIQUETTES = {"SAIN": "Sain", "SUSPECT": "Suspect", "PHISHING PROBABLE": "Phishing probable"}


def ressemble_a_une_url(mot):
    """Garde les liens (http://…, www.…, domaine.tld, adresse IP) et écarte les mots ordinaires."""
    if "://" in mot:
        return True
    hote = mot.split("/", 1)[0].split("?", 1)[0]
    return bool(re.fullmatch(r"[^\s@]*[A-Za-z0-9\-]\.[A-Za-z0-9\-]{2,}(:\d+)?", hote)) or \
        bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}(:\d+)?", hote))


def extraire_urls(texte):
    """Extrait les liens d'un texte (séparés par espaces, virgules, points-virgules ou retours à la ligne)."""
    vues, urls = set(), []
    for mot in re.split(r"[\s,;]+", texte):
        mot = mot.strip("()[]<>\"'«».!?")
        if mot and mot not in vues and ressemble_a_une_url(mot):
            vues.add(mot)
            urls.append(mot)
    return urls


class Application(ttk.Frame):
    def __init__(self, racine):
        super().__init__(racine, padding=12)
        racine.title("Détecteur de phishing")
        racine.geometry("860x620")
        racine.minsize(700, 520)
        self.pack(fill="both", expand=True)
        self.resultats = {}  # id de ligne -> Resultat
        self._construire()

    def _construire(self):
        ttk.Label(self, text="Détecteur de phishing", font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(self, text="Collez un ou plusieurs liens. L'analyse est locale : aucun site n'est visité.",
                  foreground="#555").pack(anchor="w", pady=(0, 8))

        ligne = ttk.Frame(self)
        ligne.pack(fill="x")
        self.saisie = ttk.Entry(ligne, font=("Segoe UI", 11))
        self.saisie.pack(side="left", fill="x", expand=True, ipady=4)
        self.saisie.bind("<Return>", lambda e: self.analyser_saisie())
        self.saisie.focus_set()
        ttk.Button(ligne, text="Analyser", command=self.analyser_saisie).pack(side="left", padx=(8, 0))

        barre = ttk.Frame(self)
        barre.pack(fill="x", pady=8)
        ttk.Button(barre, text="Importer un fichier .txt…", command=self.importer).pack(side="left")
        ttk.Button(barre, text="Exporter en CSV…", command=self.exporter).pack(side="left", padx=6)
        ttk.Button(barre, text="Tout effacer", command=self.effacer).pack(side="left")

        cadre = ttk.Frame(self)
        cadre.pack(fill="both", expand=True)
        self.tableau = ttk.Treeview(cadre, columns=("verdict", "score", "url"), show="headings", height=9, selectmode="browse")
        self.tableau.heading("verdict", text="Verdict")
        self.tableau.heading("score", text="Score")
        self.tableau.heading("url", text="Lien")
        self.tableau.column("verdict", width=140, anchor="w", stretch=False)
        self.tableau.column("score", width=70, anchor="center", stretch=False)
        self.tableau.column("url", width=560, anchor="w")
        for v, fond in FONDS.items():
            self.tableau.tag_configure(v, background=fond, foreground=COULEURS[v])
        defil = ttk.Scrollbar(cadre, orient="vertical", command=self.tableau.yview)
        self.tableau.configure(yscrollcommand=defil.set)
        self.tableau.pack(side="left", fill="both", expand=True)
        defil.pack(side="right", fill="y")
        self.tableau.bind("<<TreeviewSelect>>", self.afficher_detail)

        detail = ttk.LabelFrame(self, text="Détail de l'analyse", padding=8)
        detail.pack(fill="x", pady=(10, 0))
        self.verdict = ttk.Label(detail, text="Aucune analyse", font=("Segoe UI", 13, "bold"))
        self.verdict.pack(anchor="w")
        self.jauge = tk.Canvas(detail, height=16, highlightthickness=0, background="#e0e0e0")
        self.jauge.pack(fill="x", pady=6)
        self.rectangle = self.jauge.create_rectangle(0, 0, 0, 16, width=0, fill="#2e7d32")
        self.raisons = tk.Text(detail, height=6, wrap="word", state="disabled", relief="flat",
                               background=self.winfo_toplevel().cget("background"), font=("Segoe UI", 10))
        self.raisons.pack(fill="x")

    # ---- actions ----
    def analyser_urls(self, urls):
        for url in urls:
            r = analyser(url)
            ligne = self.tableau.insert("", 0, values=(ETIQUETTES[r.verdict], f"{r.score}/100", r.url), tags=(r.verdict,))
            self.resultats[ligne] = r
        if urls:
            premier = self.tableau.get_children()[0]
            self.tableau.selection_set(premier)

    def analyser_saisie(self):
        urls = extraire_urls(self.saisie.get())
        if not urls:
            messagebox.showinfo("Détecteur de phishing", "Aucun lien reconnu. Collez une adresse comme https://exemple.com ou exemple.com/page.")
            return
        self.analyser_urls(urls)
        self.saisie.delete(0, "end")

    def importer(self):
        chemin = filedialog.askopenfilename(title="Fichier de liens (un par ligne)",
                                            filetypes=[("Texte", "*.txt"), ("Tous les fichiers", "*.*")])
        if not chemin:
            return
        try:
            with open(chemin, encoding="utf-8-sig") as f:
                urls = extraire_urls(f.read())
        except (OSError, UnicodeDecodeError) as e:
            messagebox.showerror("Erreur", f"Lecture impossible :\n{e}")
            return
        if not urls:
            messagebox.showinfo("Détecteur de phishing", "Aucun lien trouvé dans ce fichier.")
            return
        self.analyser_urls(urls[:500])

    def exporter(self):
        if not self.resultats:
            messagebox.showinfo("Détecteur de phishing", "Rien à exporter pour le moment.")
            return
        chemin = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="resultats-phishing.csv",
                                              filetypes=[("CSV (Excel)", "*.csv")])
        if not chemin:
            return
        try:
            with open(chemin, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f, delimiter=";")
                w.writerow(["Lien", "Verdict", "Score", "Raisons"])
                for ligne in reversed(self.tableau.get_children()):
                    r = self.resultats[ligne]
                    w.writerow([r.url, ETIQUETTES[r.verdict], r.score, " | ".join(r.raisons)])
        except OSError as e:
            messagebox.showerror("Erreur", f"Écriture impossible :\n{e}")
            return
        messagebox.showinfo("Détecteur de phishing", "Export terminé.")

    def effacer(self):
        self.tableau.delete(*self.tableau.get_children())
        self.resultats.clear()
        self._afficher(None)

    def afficher_detail(self, _evt=None):
        sel = self.tableau.selection()
        self._afficher(self.resultats.get(sel[0]) if sel else None)

    def _afficher(self, r):
        self.raisons.configure(state="normal")
        self.raisons.delete("1.0", "end")
        if r is None:
            self.verdict.configure(text="Aucune analyse", foreground="#000")
            self.jauge.coords(self.rectangle, 0, 0, 0, 16)
        else:
            self.verdict.configure(text=f"{ETIQUETTES[r.verdict]} — score {r.score}/100", foreground=COULEURS[r.verdict])
            self.jauge.update_idletasks()
            largeur = max(self.jauge.winfo_width(), 1)
            self.jauge.coords(self.rectangle, 0, 0, largeur * r.score / 100, 16)
            self.jauge.itemconfigure(self.rectangle, fill=COULEURS[r.verdict])
            self.raisons.insert("end", "\n".join(r.raisons) if r.raisons else "Aucun indice suspect détecté.")
        self.raisons.configure(state="disabled")


def main():
    racine = tk.Tk()
    try:
        ttk.Style().theme_use("vista")  # thème natif Windows ; ignoré ailleurs
    except tk.TclError:
        pass
    Application(racine)
    racine.mainloop()


if __name__ == "__main__":
    main()
