import httpx

# On récupère le schéma (comme le fait ton parser)
url_schema = "http://localhost:5002/openapi.json"
schema = httpx.get(url_schema).json()
paths = schema["paths"]

# ── Mots-clés génériques (pas de nom propre à VAmPI) ─────────────────
MOTS_USERNAME = ["username", "email", "login", "user"]
MOTS_PASSWORD = ["password", "passwd", "pwd", "pass"]
MOTS_CHEMIN_AUTH = ["login", "signin", "authenticate", "auth", "token", "session"]
MOTS_TOKEN_REPONSE = ["token", "auth_token", "access_token", "jwt", "bearer"]


def score_login(chemin, methode, operation):
    """
    Calcule un score de probabilité qu'un endpoint soit un login.
    Plus le score est élevé, plus c'est probablement le login.
    """
    score = 0
    raisons = []

    # Signature 4 : un login est un POST
    if methode.lower() != "post":
        return 0, []   # pas un POST → jamais un login, on arrête

    # Signature 1 (la plus forte) : le body contient username ET password
    body = operation.get("requestBody", {})
    contenu = body.get("content", {}).get("application/json", {})
    proprietes = contenu.get("schema", {}).get("properties", {})
    champs = [c.lower() for c in proprietes.keys()]

    a_username = any(any(m in champ for m in MOTS_USERNAME) for champ in champs)
    a_password = any(any(m in champ for m in MOTS_PASSWORD) for champ in champs)

    if a_username and a_password:
        score += 5
        raisons.append("body contient username + password")

    # Signature 2 : le chemin contient un mot d'authentification
    if any(mot in chemin.lower() for mot in MOTS_CHEMIN_AUTH):
        score += 3
        raisons.append("chemin evoque l'authentification")

    # Signature 3 : la réponse déclare un token
    reponses = operation.get("responses", {})
    texte_reponses = str(reponses).lower()
    if any(mot in texte_reponses for mot in MOTS_TOKEN_REPONSE):
        score += 2
        raisons.append("reponse contient un token")

    return score, raisons


# ── On teste sur tous les endpoints ──────────────────────────────────
meilleur_score = 0
meilleur_login = None
meilleures_raisons = []

print("Analyse de tous les endpoints :\n")
for chemin in paths:
    for methode in paths[chemin]:
        operation = paths[chemin][methode]
        score, raisons = score_login(chemin, methode, operation)
        if score > 0:
            print(f"  {methode.upper():5} {chemin:35} -> score {score} ({', '.join(raisons)})")
        if score > meilleur_score:
            meilleur_score = score
            meilleur_login = f"{methode.upper()} {chemin}"
            meilleures_raisons = raisons

print("\n" + "="*55)
if meilleur_login:
    print(f"LOGIN DÉTECTÉ : {meilleur_login}")
    print(f"Score : {meilleur_score}")
    print(f"Raisons : {', '.join(meilleures_raisons)}")
else:
    print("Aucun endpoint de login détecté automatiquement.")