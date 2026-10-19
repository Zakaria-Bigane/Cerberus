"""
Module d'affichage pour Cerberus — API Access Control Auditor.
Gère la bannière ASCII, les couleurs du terminal et les marqueurs de statut
normalisés (à la manière des outils de sécurité comme nmap, sqlmap, nikto).
"""

# --- Couleurs ANSI ---------------------------------------------------
# colorama rend les couleurs ANSI fonctionnelles sous Windows.
try:
    from colorama import init as _cinit, Fore, Style
    _cinit()  # active la traduction ANSI -> API Windows
    _VERT   = Fore.GREEN
    _ROUGE  = Fore.RED
    _JAUNE  = Fore.YELLOW
    _BLEU   = Fore.CYAN
    _GRAS   = Style.BRIGHT
    _RESET  = Style.RESET_ALL
except ImportError:
    # Repli : si colorama n'est pas installé, on n'affiche pas de couleur
    _VERT = _ROUGE = _JAUNE = _BLEU = _GRAS = _RESET = ""


VERSION = "1.0"
AUTEUR = "Zakaria Bigane"

BANNER = r"""
   ______           __
  / ____/__  _____  / /_  ___  _______  _______
 / /   / _ \/ ___/ / __ \/ _ \/ ___/ / / / ___/
/ /___/  __/ /    / /_/ /  __/ /  / /_/ (__  )
\____/\___/_/    /_.___/\___/_/   \__,_/____/
"""


def afficher_banniere():
    """Affiche la bannière ASCII de Cerberus avec ses informations."""
    print(f"{_BLEU}{_GRAS}{BANNER}{_RESET}")
    print(f"{_GRAS}        API Access Control Auditor{_RESET}  —  BOLA / BFLA")
    print(f"        version {VERSION}   par {AUTEUR}")
    print(f"        {_JAUNE}Les trois têtes veillent : admin · user · anonyme{_RESET}")
    print()


def afficher_entete(cible, type_api, schema=None):
    """Affiche l'en-tête de scan structuré (paramètres de l'audit)."""
    ligne = "=" * 60
    print(f"{_BLEU}{ligne}{_RESET}")
    print(f"  {_GRAS}CIBLE{_RESET}      : {cible}")
    print(f"  {_GRAS}TYPE{_RESET}       : {type_api.upper()}")
    if schema:
        print(f"  {_GRAS}SCHÉMA{_RESET}     : {schema}")
    print(f"  {_GRAS}PÉRIMÈTRE{_RESET}  : BOLA (API1:2023) · BFLA (API5:2023)")
    print(f"{_BLEU}{ligne}{_RESET}\n")


# --- Marqueurs de statut normalisés ----------------------------------
def log_info(message):
    """[*] information / étape en cours (bleu)."""
    print(f"{_BLEU}[*]{_RESET} {message}")


def log_success(message):
    """[+] succès / élément trouvé (vert)."""
    print(f"{_VERT}[+]{_RESET} {message}")


def log_error(message):
    """[-] échec / accès bloqué (rouge)."""
    print(f"{_ROUGE}[-]{_RESET} {message}")


def log_warning(message):
    """[!] avertissement / à examiner (jaune)."""
    print(f"{_JAUNE}[!]{_RESET} {message}")


def log_unknown(message):
    """[?] test non concluant (gris/neutre)."""
    print(f"[?] {message}")


def log_faille(message):
    """[!!!] faille confirmée — mise en évidence forte (rouge gras)."""
    print(f"{_ROUGE}{_GRAS}[!!!] {message}{_RESET}")


def log_public(message):
    """[~] ressource publique / accessible (neutre)."""
    print(f"[~] {message}")


def separateur():
    """Ligne de séparation de section."""
    print(f"{_BLEU}{'=' * 60}{_RESET}")