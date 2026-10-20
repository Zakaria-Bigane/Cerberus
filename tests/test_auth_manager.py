"""Tests du gestionnaire d'authentification — JWT fabriqués à la main, zéro réseau."""
import base64
import json
import time

import pytest

from core.auth_manager import AuthManager


def fabriquer_jwt(payload: dict) -> str:
    """Construit un faux JWT (header.payload.signature) sans lib ni réseau."""
    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(payload)}.fakesig"


@pytest.fixture
def auth(tmp_path):
    """Un AuthManager avec une config YAML minimale, sans jamais toucher le réseau."""
    cfg = tmp_path / "audit_config.yaml"
    cfg.write_text(
        "auth:\n"
        "  type: rest\n"
        "  login_path: /login\n"
        "  token_response_key: token\n"
        "  accounts:\n"
        "    user_a:\n"
        "      username: A\n"
        "      password: a\n",
        encoding="utf-8",
    )
    return AuthManager("http://localhost:9999", str(cfg))


# ── Détection d'expiration ───────────────────────────────────────────────────

def test_token_valide_non_expire(auth):
    jwt = fabriquer_jwt({"exp": int(time.time()) + 3600})
    assert auth._is_token_expired(jwt) is False


def test_token_deja_expire(auth):
    jwt = fabriquer_jwt({"exp": int(time.time()) - 10})
    assert auth._is_token_expired(jwt) is True


def test_token_dans_la_marge_de_securite_considere_expire(auth):
    """Buffer de 10 s : un token qui expire dans 5 s doit être renouvelé."""
    jwt = fabriquer_jwt({"exp": int(time.time()) + 5})
    assert auth._is_token_expired(jwt) is True


def test_sans_champ_exp_ne_expire_pas(auth):
    jwt = fabriquer_jwt({"sub": "user"})
    assert auth._is_token_expired(jwt) is False


def test_payload_non_json_force_le_renouvellement(auth):
    """3 parties mais payload illisible → exception de parsing → renouvellement forcé."""
    assert auth._is_token_expired("aaa.ceci-n-est-pas-du-base64-json!!!.bbb") is True


def test_base64_valide_mais_pas_json_force_le_renouvellement(auth):
    """Payload décodable en texte mais invalide en JSON → par sécurité, expiré."""
    import base64 as b64m
    payload = b64m.urlsafe_b64encode(b"pas du json").rstrip(b"=").decode()
    assert auth._is_token_expired(f"h.{payload}.s") is True


def test_token_non_jwt_jamais_repute_expire(auth):
    """Un token opaque (2 parties ou sans points) n'est pas vérifiable → pas expiré."""
    assert auth._is_token_expired("abc123") is False


# ── En-têtes d'authentification ──────────────────────────────────────────────

def test_role_unauth_retourne_en_tetes_anonymes(auth):
    headers = auth.get_auth_headers("unauth")
    assert "Authorization" not in headers
    assert headers["Content-Type"] == "application/json"


def test_role_inconnu_sans_reseau_tombe_en_anonyme(auth, monkeypatch):
    """Si le login échoue (rôle absent de la config), on retombe sur anonyme
    sans lever d'exception."""
    monkeypatch.setattr(auth, "_login_and_get_token", lambda role: None)
    headers = auth.get_auth_headers("user_z")
    assert "Authorization" not in headers


def test_token_valide_reutilise_sans_reconnexion(auth, monkeypatch):
    """Un token non expiré en cache ne doit PAS déclencher un nouveau login."""
    jwt_valide = fabriquer_jwt({"exp": int(time.time()) + 3600})
    appels = []

    def faux_login(role):
        appels.append(role)
        return jwt_valide

    monkeypatch.setattr(auth, "_login_and_get_token", faux_login)

    h1 = auth.get_auth_headers("user_a")
    h2 = auth.get_auth_headers("user_a")
    assert h1["Authorization"] == f"Bearer {jwt_valide}"
    assert h2 == h1
    assert len(appels) == 1, "Le token en cache aurait dû éviter un second login"


def test_token_expire_declenche_un_refresh(auth, monkeypatch):
    expire = fabriquer_jwt({"exp": int(time.time()) - 1})
    neuf = fabriquer_jwt({"exp": int(time.time()) + 3600})
    séquence = [expire, neuf]

    monkeypatch.setattr(auth, "_login_and_get_token", lambda role: séquence.pop(0))

    h1 = auth.get_auth_headers("user_a")
    assert "Authorization" in h1          # premier login → token expiré accepté une fois ?
    # Forçons le cache sur le token expiré puis redemandons :
    auth._active_tokens["user_a"] = expire
    h2 = auth.get_auth_headers("user_a")
    assert h2["Authorization"] == f"Bearer {neuf}", "Le refresh aurait dû remplacer le token expiré"


def test_config_absente_ne_crash_pas(tmp_path):
    am = AuthManager("http://x", str(tmp_path / "inexistant.yaml"))
    assert am.config == {}
