"""Tests des oracles BOLA — faux client HTTP, aucune cible vivante requise.

On injecte un RequestHandler factice qui renvoie des réponses scriptées et on
vérifie les verdicts de l'oracle à états (REST) et de l'oracle GraphQL.
"""
import json

import pytest

from core.request_handler import AuditResponse
from engines.bola_engine import BolaEngine
from models.endpoint import ApiType, Parameter, ParamLocation, UnifiedEndpoint


class FauxAuth:
    def get_auth_headers(self, role):
        return {"Authorization": "Bearer fake", "Content-Type": "application/json"}


class FauxHandler:
    """RequestHandler simulé : renvoie une réponse programmée par (path, headers)."""

    def __init__(self, reponses):
        self.reponses = reponses   # liste de AuditResponse consommée dans l'ordre
        self.envois = []           # journal des (endpoint, headers) pour assertions

    def send(self, base_url, endpoint, headers, params_map):
        self.envois.append((endpoint, headers))
        if self.reponses:
            return self.reponses.pop(0)
        return AuditResponse(0, "", 0, 0.0)


def ep_rest(methode="GET", chemin="/users/v1/{user_id}", avec_id=True):
    e = UnifiedEndpoint(ApiType.REST, chemin, methode, f"{methode} {chemin}")
    if avec_id:
        e.parameters.append(Parameter("user_id", ParamLocation.PATH, "string", True, True))
    return e


@pytest.fixture
def engine():
    def _make(responses):
        handler = FauxHandler(responses)
        return BolaEngine(FauxAuth(), handler), handler
    return _make


# ── Oracle à états REST ──────────────────────────────────────────────────────

def test_200_avec_token_autre_utilisateur_est_vulnerable(engine):
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(200, "{}", 2, 0.1)) == "VULNERABLE"


def test_403_est_bloque(engine):
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(403, "Forbidden", 9, 0.1)) == "BLOQUE"


def test_404_est_bloque(engine):
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(404, "", 0, 0.1)) == "BLOQUE"


def test_400_et_401_sont_non_concluants(engine):
    """Une requête malformée ou un échec d'authentification ne prouve rien."""
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(400, "", 0, 0.1)) == "NON_CONCLUANT"
    assert eng._analyze_response(AuditResponse(401, "", 0, 0.1)) == "NON_CONCLUANT"


def test_erreur_reseau_est_non_concluante(engine):
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(0, "ConnectionError", 0, 0.0)) == "NON_CONCLUANT"


def test_5xx_est_non_concluant(engine):
    eng, _ = engine([])
    assert eng._analyze_response(AuditResponse(500, "", 0, 0.1)) == "NON_CONCLUANT"


# ── Contre-test « ressource publique » ───────────────────────────────────────

def test_reponse_ok_sans_token_classe_publique(engine):
    """Si l'anonyme obtient un 200, le 200 authentifié n'est PAS un BOLA."""
    eng, handler = engine([AuditResponse(200, "{\"id\": 1}", 8, 0.1)])
    assert eng._est_ressource_publique("http://x", ep_rest(), {"user_id": "2"}) is True
    assert len(handler.envois) == 1


def test_refus_anonyme_confirme_prive(engine):
    eng, _ = engine([AuditResponse(401, "", 0, 0.1)])
    assert eng._est_ressource_publique("http://x", ep_rest(), {"user_id": "2"}) is False


# ── Recherche de l'endpoint de lecture (oracle d'effet) ──────────────────────

def test_trouve_le_get_prefixe_le_plus_specifique(engine):
    eng, _ = engine([])
    ecriture = ep_rest("PUT", "/users/v1/{username}/email")
    ecriture.parameters = [Parameter("username", ParamLocation.PATH, "string", True, True)]
    candidats = [
        ep_rest("GET", "/users/v1"),                       # préfixe court, sans ID
        ep_rest("GET", "/users/v1/{username}"),            # préfixe long, avec ID ✔
        ep_rest("POST", "/users/v1/{username}"),           # pas un GET → ignoré
    ]
    trouve = eng._trouver_endpoint_lecture(ecriture, candidats)
    assert trouve is not None and trouve.path == "/users/v1/{username}"


def test_aucun_get_correspondant_renvoie_none(engine):
    eng, _ = engine([])
    ecriture = ep_rest("DELETE", "/orders/{order_id}")
    assert eng._trouver_endpoint_lecture(ecriture, [ep_rest("GET", "/users/{id}")]) is None


# ── Heuristiques d'écriture / credential ─────────────────────────────────────

def test_methods_ecriture_detectees(engine):
    eng, _ = engine([])
    assert eng._est_ecriture(ep_rest("PUT"))
    assert eng._est_ecriture(ep_rest("DELETE"))
    assert not eng._est_ecriture(ep_rest("GET"))


def test_endpoint_credential_detecte_par_chemin(engine):
    eng, _ = engine([])
    assert eng._est_endpoint_credential(ep_rest("PUT", "/users/v1/{username}/password"))


def test_endpoint_credential_detecte_par_body(engine):
    eng, _ = engine([])
    e = ep_rest("PUT", "/users/v1/{username}/account")
    e.body_template = {"email": "a@b.c", "password": "x"}
    assert eng._est_endpoint_credential(e)


def test_endpoint_normal_pas_credential(engine):
    eng, _ = engine([])
    e = ep_rest("PUT", "/users/v1/{username}/account")
    e.body_template = {"nickname": "al"}
    assert not eng._est_endpoint_credential(e)


# ── Oracle GraphQL (data vs errors, HTTP toujours 200) ───────────────────────

def gql_reponse(corps: dict):
    texte = json.dumps(corps)
    return AuditResponse(200, texte, len(texte), 0.1, "errors" in corps)


def test_graphql_error_permission_est_bloque(engine):
    eng, _ = engine([])
    rep = gql_reponse({"errors": [{"message": "Not authorized"}]})
    assert eng._analyser_reponse_graphql(rep) == "BLOQUE"


def test_graphql_data_non_nulle_est_vulnerable(engine):
    eng, _ = engine([])
    rep = gql_reponse({"data": {"paste": {"id": 2, "title": "volé"}}})
    assert eng._analyser_reponse_graphql(rep) == "VULNERABLE"


def test_graphql_data_nulle_est_bloque(engine):
    eng, _ = engine([])
    rep = gql_reponse({"data": {"paste": None}})
    assert eng._analyser_reponse_graphql(rep) == "BLOQUE"


def test_graphql_json_invalide_est_non_concluant(engine):
    eng, _ = engine([])
    assert eng._analyser_reponse_graphql(AuditResponse(200, "<html>", 6, 0.1)) == "NON_CONCLUANT"


def test_graphql_error_technique_est_non_concluant(engine):
    """Une erreur serveur GraphQL sans mot d'autorisation ne conclut pas."""
    eng, _ = engine([])
    rep = gql_reponse({"errors": [{"message": "Internal error: division by zero"}]})
    assert eng._analyser_reponse_graphql(rep) == "NON_CONCLUANT"


# ═══ Tests des correctifs de bugs fonctionnels (v1.0.8) ════════════════════

class FauxAuthEchec:
    """L'authentification échoue : get_auth_headers ne renvoie PAS d'Authorization."""
    def get_auth_headers(self, role):
        return {"Content-Type": "application/json"}


def test_run_bola_interrompu_si_attaquant_non_authentifie(engine):
    """FIX auth : sans jeton attaquant, le run s'arrête avec un verdict explicite
    au lieu de produire une cascade de faux BLOQUE/NON_CONCLUANT silencieux."""
    eng, handler = engine([])
    eng.auth_manager = FauxAuthEchec()
    resultats = eng.run([ep_rest("GET")], "http://x", "2")
    assert len(resultats) == 1
    assert resultats[0]["verdict"] == "NON_CONCLUANT"
    assert handler.envois == []   # aucune requête d'attaque envoyée


def test_ecriture_rest_jouee_une_seule_fois(engine):
    """FIX tir unique : PUT avec endpoint de lecture → la séquence oracle est
    lire_avant / attaque / lire_apres (3 envois), PAS attaque_puis 3_rejoues (4)."""
    ep_ecriture = ep_rest("PUT", "/users/v1/{username}/email")
    ep_ecriture.parameters = [Parameter("username", ParamLocation.PATH, "string", True, True)]
    ep_lecture = ep_rest("GET", "/users/v1/{username}")
    reponses = [
        AuditResponse(200, '{"email":"old@x"}', 17, 0.1),   # AVANT
        AuditResponse(200, 'ok', 2, 0.1),                    # ATTAQUE
        AuditResponse(200, '{"email":"new@x"}', 17, 0.1),   # APRÈS (changé)
    ]
    eng, handler = engine(reponses)
    resultats = eng.run([ep_ecriture, ep_lecture], "http://x", "victim")
    # L'écriture ne doit être jouée QU'UNE SEULE FOIS (avant : tir + oracle = 2).
    tirs_ecriture = [e for e in handler.envois if e[0] is ep_ecriture or e[0].method == "PUT"]
    assert len(tirs_ecriture) == 1, f"écriture jouée {len(tirs_ecriture)} fois (attendu 1)"
    # Séquence complète attendue : AVANT(lire) → ATTAQUE(écrire) → APRÈS(lire) → puis le GET lui-même testé
    assert len(handler.envois) == 4, f"attendu 4 envois, obtenu {len(handler.envois)}"
    assert resultats[0]["verdict"] == "VULNERABLE"


def test_ecriture_rest_sans_lecture_garde_le_comportement_unique(engine):
    """Sans endpoint de lecture, l'écriture n'est jouée qu'une fois aussi (pas d'oracle)."""
    ep_ecriture = ep_rest("POST", "/orders")
    ep_ecriture.parameters = [Parameter("order_id", ParamLocation.PATH, "string", True, True)]
    eng, handler = engine([AuditResponse(200, "{}", 2, 0.1)])
    eng.run([ep_ecriture], "http://x", "9")
    assert len(handler.envois) == 1   # juste le tir initial, pas de contre-test public sur POST ? -> ici 1


def test_auth_configurable_via_identity_query():
    """FIX hypothèse codée : la query d'identité se lit dans auth.identity_query."""
    from unittest.mock import MagicMock, patch
    appels = []

    class PostPirate:
        def post(self, url, json=None, headers=None, timeout=None):
            appels.append(json["query"])
            r = MagicMock()
            r.json.return_value = {"data": {"moi": {"id": 42}}}
            return r

    class AuthAvecConfig:
        config = {"auth": {"identity_query": '{ moi { id } }'}}
        def get_auth_headers(self, role):
            return {"Authorization": "Bearer tok", "Content-Type": "application/json"}

    eng = BolaEngine(AuthAvecConfig(), FauxHandler([]))
    with patch("requests.post", PostPirate().post):
        identifiant = eng._obtenir_id_attaquant("http://x/graphql")
    assert identifiant == "42"          # racine générique : première clé dict de data
    assert "moi" in appels[0]           # gabarit configurable utilisé
