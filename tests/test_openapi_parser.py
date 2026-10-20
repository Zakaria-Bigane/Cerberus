"""Tests de l'analyseur OpenAPI — aucune cible réseau requise."""
import json
from pathlib import Path

import pytest

from models.endpoint import ApiType, ParamLocation
from parsers.openapi_parser import OpenAPIParser

RACINE = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"


# ── Analyse du vrai spec VAmPI livré dans le dépôt (fixture vivante) ─────────

@pytest.fixture(scope="module")
def endpoints_vampi():
    parser = OpenAPIParser(RACINE / "vampi_openapi.json")
    return parser.parse(), parser


def test_vampi_renvoie_des_operations(endpoints_vampi):
    endpoints, _ = endpoints_vampi
    assert len(endpoints) > 0, "Le parseur ne doit retourner aucune opération sur un spec valide"


def test_vampi_methodes_uniquement_http_valides(endpoints_vampi):
    endpoints, _ = endpoints_vampi
    autorisees = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    assert all(ep.method in autorisees for ep in endpoints)


def test_vampi_api_type_rest(endpoints_vampi):
    endpoints, _ = endpoints_vampi
    assert all(ep.api_type == ApiType.REST for ep in endpoints)


def test_vampi_detection_parametre_identifiant(endpoints_vampi):
    """Un paramètre de type path comme {username} doit être marqué is_potential_id."""
    endpoints, _ = endpoints_vampi
    eps_avec_id = [ep for ep in endpoints if ep.get_id_parameters()]
    assert eps_avec_id, "Aucun endpoint avec paramètre identifiant détecté sur VAmPI"

    cible = next(ep for ep in endpoints if ep.path == "/users/v1/{username}" and ep.method == "GET")
    id_params = cible.get_id_parameters()
    assert any(p.name == "username" and p.location == ParamLocation.PATH for p in id_params)


def test_vampi_param_path_detecte_meme_sans_mot_cle_id(endpoints_vampi):
    """'book_title' n'est pas un ID lexical, mais sa location PATH le rend attaquable."""
    endpoints, _ = endpoints_vampi
    cible = next(ep for ep in endpoints if ep.path == "/books/v1/{book_title}")
    assert any(p.name == "book_title" and p.is_potential_id for p in cible.parameters)


def test_vampi_detection_register(endpoints_vampi):
    """Le parseur doit déduire l'endpoint d'inscription (POST avec username+password)."""
    _, parser = endpoints_vampi
    assert parser.register_path is not None
    body = json.loads((RACINE / "vampi_openapi.json").read_text(encoding="utf-8"))
    ops = body["paths"][parser.register_path]
    assert "post" in ops


def test_vampi_admin_sur_methods_dangerieuses(endpoints_vampi):
    """DELETE/PUT/PATCH doivent être marqués administratifs par heuristique."""
    endpoints, _ = endpoints_vampi
    pour_lui = [ep for ep in endpoints if ep.method in ("DELETE", "PUT", "PATCH")]
    assert pour_lui and all(ep.is_administrative for ep in pour_lui)


def test_vampi_body_template_extraite(endpoints_vampi):
    """Un POST déclarant un requestBody JSON doit produire un body_template."""
    endpoints, _ = endpoints_vampi
    avec_body = [ep for ep in endpoints if ep.body_template]
    assert avec_body, "Aucun body_template extrait alors que VAmPI déclare des requestBody"


# ── Comportements sur mini-specs fabriqués (cas limites) ─────────────────────

def test_fichier_inexistant_retourne_liste_vide(tmp_path):
    parser = OpenAPIParser(tmp_path / "absent.json")
    assert parser.parse() == []


def test_json_corrompu_ne_crash_pas(tmp_path):
    casse = tmp_path / "casse.json"
    casse.write_text("{ceci n'est pas du json", encoding="utf-8")
    parser = OpenAPIParser(casse)
    assert parser.parse() == []


def test_mini_spec_detecte_register_vs_login(tmp_path):
    """/login (avec username/password) ne doit PAS être pris pour le register ;
    /register doit l'être."""
    spec = {
        "paths": {
            "/login": {"post": {"operationId": "login", "requestBody": {"content": {
                "application/json": {"schema": {"properties": {
                    "username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
            "/register": {"post": {"operationId": "register", "requestBody": {"content": {
                "application/json": {"schema": {"properties": {
                    "username": {"type": "string"}, "password": {"type": "string"}}}}}}}},
        }
    }
    f = tmp_path / "mini.json"
    f.write_text(json.dumps(spec), encoding="utf-8")
    parser = OpenAPIParser(f)
    parser.parse()
    assert parser.register_path == "/register"


def test_parametre_header_ignore(tmp_path):
    spec = {"paths": {"/x": {"get": {"operationId": "getX", "parameters": [
        {"name": "X-Trace", "in": "header", "schema": {"type": "string"}}]}}}}
    f = tmp_path / "hdr.json"
    f.write_text(json.dumps(spec), encoding="utf-8")
    endpoints = OpenAPIParser(f).parse()
    assert all(p.name != "X-Trace" for ep in endpoints for p in ep.parameters)
