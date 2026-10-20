"""Tests des générateurs de rapports — vérification de la structure de sortie."""
import json

from reporters.json_reporter import JsonReporter


def faille_bola_lecture():
    return {
        "vulnerability": "BOLA", "endpoint": "GET /users/v1/{user_id}",
        "api_type": "REST", "params_injected": {"user_id": "2"},
        "status_code": 200, "verdict": "VULNERABLE", "is_vulnerable": True,
        "response_snippet": "{\"id\": 2, \"username\": \"victim\"}",
    }


def faille_bola_ecriture():
    r = faille_bola_lecture()
    r["endpoint"] = "PUT /users/v1/{username}/email"
    return r


def faille_bfla():
    return {
        "vulnerability": "BFLA", "endpoint": "DELETE /users/v1/admin/{id}",
        "api_type": "REST", "params_injected": {}, "status_code": 200,
        "verdict": "VULNERABLE", "is_vulnerable": True, "response_snippet": "ok",
    }


def test_non_concluant():
    return {
        "vulnerability": "BOLA", "endpoint": "POST /x", "api_type": "REST",
        "params_injected": {}, "status_code": 400, "verdict": "NON_CONCLUANT",
        "is_vulnerable": False, "response_snippet": "",
    }


# ── Gravité ───────────────────────────────────────────────────────────────────

def test_gravite_bfla_critique():
    assert JsonReporter()._calculer_gravite(faille_bfla()) == "CRITIQUE"


def test_gravite_bola_ecriture_critique():
    assert JsonReporter()._calculer_gravite(faille_bola_ecriture()) == "CRITIQUE"


def test_gravite_bola_lecture_haute():
    assert JsonReporter()._calculer_gravite(faille_bola_lecture()) == "HAUTE"


# ── Recommandations ───────────────────────────────────────────────────────────

def test_recommandation_par_type():
    rep = JsonReporter()
    assert "propriétaire" in rep._recommandation(faille_bola_lecture())
    assert "rôles autorisés" in rep._recommandation(faille_bfla())


# ── Rapport complet ───────────────────────────────────────────────────────────

def test_rapport_json_structure_complete(tmp_path):
    results = [faille_bola_lecture(), faille_bfla(), test_non_concluant()]
    sortie = tmp_path / "rapport.json"

    rapport = JsonReporter().generer(results, "http://localhost:8080", "REST", str(sortie))

    # Le fichier écrit doit être du JSON valide (hors métadonnées temporelles)
    assert sortie.exists()
    relu = json.loads(sortie.read_text(encoding="utf-8"))
    assert relu["resume"] == rapport["resume"]

    for section in ("metadonnees", "resume", "failles", "tests_non_concluants"):
        assert section in relu, f"Section manquante : {section}"

    assert relu["resume"]["total_tests"] == 3
    assert relu["resume"]["failles_confirmees"] == 2
    # BFLA → CRITIQUE ; GET /users/v1/{user_id} (lecture) → HAUTE
    assert relu["resume"]["critiques"] == 1
    assert relu["resume"]["hautes"] == 1
    assert relu["resume"]["tests_non_concluants"] == 1
    assert relu["metadonnees"]["cible"] == "http://localhost:8080"


def test_rapport_tri_par_gravite(tmp_path):
    results = [faille_bola_lecture(), faille_bfla()]
    rapport = JsonReporter().generer(results, "http://x", "REST", str(tmp_path / "r.json"))
    gravites = [f["gravite"] for f in rapport["failles"]]
    assert gravites == ["CRITIQUE", "HAUTE"], "Les failles doivent être triées CRITIQUE d'abord"


def test_champs_obligatoires_par_faille(tmp_path):
    rapport = JsonReporter().generer(
        [faille_bola_lecture()], "http://x", "REST", str(tmp_path / "r.json"))
    f = rapport["failles"][0]
    for champ in ("type", "endpoint", "gravite", "preuve", "recommandation", "parametres_injectes"):
        assert champ in f


def test_rapport_vide_ne_crash_pas(tmp_path):
    rapport = JsonReporter().generer([], "http://x", "REST", str(tmp_path / "r.json"))
    assert rapport["resume"]["failles_confirmees"] == 0
    assert rapport["failles"] == []
