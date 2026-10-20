import json
import uuid

import requests

from core.auth_manager import AuthManager
from core.cerberus_display import (
    log_error,
    log_faille,
    log_info,
    log_public,
    log_unknown,
    log_warning,
    separateur,
)
from core.request_handler import RequestHandler
from models.endpoint import ApiType


class BflaEngine:
    def __init__(self, auth_manager: AuthManager, request_handler: RequestHandler):
        self.auth_manager = auth_manager
        self.request_handler = request_handler
        self.register_path = None
        self.tous_endpoints = []

    def run(self, endpoints, target_url, register_path=None):
        print()
        separateur()
        log_info("DÉMARRAGE DU MOTEUR BFLA (différentiel de rôle)")
        separateur()

        self.register_path = register_path
        self.tous_endpoints = endpoints

        # Aiguillage REST / GraphQL selon le type des endpoints
        est_graphql = any(e.api_type == ApiType.GRAPHQL for e in endpoints)
        if est_graphql:
            return self._run_graphql(endpoints, target_url)
        else:
            return self._run_rest(endpoints, target_url)

    # ═══════════════════════════════════════════════════════════════
    #  BFLA REST
    # ═══════════════════════════════════════════════════════════════
    def _run_rest(self, endpoints, target_url):
        results = []

        for endpoint in endpoints:
            if not endpoint.get_id_parameters() and endpoint.method.upper() in ("GET",):
                # Les GET sans id (actions globales type /users/all) sont testables aussi
                pass
            elif not endpoint.get_id_parameters():
                # POST/PUT sans id : action globale, testable
                pass

            methode = endpoint.method.upper()

            # DELETE avec id → différentiel par EFFET (logique existante, cibles jetables)
            if methode == "DELETE" and endpoint.get_id_parameters():
                print()
                log_info(f"Test BFLA sur : {endpoint.method} {endpoint.path}")
                verdict = self._tester_endpoint_destructif(target_url, endpoint)
                self._afficher_verdict_rest(verdict)
                results.append(self._resultat_bfla(endpoint, verdict))

            # GET/POST/PUT → différentiel par ACCÈS (rôle supérieur vs inférieur vs anonyme)
            elif methode in ("GET", "POST", "PUT"):
                print()
                log_info(f"Test BFLA sur : {endpoint.method} {endpoint.path}")
                verdict = self._tester_acces_differentiel(target_url, endpoint)
                self._afficher_verdict_rest(verdict)
                results.append(self._resultat_bfla(endpoint, verdict))

        return results

    def _tester_acces_differentiel(self, target_url, endpoint) -> str:
        """
        Différentiel de rôle par accès (fonctions non destructives).
        Sans oracle sémantique, on ne peut pas confirmer un BFLA avec certitude :
        on signale les anomalies comme 'À EXAMINER' plutôt que comme failles.
        """
        succes_ref = self._role_accede(target_url, endpoint, 'admin')
        if succes_ref != "SUCCES":
            return "NON_CONCLUANT"

        succes_user = self._role_accede(target_url, endpoint, 'user_a')
        succes_anon = self._role_accede(target_url, endpoint, None)

        # Fonction accessible même en anonyme → absence totale de contrôle
        if succes_user == "SUCCES" and succes_anon == "SUCCES":
            return "OUVERT"

        # User accède à une fonction protégée par auth, sans asymétrie de rôle
        # observable → anomalie à examiner (peut être légitime ou un BFLA)
        if succes_user == "SUCCES" and succes_anon != "SUCCES":
            return "A_EXAMINER"

        # User bloqué → contrôle de rôle sain
        return "BLOQUE"

    def _role_accede(self, target_url, endpoint, role) -> str:
        """Le rôle donné accède-t-il à l'endpoint ? (None = anonyme)"""
        if role:
            headers = self.auth_manager.get_auth_headers(role)
        else:
            headers = {"Content-Type": "application/json"}

        # Paramètres : id factice + body pour POST/PUT
        params_map = {}
        for p in endpoint.get_id_parameters():
            params_map[p.name] = "1"

        response = self.request_handler.send(
            base_url=target_url, endpoint=endpoint,
            headers=headers, params_map=params_map
        )
        # Succès = 2xx ; bloqué = 401/403
        if response.status_code in (200, 201, 204):
            return "SUCCES"
        if response.status_code in (401, 403):
            return "BLOQUE"
        return "AUTRE"   # 400, 404, 500...

    def _afficher_verdict_rest(self, verdict):
        if verdict == "VULNERABLE":
            log_faille("FAILLE BFLA CONFIRMÉE ! Un rôle inférieur accède à une fonction protégée")
        elif verdict == "A_EXAMINER":
            log_warning("À EXAMINER — accessible au user sans contrôle de rôle (à qualifier manuellement)")
        elif verdict == "OUVERT":
            log_public("Fonction accessible sans authentification (contrôle absent)")
        elif verdict == "NON_CONCLUANT":
            log_unknown("Test non concluant")
        else:
            log_error("Fonction correctement réservée (contrôle de rôle OK)")

    def _resultat_bfla(self, endpoint, verdict):
        return {
            "vulnerability": "BFLA",
            "endpoint": f"{endpoint.method} {endpoint.path}",
            "api_type": endpoint.api_type.value,
            "verdict": verdict,
            "is_vulnerable": (verdict == "VULNERABLE"),
            "a_examiner": (verdict == "A_EXAMINER"),   # nouveau niveau
        }

    def _tester_endpoint_destructif(self, target_url, endpoint) -> str:
        if not self.register_path:
            log_warning("Pas d'endpoint register connu — impossible de créer des cibles.")
            return "NON_CONCLUANT"

        effet_admin = self._role_realise_action(target_url, endpoint, 'admin')
        if effet_admin != "EFFET":
            return "NON_CONCLUANT"

        effet_user = self._role_realise_action(target_url, endpoint, 'user_a')
        effet_anon = self._role_realise_action(target_url, endpoint, None)

        if effet_user == "EFFET" or effet_anon == "EFFET":
            return "VULNERABLE"
        if effet_user == "BLOQUE" and effet_anon == "BLOQUE":
            return "BLOQUE"
        return "NON_CONCLUANT"

    def _role_realise_action(self, target_url, endpoint, role) -> str:
        nom_cible = f"bfla_{uuid.uuid4().hex[:8]}"
        if not self._creer_cible(target_url, nom_cible):
            return "NON_CONCLUANT"

        if role:
            headers = self.auth_manager.get_auth_headers(role)
        else:
            headers = {"Content-Type": "application/json"}

        params_map = {}
        for param in endpoint.get_id_parameters():
            params_map[param.name] = nom_cible

        self.request_handler.send(
            base_url=target_url, endpoint=endpoint,
            headers=headers, params_map=params_map
        )

        existe_encore = self._cible_existe(target_url, endpoint, nom_cible)
        if existe_encore is None:
            return "NON_CONCLUANT"
        return "BLOQUE" if existe_encore else "EFFET"

    def _creer_cible(self, target_url, nom_cible) -> bool:
        url = target_url + self.register_path
        body = {
            "username": nom_cible,
            "password": "jetable_pwd_123",
            "email": f"{nom_cible}@test.local"
        }
        try:
            r = requests.post(url, json=body, timeout=10)
            return r.status_code in [200, 201]
        except requests.RequestException:
            return False

    def _cible_existe(self, target_url, endpoint_ecriture, nom_cible):
        ep_lecture = None
        meilleure_longueur = 0
        for ep in self.tous_endpoints:
            if ep.method.upper() != "GET":
                continue
            if endpoint_ecriture.path.startswith(ep.path) and ep.get_id_parameters():
                if len(ep.path) > meilleure_longueur:
                    ep_lecture = ep
                    meilleure_longueur = len(ep.path)

        if not ep_lecture:
            return None

        params_map = {}
        for param in ep_lecture.get_id_parameters():
            params_map[param.name] = nom_cible

        headers = self.auth_manager.get_auth_headers('admin')
        reponse = self.request_handler.send(
            base_url=target_url, endpoint=ep_lecture,
            headers=headers, params_map=params_map
        )
        if reponse.status_code == 200:
            return True
        if reponse.status_code == 404:
            return False
        return None

    # ═══════════════════════════════════════════════════════════════
    #  BFLA GraphQL
    # ═══════════════════════════════════════════════════════════════
    def _run_graphql(self, endpoints, target_url):
        results = []

        for endpoint in endpoints:
            if not self._est_cible_bfla_graphql(endpoint):
                continue

            print()
            log_info(f"Test BFLA sur : [GRAPHQL] {endpoint.action_name}")
            verdict = self._tester_differentiel_graphql(target_url, endpoint)

            if verdict == "VULNERABLE":
                log_faille("FAILLE BFLA CONFIRMÉE ! Un rôle inférieur exécute une action sensible")
            elif verdict == "NON_CONCLUANT":
                log_unknown("Test non concluant")
            else:  # BLOQUE
                log_error("Action correctement réservée (isolation OK)")

            results.append({
                "vulnerability": "BFLA",
                "endpoint": endpoint.action_name,
                "api_type": "GRAPHQL",
                "verdict": verdict,
                "is_vulnerable": (verdict == "VULNERABLE"),
            })

        return results

    def _est_cible_bfla_graphql(self, endpoint) -> bool:
        """
        Cible BFLA = action GLOBALE potentiellement administrative :
        une opération SANS paramètre d'id (pas de cible objet précise).
        Les opérations avec id (editPaste, deletePaste) agissent sur un objet
        → elles relèvent du BOLA, pas du BFLA.
        On exclut l'infrastructure et le hors-scope.
        """
        nom = endpoint.action_name.lower()
        exclusions = ["login", "createuser", "systemdiagnostics",
                      "importpaste", "uploadpaste", "createpaste"]
        if any(x in nom for x in exclusions):
            return False

        # BFLA = action globale sans cible objet (pas d'id)
        if endpoint.get_id_parameters():
            return False   # a un id → c'est une cible BOLA, pas BFLA

        return True

    def _tester_differentiel_graphql(self, target_url, endpoint) -> str:
        succes_admin = self._role_reussit_graphql(target_url, endpoint, 'admin')
        if succes_admin == "NON_CONCLUANT":
            return "NON_CONCLUANT"

        succes_user = self._role_reussit_graphql(target_url, endpoint, 'user_a')
        succes_anon = self._role_reussit_graphql(target_url, endpoint, None)

        if succes_user == "SUCCES" or succes_anon == "SUCCES":
            return "VULNERABLE"
        if succes_user == "BLOQUE" and succes_anon == "BLOQUE":
            return "BLOQUE"
        return "NON_CONCLUANT"

    def _role_reussit_graphql(self, target_url, endpoint, role) -> str:
        if role:
            headers = self.auth_manager.get_auth_headers(role)
        else:
            headers = {"Content-Type": "application/json"}

        params_map = {}
        for p in endpoint.get_id_parameters():
            params_map[p.name] = "1"
        if endpoint.is_mutation:
            for p in endpoint.parameters:
                if p.name not in params_map:
                    params_map[p.name] = self._valeur_test(p)

        response = self.request_handler.send(
            base_url=target_url, endpoint=endpoint,
            headers=headers, params_map=params_map
        )
        return self._interpreter_succes_graphql(response)

    def _interpreter_succes_graphql(self, response) -> str:
        if response.status_code == 0:
            return "NON_CONCLUANT"   # timeout ou erreur réseau
        try:
            corps = json.loads(response.response_body)
        except (json.JSONDecodeError, ValueError):
            return "NON_CONCLUANT"

        erreurs = corps.get("errors")
        if erreurs:
            texte = json.dumps(erreurs).lower()
            mots_autz = ["not authorized", "permission", "forbidden", "unauthorized"]
            if any(m in texte for m in mots_autz):
                return "BLOQUE"
            return "NON_CONCLUANT"

        data = corps.get("data")
        if data and any(v is not None for v in data.values()):
            return "SUCCES"
        return "BLOQUE"

    def _valeur_test(self, param):
        t = (param.data_type or "").lower()
        if t in ("int", "integer", "float"):
            return 1
        if t == "boolean":
            return "true"
        return "audit_test_value"