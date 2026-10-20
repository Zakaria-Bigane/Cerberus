from typing import Any, Dict, List

from core.auth_manager import AuthManager
from core.cerberus_display import (
    log_error,
    log_faille,
    log_info,
    log_public,
    log_unknown,
    separateur,
)
from core.request_handler import AuditResponse, RequestHandler
from models.endpoint import ApiType, UnifiedEndpoint


class BolaEngine:
    def __init__(self, auth_manager: AuthManager, request_handler: RequestHandler):
        self.auth_manager = auth_manager
        self.request_handler = request_handler

    def _est_endpoint_credential(self, endpoint) -> bool:
        """
        Détecte si l'endpoint modifie un mot de passe.
        Heuristique : le chemin ou un champ du corps évoque un credential.
        """
        mots_credential = ["password", "passwd", "pwd", "credential"]

        # Dans le chemin (ex: /users/{username}/password)
        if any(mot in endpoint.path.lower() for mot in mots_credential):
            return True

        # Dans les champs du corps déclaré
        if endpoint.body_template:
            for champ in endpoint.body_template:
                if any(mot in champ.lower() for mot in mots_credential):
                    return True

        return False

    def _verifier_bola_par_login(self, target_url, endpoint, victim_id) -> str:
        """
        Oracle d'effet pour les credentials.
        L'attaquant impose un mot de passe connu à la victime via l'URL,
        puis on vérifie en tentant de connecter la victime avec ce mot de passe.
        Renvoie "VULNERABLE" si la victime se connecte, sinon "BLOQUE".
        """
        mdp_test = "oracle_test_bola_999"

        # 1. L'attaquant impose ce mot de passe via l'URL de la victime
        attacker_headers = self.auth_manager.get_auth_headers('user_a')

        # On construit le body en remplaçant le champ password par notre valeur
        body = dict(endpoint.body_template) if endpoint.body_template else {}
        for champ in body:
            if any(m in champ.lower() for m in ["password", "passwd", "pwd"]):
                body[champ] = mdp_test

        params_map = {}
        for param in endpoint.get_id_parameters():
            params_map[param.name] = victim_id

        # On envoie l'attaque (le request_handler utilise endpoint.body_template,
        # mais ici on veut notre body modifié — on le passe temporairement)
        body_original = endpoint.body_template
        endpoint.body_template = body
        self.request_handler.send(
            base_url=target_url, endpoint=endpoint,
            headers=attacker_headers, params_map=params_map
        )
        endpoint.body_template = body_original  # on restaure

        # 2. PREUVE : la victime peut-elle se connecter avec ce mot de passe ?
        if self.auth_manager.tester_login(victim_id, mdp_test):
            return "VULNERABLE"   # l'attaquant a changé le mdp de la victime
        else:
            return "BLOQUE"       # aucun effet sur la victime

    def run(self, endpoints: List[UnifiedEndpoint], target_url: str, victim_id: str) -> List[Dict[str, Any]]:
        """
        Exécute la campagne de test BOLA sur la liste des endpoints fournis.
        victim_id: L'identifiant de la ressource cible à usurper.
        """
        print()
        separateur()
        log_info(f"DÉMARRAGE DU MOTEUR BOLA (Victime ID: {victim_id})")
        separateur()

        results = []
        self.tous_endpoints_graphql = endpoints   # pour l'oracle d'effet des mutations

        # 1. On s'équipe du token de l'attaquant (User A)
        log_info("Récupération du jeton pour 'user_a' (Attaquant)...")
        attacker_headers = self.auth_manager.get_auth_headers('user_a')

        for endpoint in endpoints:
            # 2. Filtrage : on ne teste que les endpoints ayant un paramètre d'ID
            id_params = endpoint.get_id_parameters()
            if not id_params:
                continue

            # Affichage lisible : nom d'opération pour GraphQL, chemin pour REST
            if endpoint.api_type == ApiType.GRAPHQL:
                cible_affichee = endpoint.action_name
            else:
                cible_affichee = endpoint.path
            print()
            log_info(f"Test BOLA sur : [{endpoint.api_type.value}] {endpoint.method} {cible_affichee}")

            # 3. Préparation des paramètres d'attaque
            params_map = {}
            for param in id_params:
                params_map[param.name] = victim_id
            # Pour les mutations GraphQL, on fournit aussi les autres arguments requis
            if endpoint.api_type == ApiType.GRAPHQL and endpoint.is_mutation:
                for param in endpoint.parameters:
                    if param.name not in params_map:
                        params_map[param.name] = self._valeur_test_pour(param)

            # 4. Déclenchement du tir
            #    Exception : pour les mutations GraphQL, on NE tire PAS ici.
            #    L'oracle d'effet gère toute la séquence (lire avant / tirer / lire après),
            #    sinon la mutation s'exécuterait deux fois et fausserait le différentiel.
            is_mutation_gql = (endpoint.api_type == ApiType.GRAPHQL and endpoint.is_mutation)

            if is_mutation_gql:
                response = None
                verdict = "VULNERABLE"   # provisoire : l'oracle d'effet tranchera
            else:
                response = self.request_handler.send(
                    base_url=target_url,
                    endpoint=endpoint,
                    headers=attacker_headers,
                    params_map=params_map
                )
                verdict = self._analyze_response(response, endpoint)

            # 5. Interprétation du résultat
            # ── Branche GraphQL ───────────────────────────────────────
            if endpoint.api_type == ApiType.GRAPHQL:
                if endpoint.is_mutation:
                    # Mutation : oracle d'effet par relecture (avant/après)
                    verdict = self._verifier_bola_mutation_graphql(
                        target_url, endpoint, params_map
                    )
                elif verdict == "VULNERABLE":
                    # Query : oracle de propriété sur le retour
                    verdict = self._verifier_bola_propriete(
                        target_url, endpoint, params_map, response
                    )

            # ── Branche REST ──────────────────────────────────────────
            else:
                if verdict == "VULNERABLE":
                    if self._est_ressource_publique(target_url, endpoint, params_map):
                        verdict = "PUBLIC"

                if verdict == "VULNERABLE" and self._est_ecriture(endpoint):
                    ep_lecture = self._trouver_endpoint_lecture(endpoint, endpoints)
                    if ep_lecture:
                        verdict = self._verifier_effet_par_lecture(
                            target_url, endpoint, ep_lecture, victim_id
                        )
                    if verdict == "BLOQUE" and self._est_endpoint_credential(endpoint):
                        verdict = self._verifier_bola_par_login(
                            target_url, endpoint, victim_id
                        )

            # 6. Affichage du verdict
            code_affiche = response.status_code if response else "—"
            if verdict == "VULNERABLE":
                log_faille(f"FAILLE BOLA CONFIRMÉE ! (Statut: {code_affiche})")
            elif verdict == "PUBLIC":
                log_public("Ressource publique — accessible sans authentification (pas un BOLA)")
            elif verdict == "NON_CONCLUANT":
                log_unknown(f"Test non concluant — requête invalide (Statut: {code_affiche})")
            else:  # BLOQUE
                log_error(f"Accès correctement bloqué (Statut: {code_affiche})")

            # 7. Enregistrement du résultat
            results.append({
                "vulnerability": "BOLA",
                "endpoint": endpoint.action_name if endpoint.api_type == ApiType.GRAPHQL else f"{endpoint.method} {endpoint.path}",
                "api_type": endpoint.api_type.value,
                "params_injected": params_map,
                "status_code": response.status_code if response else 200,
                "verdict": verdict,
                "is_vulnerable": (verdict == "VULNERABLE"),
                "response_snippet": response.response_body[:150] if response else ""
            })

        return results

    def _analyze_response(self, response: AuditResponse, endpoint=None) -> str:
        """
        Oracle à états. Aiguille vers l'oracle GraphQL si l'endpoint est GraphQL,
        sinon applique la logique REST (codes HTTP).
        """
        # Aiguillage GraphQL : le code HTTP n'y veut rien dire
        if endpoint is not None and endpoint.api_type == ApiType.GRAPHQL:
            return self._analyser_reponse_graphql(response)

        # ── Logique REST (inchangée) ──────────────────────────────────
        code = response.status_code
        if code == 0:
            return "NON_CONCLUANT"

        # Cas GraphQL : un 200 avec un tableau "errors" = l'autorisation a bloqué
        if response.is_graphql_error:
            return "BLOQUE"

        # Cas 1 : requête invalide → on n'a PAS testé l'autorisation
        #   400 = corps/paramètres malformés (ex: PUT sans body)
        #   401 = pas (ou mal) authentifié
        if code in [400, 401]:
            return "NON_CONCLUANT"

        # Cas 2 : accès réussi à une ressource qui n'est pas la nôtre → faille
        if code in [200, 201, 204]:
            return "VULNERABLE"

        # Cas 3 : refus explicite de sécurité
        #   403 = interdit (le vrai blocage d'autorisation)
        #   404 = introuvable (masquage volontaire OU mauvaise valeur injectée)
        if code in [403, 404]:
            return "BLOQUE"

        # Tout autre code (5xx, 3xx…) : on ne conclut pas
        return "NON_CONCLUANT"

    def _est_ressource_publique(self, target_url, endpoint, params_map) -> bool:
        """
        Contre-test anonyme : rejoue sans token. Si l'anonyme obtient la
        ressource, elle est publique (pas un BOLA).
        """
        headers_anonyme = {"Content-Type": "application/json"}

        response_anonyme = self.request_handler.send(
            base_url=target_url,
            endpoint=endpoint,
            headers=headers_anonyme,
            params_map=params_map
        )

        # Aiguillage : en GraphQL, le succès se lit dans data/errors, pas le code HTTP
        if endpoint.api_type == ApiType.GRAPHQL:
            verdict_anonyme = self._analyser_reponse_graphql(response_anonyme)
            return verdict_anonyme == "VULNERABLE"   # l'anonyme obtient les données → public
        else:
            return response_anonyme.status_code in [200, 201, 204]

    def _est_ecriture(self, endpoint) -> bool:
        """Une écriture est une méthode qui modifie l'état."""
        return endpoint.method.upper() in ["PUT", "POST", "PATCH", "DELETE"]

    def _trouver_endpoint_lecture(self, endpoint_ecriture, tous_les_endpoints):
        """
        Cherche un GET qui permet de lire la ressource ciblée par l'écriture.
        Principe : le chemin de lecture est un préfixe du chemin d'écriture,
        et contient le(s) même(s) identifiant(s).
        Ex: PUT /users/v1/{username}/email  ->  GET /users/v1/{username}
        """
        chemin_ecriture = endpoint_ecriture.path

        meilleur_candidat = None
        meilleure_longueur = 0

        for ep in tous_les_endpoints:
            if ep.method.upper() != "GET":
                continue
            # Le chemin du GET doit être un préfixe du chemin d'écriture
            if chemin_ecriture.startswith(ep.path):
                # On garde le préfixe le plus long (le plus spécifique)
                if len(ep.path) > meilleure_longueur:
                    # Il doit contenir au moins un identifiant à cibler
                    if ep.get_id_parameters():
                        meilleur_candidat = ep
                        meilleure_longueur = len(ep.path)

        return meilleur_candidat

    def _analyser_reponse_graphql(self, response) -> str:
        """
        Oracle GraphQL. Le code HTTP est toujours 200 : c'est le contenu
        (data vs errors) qui porte le verdict.
        """
        import json

        if response.status_code == 0:
            return "NON_CONCLUANT"

        try:
            corps = json.loads(response.response_body)
        except (json.JSONDecodeError, ValueError):
            return "NON_CONCLUANT"

        erreurs = corps.get("errors")
        if erreurs:
            texte = json.dumps(erreurs).lower()
            mots = ["not authorized", "permission", "forbidden",
                    "access denied", "unauthorized", "authentication"]
            return "BLOQUE" if any(m in texte for m in mots) else "NON_CONCLUANT"

        data = corps.get("data")
        if data and any(v is not None for v in data.values()):
            return "VULNERABLE"
        return "BLOQUE"

    def _verifier_bola_mutation_graphql(self, target_url, endpoint, params_map) -> str:
        """
        Oracle d'effet pour les mutations GraphQL (editPaste, deletePaste).
        On ne lit pas le retour de la mutation : on vérifie l'EFFET réel en
        relisant la ressource via la query correspondante (ex: paste).
        """
        import json

        # 1. Trouver la query de lecture correspondante (même racine que la mutation)
        #    editPaste/deletePaste → paste ; on cherche une query 'paste'
        query_lecture = self._trouver_query_lecture_graphql(endpoint)
        if not query_lecture:
            return "NON_CONCLUANT"   # pas de query pour vérifier l'effet

        # L'id ciblé
        id_cible = None
        for p in endpoint.get_id_parameters():
            if p.name in params_map:
                id_cible = params_map[p.name]
                break
        if id_cible is None:
            return "NON_CONCLUANT"

        # 2. Lire l'état AVANT
        avant = self._lire_ressource_graphql(target_url, query_lecture, id_cible)
        if avant is None:
            return "BLOQUE"   # la ressource n'existe pas → rien à attaquer

        # 3. Vérifier que la cible appartient à AUTRUI (sinon pas un BOLA)
        id_attaquant = self._obtenir_id_attaquant(target_url)
        proprietaire = self._extraire_proprietaire(avant)
        if proprietaire is not None and id_attaquant is not None:
            if str(proprietaire) == str(id_attaquant):
                return "BLOQUE"   # sa propre ressource, pas un BOLA

        # 4. Exécuter la mutation (l'attaque)
        attacker_headers = self.auth_manager.get_auth_headers('user_a')
        self.request_handler.send(
            base_url=target_url, endpoint=endpoint,
            headers=attacker_headers, params_map=params_map
        )

        # 5. Lire l'état APRÈS
        apres = self._lire_ressource_graphql(target_url, query_lecture, id_cible)

        # 6. Comparer : l'effet a-t-il eu lieu sur la ressource d'autrui ?
        if apres is None:
            # La ressource a disparu → deletePaste a réussi sur le paste d'autrui
            return "VULNERABLE"
        if json.dumps(avant, sort_keys=True) != json.dumps(apres, sort_keys=True):
            # La ressource a changé → editPaste a modifié le paste d'autrui
            return "VULNERABLE"

        return "BLOQUE"   # aucun effet → l'attaque a échoué

    def _trouver_query_lecture_graphql(self, endpoint_mutation):
        """Trouve la query de lecture correspondant à une mutation.
        Heuristique : la query dont le nom est contenu dans celui de la mutation
        (editPaste/deletePaste → paste)."""
        for ep in self.tous_endpoints_graphql:
            if ep.is_mutation:
                continue
            if not ep.get_id_parameters():
                continue
            # 'paste' est dans 'editPaste' / 'deletePaste'
            if ep.action_name.lower() in endpoint_mutation.action_name.lower():
                return ep
        return None

    def _lire_ressource_graphql(self, target_url, query_endpoint, id_cible):
        """Lit une ressource via une query GraphQL. Renvoie l'objet ou None."""
        import json
        attacker_headers = self.auth_manager.get_auth_headers('user_a')
        params = {}
        for p in query_endpoint.get_id_parameters():
            params[p.name] = id_cible
        response = self.request_handler.send(
            base_url=target_url, endpoint=query_endpoint,
            headers=attacker_headers, params_map=params
        )
        try:
            corps = json.loads(response.response_body)
        except (json.JSONDecodeError, ValueError):
            return None
        data = corps.get("data")
        if not data:
            return None
        return data.get(query_endpoint.action_name)   # None si null

    def _extraire_proprietaire(self, obj):
        """Cherche un champ propriétaire dans un objet (récursif simple)."""
        champs = ["ownerid", "userid", "authorid", "owner_id", "user_id"]
        if isinstance(obj, dict):
            for cle, val in obj.items():
                if cle.lower() in champs and not isinstance(val, (dict, list)):
                    return val
        return None

    def _verifier_bola_propriete(self, target_url, endpoint, params_map, response) -> str:
        """
        Oracle BOLA GraphQL par différence de propriétaire.
        Compare l'identité de l'attaquant au propriétaire de la ressource obtenue.
        Si l'attaquant obtient un objet dont il n'est pas le propriétaire → BOLA.
        """
        import json

        # 1. Extraire la ressource obtenue de la réponse
        try:
            corps = json.loads(response.response_body)
        except (json.JSONDecodeError, ValueError):
            return "NON_CONCLUANT"

        data = corps.get("data")
        if not data:
            return "BLOQUE"

        # La ressource est sous data.<action_name>
        ressource = data.get(endpoint.action_name)
        if not ressource:
            return "BLOQUE"   # rien obtenu → pas d'accès

        # La réponse peut être un objet unique OU une liste d'objets.
        # On normalise en liste pour traiter les deux cas.
        if isinstance(ressource, list):
            objets = ressource
        else:
            objets = [ressource]

        champs_proprietaire = ["ownerid", "userid", "authorid", "owner_id", "user_id", "id"]
        id_attaquant = self._obtenir_id_attaquant(target_url)
        if id_attaquant is None:
            return "NON_CONCLUANT"

        # Recherche récursive du propriétaire dans les objets (gère l'imbrication
        # comme editPaste.paste.ownerId)
        def chercher_proprietaire(obj):
            """Renvoie (trouve, est_autrui) en explorant récursivement."""
            trouve = False
            if isinstance(obj, dict):
                for cle, valeur in obj.items():
                    if cle.lower() in champs_proprietaire and not isinstance(valeur, (dict, list)):
                        trouve = True
                        if str(valeur) != id_attaquant:
                            return True, True    # propriétaire trouvé, c'est autrui
                    elif isinstance(valeur, (dict, list)):
                        t, autrui = chercher_proprietaire(valeur)
                        trouve = trouve or t
                        if autrui:
                            return True, True
            elif isinstance(obj, list):
                for item in obj:
                    t, autrui = chercher_proprietaire(item)
                    trouve = trouve or t
                    if autrui:
                        return True, True
            return trouve, False

        trouve_global = False
        for obj in objets:
            trouve, est_autrui = chercher_proprietaire(obj)
            trouve_global = trouve_global or trouve
            if est_autrui:
                return "VULNERABLE"

        if trouve_global:
            return "BLOQUE"
        return "NON_CONCLUANT"

    def _valeur_test_pour(self, param) -> Any:
        """Génère une valeur de test selon le type de l'argument GraphQL."""
        type_arg = (param.data_type or "").lower()
        if type_arg in ("int", "integer", "float"):
            return 1
        if type_arg == "boolean":
            return "true"
        # string, id, ou inconnu → une valeur de test textuelle
        return "audit_test_value"

    def _obtenir_id_attaquant(self, target_url) -> str:
        """
        Récupère l'id de l'attaquant via la query 'me'.
        Mis en cache pour ne le demander qu'une fois.
        """

        # Cache : on ne demande qu'une fois
        if hasattr(self, '_id_attaquant_cache'):
            return self._id_attaquant_cache

        headers = self.auth_manager.get_auth_headers('user_a')
        token = headers.get("Authorization", "").replace("Bearer ", "")

        # Query 'me' avec le token en argument (spécificité observée sur DVGA)
        query = f'{{ me(token: "{token}") {{ id }} }}'
        import requests
        try:
            r = requests.post(target_url, json={"query": query}, headers=headers, timeout=10)
            data = r.json().get("data", {})
            me = data.get("me")
            id_attaquant = str(me["id"]) if me else None
        except Exception:
            id_attaquant = None

        self._id_attaquant_cache = id_attaquant
        return id_attaquant

    def _verifier_effet_par_lecture(self, target_url, endpoint_ecriture,
                                     endpoint_lecture, victim_id) -> str:
        """
        Oracle d'effet par lecture.
        Lit la ressource de la victime AVANT et APRÈS l'attaque.
        Renvoie "VULNERABLE" si la ressource victime a changé, sinon "BLOQUE".
        """
        attacker_headers = self.auth_manager.get_auth_headers('user_a')
        params_lecture = {}
        for param in endpoint_lecture.get_id_parameters():
            params_lecture[param.name] = victim_id

        # 1. État de la victime AVANT
        avant = self.request_handler.send(
            base_url=target_url, endpoint=endpoint_lecture,
            headers=attacker_headers, params_map=params_lecture
        )

        # 2. L'attaque (l'écriture a déjà été jouée dans run, mais on la rejoue
        #    proprement ici pour être sûr de l'ordre avant/après)
        params_ecriture = {}
        for param in endpoint_ecriture.get_id_parameters():
            params_ecriture[param.name] = victim_id
        self.request_handler.send(
            base_url=target_url, endpoint=endpoint_ecriture,
            headers=attacker_headers, params_map=params_ecriture
        )

        # 3. État de la victime APRÈS
        apres = self.request_handler.send(
            base_url=target_url, endpoint=endpoint_lecture,
            headers=attacker_headers, params_map=params_lecture
        )

        # 4. Comparaison : la ressource de la victime a-t-elle changé ?
        if avant.response_body != apres.response_body:
            return "VULNERABLE"   # la victime a été modifiée → vrai BOLA
        else:
            return "BLOQUE"       # rien n'a changé chez la victime → faux positif