from typing import List, Dict, Any
from models.endpoint import UnifiedEndpoint
from core.auth_manager import AuthManager
from core.request_handler import RequestHandler, AuditResponse

class BolaEngine:
    def __init__(self, auth_manager: AuthManager, request_handler: RequestHandler):
        self.auth_manager = auth_manager
        self.request_handler = request_handler

    def run(self, endpoints: List[UnifiedEndpoint], target_url: str, victim_id: str) -> List[Dict[str, Any]]:
        """
        Exécute la campagne de test BOLA sur la liste des endpoints fournis.
        victim_id: L'identifiant (ex: '124' ou 'uuid-5678') de la ressource cible à usurper.
        """
        print(f"\n[==================================================]")
        print(f"[*] DÉMARRAGE DU MOTEUR BOLA (Victime ID: {victim_id})")
        print(f"[==================================================]")
        
        results = []
        
        # 1. On s'équipe du token de l'attaquant (User A)
        print("[*] Récupération du jeton pour 'user_a' (Attaquant)...")
        attacker_headers = self.auth_manager.get_auth_headers('user_a')
        
        for endpoint in endpoints:
            # 2. Filtrage intelligent : on ne teste que les endpoints ayant un paramètre d'ID
            id_params = endpoint.get_id_parameters()
            if not id_params:
                continue 
                
            print(f"\n[*] Test BOLA sur : [{endpoint.api_type.value}] {endpoint.method} {endpoint.path}")
            
            # 3. Préparation des paramètres d'attaque (Injection de l'ID de la victime)
            params_map = {}
            for param in id_params:
                params_map[param.name] = victim_id
                
            # 4. Déclenchement du tir (Envoi de la requête forgée)
            response = self.request_handler.send(
                base_url=target_url,
                endpoint=endpoint,
                headers=attacker_headers,
                params_map=params_map
            )
            
            # 5. Interprétation du résultat
            verdict = self._analyze_response(response)

            if verdict == "VULNERABLE":
                if self._est_ressource_publique(target_url, endpoint, params_map):
                    verdict = "PUBLIC"
            # Oracle par lecture : pour une écriture jugée vulnérable,
            # on vérifie que la ressource de la victime a vraiment changé.
            if verdict == "VULNERABLE" and self._est_ecriture(endpoint):
                ep_lecture = self._trouver_endpoint_lecture(endpoint, endpoints)
                if ep_lecture:
                    verdict = self._verifier_effet_par_lecture(
                        target_url, endpoint, ep_lecture, victim_id
                    )
                # Si aucun endpoint de lecture trouvé, on garde le verdict
                # (l'oracle par login prendra le relais plus tard)
            if verdict == "VULNERABLE":
                print(f"    [!!!] FAILLE BOLA CONFIRMÉE ! (Statut: {response.status_code})")
            elif verdict == "PUBLIC":
                print(f"    [~] Ressource publique — accessible sans authentification (pas un BOLA)")
            elif verdict == "NON_CONCLUANT":
                print(f"    [?] Test non concluant — requête invalide (Statut: {response.status_code})")
            else:  # BLOQUE
                print(f"    [-] Accès correctement bloqué (Statut: {response.status_code})")
                
            results.append({
                "vulnerability": "BOLA",
                "endpoint": f"{endpoint.method} {endpoint.path}",
                "api_type": endpoint.api_type.value,
                "params_injected": params_map,
                "status_code": response.status_code,
                "verdict": verdict,
                "is_vulnerable": (verdict == "VULNERABLE"),
                "response_snippet": response.response_body[:150] # On garde un extrait pour le rapport final
            })
            
        return results

    def _analyze_response(self, response: AuditResponse) -> str:

        code = response.status_code

        # Cas 0 : échec technique (timeout, connexion refusée)
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
        Contre-test anonyme : refait la requête SANS aucun token.
        Si l'anonyme obtient un succès (2xx), la ressource est publique
        → l'accès de l'attaquant n'est pas un BOLA, juste un endpoint ouvert.
        """
        # Requête sans en-tête d'authentification
        headers_anonyme = {"Content-Type": "application/json"}

        response_anonyme = self.request_handler.send(
            base_url=target_url,
            endpoint=endpoint,
            headers=headers_anonyme,
            params_map=params_map
        )

        # Si l'anonyme réussit aussi, c'est que la ressource est publique
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