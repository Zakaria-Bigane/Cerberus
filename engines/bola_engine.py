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
            is_vulnerable = self._analyze_response(response)
            
            if is_vulnerable:
                print(f"    [!!!] FAILLE BOLA CONFIRMÉE ! Le serveur a accepté l'action (Statut: {response.status_code})")
            else:
                print(f"    [-] Accès correctement bloqué (Statut: {response.status_code})")
                
            results.append({
                "vulnerability": "BOLA",
                "endpoint": f"{endpoint.method} {endpoint.path}",
                "api_type": endpoint.api_type.value,
                "params_injected": params_map,
                "status_code": response.status_code,
                "is_vulnerable": is_vulnerable,
                "response_snippet": response.response_body[:150] # On garde un extrait pour le rapport final
            })
            
        return results

    def _analyze_response(self, response: AuditResponse) -> bool:
        """
        Le 'cerveau' de l'analyse. Détermine si le contrôle d'accès a échoué.
        """
        # Si la requête n'a pas pu aboutir techniquement
        if response.status_code == 0:
            return False

        # Spécificité GraphQL : Un 200 OK avec le mot "errors" dans le JSON 
        # signifie généralement que l'autorisation au niveau du résolveur a fait son travail.
        if response.is_graphql_error:
            return False
            
        # Dans le monde REST et GraphQL (sans erreur), un code 2xx sur une ressource 
        # qui ne nous appartient pas confirme l'élévation de privilèges horizontaux.
        if response.status_code in [200, 201, 204]:
            return True
            
        return False