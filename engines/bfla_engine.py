from typing import List, Dict, Any
from models.endpoint import UnifiedEndpoint
from core.auth_manager import AuthManager
from core.request_handler import RequestHandler, AuditResponse

class BflaEngine:
    def __init__(self, auth_manager: AuthManager, request_handler: RequestHandler):
        self.auth_manager = auth_manager
        self.request_handler = request_handler

    def run(self, endpoints: List[UnifiedEndpoint], target_url: str) -> List[Dict[str, Any]]:
        """
        Exécute la campagne de test BFLA (Élévation de privilèges).
        """
        print(f"\n[==================================================]")
        print(f"[*] DÉMARRAGE DU MOTEUR BFLA (Élévation de privilèges)")
        print(f"[==================================================]")
        
        results = []
        
        # 1. On s'équipe du token d'un utilisateur standard (non-admin)
        print("[*] Récupération du jeton pour 'user_a' (Utilisateur standard)...")
        standard_headers = self.auth_manager.get_auth_headers('user_a')
        
        for endpoint in endpoints:
            # 2. Filtrage : on ne cible QUE les fonctions administratives ou sensibles
            if not endpoint.is_administrative:
                continue 
                
            print(f"\n[*] Test BFLA sur : [{endpoint.api_type.value}] {endpoint.method} {endpoint.path} (Action: {endpoint.action_name})")
            
            # 3. Préparation des paramètres factices pour que la requête soit syntaxiquement valide
            params_map = {}
            for param in endpoint.parameters:
                # Si la route demande un ID pour supprimer, on fournit un ID bidon
                if param.is_potential_id:
                    params_map[param.name] = "9999" 
                else:
                    params_map[param.name] = "test_value"
                
            # 4. Déclenchement du tir
            response = self.request_handler.send(
                base_url=target_url,
                endpoint=endpoint,
                headers=standard_headers,
                params_map=params_map
            )
            
            # 5. Interprétation du résultat
            verdict = self._analyze_response(response)

            if verdict == "VULNERABLE":
                print(f"    [!!!] FAILLE BFLA CONFIRMÉE ! Un utilisateur standard a réussi une action réservée (Statut: {response.status_code})")
            elif verdict == "NON_CONCLUANT":
                print(f"    [?] Test non concluant — requête invalide (Statut: {response.status_code})")
            else:  # BLOQUE
                print(f"    [-] Accès administratif correctement bloqué (Statut: {response.status_code})")
                
            results.append({
                "vulnerability": "BFLA",
                "endpoint": f"{endpoint.method} {endpoint.path}",
                "api_type": endpoint.api_type.value,
                "action_name": endpoint.action_name,
                "status_code": response.status_code,
                "verdict": verdict,
                "is_vulnerable": (verdict == "VULNERABLE"),
                "response_snippet": response.response_body[:150]
            })
            
        return results

    def _analyze_response(self, response: AuditResponse) -> str:
        """
        Oracle à trois états pour le BFLA. Renvoie :
          - "VULNERABLE"     : un utilisateur standard a réussi une action réservée
          - "BLOQUE"         : refus de privilège légitime (403, ou 404 de masquage)
          - "NON_CONCLUANT"  : requête invalide, le test ne prouve rien
        """
        code = response.status_code

        # Échec technique
        if code == 0:
            return "NON_CONCLUANT"

        # GraphQL : 200 avec "errors" = le résolveur a bloqué
        if response.is_graphql_error:
            return "BLOQUE"

        # Requête invalide → on n'a pas testé le privilège
        #   400 = corps/paramètres malformés
        #   401 = pas authentifié
        if code in [400, 401]:
            return "NON_CONCLUANT"

        # Un utilisateur standard a réussi une action sensible → élévation de privilège
        if code in [200, 201, 204]:
            return "VULNERABLE"

        # Refus explicite de privilège
        #   403 = interdit (le vrai blocage BFLA)
        #   404 = introuvable (masquage OU cible inexistante)
        if code in [403, 404]:
            return "BLOQUE"

        return "NON_CONCLUANT"