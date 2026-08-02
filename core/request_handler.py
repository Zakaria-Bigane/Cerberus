import requests
import urllib3
from typing import Dict, Any
from dataclasses import dataclass
from models.endpoint import UnifiedEndpoint, ApiType, ParamLocation

# Désactive les avertissements SSL (très courant lors des audits en laboratoire de pentest)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class AuditResponse:
    """Modèle standardisé pour les réponses HTTP de l'audit."""
    status_code: int
    response_body: str
    length: int
    elapsed_time: float
    is_graphql_error: bool = False # Spécifique à GraphQL (qui renvoie souvent 200 OK même en cas d'erreur)

class RequestHandler:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def send(self, base_url: str, endpoint: UnifiedEndpoint, headers: Dict[str, str], params_map: Dict[str, Any]) -> AuditResponse:
        """
        Forge et envoie la requête HTTP en fonction du type d'API.
        params_map est un dictionnaire contenant les valeurs à injecter, ex: {"user_id": 124}
        """
        # Nettoyage de l'URL pour éviter les doubles slashes (ex: http://site.com//api/v1)
        url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
        
        if endpoint.api_type == ApiType.REST:
            return self._send_rest(url, endpoint, headers, params_map)
        elif endpoint.api_type == ApiType.GRAPHQL:
            return self._send_graphql(url, endpoint, headers, params_map)
        
        return AuditResponse(0, "Type d'API inconnu", 0, 0.0)

    def _send_rest(self, url: str, endpoint: UnifiedEndpoint, headers: Dict[str, str], params_map: Dict[str, Any]) -> AuditResponse:
        """Logique d'assemblage spécifique aux APIs REST / OpenAPI."""
        final_url = url
        query_params = {}

        # 1. Injection dynamique des paramètres
        for param in endpoint.parameters:
            if param.name in params_map:
                value = params_map[param.name]
                if param.location == ParamLocation.PATH:
                    final_url = final_url.replace(f"{{{param.name}}}", str(value))
                elif param.location == ParamLocation.QUERY:
                    query_params[param.name] = value

        try:
            res = requests.request(
                method=endpoint.method,
                url=final_url,
                headers=headers,
                params=query_params,
                timeout=self.timeout,
                verify=False
            )
            return AuditResponse(res.status_code, res.text, len(res.text), res.elapsed.total_seconds())
        except requests.RequestException as e:
            return AuditResponse(0, str(e), 0, 0.0)

    def _send_graphql(self, url: str, endpoint: UnifiedEndpoint, headers: Dict[str, str], params_map: Dict[str, Any]) -> AuditResponse:
        """Logique d'assemblage spécifique à GraphQL."""
        # Construction basique des arguments de la requête GraphQL (ex: id: 123)
        args_list = []
        for p in endpoint.parameters:
            if p.name in params_map:
                val = params_map[p.name]
                # Si c'est une chaîne, il faut l'entourer de guillemets pour GraphQL
                if isinstance(val, str):
                    args_list.append(f'{p.name}: "{val}"')
                else:
                    args_list.append(f'{p.name}: {val}')
        
        args_str = f"({', '.join(args_list)})" if args_list else ""
        
        # Le mot-clé dépend de l'action. On simplifie pour le MVP :
        # Si le nom contient des mots d'action, on tente une mutation, sinon une query.
        is_mutation = any(kw in endpoint.action_name.lower() for kw in ['delete', 'update', 'create', 'add', 'remove'])
        operation_type = "mutation" if is_mutation else "query"
        
        # On demande __typename pour avoir une réponse valide minimum sans connaître la structure de retour
        gql_body = f"{operation_type} {{ {endpoint.action_name}{args_str} {{ __typename }} }}"
        
        try:
            res = requests.post(
                url=url,
                headers=headers,
                json={"query": gql_body},
                timeout=self.timeout,
                verify=False
            )
            
            # GraphQL renvoie souvent 200 OK, mais avec un tableau "errors" dans le JSON si l'autorisation échoue
            is_gql_error = False
            if res.status_code == 200 and "errors" in res.text.lower():
                is_gql_error = True
                
            return AuditResponse(res.status_code, res.text, len(res.text), res.elapsed.total_seconds(), is_gql_error)
            
        except requests.RequestException as e:
            return AuditResponse(0, str(e), 0, 0.0)