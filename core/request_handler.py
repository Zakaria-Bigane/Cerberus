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
        """
        if endpoint.api_type == ApiType.REST:
            # REST : le path est relatif, on le concatène à base_url
            url = f"{base_url.rstrip('/')}/{endpoint.path.lstrip('/')}"
            return self._send_rest(url, endpoint, headers, params_map)

        elif endpoint.api_type == ApiType.GRAPHQL:
            # GraphQL : le path EST déjà l'URL complète de l'endpoint /graphql
            url = endpoint.path
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
             # Si l'endpoint déclare un corps de requête, on l'envoie en JSON
            json_body = endpoint.body_template if endpoint.body_template else None

            res = requests.request(
                method=endpoint.method,
                url=final_url,
                headers=headers,
                params=query_params,
                json=json_body,
                timeout=self.timeout,
                verify=False
            )
            return AuditResponse(res.status_code, res.text, len(res.text), res.elapsed.total_seconds())
        except requests.RequestException as e:
            return AuditResponse(0, str(e), 0, 0.0)

    def _send_graphql(self, url, endpoint, headers, params_map):
        """Construit et envoie une requête GraphQL en demandant les vrais champs."""
         
        # 1. Construire les arguments (ex: id: 1, title: "x")
        args_list = []
        for p in endpoint.parameters:
            if p.name in params_map:
                val = params_map[p.name]
                # On respecte le type GraphQL déclaré par le schéma
                type_arg = (p.data_type or "").lower()
                if type_arg in ("int", "integer", "float", "id", "boolean"):
                    # Types numériques/ID : pas de guillemets.
                    # (En GraphQL, le type ID accepte un entier ou une chaîne nue)
                    args_list.append(f'{p.name}: {val}')
                else:
                    # Types chaîne : avec guillemets
                    args_list.append(f'{p.name}: "{val}"')
        args_str = f"({', '.join(args_list)})" if args_list else ""

        # 2. Choisir query ou mutation depuis l'info du parser (pas de devinette)
        operation_type = "mutation" if endpoint.is_mutation else "query"

        # 3. Construire les champs de retour à demander
        if endpoint.return_fields:
            champs = " ".join(endpoint.return_fields)
            selection = f" {{ {champs} }}"
        elif endpoint.is_mutation:
            # Mutation à retour objet sans champs scalaires (ex: editPaste → {paste})
            # On demande __typename pour que la requête soit valide.
            # Le verdict viendra de l'oracle d'effet (relecture), pas de ce retour.
            selection = " { __typename }"
        else:
            selection = ""

        gql_body = f"{operation_type} {{ {endpoint.action_name}{args_str}{selection} }}"
        
        try:
            res = requests.post(
                url=url,
                headers=headers,
                json={"query": gql_body},
                timeout=self.timeout,
                verify=False
            )
            # GraphQL : 200 même en cas d'erreur ; l'erreur est dans le champ "errors"
            is_gql_error = False
            if res.status_code == 200 and '"errors"' in res.text:
                is_gql_error = True
            return AuditResponse(res.status_code, res.text, len(res.text),
                                 res.elapsed.total_seconds(), is_gql_error)
        except requests.RequestException as e:
            return AuditResponse(0, str(e), 0, 0.0)