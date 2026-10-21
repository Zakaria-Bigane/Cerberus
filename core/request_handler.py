from dataclasses import dataclass
from typing import Any, Dict

import requests
import urllib3

from models.endpoint import ApiType, ParamLocation, UnifiedEndpoint

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

def _echapper_chaine_gql(valeur) -> str:
    """Échappe une valeur pour l'insertion dans une chaîne littérale GraphQL."""
    s = str(valeur)
    return (s.replace("\\", "\\\\")
             .replace('"', '\\"')
             .replace("\n", "\\n")
             .replace("\r", "\\r")
             .replace("\t", "\\t"))


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
                verify=False  # nosec B501 : les laboratoires cibles (VAmPI/DVGA/crAPI) utilisent des certificats auto-signés en local ; option à rendre configurable pour toute cible réelle.
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
                if type_arg in ("int", "integer", "float"):
                    # Types numériques : pas de guillemets, mais validation
                    # stricte. Une valeur non numérique romprait la syntaxe →
                    # on abandonne la requête plutôt que d'envoyer du brut.
                    try:
                        num = float(val)
                        net = str(int(num)) if num == int(num) else str(num)
                    except (TypeError, ValueError):
                        return AuditResponse(0, f"Valeur non numérique pour l'argument '{p.name}' : requête abandonnée", 0, 0.0)
                    args_list.append(f'{p.name}: {net}')
                elif type_arg == "boolean":
                    bool_val = str(bool(val)).lower() if isinstance(val, bool) else str(val).lower()
                    if bool_val not in ("true", "false"):
                        return AuditResponse(0, f"Valeur non booléenne pour l'argument '{p.name}' : requête abandonnée", 0, 0.0)
                    args_list.append(f'{p.name}: {bool_val}')
                else:
                    # Types chaîne et ID : entre guillemets AVEC échappement.
                    # Sans échappement, une valeur contenant " ou } rompt la
                    # syntaxe du document et permet d'y injecter du contenu.
                    args_list.append(f'{p.name}: "{_echapper_chaine_gql(val)}"')
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
                verify=False  # nosec B501 : certificats auto-signés des laboratoires locaux (voir requête REST ci-dessus).
            )
            # GraphQL : 200 même en cas d'erreur ; l'erreur est dans le champ "errors".
            # Détection Fiable par parsing JSON (la recherche de la sous-chaîne
            # '"errors"' dans le texte brut produit des faux positifs quand ce
            # mot apparaît dans une donnée légitime, et des faux négatifs si la
            # réponse n'est pas du JSON).
            is_gql_error = False
            if res.status_code == 200:
                try:
                    corps_json = res.json()
                    if isinstance(corps_json, dict):
                        erreurs = corps_json.get("errors")
                        is_gql_error = bool(erreurs) if isinstance(erreurs, list) else False
                except ValueError:
                    is_gql_error = False
            return AuditResponse(res.status_code, res.text, len(res.text),
                                 res.elapsed.total_seconds(), is_gql_error)
        except requests.RequestException as e:
            return AuditResponse(0, str(e), 0, 0.0)