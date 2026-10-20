import os
import sys
from typing import List

import requests

from core.cerberus_display import log_error
from models.endpoint import ApiType, Parameter, ParamLocation, UnifiedEndpoint


class GraphQLParser:
    def __init__(self, url: str):
        self.url = url
        self.id_keywords = ['id', 'uuid', 'uid', 'reference']

    # ─────────────────────────────────────────────────────────────────
    def fetch_schema(self) -> dict:
        """Introspection complète : opérations + types (pour résoudre les champs)."""
        introspection_query = """
        {
          __schema {
            queryType {
              fields {
                name
                type { name kind ofType { name kind ofType { name kind } } }
                args { name type { name kind ofType { name kind } } }
              }
            }
            mutationType {
              fields {
                name
                type { name kind ofType { name kind ofType { name kind } } }
                args { name type { name kind ofType { name kind } } }
              }
            }
            types {
              name
              fields {
                name
                type { name kind ofType { name kind ofType { name kind } } }
              }
            }
          }
        }
        """
        try:
            response = requests.post(self.url, json={"query": introspection_query}, timeout=10)
            if response.status_code == 200:
                return response.json()
            log_error(f"Échec de l'introspection. Statut: {response.status_code}")
            return {}
        except Exception as e:
            log_error(f"Connexion impossible à {self.url}: {e}")
            return {}

    # ─────────────────────────────────────────────────────────────────
    def _est_scalaire(self, champ_type) -> bool:
        """Descend dans les couches NON_NULL/LIST pour trouver le kind réel."""
        while champ_type:
            kind = champ_type.get("kind")
            if kind in ("SCALAR", "ENUM"):
                return True
            if kind in ("OBJECT", "INTERFACE", "UNION"):
                return False
            champ_type = champ_type.get("ofType")
        return False

    def _resoudre_nom_type(self, type_info) -> str:
        """Descend dans ofType pour trouver le nom du type réel."""
        while type_info:
            if type_info.get("name"):
                return type_info["name"]
            type_info = type_info.get("ofType")
        return None

    # ─────────────────────────────────────────────────────────────────
    def parse(self) -> List[UnifiedEndpoint]:
        endpoints = []
        schema_data = self.fetch_schema()

        if not schema_data or 'data' not in schema_data or not schema_data['data']:
            log_error("Introspection vide ou invalide.")
            return endpoints

        schema = schema_data['data']['__schema']

        # 1. Construire le dictionnaire : nom_type -> champs scalaires
        champs_par_type = {}
        for t in schema.get('types', []):
            if not t.get('fields'):
                continue
            scalaires = [c['name'] for c in t['fields'] if self._est_scalaire(c['type'])]
            champs_par_type[t['name']] = scalaires

        # 2. Traiter les queries (lectures) et mutations (écritures)
        for type_ops, is_mutation in [('queryType', False), ('mutationType', True)]:
            bloc = schema.get(type_ops)
            if not bloc or not bloc.get('fields'):
                continue

            for field in bloc['fields']:
                action_name = field['name']

                # Type de retour et ses champs scalaires
                type_retour = self._resoudre_nom_type(field.get('type', {}))
                return_fields = champs_par_type.get(type_retour, [])

                endpoint = UnifiedEndpoint(
                    api_type=ApiType.GRAPHQL,
                    path=self.url,
                    method="POST",
                    action_name=action_name,
                    is_administrative=False,   # le BFLA différentiel n'en dépend plus
                    is_mutation=is_mutation,
                    return_fields=return_fields
                )

                # Les arguments (dont les identifiants)
                for arg in field.get('args', []):
                    arg_name = arg['name']
                    is_id = any(kw in arg_name.lower() for kw in self.id_keywords)
                    param = Parameter(
                        name=arg_name,
                        location=ParamLocation.GQL_ARG,
                        data_type=self._resoudre_nom_type(arg.get('type', {})) or 'unknown',
                        is_required=(arg.get('type', {}).get('kind') == 'NON_NULL'),
                        is_potential_id=is_id
                    )
                    endpoint.parameters.append(param)

                endpoints.append(endpoint)

        return endpoints


# --- Test autonome ---
if __name__ == "__main__":
    target_url = sys.argv[1] if len(sys.argv) > 1 else os.getenv("GRAPHQL_TARGET_URL")
    if not target_url:
        print("Usage: python -m parsers.graphql_parser <URL>")
        sys.exit(1)

    parser = GraphQLParser(target_url)
    for ep in parser.parse():
        type_op = "MUTATION" if ep.is_mutation else "QUERY"
        ids = [p.name for p in ep.get_id_parameters()]
        print(f"[{type_op:8}] {ep.action_name:20} | ids: {ids} | champs: {ep.return_fields[:4]}...")