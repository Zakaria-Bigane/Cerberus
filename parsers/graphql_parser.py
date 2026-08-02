import requests
import sys
import os
from typing import List
from models.endpoint import UnifiedEndpoint, ApiType, Parameter, ParamLocation

class GraphQLParser:
    def __init__(self, url: str):
        self.url = url
        self.id_keywords = ['id', 'uuid', 'uid', 'reference']
        self.admin_keywords = ['admin', 'manage', 'delete', 'update', 'create']

    def fetch_schema(self) -> dict:
        introspection_query = """
        query {
          __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              fields {
                name
                args {
                  name
                  type { name kind }
                }
              }
            }
          }
        }
        """
        try:
            response = requests.post(self.url, json={"query": introspection_query}, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                print(f"[ERREUR] Échec de l'introspection. Statut: {response.status_code}")
                return {}
        except Exception as e:
            print(f"[ERREUR] Connexion impossible à {self.url}: {e}")
            return {}

    def parse(self) -> List[UnifiedEndpoint]:
        endpoints = []
        schema_data = self.fetch_schema()
        
        if not schema_data or 'data' not in schema_data:
            return endpoints
            
        schema = schema_data['data']['__schema']
        query_type_name = schema['queryType']['name'] if schema.get('queryType') else 'Query'
        mutation_type_name = schema['mutationType']['name'] if schema.get('mutationType') else 'Mutation'
        
        for gql_type in schema.get('types', []):
            if gql_type['name'] not in [query_type_name, mutation_type_name]:
                continue
                
            is_mutation = (gql_type['name'] == mutation_type_name)
            fields = gql_type.get('fields') or []
            
            for field in fields:
                action_name = field['name']
                is_admin = is_mutation or any(kw in action_name.lower() for kw in self.admin_keywords)
                
                endpoint = UnifiedEndpoint(
                    api_type=ApiType.GRAPHQL,
                    path=self.url, 
                    method="POST",
                    action_name=action_name,
                    is_administrative=is_admin
                )
                
                args = field.get('args', [])
                for arg in args:
                    arg_name = arg['name']
                    is_id = any(kw in arg_name.lower() for kw in self.id_keywords)
                    
                    param = Parameter(
                        name=arg_name,
                        location=ParamLocation.GQL_ARG,
                        data_type=arg.get('type', {}).get('name', 'unknown'),
                        is_required=arg.get('type', {}).get('kind') == 'NON_NULL',
                        is_potential_id=is_id
                    )
                    endpoint.parameters.append(param)
                    
                endpoints.append(endpoint)
                
        return endpoints

# --- Test d'exécution autonome sans Hardcoding ---
if __name__ == "__main__":
    # Récupération dynamique de l'URL (Argument CLI ou Variable d'Environnement)
    target_url = None
    
    if len(sys.argv) > 1:
        target_url = sys.argv[1]
    else:
        target_url = os.getenv("GRAPHQL_TARGET_URL")
        
    if not target_url:
        print("[ERREUR] Aucune URL cible fournie.")
        print("Usage: python -m parsers.graphql_parser <URL_CIBLE>")
        print("Exemple: python -m parsers.graphql_parser http://localhost:5013/graphql")
        sys.exit(1)

    print(f"[*] Test du parseur GraphQL sur la cible : {target_url}")
    parser = GraphQLParser(target_url)
    results = parser.parse()
    
    for ep in results:
        print(ep)