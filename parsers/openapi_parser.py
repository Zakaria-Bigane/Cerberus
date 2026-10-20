import json
from pathlib import Path
from typing import List

from core.cerberus_display import log_error, log_success, log_warning
from models.endpoint import ApiType, Parameter, ParamLocation, UnifiedEndpoint


class OpenAPIParser:
    # file_path peut être une chaîne de caractères ou un objet Path
    def __init__(self, file_path):
        # Path() convertit automatiquement le chemin selon l'OS (Windows ou Linux)
        self.file_path = Path(file_path)
        self.id_keywords = ['id', 'uuid', 'uid', 'reference', 'token']
        self.admin_keywords = ['admin', 'manage', 'delete', 'update', 'config']
        self.register_path = None 

    def parse(self) -> List[UnifiedEndpoint]:
        endpoints = []
        
        # Vérification robuste de l'existence du fichier
        if not self.file_path.exists():
            log_error(f"Le fichier est introuvable : {self.file_path.resolve()}")
            return endpoints

        try:
            # newline='' permet à Python de gérer universellement les retours chariots (CRLF vs LF)
            with self.file_path.open('r', encoding='utf-8', newline='') as f:
                spec = json.load(f)
        except Exception as e:
            log_error(f"Impossible de lire le fichier {self.file_path.name}: {e}")
            return endpoints

        paths = spec.get('paths', {})

        for path_url, path_items in paths.items():
            for method, operation in path_items.items():
                if method.lower() not in ['get', 'post', 'put', 'delete', 'patch']:
                    continue

                is_admin = False
                if method.lower() in ['delete', 'put', 'patch'] or \
                   any(kw in path_url.lower() for kw in self.admin_keywords) or \
                   any(kw in operation.get('operationId', '').lower() for kw in self.admin_keywords):
                    is_admin = True

                endpoint = UnifiedEndpoint(
                    api_type=ApiType.REST,
                    path=path_url,
                    method=method.upper(),
                    action_name=operation.get('operationId', f"{method}_{path_url}"),
                    is_administrative=is_admin
                )

                parameters = operation.get('parameters', [])
                for param in parameters:
                    if '$ref' in param:
                        continue 
                    
                    param_name = param.get('name', '')
                    param_in = param.get('in', '').upper()
                    is_id_by_location = (param_in == 'PATH')
                    is_id_by_name = any(kw in param_name.lower() for kw in self.id_keywords)
                    is_id = is_id_by_location or is_id_by_name
                    
                    location = ParamLocation.QUERY
                    if param_in == 'PATH':
                        location = ParamLocation.PATH
                    elif param_in == 'HEADER':
                        continue 
                        
                    parsed_param = Parameter(
                        name=param_name,
                        location=location,
                        data_type=param.get('schema', {}).get('type', 'string'),
                        is_required=param.get('required', False),
                        is_potential_id=is_id
                    )
                    endpoint.parameters.append(parsed_param)
                # Extraction du corps de requête (pour POST/PUT/PATCH)
                request_body = operation.get('requestBody', {})
                if request_body:
                    content = request_body.get('content', {})
                    json_content = content.get('application/json', {})
                    body_schema = json_content.get('schema', {})
                    properties = body_schema.get('properties', {})

                    # On construit un body d'exemple à partir des propriétés déclarées
                    body_template = {}
                    for prop_name, prop_details in properties.items():
                        # On utilise l'exemple du schéma s'il existe, sinon une valeur par défaut selon le type
                        if 'example' in prop_details:
                            body_template[prop_name] = prop_details['example']
                        elif prop_details.get('type') == 'string':
                            body_template[prop_name] = 'test_string'
                        elif prop_details.get('type') in ['integer', 'number']:
                            body_template[prop_name] = 1
                        else:
                            body_template[prop_name] = 'test_value'

                    endpoint.body_template = body_template
                endpoints.append(endpoint)

        # Déduction de l'infrastructure : l'endpoint de register
        self.register_path = self._detecter_register(paths)
        if self.register_path:
            log_success(f"Endpoint de register déduit : {self.register_path}")
        else:
            log_warning("Aucun endpoint de register détecté dans le schéma.")

        return endpoints


    def _detecter_register(self, paths):

        MOTS_USERNAME = ["username", "email", "login", "user"]
        MOTS_PASSWORD = ["password", "passwd", "pwd", "pass"]
        MOTS_CHEMIN_AUTH = ["login", "signin", "authenticate", "session"]

        for chemin, operations in paths.items():
            for methode, operation in operations.items():
                if methode.lower() != "post":
                    continue

                body = operation.get("requestBody", {})
                contenu = body.get("content", {}).get("application/json", {})
                props = contenu.get("schema", {}).get("properties", {})
                champs = [c.lower() for c in props.keys()]

                a_user = any(any(m in c for m in MOTS_USERNAME) for c in champs)
                a_pass = any(any(m in c for m in MOTS_PASSWORD) for c in champs)

                if a_user and a_pass:
                    est_login = any(m in chemin.lower() for m in MOTS_CHEMIN_AUTH)
                    if not est_login:
                        return chemin

        return None

# --- Test d'exécution autonome sans Hardcoding ---
if __name__ == "__main__":
    import sys
    
    # Le chemin cible peut être passé en argument dans le terminal
    if len(sys.argv) > 1:
        target_file = Path(sys.argv[1])
    else:
        # Création dynamique d'un fichier de test propre à l'OS courant
        target_file = Path("test_swagger_temp.json")
        dummy_swagger = {
            "paths": {
                "/api/users/{user_id}": {
                    "get": {"operationId": "getUser", "parameters": [{"name": "user_id", "in": "path"}]},
                    "delete": {"operationId": "deleteUser", "parameters": [{"name": "user_id", "in": "path"}]}
                }
            }
        }
        target_file.write_text(json.dumps(dummy_swagger), encoding='utf-8')
        print(f"[*] Fichier temporaire créé : {target_file.resolve()}")

    print(f"[*] Analyse du fichier : {target_file.name}...")
    parser = OpenAPIParser(target_file)
    results = parser.parse()
    
    for ep in results:
        print(ep)
        
    # Nettoyage automatique si on a utilisé le fichier temporaire
    if target_file.name == "test_swagger_temp.json" and target_file.exists():
        target_file.unlink()