import yaml
import requests
import base64
import json
import time
from pathlib import Path
from typing import Dict, Optional

class AuthManager:
    def __init__(self, target_url: str, config_path: str = "config/audit_config.yaml"):
        self.target_url = target_url.rstrip('/')
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._active_tokens = {}
        # Marge de sécurité en secondes (renouvelle le token s'il expire dans moins d'une minute)
        self.expiration_buffer = 60 

    def _load_config(self) -> dict:
        if not self.config_path.exists():
            print(f"[ERREUR] Fichier de configuration introuvable : {self.config_path.resolve()}")
            return {}
        try:
            with self.config_path.open('r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            print(f"[ERREUR] Impossible de lire {self.config_path.name}: {e}")
            return {}

    def _is_token_expired(self, token: str) -> bool:
        """Décode le JWT pour vérifier son timestamp d'expiration (champ 'exp')."""
        try:
            # Un JWT standard contient 3 parties séparées par des points
            parts = token.split('.')
            if len(parts) != 3:
                # Si ce n'est pas un JWT standard, on ne peut pas lire l'expiration côté client
                return False
            
            # Le payload est la 2ème partie. On corrige le padding Base64 si nécessaire.
            payload_b64 = parts[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            
            # Décodage propre en JSON
            payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            payload = json.loads(payload_json)
            
            # Vérification du champ d'expiration
            if 'exp' in payload:
                exp_time = int(payload['exp'])
                current_time = int(time.time())
                
                # Retourne True si le temps restant est inférieur à la marge de sécurité
                return (exp_time - current_time) < self.expiration_buffer
                
            return False # S'il n'y a pas de champ 'exp', on suppose qu'il n'expire pas
        except Exception as e:
            # En cas d'erreur de parsing, on log en debug et on force le renouvellement par sécurité
            print(f"[DEBUG] Erreur lors de la lecture de l'expiration du token : {e}")
            return True

    def _login_and_get_token(self, role: str) -> Optional[str]:
        auth_config = self.config.get('auth', {})
        accounts = auth_config.get('accounts', {})
        
        if role not in accounts:
            return None

        login_path = auth_config.get('login_path', '/login')
        token_key = auth_config.get('token_response_key', 'token')
        login_url = f"{self.target_url}{login_path}"
        credentials = accounts[role]

        try:
            response = requests.post(login_url, json=credentials, timeout=10)
            if response.status_code in [200, 201]:
                data = response.json()
                return data.get(token_key)
            else:
                print(f"[ERREUR AUTH] Échec connexion pour '{role}'. Statut: {response.status_code}")
                return None
        except requests.RequestException as e:
            print(f"[ERREUR AUTH] Impossible de joindre l'endpoint de login ({login_url}): {e}")
            return None

    def get_auth_headers(self, role: str) -> Dict[str, str]:
        """Retourne les en-têtes HTTP et renouvelle automatiquement le jeton si nécessaire."""
        if role == 'unauth':
            return {"Content-Type": "application/json"}

        # 1. On vérifie si on doit générer ou renouveler le token
        token = self._active_tokens.get(role)
        needs_refresh = False

        if not token:
            needs_refresh = True
        elif self._is_token_expired(token):
            print(f"[*] Le jeton pour le rôle '{role}' est sur le point d'expirer. Renouvellement automatique...")
            needs_refresh = True

        # 2. Exécution du renouvellement si flaggué
        if needs_refresh:
            new_token = self._login_and_get_token(role)
            if new_token:
                self._active_tokens[role] = new_token
            else:
                print(f"[ATTENTION] Impossible de générer le jeton pour le rôle '{role}'")
                return {"Content-Type": "application/json"}
        
        # 3. Retour des en-têtes valides
        return {
            "Authorization": f"Bearer {self._active_tokens[role]}",
            "Content-Type": "application/json"
        }