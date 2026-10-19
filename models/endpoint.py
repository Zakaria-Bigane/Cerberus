from dataclasses import dataclass, field
from typing import List, Optional
from enum import Enum

class ApiType(Enum):
    REST = "REST"
    GRAPHQL = "GRAPHQL"

class ParamLocation(Enum):
    PATH = "PATH"
    QUERY = "QUERY"
    BODY = "BODY"
    GQL_ARG = "GQL_ARG"

@dataclass
class Parameter:
    name: str
    location: ParamLocation
    data_type: str
    is_required: bool
    is_potential_id: bool = False

@dataclass
class UnifiedEndpoint:
    api_type: ApiType
    path: str
    method: str
    action_name: str
    
    parameters: List[Parameter] = field(default_factory=list)
    graphql_payload_template: Optional[str] = None 
    is_administrative: bool = False 
    body_template: Optional[dict] = None
    # ── Spécifique GraphQL ────────────────────────────────────────────
    is_mutation: bool = False              # True = mutation (écriture), False = query (lecture)
    return_fields: List[str] = field(default_factory=list)  # champs scalaires à demander
    
    def get_id_parameters(self) -> List[Parameter]:
        """Retourne uniquement les paramètres qui ressemblent à des identifiants (pour le BOLA)"""
        return [p for p in self.parameters if p.is_potential_id]
        
    def __repr__(self):
        # En GraphQL, le path est toujours /graphql : on affiche action_name à la place
        if self.api_type == ApiType.GRAPHQL:
            identifiant = self.action_name
        else:
            identifiant = self.path
        return f"[{self.api_type.value}] {self.method.upper()} {identifiant} (Admin: {self.is_administrative}) - Params: {[p.name for p in self.parameters]}"