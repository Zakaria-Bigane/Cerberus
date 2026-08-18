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
    
    def get_id_parameters(self) -> List[Parameter]:
        """Retourne uniquement les paramètres qui ressemblent à des identifiants (pour le BOLA)"""
        return [p for p in self.parameters if p.is_potential_id]
        
    def __repr__(self):
        return f"[{self.api_type.value}] {self.method.upper()} {self.path} (Admin: {self.is_administrative}) - Params: {[p.name for p in self.parameters]}"