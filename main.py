import argparse
import sys
from core.auth_manager import AuthManager
from core.request_handler import RequestHandler
from parsers.openapi_parser import OpenAPIParser
from parsers.graphql_parser import GraphQLParser
from engines.bola_engine import BolaEngine
from engines.bfla_engine import BflaEngine

def setup_cli():
    """Configure les arguments en ligne de commande de l'outil."""
    parser = argparse.ArgumentParser(
        description="Module d'audit automatisé de contrôle d'accès (BOLA/BFLA) pour APIs."
    )
    
    # Paramètres obligatoires de base
    parser.add_argument("-t", "--target", required=True, help="L'URL de base de l'API ciblée")
    parser.add_argument("--type", choices=['rest', 'graphql'], required=True, help="Le type d'API à auditer")
    
    # Paramètre spécifique REST/OpenAPI
    parser.add_argument("-s", "--schema", help="Chemin vers le fichier Swagger.json (Obligatoire pour REST)")
    
    # Paramètres d'attaque obligatoires
    parser.add_argument("-v", "--victim-id", required=True, help="L'ID de l'utilisateur victime pour le test BOLA (ex: 124)")
    
    # Paramètre optionnel
    parser.add_argument("-c", "--config", default="config/audit_config.yaml", help="Chemin vers la config YAML")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = setup_cli()
    
    # Vérification de cohérence des arguments
    if args.type == 'rest' and not args.schema:
        print("[ERREUR] Vous devez fournir un fichier de spécification (-s) pour auditer une API REST.")
        sys.exit(1)

    print("\n" + "="*60)
    print("   AUTOMATED API AUDITOR - CONTRÔLE D'ACCÈS (BOLA/BFLA)")
    print("="*60)
    print(f"[*] Cible : {args.target}")
    print(f"[*] Type  : {args.type.upper()}")
    
    # 1. Initialisation des modules centraux
    auth_manager = AuthManager(target_url=args.target, config_path=args.config)
    request_handler = RequestHandler(timeout=10)
    
    # 2. Étape de Reconnaissance (Parsing)
    endpoints = []
    if args.type == 'rest':
        print(f"[*] Analyse du fichier OpenAPI : {args.schema}...")
        parser = OpenAPIParser(args.schema)
        endpoints = parser.parse()
    elif args.type == 'graphql':
        print("[*] Lancement de l'introspection GraphQL...")
        parser = GraphQLParser(args.target)
        endpoints = parser.parse()
        
    if not endpoints:
        print("[-] Aucun endpoint valide trouvé. Vérifiez votre cible ou votre schéma.")
        sys.exit(1)
        
    print(f"[+] {len(endpoints)} opérations cibles chargées avec succès.")

    # 3. Étape d'Attaque (Exécution des moteurs)
    all_results = []
    
    # Lancement du BOLA
    bola_engine = BolaEngine(auth_manager, request_handler)
    bola_results = bola_engine.run(endpoints, target_url=args.target, victim_id=args.victim_id)
    all_results.extend(bola_results)
    
    # Lancement du BFLA
    bfla_engine = BflaEngine(auth_manager, request_handler)
    bfla_results = bfla_engine.run(endpoints, target_url=args.target)
    all_results.extend(bfla_results)
    
    # 4. Synthèse brute des résultats (En attendant le module Reporter)
    print("\n" + "="*60)
    print("   BILAN DE L'AUDIT")
    print("="*60)
    
    vulnerabilities = [r for r in all_results if r['is_vulnerable']]
    
    print(f"Total des requêtes de test  : {len(all_results)}")
    print(f"Failles confirmées          : {len(vulnerabilities)}")
    
    if vulnerabilities:
        for v in vulnerabilities:
            print(f"  -> [CRITIQUE] {v['vulnerability']} détecté sur : {v['endpoint']}")
    else:
        print("  -> Aucun défaut de contrôle d'accès détecté avec ce jeu de tests.")