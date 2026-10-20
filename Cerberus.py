import argparse
import sys

from core.auth_manager import AuthManager
from core.cerberus_display import (
    afficher_banniere,
    afficher_entete,
    log_error,
    log_faille,
    log_info,
    log_success,
    separateur,
)
from core.request_handler import RequestHandler
from engines.bfla_engine import BflaEngine
from engines.bola_engine import BolaEngine
from parsers.graphql_parser import GraphQLParser
from parsers.openapi_parser import OpenAPIParser
from reporters.html_reporter import HtmlReporter
from reporters.json_reporter import JsonReporter


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


def main():
    """Point d'entrée de Cerberus (utilisé par `python Cerberus.py` et le script console `cerberus`)."""
    args = setup_cli()

    # Vérification de cohérence des arguments
    if args.type == 'rest' and not args.schema:
        log_error("Vous devez fournir un fichier de spécification (-s) pour auditer une API REST.")
        sys.exit(1)

    afficher_banniere()
    afficher_entete(args.target, args.type, args.schema)

    # 1. Initialisation des modules centraux
    auth_manager = AuthManager(target_url=args.target, config_path=args.config)
    request_handler = RequestHandler(timeout=10)

    # 2. Étape de Reconnaissance (Parsing)
    endpoints = []
    if args.type == 'rest':
        log_info(f"Analyse du fichier OpenAPI : {args.schema}...")
        parser = OpenAPIParser(args.schema)
        endpoints = parser.parse()
    elif args.type == 'graphql':
        log_info("Lancement de l'introspection GraphQL...")
        parser = GraphQLParser(args.target)
        endpoints = parser.parse()

    if not endpoints:
        log_error("Aucun endpoint valide trouvé. Vérifiez votre cible ou votre schéma.")
        sys.exit(1)

    log_success(f"{len(endpoints)} opérations cibles chargées avec succès.")

    # 3. Étape d'Attaque (Exécution des moteurs)
    all_results = []

    # Lancement du BOLA
    bola_engine = BolaEngine(auth_manager, request_handler)
    bola_results = bola_engine.run(endpoints, target_url=args.target, victim_id=args.victim_id)
    all_results.extend(bola_results)

    # Lancement du BFLA
    bfla_engine = BflaEngine(auth_manager, request_handler)
    register_path = getattr(parser, 'register_path', None)
    bfla_results = bfla_engine.run(endpoints, target_url=args.target, register_path=register_path)
    all_results.extend(bfla_results)

    # 4. Bilan de l'audit
    print()
    separateur()
    log_info("BILAN DE L'AUDIT")
    separateur()

    vulnerabilities = [r for r in all_results if r['is_vulnerable']]

    log_info(f"Total des requêtes de test  : {len(all_results)}")
    log_info(f"Failles confirmées          : {len(vulnerabilities)}")

    if vulnerabilities:
        for v in vulnerabilities:
            log_faille(f"{v['vulnerability']} détecté sur : {v['endpoint']}")
    else:
        log_success("Aucun défaut de contrôle d'accès détecté avec ce jeu de tests.")

    # 5. Génération des rapports
    JsonReporter().generer(all_results, cible=args.target, api_type=args.type.upper())
    HtmlReporter().generer(all_results, cible=args.target, api_type=args.type.upper())

if __name__ == "__main__":
    main()
