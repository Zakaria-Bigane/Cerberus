"""
Générateur de rapport JSON pour l'outil d'audit de contrôle d'accès.
Transforme les résultats bruts des moteurs en un rapport structuré et exploitable.
"""
import json
from datetime import datetime
from core.cerberus_display import log_success


class JsonReporter:
    # Mapping gravité selon le type de faille et l'action
    def _calculer_gravite(self, resultat) -> str:
        """
        Attribue une gravité défendable :
        - BFLA (fonction admin) → CRITIQUE (élévation de privilège)
        - BOLA en écriture (PUT/DELETE/mutation) → CRITIQUE (intégrité)
        - BOLA en lecture (GET/query) → HAUTE (fuite de données)
        """
        vuln = resultat.get("vulnerability", "")
        endpoint = resultat.get("endpoint", "").upper()

        if vuln == "BFLA":
            return "CRITIQUE"

        # BOLA : distinguer lecture / écriture
        actions_ecriture = ["PUT", "DELETE", "POST", "PATCH",
                            "EDITPASTE", "DELETEPASTE"]
        if any(a in endpoint for a in actions_ecriture):
            return "CRITIQUE"
        return "HAUTE"

    def _recommandation(self, resultat) -> str:
        """Recommandation de correction selon le type de faille."""
        vuln = resultat.get("vulnerability", "")
        if vuln == "BOLA":
            return ("Vérifier, côté serveur, que l'utilisateur authentifié est "
                    "bien le propriétaire de la ressource demandée avant de la "
                    "retourner ou de la modifier (contrôle d'accès au niveau objet).")
        if vuln == "BFLA":
            return ("Restreindre l'accès à cette fonction aux rôles autorisés "
                    "(vérification de rôle côté serveur), et ne jamais se fier "
                    "au masquage de l'interface cliente.")
        return "Revoir la logique d'autorisation de cet endpoint."

    def generer(self, results, cible, api_type, chemin_sortie="rapport_audit.json"):
        """
        Génère le rapport JSON complet.
        results : liste de dicts produits par les moteurs BOLA/BFLA
        """
        # Séparer les failles confirmées des tests non concluants
        failles = [r for r in results if r.get("is_vulnerable")]
        non_concluants = [r for r in results
                          if r.get("verdict") == "NON_CONCLUANT"]
        
        a_examiner = [r for r in results if r.get("a_examiner")]

        # Enrichir chaque faille de sa gravité et sa recommandation
        failles_enrichies = []
        for r in failles:
            failles_enrichies.append({
                "type": r.get("vulnerability"),
                "endpoint": r.get("endpoint"),
                "api_type": r.get("api_type"),
                "gravite": self._calculer_gravite(r),
                "verdict": r.get("verdict"),
                "parametres_injectes": r.get("params_injected", {}),
                "preuve": r.get("response_snippet", "")[:300],
                "recommandation": self._recommandation(r),
            })

        # Trier par gravité (CRITIQUE d'abord)
        ordre = {"CRITIQUE": 0, "HAUTE": 1, "MOYENNE": 2}
        failles_enrichies.sort(key=lambda f: ordre.get(f["gravite"], 3))

        # Compteurs pour le résumé
        nb_critique = sum(1 for f in failles_enrichies if f["gravite"] == "CRITIQUE")
        nb_haute = sum(1 for f in failles_enrichies if f["gravite"] == "HAUTE")

        rapport = {
            "metadonnees": {
                "outil": "Cerberus — API Access Control Auditor",
                "date_audit": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "cible": cible,
                "type_api": api_type,
                "perimetre": ["BOLA (API1:2023)", "BFLA (API5:2023)"],
            },
            "resume": {
                "total_tests": len(results),
                "failles_confirmees": len(failles_enrichies),
                "critiques": nb_critique,
                "hautes": nb_haute,
                "points_a_examiner": len(a_examiner),
                "tests_non_concluants": len(non_concluants),
            },
            "failles": failles_enrichies,
            "points_a_examiner": [
                {"endpoint": r.get("endpoint"), "type": r.get("vulnerability"),
                 "note": "Accessible à un utilisateur standard sans contrôle de rôle "
                         "observable. À qualifier selon la sensibilité métier de la fonction."}
                for r in a_examiner
            ],
            "tests_non_concluants": [
                {"endpoint": r.get("endpoint"), "type": r.get("vulnerability"),
                 "raison": "requête invalide ou effet indéterminable"}
                for r in non_concluants
            ],
        }

        # Écrire le fichier
        with open(chemin_sortie, "w", encoding="utf-8") as f:
            json.dump(rapport, f, indent=2, ensure_ascii=False)

        print()
        log_success(f"Rapport JSON généré : {chemin_sortie}")
        log_success(f"{len(failles_enrichies)} faille(s) — "
                    f"{nb_critique} critique(s), {nb_haute} haute(s), "
                    f"{len(a_examiner)} à examiner")

        return rapport