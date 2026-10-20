"""
Générateur de rapport HTML pour l'outil d'audit de contrôle d'accès.
Produit un document autonome (CSS inclus) présentable à un client.
"""
import html
from datetime import datetime

from core.cerberus_display import log_success


class HtmlReporter:

    # ── Gravité et recommandation : même logique que le reporter JSON ──
    def _calculer_gravite(self, resultat) -> str:
        vuln = resultat.get("vulnerability", "")
        endpoint = resultat.get("endpoint", "").upper()
        if vuln == "BFLA":
            return "CRITIQUE"
        actions_ecriture = ["PUT", "DELETE", "POST", "PATCH",
                            "EDITPASTE", "DELETEPASTE"]
        if any(a in endpoint for a in actions_ecriture):
            return "CRITIQUE"
        return "HAUTE"

    def _recommandation(self, resultat) -> str:
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

    def _description(self, resultat) -> str:
        vuln = resultat.get("vulnerability", "")
        if vuln == "BOLA":
            return ("Un utilisateur authentifié a pu accéder à une ressource "
                    "appartenant à un autre utilisateur en manipulant son "
                    "identifiant. L'API ne vérifie pas la propriété de l'objet.")
        if vuln == "BFLA":
            return ("Un utilisateur d'un rôle inférieur a pu exécuter une "
                    "fonction qui devrait être réservée à un rôle privilégié. "
                    "L'API ne vérifie pas correctement le rôle de l'appelant.")
        return "Défaut de contrôle d'accès détecté."

    # ── Génération ────────────────────────────────────────────────────
    def generer(self, results, cible, api_type, chemin_sortie="rapport_audit.html"):
        failles = [r for r in results if r.get("is_vulnerable")]
        a_examiner = [r for r in results if r.get("a_examiner")]
        non_concluants = [r for r in results if r.get("verdict") == "NON_CONCLUANT"]

        # Enrichir + trier par gravité
        enrichies = []
        for r in failles:
            enrichies.append({
                "type": r.get("vulnerability"),
                "endpoint": r.get("endpoint"),
                "api_type": r.get("api_type"),
                "gravite": self._calculer_gravite(r),
                "params": r.get("params_injected", {}),
                "preuve": r.get("response_snippet", ""),
                "description": self._description(r),
                "recommandation": self._recommandation(r),
            })
        ordre = {"CRITIQUE": 0, "HAUTE": 1, "MOYENNE": 2}
        enrichies.sort(key=lambda f: ordre.get(f["gravite"], 3))

        nb_critique = sum(1 for f in enrichies if f["gravite"] == "CRITIQUE")
        nb_haute = sum(1 for f in enrichies if f["gravite"] == "HAUTE")
        date_audit = datetime.now().strftime("%d/%m/%Y à %H:%M")

        # Construire les blocs de failles
        blocs_failles = ""
        for i, f in enumerate(enrichies, 1):
            params_str = ", ".join(f"{k} = {v}" for k, v in f["params"].items())
            preuve = html.escape(f["preuve"][:400]) if f["preuve"] else "(aucun extrait)"
            blocs_failles += f"""
        <article class="finding finding--{f['gravite'].lower()}">
          <header class="finding__head">
            <span class="finding__num">{i:02d}</span>
            <div class="finding__title">
              <span class="badge badge--{f['type'].lower()}">{html.escape(f['type'])}</span>
              <code class="finding__endpoint">{html.escape(f['endpoint'])}</code>
            </div>
            <span class="sev sev--{f['gravite'].lower()}">{f['gravite']}</span>
          </header>
          <div class="finding__body">
            <p class="finding__desc">{html.escape(f['description'])}</p>
            <div class="finding__meta">
              <span class="tag">{html.escape(f['api_type'])}</span>
              <span class="tag">Paramètre injecté : {html.escape(params_str) or '—'}</span>
            </div>
            <div class="proof">
              <div class="proof__label">Preuve — réponse obtenue</div>
              <pre class="proof__code">{preuve}</pre>
            </div>
            <div class="reco">
              <div class="reco__label">Recommandation</div>
              <p>{html.escape(f['recommandation'])}</p>
            </div>
          </div>
        </article>"""

        # Section « à examiner »
        blocs_examen = ""
        if a_examiner:
            lignes_ex = ""
            for r in a_examiner:
                lignes_ex += f"""
              <tr>
                <td><code>{html.escape(r.get('endpoint', ''))}</code></td>
                <td>{html.escape(r.get('vulnerability', ''))}</td>
                <td>{html.escape(r.get('api_type', ''))}</td>
              </tr>"""
            blocs_examen = f"""
        <section class="section">
          <h2 class="section__title">Points à examiner</h2>
          <p class="section__intro">Ces fonctions sont accessibles à un utilisateur standard sans contrôle de rôle observable. L'outil ne peut pas déterminer automatiquement si cet accès est légitime ou constitue une faille : leur qualification requiert une analyse humaine de la sensibilité métier de chaque fonction.</p>
          <table class="nc-table">
            <thead><tr><th>Endpoint</th><th>Test</th><th>Type d'API</th></tr></thead>
            <tbody>{lignes_ex}
            </tbody>
          </table>
        </section>"""

        # Section non concluants
        blocs_nc = ""
        if non_concluants:
            lignes_nc = ""
            for r in non_concluants:
                lignes_nc += f"""
              <tr>
                <td><code>{html.escape(r.get('endpoint', ''))}</code></td>
                <td>{html.escape(r.get('vulnerability', ''))}</td>
                <td>Requête invalide ou effet indéterminable</td>
              </tr>"""
            blocs_nc = f"""
        <section class="section">
          <h2 class="section__title">Tests non concluants</h2>
          <p class="section__intro">Ces opérations n'ont pas pu être tranchées automatiquement (requête invalide, absence d'oracle applicable ou dépassement de délai). Elles méritent une vérification manuelle.</p>
          <table class="nc-table">
            <thead><tr><th>Endpoint</th><th>Test</th><th>Raison</th></tr></thead>
            <tbody>{lignes_nc}
            </tbody>
          </table>
        </section>"""

        # Message si aucune faille
        if not enrichies:
            blocs_failles = """
        <div class="empty">
          <p>Aucune faille de contrôle d'accès confirmée sur ce périmètre.</p>
        </div>"""

        # Le document complet
        doc = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport d'audit — Contrôle d'accès API</title>
<style>
  :root {{
    --ink: #1a1f2b;
    --ink-soft: #4a5262;
    --line: #e2e5ea;
    --bg: #f7f8fa;
    --card: #ffffff;
    --critique: #c0392b;
    --critique-bg: #fdecea;
    --haute: #d97706;
    --haute-bg: #fef4e6;
    --examen: #b7791f;
    --examen-bg: #fdf6e3;
    --accent: #2c5282;
    --mono: 'SFMono-Regular', 'Consolas', 'Liberation Mono', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: var(--ink);
    background: var(--bg);
    line-height: 1.55;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{ max-width: 880px; margin: 0 auto; padding: 48px 24px 80px; }}

  /* En-tête */
  .header {{ border-bottom: 3px solid var(--ink); padding-bottom: 24px; margin-bottom: 8px; }}
  .header__eyebrow {{
    font-size: 12px; letter-spacing: 0.14em; text-transform: uppercase;
    color: var(--accent); font-weight: 700; margin-bottom: 10px;
  }}
  .header__title {{ font-size: 30px; font-weight: 800; letter-spacing: -0.02em; }}
  .header__sub {{ color: var(--ink-soft); font-size: 15px; margin-top: 6px; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1px; background: var(--line); border: 1px solid var(--line);
    margin: 28px 0 40px; border-radius: 6px; overflow: hidden;
  }}
  .meta-cell {{ background: var(--card); padding: 14px 16px; }}
  .meta-cell__k {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--ink-soft); }}
  .meta-cell__v {{ font-size: 15px; font-weight: 600; margin-top: 3px; word-break: break-word; }}

  /* Résumé chiffré */
  .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 14px; margin-bottom: 44px; }}
  .stat {{ background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 18px 20px; }}
  .stat__n {{ font-size: 34px; font-weight: 800; letter-spacing: -0.03em; line-height: 1; }}
  .stat__l {{ font-size: 13px; color: var(--ink-soft); margin-top: 6px; }}
  .stat--critique .stat__n {{ color: var(--critique); }}
  .stat--haute .stat__n {{ color: var(--haute); }}
  .stat--examen .stat__n {{ color: var(--examen); }}

  /* Sections */
  .section {{ margin-bottom: 44px; }}
  .section__title {{ font-size: 20px; font-weight: 700; margin-bottom: 6px; letter-spacing: -0.01em; }}
  .section__intro {{ color: var(--ink-soft); font-size: 14px; margin-bottom: 20px; }}

  /* Faille */
  .finding {{
    background: var(--card); border: 1px solid var(--line);
    border-left: 4px solid var(--line); border-radius: 8px;
    margin-bottom: 20px; overflow: hidden;
  }}
  .finding--critique {{ border-left-color: var(--critique); }}
  .finding--haute {{ border-left-color: var(--haute); }}
  .finding__head {{
    display: flex; align-items: center; gap: 14px;
    padding: 16px 20px; border-bottom: 1px solid var(--line);
  }}
  .finding__num {{ font-family: var(--mono); font-size: 13px; color: var(--ink-soft); font-weight: 600; }}
  .finding__title {{ flex: 1; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
  .finding__endpoint {{ font-family: var(--mono); font-size: 13px; color: var(--ink); word-break: break-all; }}
  .badge {{ font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 4px; letter-spacing: 0.03em; }}
  .badge--bola {{ background: #e8eef7; color: var(--accent); }}
  .badge--bfla {{ background: #f3e8f7; color: #7b2d8e; }}
  .sev {{ font-size: 11px; font-weight: 800; letter-spacing: 0.06em; padding: 4px 10px; border-radius: 4px; }}
  .sev--critique {{ background: var(--critique-bg); color: var(--critique); }}
  .sev--haute {{ background: var(--haute-bg); color: var(--haute); }}
  .finding__body {{ padding: 20px; }}
  .finding__desc {{ font-size: 14px; margin-bottom: 16px; }}
  .finding__meta {{ display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 18px; }}
  .tag {{ font-size: 12px; background: var(--bg); border: 1px solid var(--line); border-radius: 20px; padding: 3px 12px; color: var(--ink-soft); }}

  .proof {{ margin-bottom: 18px; }}
  .proof__label, .reco__label {{
    font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;
    color: var(--ink-soft); font-weight: 700; margin-bottom: 7px;
  }}
  .proof__code {{
    font-family: var(--mono); font-size: 12.5px; line-height: 1.5;
    background: #1a1f2b; color: #e8eaed; padding: 14px 16px;
    border-radius: 6px; overflow-x: auto; white-space: pre-wrap; word-break: break-word;
  }}
  .reco {{ background: #f0f7f2; border: 1px solid #cfe6d8; border-radius: 6px; padding: 14px 16px; }}
  .reco__label {{ color: #2f7d52; }}
  .reco p {{ font-size: 14px; }}

  /* Table non concluants / à examiner */
  .nc-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .nc-table th {{
    text-align: left; padding: 10px 12px; background: var(--card);
    border-bottom: 2px solid var(--line); font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.06em; color: var(--ink-soft);
  }}
  .nc-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--line); background: var(--card); }}
  .nc-table code {{ font-family: var(--mono); font-size: 12px; }}

  .empty {{ background: #f0f7f2; border: 1px solid #cfe6d8; border-radius: 8px; padding: 28px; text-align: center; color: #2f7d52; font-weight: 600; }}

  .footer {{ margin-top: 56px; padding-top: 20px; border-top: 1px solid var(--line); font-size: 12px; color: var(--ink-soft); }}

  @media print {{
    body {{ background: #fff; }}
    .finding, .stat, .meta-grid {{ break-inside: avoid; }}
  }}
</style>
</head>
<body>
  <div class="wrap">
    <div class="header">
      <div class="header__eyebrow">Rapport d'audit de sécurité — Cerberus</div>
      <h1 class="header__title">Contrôle d'accès des API</h1>
      <p class="header__sub">Détection automatisée des vulnérabilités BOLA et BFLA</p>
    </div>

    <div class="meta-grid">
      <div class="meta-cell"><div class="meta-cell__k">Cible</div><div class="meta-cell__v">{html.escape(cible)}</div></div>
      <div class="meta-cell"><div class="meta-cell__k">Type d'API</div><div class="meta-cell__v">{html.escape(api_type)}</div></div>
      <div class="meta-cell"><div class="meta-cell__k">Date</div><div class="meta-cell__v">{date_audit}</div></div>
      <div class="meta-cell"><div class="meta-cell__k">Périmètre</div><div class="meta-cell__v">BOLA · BFLA</div></div>
    </div>

    <div class="summary">
      <div class="stat"><div class="stat__n">{len(results)}</div><div class="stat__l">Tests exécutés</div></div>
      <div class="stat"><div class="stat__n">{len(enrichies)}</div><div class="stat__l">Failles confirmées</div></div>
      <div class="stat stat--critique"><div class="stat__n">{nb_critique}</div><div class="stat__l">Critiques</div></div>
      <div class="stat stat--haute"><div class="stat__n">{nb_haute}</div><div class="stat__l">Hautes</div></div>
      <div class="stat stat--examen"><div class="stat__n">{len(a_examiner)}</div><div class="stat__l">À examiner</div></div>
    </div>

    <section class="section">
      <h2 class="section__title">Failles confirmées</h2>
      <p class="section__intro">Chaque faille ci-dessous a été vérifiée par l'outil au moyen d'un test différentiel et d'un contrôle de l'effet réel sur la ressource ciblée.</p>
      {blocs_failles}
    </section>

    {blocs_examen}

    {blocs_nc}

    <div class="footer">
      Rapport généré automatiquement par Cerberus — outil d'audit de contrôle d'accès (BOLA/BFLA) — le {date_audit}.
      Les résultats reflètent les détections automatiques ; une revue manuelle des cas signalés reste recommandée.
    </div>
  </div>
</body>
</html>"""

        with open(chemin_sortie, "w", encoding="utf-8") as f:
            f.write(doc)

        log_success(f"Rapport HTML généré : {chemin_sortie}")
        return doc