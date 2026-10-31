#!/usr/bin/env python3
import json, requests, urllib3, logging, time
from datetime import datetime
urllib3.disable_warnings()

GROQ_API_KEY     = "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"
GROQ_MODEL       = "groq/compound-mini"
GROQ_MODEL_EMAIL = "groq/compound-mini"
OS_HOST          = "https://192.168.56.20:9200"
OS_USER          = "admin"
OS_PASS          = "WAZUH2026@@safiabenali+"

processed_rules = {}

logging.basicConfig(
    filename="/var/ossec/logs/ai_enrichment.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

def get_new_alerts():
    try:
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"rule.id": ["100132","100900","100901","100211"]}},
                        {"bool": {
                            "must": [
                                {"range": {"rule.level": {"gte": 12}}},
                                {"terms": {"rule.groups": [
                                    "kerberoasting","dcsync",
                                    "pass_the_hash","gstr"
                                ]}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1,
                    "must_not": [
                        {"exists": {"field": "ai.attack_type"}}
                    ],
                    "filter": [
                        {"range": {"timestamp": {"gte": "now-2m"}}}
                    ]
                }
            },
            "size": 5
        }
        r = requests.post(
            f"{OS_HOST}/wazuh-alerts-*/_search",
            json=query,
            auth=(OS_USER, OS_PASS),
            verify=False,
            timeout=10
        )
        return r.json().get("hits", {}).get("hits", [])
    except Exception as e:
        logging.error(f"Erreur recherche : {e}")
        return []

def get_related_alerts(agent_name, minutes=30):
    try:
        query = {
            "query": {
                "bool": {
                    "should": [
                        {"terms": {"rule.id": ["100132","100900","100901"]}},
                        {"bool": {
                            "must": [
                                {"range": {"rule.level": {"gte": 12}}},
                                {"terms": {"rule.groups": [
                                    "kerberoasting","dcsync",
                                    "pass_the_hash","gstr"
                                ]}}
                            ]
                        }}
                    ],
                    "minimum_should_match": 1,
                    "must": [
                        {"match": {"agent.name": agent_name}}
                    ],
                    "filter": [
                        {"range": {"timestamp": {"gte": f"now-{minutes}m"}}}
                    ]
                }
            },
            "sort": [{"timestamp": "asc"}],
            "size": 10
        }
        r = requests.post(
            f"{OS_HOST}/wazuh-alerts-*/_search",
            json=query,
            auth=(OS_USER, OS_PASS),
            verify=False,
            timeout=10
        )
        return r.json().get("hits", {}).get("hits", [])
    except Exception as e:
        logging.error(f"Erreur alertes liées : {e}")
        return []

def build_prompt(alert):
    source = alert.get("_source", {})
    return f"""Tu es un expert SOC. Analyse cette alerte Wazuh.
Reponds UNIQUEMENT en JSON valide, rien d'autre.

Alerte :
- Regle   : {source.get('rule', {}).get('description')}
- Niveau  : {source.get('rule', {}).get('level')}
- Groupes : {source.get('rule', {}).get('groups')}
- Agent   : {source.get('agent', {}).get('name')}
- Log     : {str(source.get('full_log', ''))[:300]}

JSON attendu :
{{
  "attack_type": "type d attaque",
  "mitre_tactic": "tactique MITRE",
  "mitre_technique": "ex: T1558.003",
  "is_false_positive": false,
  "severity_confirmed": "critical|high|medium|low",
  "recommended_action": "action immediate",
  "explanation": "explication courte en francais",
  "confidence": 95
}}"""

def build_email_prompt(alert):
    source   = alert.get("_source", {})
    data     = source.get("data", {})
    sources  = data.get('sources_array', [])
    nb_total = len(sources)

    # Détecter doublons localement
    sources_lower   = [s.lower().split('(')[0].strip() for s in sources]
    doublons        = list(set([s for s in sources_lower
                                if sources_lower.count(s) > 1]))
    sources_uniques = nb_total - len(doublons)

    return f"""Expert SOC et threat intelligence.
Analyse comportementale de cette compromission email.
JSON uniquement, rien d'autre.

=== LEAKCHECK ===
Email        : {data.get('Email')}
Found        : {data.get('found')} enregistrements
Nb sources   : {nb_total} sites
Src uniques  : {sources_uniques}
Doublons     : {doublons}
Date leak    : {data.get('date_leak')}

=== HUDSON ROCK ===
Machine infectee  : {data.get('hudsonrock_infecte')}
Nb infections     : {data.get('hudsonrock_nombre_infections')}
Date compromission: {data.get('hudsonrock_date_compromission')}
Chemin malware    : {data.get('hudsonrock_chemin_malware')}
Nom machine       : {data.get('hudsonrock_nom_machine')}

=== SCORING INTERNE ===
Risque calcule    : {data.get('risque')}
Score             : {data.get('score')}
Total compromis   : {data.get('total_compromised')}/{data.get('total_scanned')}

ANALYSE COMPORTEMENTALE :
1. found ({data.get('found')}) > sources ({nb_total}) ?
   expliquer pourquoi
2. Corréler date malware vs date leak
3. Le risque ({data.get('risque')}) est-il correct ?
4. Probabilite acces attaquant encore actif ?

JSON:
{{
  "attack_type": "Email Compromis - Credential Leak",
  "found_total": {data.get('found')},
  "found_vs_sources_analyse": "explication found vs nb sources",
  "sources_uniques_reelles": {sources_uniques},
  "doublons_detectes": {doublons},
  "scoring_interne_correct": true/false,
  "scoring_correction": "si incorrect risque reel",
  "correlation_malware_leak": "analyse temporelle",
  "acces_attaquant_probable": true/false,
  "risque_reel": "critical|high|medium|low",
  "risque_reel_score": 0-100,
  "priorite": "URGENT|HIGH|MEDIUM|LOW",
  "mitre_technique": "T1589.002",
  "is_false_positive": false,
  "severity_confirmed": "critical|high|medium|low",
  "recommended_action": "actions prioritaires",
  "machine_compromise": true/false,
  "explanation": "analyse comportementale complete",
  "confidence": 0-100
}}"""

def build_killchain_prompt(alerts):
    alerts_summary = ""
    for i, alert in enumerate(alerts):
        source   = alert.get("_source", {})
        mitre    = source.get("rule", {}).get("mitre", {})
        mitre_id = mitre.get("id", ["?"])[0] if mitre else "?"
        alerts_summary += f"""
Alerte {i+1} :
- Heure  : {source.get('timestamp')}
- Règle  : {source.get('rule', {}).get('description')}
- Niveau : {source.get('rule', {}).get('level')}
- Agent  : {source.get('agent', {}).get('name')}
- MITRE  : {mitre_id}
"""
    return f"""Tu es un expert SOC.
Voici une séquence d'alertes sur 30 minutes pour le même agent :
{alerts_summary}
Analyse ces alertes ENSEMBLE.
Reponds UNIQUEMENT en JSON valide :
{{
  "is_kill_chain": true/false,
  "kill_chain_description": "description",
  "attack_stage": "étape actuelle",
  "overall_severity": "critical|high|medium|low",
  "domain_compromised": true/false,
  "recommended_actions": "actions prioritaires",
  "confidence": 0-100
}}"""

def call_groq(prompt, model=None, retry=0, max_tokens=500):
    if model is None:
        model = GROQ_MODEL
    try:
        r = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
                "max_tokens": max_tokens
            },
            timeout=30
        )
        if r.status_code == 429:
            if retry >= 3:
                logging.error("Rate limit persistant → abandon")
                return None
            wait = (retry + 1) * 30
            logging.warning(f"Rate limit → attendre {wait} sec (tentative {retry+1}/3)")
            time.sleep(wait)
            return call_groq(prompt, model, retry + 1, max_tokens)

        if r.status_code != 200:
            logging.error(f"Erreur Groq status : {r.status_code}")
            return None

        content = r.json()["choices"][0]["message"]["content"]
        content = content.replace("```json","").replace("```","").strip()
        logging.info(f"Reponse Groq : {content}")
        time.sleep(2)
        return json.loads(content)
    except Exception as e:
        logging.error(f"Erreur Groq : {e}")
        return None

def update_opensearch(alert_id, index, ai_fields):
    try:
        clean_index = index.replace("*","")
        url = f"{OS_HOST}/{clean_index}/_update/{alert_id}"
        r = requests.post(
            url,
            json={"doc": ai_fields, "doc_as_upsert": True},
            auth=(OS_USER, OS_PASS),
            verify=False,
            timeout=10
        )
        logging.info(f"OpenSearch response : {r.status_code}")
        if r.status_code in [200, 201]:
            logging.info(f"Alerte {alert_id} enrichie OK ✅")
        else:
            logging.error(f"Erreur : {r.text}")
    except Exception as e:
        logging.error(f"Erreur OpenSearch : {e}")

def main():
    logging.info("=== AI Monitor démarré ===")

    while True:
        alerts = get_new_alerts()

        if alerts:
            logging.info(f"{len(alerts)} nouvelle(s) alerte(s) trouvée(s)")

            for alert in alerts:
                alert_id = alert["_id"]
                index    = alert["_index"]
                source   = alert["_source"]
                rule_id  = source.get("rule", {}).get("id", "")
                agent    = source.get("agent", {}).get("name", "")

                # ── DÉDOUBLONNAGE ──
                if rule_id == "100211":
                    time_slot = datetime.utcnow().strftime('%Y%m%d%H')
                else:
                    time_slot = datetime.utcnow().strftime('%Y%m%d%H%M')

                dedup_key = f"{rule_id}_{agent}_{time_slot}"

                if dedup_key in processed_rules:
                    logging.info(f"Doublon ignoré : {dedup_key}")
                    continue

                processed_rules[dedup_key] = datetime.utcnow()
                logging.info(f"Traitement alerte {alert_id} — rule {rule_id}")

                # ── NIVEAU 1 : prompt selon type ──
                if rule_id == "100211":
                    prompt    = build_email_prompt(alert)
                    logging.info(f"Taille prompt Email : {len(prompt)} chars")
                    ai_result = call_groq(prompt, model=GROQ_MODEL_EMAIL, max_tokens=600)
                else:
                    prompt    = build_prompt(alert)
                    logging.info(f"Taille prompt AD : {len(prompt)} chars")
                    ai_result = call_groq(prompt, max_tokens=500)

                if not ai_result:
                    logging.error(f"IA échouée pour {alert_id}")
                    continue

                # ── Champs enrichis selon type ──
                if rule_id == "100211":
                    enriched = {
                        "ai.attack_type":              ai_result.get("attack_type"),
                        "ai.mitre_technique":          ai_result.get("mitre_technique"),
                        "ai.is_false_positive":        ai_result.get("is_false_positive"),
                        "ai.severity_confirmed":       ai_result.get("severity_confirmed"),
                        "ai.recommended_action":       ai_result.get("recommended_action"),
                        "ai.explanation":              ai_result.get("explanation"),
                        "ai.confidence":               ai_result.get("confidence"),
                        "ai.risque_reel":              ai_result.get("risque_reel"),
                        "ai.risque_reel_score":        ai_result.get("risque_reel_score"),
                        "ai.priorite":                 ai_result.get("priorite"),
                        "ai.machine_compromise":       ai_result.get("machine_compromise"),
                        "ai.found_total":              ai_result.get("found_total"),
                        "ai.found_vs_sources_analyse": ai_result.get("found_vs_sources_analyse"),
                        "ai.sources_uniques_reelles":  ai_result.get("sources_uniques_reelles"),
                        "ai.doublons_detectes":        ai_result.get("doublons_detectes"),
                        "ai.scoring_interne_correct":  ai_result.get("scoring_interne_correct"),
                        "ai.scoring_correction":       ai_result.get("scoring_correction"),
                        "ai.correlation_malware_leak": ai_result.get("correlation_malware_leak"),
                        "ai.acces_attaquant_probable": ai_result.get("acces_attaquant_probable"),
                        "ai.model_used":               GROQ_MODEL_EMAIL,
                        "ai.analyzed_at":              datetime.utcnow().isoformat()
                    }
                else:
                    enriched = {
                        "ai.attack_type":        ai_result.get("attack_type"),
                        "ai.mitre_tactic":       ai_result.get("mitre_tactic"),
                        "ai.mitre_technique":    ai_result.get("mitre_technique"),
                        "ai.is_false_positive":  ai_result.get("is_false_positive"),
                        "ai.severity_confirmed": ai_result.get("severity_confirmed"),
                        "ai.recommended_action": ai_result.get("recommended_action"),
                        "ai.explanation":        ai_result.get("explanation"),
                        "ai.confidence":         ai_result.get("confidence"),
                        "ai.model_used":         GROQ_MODEL,
                        "ai.analyzed_at":        datetime.utcnow().isoformat()
                    }

                # ── NIVEAU 2 : kill chain AD uniquement ──
                if agent and rule_id != "100211":
                    related = get_related_alerts(agent, minutes=30)
                    if len(related) >= 2:
                        logging.info(f"{len(related)} alertes liées pour {agent}")
                        kc_result = call_groq(
                            build_killchain_prompt(related),
                            max_tokens=400
                        )
                        if kc_result:
                            enriched["ai.kill_chain"]         = kc_result.get("is_kill_chain")
                            enriched["ai.kill_chain_desc"]    = kc_result.get("kill_chain_description")
                            enriched["ai.attack_stage"]       = kc_result.get("attack_stage")
                            enriched["ai.domain_compromised"] = kc_result.get("domain_compromised")
                            enriched["ai.overall_severity"]   = kc_result.get("overall_severity")
                            enriched["ai.killchain_actions"]  = kc_result.get("recommended_actions")
                            logging.info(f"Kill chain : {kc_result.get('kill_chain_description')}")

                update_opensearch(alert_id, index, enriched)

                if rule_id == "100211":
                    logging.info("Pause 30 sec après Email Compromis")
                    time.sleep(30)

        time.sleep(10)

if __name__ == "__main__":
    main()
