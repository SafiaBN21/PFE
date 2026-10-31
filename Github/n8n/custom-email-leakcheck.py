#!/usr/bin/env python3
"""
custom-email-leakcheck.py
Wazuh Custom Integration : envoie un email HTML "Rapport des Emails
Compromis" quand Wazuh détecte une alerte de type NOTIFICATION.
"""

import sys
import os
import json
import smtplib
import logging
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from datetime import datetime
from zoneinfo import ZoneInfo

LOG_FILE = "/var/ossec/logs/integrations.log"

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [custom-email-leakcheck] %(message)s",
)

LOGO_DIR = "/var/ossec/integrations/logos"
WAZUH_LOGO = f"{LOGO_DIR}/wazuh.png"
MEDI1_LOGO = f"{LOGO_DIR}/Meditv.jpg"
N8N_LOGO   = f"{LOGO_DIR}/n8n.png"


# ----------------------------------------------------------------------
# 1. Extraction du payload LeakCheck depuis l'alerte Wazuh
# ----------------------------------------------------------------------
def extract_leakcheck_payload(alert_json):
    candidates = []

    if isinstance(alert_json.get("data"), dict):
        candidates.append(alert_json["data"])

    full_log = alert_json.get("full_log")
    if isinstance(full_log, str):
        try:
            candidates.append(json.loads(full_log))
        except (json.JSONDecodeError, TypeError):
            pass

    candidates.append(alert_json)

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue

        if "payload" in candidate:
            raw_payload = candidate["payload"]
            try:
                payload_obj = (
                    json.loads(raw_payload)
                    if isinstance(raw_payload, str)
                    else raw_payload
                )
                if isinstance(payload_obj, dict) and "emails" in payload_obj:
                    return payload_obj
            except (json.JSONDecodeError, TypeError):
                pass

        if "emails" in candidate and isinstance(candidate["emails"], list):
            return candidate

    return None


# ----------------------------------------------------------------------
# 2. Helpers de formatage
# ----------------------------------------------------------------------
RISK_LABELS = {"critical": "Critique", "high": "Élevé", "medium": "Moyen", "low": "Faible"}
RISK_COLORS = {
    "critical": {"text": "#C4293A", "bg": "#FDEBEC", "border": "#F3C1C6"},
    "high":     {"text": "#B3650A", "bg": "#FFF3E0", "border": "#F3D6A8"},
    "medium":   {"text": "#1D63D6", "bg": "#E9F1FF", "border": "#BBD6FA"},
    "low":      {"text": "#12876B", "bg": "#E6F7F1", "border": "#B7E5D6"},
}


def escape_html(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def format_number(n):
    try:
        return f"{int(n):,}".replace(",", " ")
    except (ValueError, TypeError):
        return str(n)


def badge_html(risk):
    c = RISK_COLORS.get(risk, RISK_COLORS["low"])
    label = RISK_LABELS.get(risk, risk)
    return (
        f'<span style="display:inline-block;padding:4px 10px;border-radius:5px;'
        f"font-family:'Courier New',monospace;font-size:11px;font-weight:700;"
        f"text-transform:uppercase;letter-spacing:0.03em;color:{c['text']};"
        f"background-color:{c['bg']};border:1px solid {c['border']};\">{label}</span>"
    )


# ----------------------------------------------------------------------
# 3. Génération du HTML complet de l'email
# ----------------------------------------------------------------------
def build_html(payload_obj):
    emails = payload_obj.get("emails", [])
    source = payload_obj.get("source", "LeakCheck + HudsonRock")
    timestamp_raw = payload_obj.get("timestamp", "")

    try:
        dt_utc = datetime.fromisoformat(timestamp_raw.replace("Z", "+00:00"))
        dt_maroc = dt_utc.astimezone(ZoneInfo("Africa/Casablanca"))
        offset = dt_maroc.strftime("%z")
        offset_formatted = f"UTC{offset[:3]}:{offset[3:]}" if offset else ""
        timestamp = dt_maroc.strftime("%Y-%m-%d %H:%M:%S") + f" {offset_formatted}"
    except (ValueError, TypeError):
        timestamp = timestamp_raw

    emails_sorted = sorted(emails, key=lambda e: e.get("found", 0), reverse=True)

    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for e in emails_sorted:
        r = str(e.get("risque", "")).lower()
        if r in stats:
            stats[r] += 1
    total = len(emails_sorted)

    rows_html = ""
    for idx, e in enumerate(emails_sorted):
        bg = "#FFFFFF" if idx % 2 == 0 else "#F7F8FB"
        risk = str(e.get("risque", "")).lower()
        date_leak = e.get("date_leak", "—")
        hudsonrock_infections = e.get("hudsonrock_nombre_infections", 0)
        rows_html += f"""
    <tr>
      <td style="padding:10px 10px;border-bottom:1px solid #E4E7EE;background-color:{bg};">
        <span style="font-family:'Courier New',monospace;font-size:12.5px;color:#1A2233;">{escape_html(e.get('email', ''))}</span>
      </td>
      <td style="padding:10px 10px;border-bottom:1px solid #E4E7EE;background-color:{bg};text-align:center;">
        <span style="font-family:'Courier New',monospace;font-size:14px;font-weight:700;color:#1A2233;">{format_number(e.get('found', 0))}</span>
      </td>
      <td style="padding:10px 10px;border-bottom:1px solid #E4E7EE;background-color:{bg};text-align:center;">
        <span style="font-family:'Courier New',monospace;font-size:14px;font-weight:700;color:#1A2233;">{format_number(hudsonrock_infections)}</span>
      </td>
      <td style="padding:10px 10px;border-bottom:1px solid #E4E7EE;background-color:{bg};text-align:center;">
        <span style="font-family:'Courier New',monospace;font-size:12px;color:#6B7280;">{escape_html(date_leak)}</span>
      </td>
      <td style="padding:10px 10px;border-bottom:1px solid #E4E7EE;background-color:{bg};text-align:right;">
        {badge_html(risk)}
      </td>
    </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Rapport des E-mails Compromis</title>
</head>
<body style="margin:0;padding:0;background-color:#F0F2F6;font-family:Arial,Helvetica,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#F0F2F6;">
  <tr>
    <td align="center" style="padding:32px 16px;">
      <table role="presentation" width="480" cellpadding="0" cellspacing="0" style="max-width:480px;width:100%;background-color:#FFFFFF;border-radius:8px;overflow:hidden;">

        <!-- LOGOS -->
        <tr>
          <td style="padding:12px 16px;border-bottom:1px solid #E4E7EE;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="text-align:left;vertical-align:middle;">
                  <img src="cid:logo_wazuh" alt="Wazuh" style="height:52px;display:block;">
                </td>
                <td style="text-align:center;vertical-align:middle;">
                  <img src="cid:logo_n8n" alt="n8n" style="height:40px;display:block;margin:0 auto;">
                </td>
                <td style="text-align:right;vertical-align:middle;">
                  <img src="cid:logo_medi1" alt="Medi1tv" style="height:72px;display:block;margin-left:auto;">
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- BANDEAU TITRE -->
        <tr>
          <td style="background-color:#8B0000;padding:12px 16px;">
            <div style="color:#ffffff;font-size:17px;font-weight:bold;margin-bottom:4px;">Rapport des e-mails compromis</div>
            <div style="color:rgba(255,255,255,0.75);font-size:12px;">Source : {escape_html(source)} · Généré le {escape_html(timestamp)}</div>
          </td>
        </tr>

        <!-- STATS -->
        <tr>
          <td style="padding-top:0;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td width="20%" style="background-color:#F7F8FB;border:1px solid #E4E7EE;border-top:2px solid #1A2233;padding:16px 10px;text-align:center;">
                  <div style="font-size:26px;font-weight:700;color:#1A2233;">{total}</div>
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;font-weight:600;margin-top:4px;">Total</div>
                </td>
                <td width="20%" style="background-color:#F7F8FB;border:1px solid #E4E7EE;border-top:2px solid #C4293A;padding:16px 10px;text-align:center;">
                  <div style="font-size:26px;font-weight:700;color:#C4293A;">{stats['critical']}</div>
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;font-weight:600;margin-top:4px;">Critique</div>
                </td>
                <td width="20%" style="background-color:#F7F8FB;border:1px solid #E4E7EE;border-top:2px solid #B3650A;padding:16px 10px;text-align:center;">
                  <div style="font-size:26px;font-weight:700;color:#B3650A;">{stats['high']}</div>
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;font-weight:600;margin-top:4px;">Élevé</div>
                </td>
                <td width="20%" style="background-color:#F7F8FB;border:1px solid #E4E7EE;border-top:2px solid #1D63D6;padding:16px 10px;text-align:center;">
                  <div style="font-size:26px;font-weight:700;color:#1D63D6;">{stats['medium']}</div>
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;font-weight:600;margin-top:4px;">Moyen</div>
                </td>
                <td width="20%" style="background-color:#F7F8FB;border:1px solid #E4E7EE;border-top:2px solid #12876B;padding:16px 10px;text-align:center;">
                  <div style="font-size:26px;font-weight:700;color:#12876B;">{stats['low']}</div>
                  <div style="font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;font-weight:600;margin-top:4px;">Faible</div>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- TABLEAU -->
        <tr>
          <td style="padding:16px 16px 8px;">
            <span style="font-size:19px;font-weight:700;color:#1A2233;">Comptes compromis détectés</span>
          </td>
        </tr>

        <tr>
          <td style="padding:0 16px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #E4E7EE;border-radius:8px;overflow:hidden;">
              <tr>
                <th align="left" style="padding:10px 10px;font-size:13px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;background-color:#F0F2F6;border-bottom:1px solid #E4E7EE;white-space:nowrap;">E-mail compromis</th>
                <th align="center" style="padding:10px 10px;font-size:13px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;background-color:#F0F2F6;border-bottom:1px solid #E4E7EE;white-space:nowrap;">Nombre de compromissions</th>
                <th align="center" style="padding:10px 10px;font-size:13px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;background-color:#F0F2F6;border-bottom:1px solid #E4E7EE;white-space:nowrap;">Machines infectées</th>
                <th align="center" style="padding:10px 10px;font-size:13px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;background-color:#F0F2F6;border-bottom:1px solid #E4E7EE;white-space:nowrap;">Date de compromission</th>
                <th align="right" style="padding:10px 10px;font-size:13px;text-transform:uppercase;letter-spacing:0.06em;color:#6B7280;background-color:#F0F2F6;border-bottom:1px solid #E4E7EE;white-space:nowrap;">Risque</th>
              </tr>
              {rows_html}
            </table>
          </td>
        </tr>

        <!-- FOOTER -->
        <tr>
          <td style="padding:12px 16px;border-top:1px solid #E4E7EE;text-align:center;font-size:11.5px;color:#6B7280;">
            Rapport généré automatiquement par Wazuh SIEM
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
</body>
</html>"""

    unique_id = datetime.now().strftime('%Y%m%d-%H%M%S')
    subject = f"[ALERTE SÉCURITÉ] {total} compte(s) compromis détecté(s) — {stats['critical']} critique(s) — {unique_id}"
    return subject, html, total


# ----------------------------------------------------------------------
# 4. Envoi SMTP avec logos inline
# ----------------------------------------------------------------------
def send_email(options, subject, html_body, max_retries=5):
    msg = MIMEMultipart("related")
    msg["Subject"] = subject
    msg["From"] = options["email_from"]
    msg["To"] = options["email_to"]

    msg_alt = MIMEMultipart("alternative")
    msg.attach(msg_alt)
    msg_alt.attach(MIMEText(html_body, "html", "utf-8"))

    # Logos inline
    for logo_path, cid, filename in [
        (WAZUH_LOGO, "logo_wazuh", "wazuh.png"),
        (MEDI1_LOGO, "logo_medi1", "medi1tv.jpg"),
        (N8N_LOGO,   "logo_n8n",   "n8n.png"),
    ]:
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                img = MIMEImage(f.read())
                img.add_header("Content-ID", f"<{cid}>")
                img.add_header("Content-Disposition", "inline", filename=filename)
                msg.attach(img)
        else:
            logging.warning("Logo introuvable : %s", logo_path)

    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            server = smtplib.SMTP(options["smtp_server"], options.get("smtp_port", 587), timeout=20)
            try:
                if options.get("use_tls", True):
                    server.starttls()
                if options.get("smtp_user") and options.get("smtp_password"):
                    server.login(options["smtp_user"], options["smtp_password"])
                server.sendmail(options["email_from"], [options["email_to"]], msg.as_string())
            finally:
                server.quit()
            return
        except Exception as e:
            last_error = e
            logging.warning("Tentative %d/%d échouée: %s", attempt, max_retries, e)
            if attempt < max_retries:
                time.sleep(3)

    raise last_error


# ----------------------------------------------------------------------
# 5. Point d'entrée
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) < 2:
        logging.error("Arguments insuffisants reçus de Wazuh: %s", sys.argv)
        sys.exit(1)

    alert_file_path = sys.argv[1]

    options_file_path = None
    for arg in sys.argv[2:]:
        if arg.endswith(".options"):
            options_file_path = arg
            break

    if not options_file_path:
        logging.error("Aucun argument se terminant par '.options' trouvé parmi: %s", sys.argv)
        sys.exit(1)

    try:
        with open(options_file_path, "r", encoding="utf-8") as f:
            options_raw = f.read().strip()
        options = json.loads(options_raw)
    except Exception as e:
        logging.error("Impossible de lire/parser le fichier d'options %s: %s", options_file_path, e)
        sys.exit(1)

    required = ["smtp_server", "email_from", "email_to"]
    missing = [k for k in required if k not in options]
    if missing:
        logging.error("Options manquantes dans ossec.conf <options>: %s", missing)
        sys.exit(1)

    try:
        with open(alert_file_path, "r", encoding="utf-8") as f:
            alert_json = json.load(f)
    except Exception as e:
        logging.error("Impossible de lire le fichier d'alerte %s: %s", alert_file_path, e)
        sys.exit(1)

    payload_obj = extract_leakcheck_payload(alert_json)
    if not payload_obj:
        logging.warning(
            "Aucun payload LeakCheck trouvé dans l'alerte. Alerte brute: %s",
            json.dumps(alert_json)[:500],
        )
        sys.exit(0)

    emails = payload_obj.get("emails", [])
    if not emails:
        logging.info("Payload trouvé mais liste 'emails' vide — aucun email envoyé.")
        sys.exit(0)

    subject, html_body, total = build_html(payload_obj)

    try:
        send_email(options, subject, html_body)
        logging.info("Email envoyé avec succès — %d compte(s) compromis.", total)
    except Exception as e:
        logging.error("Échec de l'envoi SMTP: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
