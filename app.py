import os
import re
import json
import time
import hashlib
import mimetypes
from urllib.parse import urlparse

import requests
from flask import Flask, request, jsonify


app = Flask(__name__)


# =========================
# Environment variables
# =========================

META_VERIFY_TOKEN = os.getenv("META_VERIFY_TOKEN", "checkpoint-whatsapp-lab")
META_ACCESS_TOKEN = os.getenv("META_ACCESS_TOKEN", "")
META_PHONE_NUMBER_ID = os.getenv("META_PHONE_NUMBER_ID", "")

CP_REP_CLIENT_KEY = os.getenv("CP_REP_CLIENT_KEY", "")
CP_REP_TOKEN = os.getenv("CP_REP_TOKEN", "")

CP_TE_API_KEY = os.getenv("CP_TE_API_KEY", "")
CP_TE_SERVICE_ADDRESS = os.getenv("CP_TE_SERVICE_ADDRESS", "te-api.checkpoint.com")
CP_TE_API_VERSION = os.getenv("CP_TE_API_VERSION", "v1")

LAB_MODE = os.getenv("LAB_MODE", "true").lower() == "true"


# =========================
# Basic routes
# =========================

@app.route("/", methods=["GET"])
def health_check():
    return "WhatsApp + Check Point Lab is running", 200


@app.route("/webhook", methods=["GET"])
def verify_webhook():
    """
    Meta calls this endpoint when you click Verify and Save.
    """
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode == "subscribe" and token == META_VERIFY_TOKEN:
        print("Webhook verified successfully")
        return challenge, 200

    print("Webhook verification failed")
    return "Verification failed", 403


@app.route("/webhook", methods=["POST"])
def receive_webhook():
    """
    Meta sends incoming WhatsApp messages here.
    """
    data = request.get_json()
    print("Webhook received:")
    print(json.dumps(data, indent=2))

    try:
        value = data["entry"][0]["changes"][0]["value"]

        if "messages" not in value:
            return jsonify({"status": "ignored"}), 200

        message = value["messages"][0]
        from_number = message["from"]
        message_type = message["type"]

        if message_type == "text":
            handle_text_message(from_number, message)

        elif message_type == "document":
            handle_document_message(from_number, message)

        elif message_type == "image":
            handle_image_message(from_number, message)

        else:
            reply_text(
                from_number,
                f"Mensaje recibido tipo '{message_type}'. En este lab solo estoy analizando texto, URLs, documentos e imágenes."
            )

    except Exception as e:
        print(f"Error processing webhook: {e}")

    return jsonify({"status": "EVENT_RECEIVED"}), 200


# =========================
# WhatsApp message handlers
# =========================

def handle_text_message(from_number, message):
    text = message["text"]["body"]
    urls = extract_urls(text)

    if not urls:
        reply_text(
            from_number,
            "Mensaje recibido. Envíame una URL o un archivo para analizarlo con Check Point."
        )
        return

    results = []

    for url in urls:
        rep = check_url_reputation(url)
        decision = decide_from_reputation(rep)

        results.append({
            "url": url,
            "classification": rep.get("classification", "unknown"),
            "risk": rep.get("risk", "unknown"),
            "action": decision
        })

    response_lines = ["Resultado del análisis de URL:"]
    for result in results:
        response_lines.append(
            f"- {result['url']}\n"
            f"  Clasificación: {result['classification']}\n"
            f"  Riesgo: {result['risk']}\n"
            f"  Acción lab: {result['action']}"
        )

    reply_text(from_number, "\n".join(response_lines))


def handle_document_message(from_number, message):
    document = message["document"]

    media_id = document["id"]
    filename = document.get("filename", "unknown-file")
    mime_type = document.get("mime_type", "application/octet-stream")

    process_whatsapp_media(from_number, media_id, filename, mime_type)


def handle_image_message(from_number, message):
    image = message["image"]

    media_id = image["id"]
    mime_type = image.get("mime_type", "image/jpeg")
    filename = f"whatsapp-image.{extension_from_mime(mime_type)}"

    process_whatsapp_media(from_number, media_id, filename, mime_type)


def process_whatsapp_media(from_number, media_id, filename, mime_type):
    reply_text(from_number, f"Recibí {filename}. Iniciando análisis de laboratorio...")

    media_url = get_whatsapp_media_url(media_id)
    file_bytes = download_whatsapp_media(media_url)

    sha256 = calculate_sha256(file_bytes)
    file_size = len(file_bytes)

    print(f"File received: {filename}")
    print(f"MIME type: {mime_type}")
    print(f"Size: {file_size}")
    print(f"SHA256: {sha256}")

    file_rep = check_file_reputation(sha256)
    rep_decision = decide_from_reputation(file_rep)

    classification = file_rep.get("classification", "unknown")
    risk = file_rep.get("risk", "unknown")

    if rep_decision == "block":
        reply_text(
            from_number,
            f"Archivo bloqueado por Reputation Services.\n"
            f"Archivo: {filename}\n"
            f"SHA256: {sha256}\n"
            f"Clasificación: {classification}\n"
            f"Riesgo: {risk}"
        )
        return

    if classification.lower() in ["unknown", "unclassified"] or rep_decision == "unknown":
        reply_text(
            from_number,
            f"Reputation Services no tiene suficiente información del archivo.\n"
            f"Archivo: {filename}\n"
            f"SHA256: {sha256}\n"
            f"Enviando a Threat Emulation Cloud API..."
        )

        te_upload = upload_file_to_threat_emulation(
            file_bytes=file_bytes,
            filename=filename,
            mime_type=mime_type,
            sha256=sha256
        )

        te_status = get_te_status_label(te_upload)

        reply_text(
            from_number,
            f"Archivo enviado a Threat Emulation.\n"
            f"Archivo: {filename}\n"
            f"SHA256: {sha256}\n"
            f"Estado inicial TE: {te_status}\n\n"
            f"Nota lab: si queda en pending/upload_success, se debe consultar luego con Query API."
        )
        return

    reply_text(
        from_number,
        f"Archivo permitido en laboratorio.\n"
        f"Archivo: {filename}\n"
        f"SHA256: {sha256}\n"
        f"Clasificación: {classification}\n"
        f"Riesgo: {risk}\n"
        f"Acción lab: {rep_decision}"
    )


# =========================
# WhatsApp API helpers
# =========================

def reply_text(to_number, text):
    if not META_ACCESS_TOKEN or not META_PHONE_NUMBER_ID:
        print("Missing Meta credentials. Cannot send WhatsApp reply.")
        print("Reply would be:", text)
        return

    url = f"https://graph.facebook.com/v20.0/{META_PHONE_NUMBER_ID}/messages"

    headers = {
        "Authorization": f"Bearer {META_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "messaging_product": "whatsapp",
        "to": to_number,
        "type": "text",
        "text": {
            "body": text[:4000]
        }
    }

    response = requests.post(url, headers=headers, json=payload, timeout=30)
    print("WhatsApp reply status:", response.status_code)
    print("WhatsApp reply body:", response.text)


def get_whatsapp_media_url(media_id):
    url = f"https://graph.facebook.com/v20.0/{media_id}"

    headers = {
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }

    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()

    return response.json()["url"]


def download_whatsapp_media(media_url):
    headers = {
        "Authorization": f"Bearer {META_ACCESS_TOKEN}"
    }

    response = requests.get(media_url, headers=headers, timeout=60)
    response.raise_for_status()

    return response.content


# =========================
# Check Point Reputation Services
# =========================

def check_url_reputation(url_to_check):
    """
    Reputation Service URL API.
    Docs:
    POST https://rep.checkpoint.com/url-rep/service/v3.0/query?resource={url}
    Headers: Client-Key + token
    Body: {"request": [{"resource": "{url}"}]}
    """
    if LAB_MODE and not CP_REP_CLIENT_KEY:
        return fake_reputation_response(url_to_check)

    endpoint = "https://rep.checkpoint.com/url-rep/service/v3.0/query"

    headers = {
        "Client-Key": CP_REP_CLIENT_KEY,
        "token": CP_REP_TOKEN,
        "Content-Type": "application/json"
    }

    payload = {
        "request": [
            {
                "resource": url_to_check
            }
        ]
    }

    response = requests.post(
        endpoint,
        headers=headers,
        params={"resource": url_to_check},
        json=payload,
        timeout=30
    )

    response.raise_for_status()
    return normalize_reputation_response(response.json())


def check_file_reputation(file_hash):
    """
    Reputation Service File API.
    Docs:
    POST https://rep.checkpoint.com/file-rep/service/v3.0/query?resource={file-hash}
    Headers: Client-Key + token
    Body: {"request": [{"resource": "{file-hash}"}]}
    """
    if LAB_MODE and not CP_REP_CLIENT_KEY:
        return fake_reputation_response(file_hash, is_file=True)

    endpoint = "https://rep.checkpoint.com/file-rep/service/v3.0/query"

    headers = {
        "Client-Key": CP_REP_CLIENT_KEY,
        "token": CP_REP_TOKEN,
        "Content-Type": "application/json"
    }

    payload = {
        "request": [
            {
                "resource": file_hash
            }
        ]
    }

    response = requests.post(
        endpoint,
        headers=headers,
        params={"resource": file_hash},
        json=payload,
        timeout=30
    )

    response.raise_for_status()
    return normalize_reputation_response(response.json())


def normalize_reputation_response(raw):
    """
    Tries to normalize Check Point response into:
    classification, risk, severity, confidence, raw
    """
    try:
        response_obj = raw.get("response", raw)

        if isinstance(response_obj, list):
            item = response_obj[0]
        elif isinstance(response_obj, dict) and "response" in response_obj:
            item = response_obj["response"][0]
        else:
            item = response_obj

        reputation = item.get("reputation", item)

        classification = (
            reputation.get("classification")
            or item.get("classification")
            or "unknown"
        )

        risk = (
            reputation.get("risk")
            or item.get("risk")
            or 34
        )

        severity = (
            reputation.get("severity")
            or item.get("severity")
            or "N/A"
        )

        confidence = (
            reputation.get("confidence")
            or item.get("confidence")
            or "N/A"
        )

        return {
            "classification": str(classification),
            "risk": int(risk) if str(risk).isdigit() else risk,
            "severity": severity,
            "confidence": confidence,
            "raw": raw
        }

    except Exception as e:
        print("Could not normalize reputation response:", e)
        return {
            "classification": "unknown",
            "risk": 34,
            "severity": "N/A",
            "confidence": "N/A",
            "raw": raw
        }


def fake_reputation_response(resource, is_file=False):
    """
    Lab simulation when you don't have the Check Point key yet.
    Useful for showing the workflow.
    """
    resource_lower = resource.lower()

    if "malware" in resource_lower or "phishing" in resource_lower or "evil" in resource_lower:
        return {
            "classification": "Malware" if is_file else "Phishing",
            "risk": 100,
            "severity": "High",
            "confidence": "High",
            "raw": {
                "lab_mode": True,
                "resource": resource
            }
        }

    if "unknown" in resource_lower:
        return {
            "classification": "Unknown" if is_file else "Unclassified",
            "risk": 34,
            "severity": "N/A",
            "confidence": "Low",
            "raw": {
                "lab_mode": True,
                "resource": resource
            }
        }

    return {
        "classification": "Benign",
        "risk": 0,
        "severity": "N/A",
        "confidence": "High",
        "raw": {
            "lab_mode": True,
            "resource": resource
        }
    }


def decide_from_reputation(rep):
    risk = rep.get("risk", 34)
    classification = str(rep.get("classification", "unknown")).lower()

    try:
        risk = int(risk)
    except Exception:
        risk = 34

    if risk >= 80 or classification in ["malware", "phishing", "malicious", "cnc server"]:
        return "block"

    if risk >= 64:
        return "caution"

    if classification in ["unknown", "unclassified"]:
        return "unknown"

    return "allow"


# =========================
# Check Point Threat Emulation Cloud API
# =========================

def query_threat_emulation_by_sha256(sha256, filename="unknown"):
    """
    Query API:
    POST https://<service_address>/tecloud/api/<version>/file/query
    Header: Authorization: <API KEY>
    """
    if LAB_MODE and not CP_TE_API_KEY:
        return {
            "response": {
                "status": {
                    "code": 9999,
                    "label": "LAB_MODE",
                    "message": "Simulated TE query because CP_TE_API_KEY is missing"
                },
                "sha256": sha256,
                "file_name": filename,
                "features": ["te"],
                "te": {
                    "combined_verdict": "benign",
                    "status": {
                        "label": "FOUND"
                    }
                }
            }
        }

    endpoint = f"https://{CP_TE_SERVICE_ADDRESS}/tecloud/api/{CP_TE_API_VERSION}/file/query"

    headers = {
        "Authorization": CP_TE_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "request": [
            {
                "sha256": sha256,
                "file_name": filename,
                "features": ["te"],
                "te": {
                    "reports": ["summary"]
                }
            }
        ]
    }

    response = requests.post(endpoint, headers=headers, json=payload, timeout=60)
    response.raise_for_status()

    return response.json()


def upload_file_to_threat_emulation(file_bytes, filename, mime_type, sha256):
    """
    Upload API:
    POST https://<service_address>/tecloud/api/<version>/file/upload
    Header: Authorization: <API KEY>
    multipart:
      request = JSON
      file = binary file
    """
    if LAB_MODE and not CP_TE_API_KEY:
        return {
            "response": {
                "status": {
                    "code": 1002,
                    "label": "UPLOAD_SUCCESS",
                    "message": "Simulated upload in lab mode"
                },
                "sha256": sha256,
                "file_name": filename,
                "features": ["te"],
                "te": {
                    "status": {
                        "code": 1002,
                        "label": "UPLOAD_SUCCESS",
                        "message": "Simulated TE upload"
                    },
                    "combined_verdict": "unknown"
                }
            }
        }

    endpoint = f"https://{CP_TE_SERVICE_ADDRESS}/tecloud/api/{CP_TE_API_VERSION}/file/upload"

    headers = {
        "Authorization": CP_TE_API_KEY
    }

    file_type = filename.split(".")[-1].lower() if "." in filename else ""

    request_payload = {
        "request": [
            {
                "sha256": sha256,
                "file_name": filename,
                "file_type": file_type,
                "features": ["te"],
                "te": {
                    "reports": ["summary"]
                }
            }
        ]
    }

    files = {
        "request": (
            None,
            json.dumps(request_payload),
            "application/json"
        ),
        "file": (
            filename,
            file_bytes,
            mime_type or "application/octet-stream"
        )
    }

    response = requests.post(endpoint, headers=headers, files=files, timeout=120)
    response.raise_for_status()

    return response.json()


def get_te_status_label(te_response):
    try:
        response_obj = te_response.get("response", {})
        status = response_obj.get("status", {})
        label = status.get("label", "unknown")

        te_obj = response_obj.get("te", {})
        te_status = te_obj.get("status", {})
        te_label = te_status.get("label")

        combined = te_obj.get("combined_verdict")

        if combined:
            return f"{label} / verdict={combined}"

        if te_label:
            return f"{label} / te={te_label}"

        return label

    except Exception:
        return "unknown"


# =========================
# Utility functions
# =========================

def extract_urls(text):
    pattern = r"(https?://[^\s]+|www\.[^\s]+)"
    urls = re.findall(pattern, text)

    normalized = []
    for url in urls:
        if url.startswith("www."):
            url = "https://" + url
        normalized.append(url)

    return normalized


def calculate_sha256(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def extension_from_mime(mime_type):
    extension = mimetypes.guess_extension(mime_type or "")
    if extension:
        return extension.replace(".", "")
    return "bin"


if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
