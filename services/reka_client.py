import asyncio
import base64
import json
import logging
import os
import re
import httpx

from services.rag.retriever import retrieve_context

logger = logging.getLogger(__name__)

REKA_API_URL = os.getenv("REKA_API_URL", "https://api.reka.ai/v1")
REKA_API_KEY = os.getenv("REKA_API_KEY")
REKA_MODEL_FLASH = os.getenv("REKA_MODEL_FLASH", "reka-flash")
REKA_MODEL_CORE = os.getenv("REKA_MODEL_CORE", "reka-core-20240501")

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_AUDIO_BYTES = 20 * 1024 * 1024

# Image MIME detection via magic bytes 
def _detect_image_mime(data: bytes) -> str:
    """
    Detect MIME type from the first few bytes of image data.
    Returns 'application/octet-stream' if unknown.
    """
    if len(data) < 12:
        return "application/octet-stream"

    # JPEG: FF D8 FF
    if data[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    # PNG: 89 50 4E 47 0D 0A 1A 0A
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    # GIF: GIF87a or GIF89a
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return "image/gif"
    # WebP: RIFF....WEBP
    if data[:4] == b'RIFF' and len(data) >= 12 and data[8:12] == b'WEBP':
        return "image/webp"
    # BMP: BM
    if data[:2] == b'BM':
        return "image/bmp"
    # SVG: starts with '<svg' or '<?xml' – treat as text, but we'll return image/svg+xml
    if data[:4] in (b'<svg', b'<?xm'):
        return "image/svg+xml"

    return "application/octet-stream"


# API call with retry 
async def _call_reka(messages: list, model: str = REKA_MODEL_FLASH, timeout: float = 60.0) -> str:
    if not REKA_API_KEY:
        raise RuntimeError("REKA_API_KEY not set")
    headers = {"X-Api-Key": REKA_API_KEY, "Content-Type": "application/json"}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{REKA_API_URL}/chat/completions",
            headers=headers,
            json={ 
                "model": model, 
                "messages": messages,
                "temperature": 0.2
            },
        )
        if resp.status_code >= 400:
            error_details = resp.text 
            raise RuntimeError(f"Reka API error: {resp.status_code} - {error_details}")        
        data = resp.json()
    raw = data["choices"][0]["message"]["content"]
    return re.sub(r"```(?:json)?|```", "", raw).replace("json", "").strip()

async def _chat_with_retry(messages: list, model: str = REKA_MODEL_FLASH, max_retries: int = 3) -> str:
    for attempt in range(1, max_retries + 1):
        try:
            return await _call_reka(messages, model)
        except (httpx.TimeoutException, RuntimeError) as e:
            if attempt == max_retries:
                raise RuntimeError("Reka unavailable after retries") from None
            if isinstance(e, RuntimeError) and "429" not in str(e) and "5" not in str(e):
                raise
            await asyncio.sleep(2 ** attempt)

def _data_url(media_type: str, raw: bytes) -> str:
    return f"data:{media_type};base64,{base64.b64encode(raw).decode()}"

# Response parsing 
def _parse_response(raw: str) -> dict:
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return _fallback("parse error")
    verdict = data.get("verdict", "SAFE").upper()
    if verdict not in ("SAFE", "SUSPICIOUS", "HIGH_RISK"):
        verdict = "SAFE"
    conf = max(0, min(100, int(data.get("confidence_score", 20))))
    return {
        "verdict": verdict,
        "confidence_score": conf,
        "scam_type": data.get("scam_type", "NONE"),
        "analysis_summary": data.get("analysis_summary", ""),
        "indicators_found": data.get("indicators_found", []),
        "extracted_entities": data.get("extracted_entities", {"domain": None, "impersonated_org": None, "payment_request": []}),
        "recommended_action": data.get("recommended_action", "ALLOW"),
    }

def _fallback(reason: str) -> dict:
    return {
        "verdict": "SAFE",
        "confidence_score": 20,
        "scam_type": "NONE",
        "analysis_summary": f"Analysis unavailable: {reason}",
        "indicators_found": [],
        "extracted_entities": {"domain": None, "impersonated_org": None, "payment_request": []},
        "recommended_action": "ALLOW",
    }

# System prompts 
SYSTEM_PROMPT = (
    "You are a forensic scam detection engine. Detect ANY scam pattern, prioritising:\n"
    "1. GOVERNMENT IMPERSONATION (SPF, CPF, IRAS, ICA, MOM, MAS)\n"
    "2. INVESTMENT SCAMS (crypto, pig‑butchering, fake trading)\n"
    "3. JOB SCAMS (task‑based, upfront deposit)\n"
    "4. PHISHING LINKS (credential harvesting)\n"
    "Also detect: romance, tech support, lottery, parcel, SIM swap, fake emergency, charity, rental.\n\n"
    "For inputs WITHOUT a URL, apply signal‑based: two clear indicators → HIGH_RISK; one → SUSPICIOUS; none → SAFE.\n"
    "Exception: a single definitive government impersonation (arrest warrant, safe‑account, badge) → HIGH_RISK if confidence ≥80.\n\n"
    "URL CLASSIFICATION:\n"
    "STEP 1 — TYPOSQUAT/HOMOGLYPH: g00gle.com, d‑b‑s, dbs.verify‑now, singpas.gov.sg → HIGH_RISK (85‑95).\n"
    "STEP 2 — LEGITIMACY: if domain in known institutions (dbs.com.sg, ocbc.com, cpf.gov.sg, singpass.gov.sg, gov.sg, google.com, github.com, etc.) and NO open redirect → SAFE (80‑90).\n"
    "STEP 3 — OPEN REDIRECT: ?url=, ?redirect=, ?next= to external domain → HIGH_RISK (80‑90).\n"
    "STEP 4 — SIGNALS:\n"
    "  B: credential/payment request (OTP, password, card, transfer) [HIGH]\n"
    "  C: urgency + link (within 24h, account frozen) [MEDIUM]\n"
    "  D: identity mismatch (claimed brand not in domain) [MEDIUM]\n"
    "Rules: zero signals → SAFE (50‑70); B alone → SUSPICIOUS (60‑70); C or D alone → SUSPICIOUS (55‑65); B+other or C+D → HIGH_RISK (70‑85).\n"
    "Shortened links: no signals → SAFE (≤65); with B/C → apply rules.\n"
    "CALIBRATION: Unfamiliarity is not evidence. Unknown domain + no signals = SAFE.\n\n"
    "OUTPUT JSON:\n"
    '{"verdict":"SAFE|SUSPICIOUS|HIGH_RISK","confidence_score":0,'
    '"scam_type":"GOVERNMENT_IMPERSONATION|INVESTMENT_SCAM|JOB_SCAM|PHISHING_LINK|ROMANCE_SCAM|TECH_SUPPORT_SCAM|LOTTERY_SCAM|PARCEL_SCAM|SIM_SWAP_SCAM|OTHER|NONE",'
    '"analysis_summary":"...","indicators_found":[],'
    '"extracted_entities":{"domain":null,"impersonated_org":null,"payment_request":[]},'
    '"recommended_action":"BLOCK_AND_REPORT|FLAG_FOR_HUMAN_REVIEW|ALLOW"}'
)

REPORT_SYSTEM_PROMPT = (
    "You are an assistant helping Singapore residents draft police reports for scam or deepfake incidents.\n"
    "Given a JSON analysis result from a deepfake/scam detection scan, produce a clear, formal "
    "draft police report addressing these points in order:\n\n"
    "1. Any identified subject or impersonated party name - e.g. any unique features of the person, what is the number that is used to contact.\n"
    "2. What was the type of scam being conducted - e.g. impersonation, financial fraud, misinformation.\n"
    "3. The date and time the image was submitted for analysis.\n"
    "4. The platform or context where the content was encountered (if determinable from the analysis).\n"
    "5. What key information is used to make the scam believable.\n"
    "6. Recommended action based on the verdict.\n\n"
    "Format each section with a clear heading (e.g., '1. Subject: ...'). "
    "Use formal, factual language. "
    "Do not invent details not present in the analysis."
)

#  RAG injection
def _build_prompt(query: str) -> str:
    if query and query.strip():
        rag = retrieve_context(query, top_k=3)
        if rag:
            parts = SYSTEM_PROMPT.split("\n\n", 1)
            return f"{parts[0]}\n\n{rag}\n\n{parts[1] if len(parts)>1 else ''}"
    return SYSTEM_PROMPT

# Core escalation logic 
async def _scan_with_escalation(content, query_text: str, size_limit=None, raw_data=None) -> dict:
    if raw_data and size_limit and len(raw_data) > size_limit:
        raise ValueError(f"Exceeds {size_limit//1024//1024} MB limit")

    flash_raw = await _chat_with_retry(
        [{"role": "system", "content": _build_prompt(query_text)}, {"role": "user", "content": content}],
        model=REKA_MODEL_FLASH
    )
    flash_parsed = _parse_response(flash_raw)
    logger.info(f"Flash: verdict={flash_parsed['verdict']}, conf={flash_parsed['confidence_score']}")

    if 30 <= flash_parsed["confidence_score"] <= 70:
        logger.info("Escalating to Core due to ambiguous confidence")
        core_raw = await _chat_with_retry(
            [{"role": "system", "content": _build_prompt(query_text + " (detailed)")},
             {"role": "user", "content": content}],
            model=REKA_MODEL_CORE
        )
        core_parsed = _parse_response(core_raw)
        logger.info(f"Core: verdict={core_parsed['verdict']}, conf={core_parsed['confidence_score']}")
        return core_parsed
    return flash_parsed

# Public scan functions 
async def scan_text(text: str) -> dict:
    return await _scan_with_escalation(text, text)

async def scan_image(data: bytes, caption: str = "") -> dict:
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError(f"Image exceeds {MAX_IMAGE_BYTES//1024//1024} MB")
    mime = _detect_image_mime(data)
    content = [
        {"type": "image_url", "image_url": {"url": _data_url(mime, data)}},
        {"type": "text", "text": "Analyse this image for scam indicators." + (f" User caption: {caption}" if caption else "")}
    ]
    return await _scan_with_escalation(content, caption, MAX_IMAGE_BYTES, data)

async def scan_voice(data: bytes, caption: str = "") -> dict:
    if len(data) > MAX_AUDIO_BYTES:
        raise ValueError(f"Audio exceeds {MAX_AUDIO_BYTES//1024//1024} MB")
    content = [
        {"type": "audio_url", "audio_url": {"url": _data_url("audio/wav", data)}},
        {"type": "text", "text": "Listen to this voice message and analyse it for scam indicators." + (f" User caption: {caption}" if caption else "")}
    ]
    return await _scan_with_escalation(content, caption, MAX_AUDIO_BYTES, data)

# Core‑only functions 
async def scan_text_core(text: str) -> dict:
    raw = await _chat_with_retry(
        [{"role": "system", "content": _build_prompt(text)}, {"role": "user", "content": text}],
        REKA_MODEL_CORE
    )
    return _parse_response(raw)

async def scan_image_core(data: bytes, caption: str = "") -> dict:
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError(f"Image exceeds {MAX_IMAGE_BYTES//1024//1024} MB")
    mime = _detect_image_mime(data)
    content = [{"type": "image_url", "image_url": {"url": _data_url(mime, data)}},
               {"type": "text", "text": "Analyse this image in detail." + (f" Caption: {caption}" if caption else "")}]
    raw = await _chat_with_retry(
        [{"role": "system", "content": _build_prompt(caption or "detailed image scam analysis")}, {"role": "user", "content": content}],
        REKA_MODEL_CORE
    )
    return _parse_response(raw)

async def scan_voice_core(data: bytes, caption: str = "") -> dict:
    if len(data) > MAX_AUDIO_BYTES:
        raise ValueError(f"Audio exceeds {MAX_AUDIO_BYTES//1024//1024} MB")
    content = [{"type": "audio_url", "audio_url": {"url": _data_url("audio/wav", data)}},
               {"type": "text", "text": "Analyse this voice message in detail." + (f" Caption: {caption}" if caption else "")}]
    raw = await _chat_with_retry(
        [{"role": "system", "content": _build_prompt(caption or "detailed voice scam analysis")}, {"role": "user", "content": content}],
        REKA_MODEL_CORE
    )
    return _parse_response(raw)

async def generate_report(analysis_json: str, submitted_at: str) -> str:
    try:
        clean = json.dumps(json.loads(analysis_json), ensure_ascii=False)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON")
    msg = f"The following scan result was produced on {submitted_at}:\n\n{clean}\n\nGenerate the police report."
    raw_report = await _chat_with_retry(
        [{"role": "system", "content": REPORT_SYSTEM_PROMPT}, {"role": "user", "content": msg}],
        REKA_MODEL_FLASH
    )
    # Replace Markdown bold with HTML bold
    clean_report = raw_report.replace("**", "").strip()  # Remove entirely? Better to convert.
    # Or convert: 
    import re
    clean_report = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', raw_report)
    return clean_report