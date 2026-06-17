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

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_AUDIO_BYTES = 20 * 1024 * 1024

# Image MIME detection 
def _detect_image_mime(data: bytes) -> str:
    if len(data) < 12:
        return "application/octet-stream"
    if data[:3] == b'\xff\xd8\xff':
        return "image/jpeg"
    if data[:8] == b'\x89PNG\r\n\x1a\n':
        return "image/png"
    if data[:6] in (b'GIF87a', b'GIF89a'):
        return "image/gif"
    if data[:4] == b'RIFF' and len(data) >= 12 and data[8:12] == b'WEBP':
        return "image/webp"
    if data[:2] == b'BM':
        return "image/bmp"
    if data[:4] in (b'<svg', b'<?xm'):
        return "image/svg+xml"
    return "application/octet-stream"

# API call with retry and temperature 
async def _call_reka(messages: list, model: str = REKA_MODEL_FLASH, timeout: float = 60.0, temperature: float = 0.2) -> str:
    if not REKA_API_KEY:
        raise RuntimeError("REKA_API_KEY not set")
    headers = {"X-Api-Key": REKA_API_KEY, "Content-Type": "application/json"}
    payload = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{REKA_API_URL}/chat/completions",
            headers=headers,
            json=payload,
        )
        if resp.status_code >= 400:
            error_details = resp.text
            raise RuntimeError(f"Reka API error: {resp.status_code} - {error_details}")
        data = resp.json()
    raw = data["choices"][0]["message"]["content"]
    return _extract_json(raw)


# Strip markdown code fences and pull out the first JSON object from the
# model's reply. We must NOT do .replace("json", "") on the whole reply —
# that destroys the substring "json" wherever it legitimately appears in
# analysis text, JSON keys, or values (e.g. "JSON-style encoding", a
# reference to a JSON payload, etc.) and silently corrupts otherwise-valid
# output, sending it to the parse-error fallback.
def _extract_json(raw: str) -> str:
    # Strip code fences (``` or ```json / ```JSON). The pattern only
    # matches the fence markers themselves, not any other occurrence of
    # the word "json" in the response.
    cleaned = re.sub(r"```(?:json|JSON)?\s*|```", "", raw).strip()
    if not cleaned:
        raise RuntimeError("Reka returned an empty response")

    # Find the first '{' and the matching last '}'. If the model wrapped
    # its JSON in prose ("Here is the analysis: { ... }"), we take only
    # the JSON object, not the surrounding text.
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise RuntimeError("Reka response contained no JSON object")
    return cleaned[start : end + 1]

async def _chat_with_retry(messages: list, model: str = REKA_MODEL_FLASH, max_retries: int = 3, temperature: float = 0.2) -> str:
    for attempt in range(1, max_retries + 1):
        try:
            return await _call_reka(messages, model, temperature=temperature)
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
    # If the model returned valid JSON but with a missing/unknown verdict
    # field, escalate rather than silently treating it as SAFE. Same
    # reasoning as _fallback: for a scam detector, "we don't know" must
    # not default to "allow".
    verdict = data.get("verdict", "SUSPICIOUS").upper()
    if verdict not in ("SAFE", "SUSPICIOUS", "HIGH_RISK"):
        verdict = "SUSPICIOUS"
    conf = max(0, min(100, int(data.get("confidence_score", 0))))
    return {
        "verdict": verdict,
        "confidence_score": conf,
        "scam_type": data.get("scam_type", "NONE"),
        "analysis_summary": data.get("analysis_summary", ""),
        "indicators_found": data.get("indicators_found", []),
        "extracted_entities": data.get("extracted_entities", {"domain": None, "impersonated_org": None, "payment_request": []}),
        # Action must be consistent with the verdict: SAFE→ALLOW, anything
        # else→FLAG_FOR_HUMAN_REVIEW. A model that omits this field should
        # not default to "ALLOW" — that would let an unparsed/escalated
        # result auto-pass without human check.
        "recommended_action": data.get(
            "recommended_action",
            "ALLOW" if verdict == "SAFE" else "FLAG_FOR_HUMAN_REVIEW",
        ),
    }

def _fallback(reason: str) -> dict:
    # Default to SUSPICIOUS / FLAG_FOR_HUMAN_REVIEW when we can't get a
    # usable result from the model. For a safety-critical classifier, an
    # undecidable case must escalate — never auto-allow, because that
    # would let real scams pass as "safe" on transient errors (bad JSON,
    # network blip, model refusal, etc.). The escalation pipeline already
    # uses SUSPICIOUS/55% on disagreement, so this stays consistent.
    return {
        "verdict": "SUSPICIOUS",
        "confidence_score": 0,
        "scam_type": "OTHER",
        "analysis_summary": (
            f"Analysis could not be completed: {reason}. "
            "Treat as unverified and review manually before acting on it."
        ),
        "indicators_found": [],
        "extracted_entities": {"domain": None, "impersonated_org": None, "payment_request": []},
        "recommended_action": "FLAG_FOR_HUMAN_REVIEW",
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

# RAG injection 
def _build_prompt(query: str) -> str:
    if query and query.strip():
        rag = retrieve_context(query, top_k=3)
        if rag:
            parts = SYSTEM_PROMPT.split("\n\n", 1)
            return f"{parts[0]}\n\n{rag}\n\n{parts[1] if len(parts)>1 else ''}"
    return SYSTEM_PROMPT

# Self‑Reflection Escalation 
async def _scan_with_escalation(content, query_text: str, size_limit=None, raw_data=None) -> dict:
    if raw_data and size_limit and len(raw_data) > size_limit:
        raise ValueError(f"Exceeds {size_limit//1024//1024} MB limit")

    # First Flash pass
    flash_raw = await _chat_with_retry(
        [{"role": "system", "content": _build_prompt(query_text)}, {"role": "user", "content": content}],
        model=REKA_MODEL_FLASH
    )
    flash_parsed = _parse_response(flash_raw)
    logger.info(f"Flash 1st pass: verdict={flash_parsed['verdict']}, conf={flash_parsed['confidence_score']}")

    # If not ambiguous, return immediately
    if not (30 <= flash_parsed["confidence_score"] <= 70):
        return flash_parsed

    # Ambiguous -> verification pass
    logger.info("Confidence ambiguous – running verification pass with step‑by‑step reasoning")

    verification_instruction = (
        "You are now performing a forensic verification. Re‑examine the content and the initial analysis. "
        "Follow these steps exactly:\n"
        "1. List all scam indicators you can clearly observe (e.g., urgency, credential request, domain mismatch, impersonation). "
        "2. For each indicator, rate its strength as HIGH, MEDIUM, or LOW. "
        "3. Check for any false‑positive triggers – are any indicators ambiguous or explained by legitimate context? "
        "4. Based on the remaining strong indicators, produce a final verdict (SAFE, SUSPICIOUS, or HIGH_RISK) with a new confidence score (0–100). "
        "5. Provide a concise summary explaining the reasoning.\n\n"
        "Content to re‑analyse:\n" + (
            content if isinstance(content, str) else "Multimedia content attached. Review the previously extracted text and visual context."
        )
    )

    if isinstance(content, list):
        verification_content = content + [{"type": "text", "text": verification_instruction}]
        verification_messages = [
            {"role": "system", "content": _build_prompt(query_text + " (verification)")},
            {"role": "user", "content": verification_content}
        ]
    else:
        verification_messages = [
            {"role": "system", "content": _build_prompt(query_text + " (verification)")},
            {"role": "user", "content": verification_instruction}
        ]

    # Run verification with lower temperature for determinism
    verify_raw = await _chat_with_retry(verification_messages, model=REKA_MODEL_FLASH, temperature=0.0)
    verify_parsed = _parse_response(verify_raw)
    logger.info(f"Verification pass: verdict={verify_parsed['verdict']}, conf={verify_parsed['confidence_score']}")

    # Combine: if agree, take higher confidence; else SUSPICIOUS 55%
    if flash_parsed["verdict"] == verify_parsed["verdict"]:
        return flash_parsed if flash_parsed["confidence_score"] >= verify_parsed["confidence_score"] else verify_parsed
    else:
        logger.info("Disagreement between passes; returning SUSPICIOUS (55%)")
        return {
            "verdict": "SUSPICIOUS",
            "confidence_score": 55,
            "scam_type": flash_parsed.get("scam_type") or verify_parsed.get("scam_type") or "OTHER",
            "analysis_summary": (
                f"Two analyses disagreed. Pass 1: {flash_parsed['verdict']} ({flash_parsed['confidence_score']}%). "
                f"Pass 2: {verify_parsed['verdict']} ({verify_parsed['confidence_score']}%). Flagged for review."
            ),
            "indicators_found": list(set(
                flash_parsed.get("indicators_found", []) + verify_parsed.get("indicators_found", [])
            )),
            "extracted_entities": flash_parsed.get("extracted_entities", 
                {"domain": None, "impersonated_org": None, "payment_request": []}),
            "recommended_action": "FLAG_FOR_HUMAN_REVIEW",
        }

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

# Report generation (uses Flash)
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
    # Clean up any stray "html" text if present
    clean_report = raw_report.replace("html", "").replace("```", "").strip()
    return clean_report