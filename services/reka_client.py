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
ELEVENLABS_API_KEY = os.getenv("ELEVENLABS_API_KEY")
ELEVENLABS_API_URL = os.getenv("ELEVENLABS_API_URL", "https://api.elevenlabs.io/v1")
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

async def _call_reka_raw(messages: list, model: str = REKA_MODEL_FLASH, timeout: float = 60.0, temperature: float = 0.2) -> str:
    """Like _call_reka but returns raw prose — skips JSON extraction."""
    if not REKA_API_KEY:
        raise RuntimeError("REKA_API_KEY not set")
    headers = {"X-Api-Key": REKA_API_KEY, "Content-Type": "application/json"}
    payload = {"model": model, "messages": messages, "temperature": temperature}
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(
            f"{REKA_API_URL}/chat/completions",
            headers=headers,
            json=payload,
        )
        if resp.status_code >= 400:
            raise RuntimeError(f"Reka API error: {resp.status_code} - {resp.text}")
        data = resp.json()
    return data["choices"][0]["message"]["content"].strip()

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
    "You are an assistant helping Singapore residents draft police reports for scam incidents.\n"
    "Where and how did you get to know the other party? What are the exact details of the other party? \n"
    "what were the words said? What was promised to you by the other party? \n"
    "Did you receive any goods, services, and/or money or equivalent? If yes, what did you receive in total and how much? \n"
    "How much money or equivalent, have you paid or transferred to the other party in total? \n"
    "Details of each payment or transfer will be asked later. [Note: If you are making this report on behalf of another person, please add in a placeholder on behalf of the other person.] \n"
    "What/how (e.g. signed contract, over phone) was the agreement established between you and the other party? \n"
    "Details of transaction involved (e.g. data/time/mode/amount/location of payment or transfer, bank account number of all parties if applicable) \n"
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

# Dedicated audio transcription via Reka's Speech API. We do this BEFORE
# running scam analysis so the model works on real text content rather
# than guessing from a prompt + RAG examples. 
async def transcribe_audio(wav_bytes: bytes) -> str:
    """Transcribe a WAV clip via ElevenLabs Speech-to-Text API."""
    if not ELEVENLABS_API_KEY:
        raise RuntimeError("ELEVENLABS_API_KEY not set")

    headers = {"xi-api-key": ELEVENLABS_API_KEY}

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(
            f"{ELEVENLABS_API_URL}/speech-to-text",
            headers=headers,
            files={"file": ("audio.wav", wav_bytes, "audio/wav")},
            data={"model_id": "scribe_v1"},
        )

    if resp.status_code >= 400:
        raise RuntimeError(
            f"ElevenLabs transcription error: {resp.status_code} - {resp.text[:300]}"
        )

    data = resp.json()
    transcript = (data.get("text") or "").strip()
    return transcript

async def scan_voice(data: bytes, caption: str = "") -> dict:
    """Transcribe the audio first, then run text-based scam analysis."""
    if len(data) > MAX_AUDIO_BYTES:
        raise ValueError(f"Audio exceeds {MAX_AUDIO_BYTES//1024//1024} MB")

    logger.info(f"Voice scan: bytes_in={len(data)}, starting transcription")
    try:
        transcript = await transcribe_audio(data)
    except Exception as e:
        # if there is error, it will be in the logger 
        logger.error(f"Voice transcription failed: {e}")
        return _fallback("the audio could not be transcribed")

    logger.info(f"Voice scan: transcript_len={len(transcript)}")
    if not transcript:
        # Transcription succeeded at the HTTP level but returned empty
        # content — e.g. silent clip, or model filtered the audio. Don't
        # let the caller think the message was analysed.
        return _fallback("the audio was silent or could not be understood")

    # Use the transcript as the analysis input. Prefix with a marker so
    # the model and any log reader can see the source of the text.
    analysis_input = transcript
    if caption:
        analysis_input = f"[User caption: {caption}]\n\n{transcript}"

    # Run the standard text-based pipeline on the transcript. This goes
    # through RAG grounding (which now matches real text) and the
    # escalation logic.
    return await scan_text(analysis_input)

# Report generation (uses Flash)
async def generate_report(analysis_json: str, submitted_at: str) -> str:
    try:
        clean = json.dumps(json.loads(analysis_json), ensure_ascii=False)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON")
    msg = f"The following scan result was produced on {submitted_at}:\n\n{clean}\n\nGenerate the police report."

    raw_report = await _call_reka_raw(
        [{"role": "system", "content": REPORT_SYSTEM_PROMPT}, {"role": "user", "content": msg}],
        REKA_MODEL_FLASH,
    )
    # Strip any stray markdown code fences the model may have added
    return re.sub(r"```[a-z]*\s*|```", "", raw_report).strip()