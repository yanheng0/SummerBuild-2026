import base64
import os
import re

import httpx

from services.rag.retriever import retrieve_context

REKA_API_URL = os.getenv("REKA_API_URL", "https://api.reka.ai/v1")
REKA_API_KEY = os.getenv("REKA_API_KEY")
REKA_MODEL_FLASH = os.getenv("REKA_MODEL_FLASH", "reka-flash")
REKA_MODEL_CORE = os.getenv("REKA_MODEL_CORE", "reka-core")  

# low-level call
async def _chat(messages: list, model: str, timeout: float = 60.0) -> str:
    """
    Send `messages` to /chat/completions and return the assistant's reply text.
    Auth header must be X-Api-Key, not Authorization: Bearer.
    """
    if not REKA_API_KEY:
        raise RuntimeError("REKA_API_KEY is not set in the environment.")

    headers = {
        "X-Api-Key": REKA_API_KEY,
        "Content-Type": "application/json",
    }
    payload = {"model": model, "messages": messages}

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            f"{REKA_API_URL}/chat/completions",
            headers=headers,
            json=payload,
        )
        r.raise_for_status()
        data = r.json()

    # Reka follows an OpenAI-ish shape: choices[0].message.content
    raw = data["choices"][0]["message"]["content"]

    cleaned = re.sub(r"```(?:json)?|```", "", raw)
    cleaned = re.sub(r"^\s*json\s*$", "", cleaned, flags=re.MULTILINE)
    return cleaned.strip()


def _data_url(media_type: str, raw: bytes) -> str:
    return f"data:{media_type};base64,{base64.b64encode(raw).decode()}"


# public, typed entry prompt to reka
SYSTEM_PROMPT = (
    "You are a senior forensic fraud investigator and an expert multimodal safety engine. "
    "Your task is to analyze the provided multi-channel evidence (which may include chat "
    "transcripts, profile screenshots, document images, audio descriptors, and links) to "
    "determine the likelihood of an impersonation or financial scam.\n\n"
    
    "Analyze the inputs systematically across these four vectors:\n"
    "1. LINGUISTIC ALIGNMENT: Check for high-pressure tactics, artificial urgency, requests "
    "for anomalous payment channels (crypto, third-party apps), or sudden shifts in tone/language proficiency.\n"
    "2. VISUAL VERIFICATION: Cross-examine profile elements. Identify if logos (e.g., government "
    "agencies, banks, commercial brands) are used illegitimately. Look for visual tampering, "
    "doctoring, or mismatched artifacts in receipts or documents.\n"
    "3. CONTEXTUAL REASONING: Compare the sender's claimed identity against their behavioral "
    "patterns (e.g., an official bank representative messaging via an unverified Telegram handle "
    "or personal WhatsApp account).\n"
    "4. LINK & ENTITY ANALYSIS — Follow the URL CLASSIFICATION PROTOCOL below.\n\n"
    
    "--- URL CLASSIFICATION PROTOCOL (Zero False-Positive Bias) ---\n"
    "Your job is forensic, not precautionary. A URL must earn a risk classification "
    "through observable evidence. Classifying a safe link as SUSPICIOUS or HIGH_RISK "
    "breaks user trust. When in doubt, SAFE wins.\n\n"
    
    "STEP 1 — CANONICALIZATION & SANITIZATION\n"
    "If no URL is present, skip to STEP 5.\n"
    "If a URL is present, inspect it for Open Redirect vectors or Shorteners BEFORE checking legitimacy:\n"
    "  • CRITICAL OPEN REDIRECT CHECK: Inspect query parameters for variables like "
    "`?q=`, `?url=`, `?redirect=`, `?next=`, `?return=`, `?continue=`, `?goto=`, "
    "`?link=`, or `?target=`. If these parameters contain a secondary URL or "
    "external domain that does not match the base domain, treat that secondary URL "
    "as the TRUE destination domain for the remainder of this analysis.\n"
    "  • SHORTENER HANDLING: If the domain is a known shortener (e.g., bit.ly, "
    "tinyurl.com, t.co, goo.gl), flag it as `AMBIGUOUS_SHORTENER` and proceed "
    "directly to STEP 4 (Phishing Signals). Do not grant an early safe exit.\n\n"
    
    "STEP 2 — ISOLATE THE TRUE REGISTRABLE DOMAIN\n"
    "Extract the exact registrable domain (the last two labels before the public "
    "suffix, e.g., `dbs.com.sg` from `secure.dbs.com.sg`, or `verify-now.net` from "
    "`dbs.verify-now.net`).\n"
    "If an open redirect was detected in Step 1, use the extracted destination "
    "domain as the \"true domain\" for the remainder of the analysis.\n\n"
    
    "STEP 3 — CONDITIONAL LEGITIMACY CHECK (Early Exit Guard)\n"
    "A domain qualifies for an early SAFE exit ONLY if it matches a KNOWN INSTITUTION "
    "(listed below) AND passes the Open Redirect Check (i.e., Step 1 did not flag "
    "an open redirect).\n"
    "  • TRUSTED REGISTRIES: Domains ending exactly in `.gov.sg`, `.edu.sg`, or "
    "`.mil.sg` bypass STEP 4 and exit as SAFE (confidence 85–90), unless an "
    "Open Redirect was flagged in Step 1 (in which case, proceed to STEP 4).\n"
    "Path inspection (e.g., `/form/`, `/shared/`) is NOT required – legitimate "
    "domains can safely host such paths. Only open redirect parameters void "
    "the early exit.\n\n"
    
    "KNOWN INSTITUTIONS (not exhaustive but authoritative):\n"
    "dbs.com.sg, posb.com.sg, ocbc.com, uob.com.sg, maybank2u.com.sg, cimb.com.sg, "
    "cpf.gov.sg, iras.gov.sg, mom.gov.sg, spf.gov.sg, singpass.gov.sg, gov.sg, "
    "google.com, microsoft.com, apple.com, amazon.com, lazada.sg, shopee.sg\n\n"
    
    "STEP 4 — PHISHING SIGNALS (Require Concrete Direct Observation)\n"
    "Do not infer signals that are absent. Mark each signal explicitly if observed:\n"
    "  • SIGNAL A — Domain Impersonation (HIGH weight):\n"
    "    Observable: digits replacing letters (g00gle.com), brand names with "
    "abnormal hyphens (d-b-s), brand strings as subdomains of unrelated roots "
    "(dbs.pay-verification.com), or deceptive misspellings (singpas.gov.sg).\n"
    "  • SIGNAL B — Credential/Payment Harvesting (HIGH weight):\n"
    "    Observable: message explicitly demands an OTP, password, full credit card "
    "details, NRIC, CVV, or instructs a direct money transfer immediately after clicking.\n"
    "  • SIGNAL C — Urgency + Link (MEDIUM weight):\n"
    "    Observable: a highly specific, time‑limited threat (\"within 24 hours\", "
    "\"account will be frozen\", \"or you will be fined\") directly paired with an "
    "instruction to use the URL.\n"
    "  • SIGNAL D — Claimed‑Identity Mismatch (MEDIUM weight):\n"
    "    Observable: sender text claims \"From DBS\" or \"Singpass Officer\", but the "
    "Isolated Registrable Domain contains no reference to that brand.\n"
    "    (If no brand is claimed, ignore this signal.)\n\n"
    
    "STEP 5 — CLASSIFICATION & DECISION TABLE\n"
    "Match your observed signals to the exact matrix below:\n"
    "  • Qualified Step 3 match (known domain + no open redirect)\n"
    "      → VERDICT: SAFE (Confidence = 80–90)\n"
    "  • Zero Phishing Signals Observed (unknown domain, no signals)\n"
    "      → VERDICT: SAFE (Confidence = 50–70)\n"
    "        *REMINDER: Unfamiliarity is not evidence. A domain you have never seen "
    "        before with no scam indicators is SAFE.*\n"
    "  • AMBIGUOUS_SHORTENER + Zero Phishing Signals\n"
    "      → VERDICT: SAFE (Confidence = 50–60)\n"
    "  • Signal A Observed (impersonation)\n"
    "      → VERDICT: HIGH_RISK (Confidence = 85–95)\n"
    "  • Signal B + (C or D) Observed\n"
    "      → VERDICT: HIGH_RISK (Confidence = 75–85)\n"
    "  • Signal B Alone OR Signal C Alone\n"
    "      → VERDICT: SUSPICIOUS (Confidence = 55–65)\n"
    "  • Signal D Alone\n"
    "      → VERDICT: SUSPICIOUS (Confidence = 50–60)\n"
    "  • AMBIGUOUS_SHORTENER + Any Phishing Signal (A–D)\n"
    "      → VERDICT: HIGH_RISK (Confidence = 70–80)\n\n"
    
    "CALIBRATION NOTE\n"
    "If you cannot point to a specific observable signal from Step 4, you must "
    "classify as SAFE. For SAFE verdicts with unknown domains, set confidence "
    "between 50 and 70 – honesty about uncertainty is better than overconfidence.\n\n"
    
    "--- END OF URL CLASSIFICATION PROTOCOL ---\n\n"
    
    "You must return your findings strictly as a JSON object. Do not include any conversational "
    "preamble or postscript. Use the following schema:\n"
    "{\n"
    '  "verdict": "SAFE" | "SUSPICIOUS" | "HIGH_RISK",\n'
    '  "confidence_score": 0, // Integer between 0 and 100\n'
    '  "primary_threat_vector": "IMPERSONATION" | "INVESTMENT_FRAUD" | "PHISHING" | "ADVANCE_FEE" | "NONE",\n'
    '  "open_redirect_detected": true | false,\n'
    '  "analysis_summary": "A concise overview of the findings, referencing specific signals.",\n'
    '  "forensic_indicators": {\n'
    '    "linguistic_flags": ["List of specific phrases, tones, or psychological triggers identified"],\n'
    '    "visual_anomalies": ["List of doctored elements, unauthorized logos, or visual mismatches noticed"],\n'
    '    "behavioral_contradictions": ["List of logical flaws between claimed identity and platform behavior"]\n'
    "  },\n"
    '  "extracted_entities": {\n'
    '    "true_destination_domain": "The extracted domain after sanitization (or original if no redirect)",\n'
    '    "impersonated_target": "Name of organization or individual being cloned, or null",\n'
    '    "scammer_identifiers": ["Handles, numbers, names, or crypto wallets found in the text"]\n'
    "  },\n"
    '  "recommended_action": "BLOCK_AND_REPORT" | "FLAG_FOR_HUMAN_REVIEW" | "ALLOW"\n'
    "}"
)

REPORT_SYSTEM_PROMPT = (
    "You are an assistant helping Singapore residents draft police reports for scam or deepfake incidents.\n"
    "Given a JSON analysis result from a deepfake/scam detection scan, produce a clear, formal "
    "draft police report using these questions:\n\n"
    "Any identified subject or impersonated party name - e.g. any unique features of the person, what is the number that is used to contact\n"
    "What was the type of scam being conducted - e.g. impersonation, financial fraud, misinformation\n"
    "The date and time the image was submitted for analysis\n"
    "The platform or context where the content was encountered (if determinable from the analysis)\n"
    "What key information is used to make the scam believable"
    "Format each section using formal, factual language. "
    "Do not invent details not present in the analysis. "
)


# RAG injection helper
def _build_system_prompt(query_text: str) -> str:
    """
    Retrieve relevant KB cases and prepend them to the base system prompt.
    The retrieval is keyed on whatever text we have (transcription hint,
    user message text, or a generic fallback for pure image/audio scans).
    """
    rag_block = retrieve_context(query_text, top_k=3)
    if rag_block:
        return f"{SYSTEM_PROMPT}\n\n{rag_block}"
    return SYSTEM_PROMPT


async def scan_voice(wav_bytes: bytes) -> str:
    """Transcribe + analyse a voice clip for scam indicators."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {
                    "type": "audio_url",
                    "audio_url": {"url": _data_url("audio/wav", wav_bytes)},
                },
                {
                    "type": "text",
                    "text": (
                        "Listen to this voice message. Is it a scam, suspicious, "
                        "or likely safe? Consider common Singapore scam patterns "
                        "(fake government calls, bank impersonation, investment scams)."
                    ),
                },
            ],
        },
    ]
    return await _chat(messages)


async def scan_image(image_bytes: bytes) -> str:
    """Analyse an image for signs of being AI-generated or part of a scam."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": _data_url("image/jpeg", image_bytes)},
                },
                {
                    "type": "text",
                    "text": (
                        "Look at this image. Does it appear AI-generated, or is "
                        "it being used in a scam (fake prize, fake product, fake "
                        "news, phishing)? Reply in the required format."
                    ),
                },
            ],
        },
    ]
    return await _chat(messages, REKA_MODEL_FLASH)


async def scan_text(text: str) -> str:
    """Analyse text for scam patterns using the flash model."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Does the following message look like a scam? Consider common "
                f"Singapore scam patterns (phishing, fake government, investment, "
                f"job, romance, parcel/IMDA, fake bank SMS).\n\nMESSAGE:\n{text}"
            ),
        },
    ]
    return await _chat(messages, REKA_MODEL_FLASH)


async def scan_text_core(text: str) -> str:
    """Analyse text for scam patterns using the core model."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"Does the following message look like a scam? Consider common "
                f"Singapore scam patterns (phishing, fake government, investment, "
                f"job, romance, parcel/IMDA, fake bank SMS).\n\nMESSAGE:\n{text}"
            ),
        },
    ]
    return await _chat(messages, REKA_MODEL_CORE)


async def scan_image_core(image_bytes: bytes) -> str:
    """Analyse an image for signs of being AI-generated or part of a scam using the core model."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {
                    "type": "image_url",
                    "image_url": {"url": _data_url("image/jpeg", image_bytes)},
                },
                {
                    "type": "text",
                    "text": (
                        "Look at this image. Does it appear AI-generated, or is "
                        "it being used in a scam (fake prize, fake product, fake "
                        "news, phishing)? Reply in the required format."
                    ),
                },
            ],
        },
    ]
    return await _chat(messages, REKA_MODEL_CORE)


async def scan_voice_core(wav_bytes: bytes) -> str:
    """Transcribe + analyse a voice clip for scam indicators using the core model."""
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": [
                {
                    "type": "audio_url",
                    "audio_url": {"url": _data_url("audio/wav", wav_bytes)},
                },
                {
                    "type": "text",
                    "text": (
                        "Listen to this voice message. Is it a scam, suspicious, "
                        "or likely safe? Consider common Singapore scam patterns "
                        "(fake government calls, bank impersonation, investment scams)."
                    ),
                },
            ],
        },
    ]
    return await _chat(messages, REKA_MODEL_CORE)


async def generate_report(analysis_json: str, submitted_at: str) -> str:
    messages = [
        {"role": "system", "content": REPORT_SYSTEM_PROMPT},
        {
            "role": "user",
            "content": (
                f"The following scan result was produced on {submitted_at}:\n\n"
                f"{analysis_json}\n\n"
                "Please generate the 5W1H draft police report."
            ),
        },
    ]
    return await _chat(messages, REKA_MODEL_FLASH)

