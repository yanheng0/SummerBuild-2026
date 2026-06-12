import base64
import os
import re

import httpx

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
    "You are a senior forensic fraud investigator and an expert multimodal safety engine. Your task is to analyze the provided multi-channel evidence (which may include chat transcripts, profile screenshots, document images, audio descriptors, and links) to determine the likelihood of an impersonation or financial scam.\n\n"
    "Analyze the inputs systematically across these four vectors:\n"
    "1. LINGUISTIC ALIGNMENT: Check for high-pressure tactics, artificial urgency, requests for anomalous payment channels (crypto, third-party apps), or sudden shifts in tone/language proficiency.\n"
    "2. VISUAL VERIFICATION: Cross-examine profile elements. Identify if logos (e.g., government agencies, banks, commercial brands) are used illegitimately. Look for visual tampering, doctoring, or mismatched artifacts in receipts or documents.\n"
    "3. CONTEXTUAL REASONING: Compare the sender's claimed identity against their behavioral patterns (e.g., an official bank representative messaging via an unverified Telegram handle or personal WhatsApp account).\n"
    
    "4. LINK & ENTITY ANALYSIS: Evaluate any raw URLs or text-based URLs found in the evidence for domain spoofing or look-alike phishing characteristics.\n\n"
    "You must return your findings strictly as a JSON object. Do not include any conversational preamble or postscript. Use the following schema:\n"
    "{\n"
    '  "verdict": "SAFE" | "SUSPICIOUS" | "HIGH_RISK",\n'
    '  "confidence_score": 0, // Integer between 0 and 100\n'
    '  "primary_threat_vector": "IMPERSONATION" | "INVESTMENT_FRAUD" | "PHISHING" | "ADVANCE_FEE" | "NONE",\n'
    '  "analysis_summary": "A concise overview of the findings.",\n'
    '  "forensic_indicators": {\n'
    '    "linguistic_flags": ["List of specific phrases, tones, or psychological triggers identified"],\n'
    '    "visual_anomalies": ["List of doctored elements, unauthorized logos, or visual mismatches noticed"],\n'
    '    "behavioral_contradictions": ["List of logical flaws between claimed identity and platform behavior"]\n'
    "  },\n"
    '  "extracted_entities": {\n'
    '    "impersonated_target": "Name of organization or individual being cloned, or null",\n'
    '    "scammer_identifiers": ["Handles, numbers, names, or crypto wallets found in the text"],\n'
    '    "malicious_urls": ["Any suspicious links extracted from the context"]\n'
    "  },\n"
    '  "recommended_action": "BLOCK_AND_REPORT" | "FLAG_FOR_HUMAN_REVIEW" | "ALLOW"\n'
    "}"
)


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
    return await _chat(messages)


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
