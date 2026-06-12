import base64
import os
import re

import httpx

REKA_API_URL = os.getenv("REKA_API_URL", "https://api.reka.ai/v1")
REKA_API_KEY = os.getenv("REKA_API_KEY")
REKA_MODEL = os.getenv("REKA_MODEL", "reka-flash")  

# low-level call 
async def _chat(messages: list, timeout: float = 60.0) -> str:
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
    payload = {"model": REKA_MODEL, "messages": messages}

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
    "You are a scam and deepfake detection assistant for users in Singapore. "
    "You analyse text messages, images, and video frames for signs of impersonation scams, "
    "social engineering, and AI-generated or manipulated media.\n\n"
    "Always respond ONLY with a valid JSON object in this exact structure:\n"
    "{\n"
    '  "verdict": "scam" | "suspicious" | "safe",\n'
    '  "confidence": <float 0.0-1.0>,\n'
    '  "reason": "<one concise sentence summarising the overall risk>",\n'
    '  "indicators": ["<specific finding 1>", "<specific finding 2>"]\n'
    "}\n\n"
    "Rules:\n"
    "- indicators must be an empty list [] if nothing suspicious is found\n"
    "- reason must always be present, even for safe content\n"
    "- Do not include any text outside the JSON object\n"
    "- Calibrate confidence to the Singapore threat landscape: "
    "government impersonation (MOM, IRAS, SPF, MAS, CPF), parcel scams, "
    "banking fraud, love scams, and job scams are high-prevalence"
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
    """Analyse text for scam patterns."""
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
    return await _chat(messages)
