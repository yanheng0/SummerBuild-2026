import base64
import os

import httpx

REKA_API_URL = os.getenv("REKA_API_URL", "https://api.reka.ai/v1")
REKA_API_KEY = os.getenv("REKA_API_KEY")
REKA_MODEL = os.getenv("REKA_MODEL", "reka-flash")  # cheapest multimodal model

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
    return data["choices"][0]["message"]["content"]


def _data_url(media_type: str, raw: bytes) -> str:
    return f"data:{media_type};base64,{base64.b64encode(raw).decode()}"


# public, typed entry points 
SYSTEM_PROMPT = (
    "You are a safety assistant helping a user in Singapore spot scams. "
    "Analyse the user's input and respond in this exact format:\n"
    "VERDICT: <scam|suspicious|likely_safe>\n"
    "CONFIDENCE: <0-100>\n"
    "REASON: <one short sentence>\n"
    "Be concise."
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
