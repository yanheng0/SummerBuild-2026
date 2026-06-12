"""
Format Reka's JSON reply into a clean Telegram message.

Reka is asked to respond in JSON format:
    {
        "verdict": "scam" | "suspicious" | "safe",
        "confidence": <float 0.0-1.0>,
        "reason": "<one concise sentence>",
        "indicators": ["<specific finding 1>", "<specific finding 2>"]
    }


We parse that and re-emit it with friendly styling + safety advice.
If parsing fails, we just print the raw reply.
"""
import json
import re

# cleanly extract the JSON object from reka  
def _extract_json(raw: str) -> str:
    # Strip any markdown fence tokens and bare 'json' language tags
    cleaned = re.sub(r"```(?:json)?|```", "", raw)
    cleaned = re.sub(r"^\s*json\s*$", "", cleaned, flags=re.MULTILINE)
    cleaned = cleaned.strip()
 
    # Extract the outermost JSON object by brace matching
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned

def _parse(raw: str) -> dict:
    cleaned = _extract_json(raw)
    # Try to parse as JSON first
    try:
        data = json.loads(cleaned)
        # Convert confidence into readible percentage
        confidence = int(data.get("confidence", 0) * 100)
        return {
            "verdict": data.get("verdict", "unknown").lower(),
            "confidence": confidence,
            "reason": data.get("reason", raw.strip())
        }
    except (json.JSONDecodeError, AttributeError, ValueError):
        # Fallback to old free-text format parsing if JSON fails
        v_match = re.search(r"VERDICT\s*:\s*(\w+)", raw, re.IGNORECASE)
        c_match = re.search(r"CONFIDENCE\s*:\s*(\d{1,3})", raw, re.IGNORECASE)
        r_match = re.search(r"REASON\s*:\s*(.+)", raw, re.IGNORECASE)

        v = v_match.group(1).lower() if v_match else "unknown"
        c = int(c_match.group(1)) if c_match else 0
        r = r_match.group(1).strip() if r_match else raw.strip()
        return {"verdict": v, "confidence": c, "reason": r, "indicators" : []}

def _format(parsed: dict) -> str:
    v, c, r, indicators = parsed["verdict"], parsed["confidence"], parsed["reason"], parsed.get("indicators", [])

    indicators_block = ""
    if indicators:
        bullet_list = "\n".join(f"• {i}" for i in indicators)
        indicators_block = f"\nIndicators:\n{bullet_list}\n"
        
    if v in ("scam",) and c >= 70:
        return (
            f"*HIGH RISK — likely scam*\n\n"
            f"Confidence: {c}%\n"
            f"Reason: {r}\n\n"
            f"{indicators_block}\n"
            f"❗ Do not click links, send money, or share OTPs. "
            f"If this claimed to be from a government agency or bank, "
            f"hang up and call them back on their official number."
        )
    if v in ("scam", "suspicious") and c >= 40:
        return (
            f"*CAUTION — scam indicators detected*\n\n"
            f"Confidence: {c}%\n"
            f"Reason: {r}\n\n"
            f"{indicators_block}\n"
            f"Be wary. Verify the sender through an official channel before "
            f"acting on any requests."
        )
    # likely_safe / unknown / low confidence
    return (
        f"*Likely safe*\n\n"
        f"Confidence: {c}%\n"
        f"Reason: {r}\n\n"
        f"{indicators_block}\n"
        f"Reminder: even safe-looking messages can be scams. "
        f"Never share OTPs or transfer money under pressure."
    )


def format_voice_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_image_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_text_verdict(raw: str) -> str:
    return _format(_parse(raw))
