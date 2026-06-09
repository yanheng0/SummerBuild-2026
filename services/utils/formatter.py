"""
Format Reka's free-text reply into a clean Telegram message.

Reka is asked to respond in:
    VERDICT: <scam|suspicious|likely_safe>
    CONFIDENCE: <0-100>
    REASON: <one short sentence>

We parse that and re-emit it with friendly styling + safety advice.
If parsing fails, we just print the raw reply.
"""
import re

_VERDICT_RE = re.compile(r"VERDICT\s*:\s*(\w+)", re.IGNORECASE)
_CONF_RE = re.compile(r"CONFIDENCE\s*:\s*(\d{1,3})", re.IGNORECASE)
_REASON_RE = re.compile(r"REASON\s*:\s*(.+)", re.IGNORECASE)


def _parse(raw: str) -> dict:
    v = (_VERDICT_RE.search(raw).group(1).lower()
         if _VERDICT_RE.search(raw) else "unknown")
    c = int(_CONF_RE.search(raw).group(1)) if _CONF_RE.search(raw) else 0
    r = (_REASON_RE.search(raw).group(1).strip()
         if _REASON_RE.search(raw) else raw.strip())
    return {"verdict": v, "confidence": c, "reason": r}


def _format(parsed: dict) -> str:
    v, c, r = parsed["verdict"], parsed["confidence"], parsed["reason"]
    if v in ("scam",) and c >= 70:
        return (
            f"*HIGH RISK — likely scam*\n\n"
            f"Confidence: {c}%\n"
            f"Reason: {r}\n\n"
            f"❗ Do not click links, send money, or share OTPs. "
            f"If this claimed to be from a government agency or bank, "
            f"hang up and call them back on their official number."
        )
    if v in ("scam", "suspicious") and c >= 40:
        return (
            f"*CAUTION — scam indicators detected*\n\n"
            f"Confidence: {c}%\n"
            f"Reason: {r}\n\n"
            f"Be wary. Verify the sender through an official channel before "
            f"acting on any requests."
        )
    # likely_safe / unknown / low confidence
    return (
        f"*Likely safe*\n\n"
        f"Confidence: {c}%\n"
        f"Reason: {r}\n\n"
        f"Reminder: even safe-looking messages can be scams. "
        f"Never share OTPs or transfer money under pressure."
    )


def format_voice_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_image_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_text_verdict(raw: str) -> str:
    return _format(_parse(raw))
