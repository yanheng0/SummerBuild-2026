import json
import re

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
        # Normalize fields
        verdict = data.get("verdict", "UNKNOWN").upper()
        confidence = data.get("confidence_score", 0)
        # Ensure confidence is int 0-100
        try:
            confidence = int(confidence)
        except (ValueError, TypeError):
            confidence = 0
        primary_threat = data.get("primary_threat_vector", "NONE").upper()
        analysis_summary = data.get("analysis_summary", "")
        forensic = data.get("forensic_indicators", {})
        extracted = data.get("extracted_entities", {})
        recommended = data.get("recommended_action", "FLAG_FOR_HUMAN_REVIEW").upper()
        return {
            "verdict": verdict,
            "confidence": confidence,
            "primary_threat": primary_threat,
            "analysis_summary": analysis_summary,
            "forensic": forensic,
            "extracted": extracted,
            "recommended": recommended,
            "raw": raw  # keep for fallback
        }
    except (json.JSONDecodeError, AttributeError, ValueError):
        # Fallback to old free-text format parsing if JSON fails
        v_match = re.search(r"VERDICT\s*:\s*(\w+)", raw, re.IGNORECASE)
        c_match = re.search(r"CONFIDENCE\s*:\s*(\d{1,3})", raw, re.IGNORECASE)
        r_match = re.search(r"REASON\s*:\s*(.+)", raw, re.IGNORECASE)

        v = v_match.group(1).upper() if v_match else "UNKNOWN"
        c = int(c_match.group(1)) if c_match else 0
        r = r_match.group(1).strip() if r_match else raw.strip()
        return {
            "verdict": v,
            "confidence": c,
            "primary_threat": "NONE",
            "analysis_summary": r,
            "forensic": {},
            "extracted": {},
            "recommended": "FLAG_FOR_HUMAN_REVIEW",
            "raw": raw
        }

def _format(parsed: dict) -> str:
    v = parsed["verdict"]
    c = parsed["confidence"]
    primary = parsed["primary_threat"]
    summary = parsed["analysis_summary"]
    forensic = parsed["forensic"]
    extracted = parsed["extracted"]
    recommended = parsed["recommended"]

    # Build sections
    lines = []
    # Header based on verdict
    if v == "HIGH_RISK":
        lines.append("*HIGH RISK — likely scam*")
    elif v == "SUSPICIOUS":
        lines.append("*CAUTION — suspicious indicators*")
    else:
        lines.append("*Likely safe*")
    lines.append("")  # blank line

    lines.append(f"Confidence: {c}%")
    if primary != "NONE":
        lines.append(f"Primary threat: {primary.replace('_', ' ').title()}")
    lines.append("")
    if summary:
        lines.append(f"Analysis: {summary}")
        lines.append("")

    # Forensic indicators
    ling = forensic.get("linguistic_flags", [])
    vis = forensic.get("visual_anomalies", [])
    beh = forensic.get("behavioral_contradictions", [])
    if ling or vis or beh:
        lines.append("*Forensic indicators:*")
        if ling:
            lines.append("Linguistic flags:")
            lines.extend(f"• {i}" for i in ling)
        if vis:
            lines.append("Visual anomalies:")
            lines.extend(f"• {i}" for i in vis)
        if beh:
            lines.append("Behavioral contradictions:")
            lines.extend(f"• {i}" for i in beh)
        lines.append("")

    # Extracted entities
    imp = extracted.get("impersonated_target")
    scam_ids = extracted.get("scammer_identifiers", [])
    mal_urls = extracted.get("malicious_urls", [])
    if imp or scam_ids or mal_urls:
        lines.append("*Extracted entities:*")
        if imp:
            lines.append(f"Impersonated target: {imp}")
        if scam_ids:
            lines.append("Scammer identifiers:")
            lines.extend(f"• {i}" for i in scam_ids)
        if mal_urls:
            lines.append("Malicious URLs:")
            lines.extend(f"• {u}" for u in mal_urls)
        lines.append("")

    # Recommended action
    action_map = {
        "BLOCK_AND_REPORT": "🚫 Block and report",
        "FLAG_FOR_HUMAN_REVIEW": "⚠️ Flag for human review",
        "ALLOW": "✅ Allow"
    }
    action_text = action_map.get(recommended, recommended)
    lines.append(f"Recommended action: {action_text}")

    return "\n".join(lines)


def format_voice_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_image_verdict(raw: str) -> str:
    return _format(_parse(raw))


def format_text_verdict(raw: str) -> str:
    return _format(_parse(raw))
