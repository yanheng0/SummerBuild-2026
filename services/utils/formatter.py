def format_verdict(result: dict) -> str:
    verdict = result.get("verdict", "SAFE")
    conf = result.get("confidence_score", 0)
    scam_type = result.get("scam_type", "NONE")
    summary = result.get("analysis_summary", "No details available.")
    action = result.get("recommended_action", "ALLOW")

    emoji = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "HIGH_RISK": "🚨"}.get(verdict, "❓")
    
    lines = [
        f"{emoji} <b>Verdict:</b> {verdict} (confidence {conf}%)",
        f"<b>Scam Type:</b> {scam_type.replace('_', ' ').title()}",
        f"<b>Summary:</b> {summary}",
    ]
    if result.get("indicators_found"):
        indicators = ", ".join(result["indicators_found"])
        lines.append(f"<b>Indicators:</b> {indicators}")

    lines.append(f"<b>Suggested Action:</b> {action.replace('_', ' ').title()}")

    return "\n\n".join(lines)