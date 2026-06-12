import json
import logging
import re
from typing import Any, Dict, List

from telegram import Update
from telegram.ext import ContextTypes

from services.reka_client import scan_text, scan_text_core
from services.utils.formatter import format_text_verdict

log = logging.getLogger(__name__)

URL_PATTERN = re.compile(
    r"https?://(?:www\.)?[^\s/$.?#].[^\s]*|www\.[^\s/$.?#].[^\s]*"
)


def _extract_urls(text: str) -> List[str]:
    """Return a list of unique URLs found in the text."""
    return list(dict.fromkeys(URL_PATTERN.findall(text)))


def _parse_reka_response_new(raw: str) -> Dict[str, Any]:
    """
    Parse Reka response expecting new schema.
    If parsing fails, return a safe default.
    """
    try:
        data = json.loads(raw)
        # Ensure expected keys exist (new schema)
        data.setdefault("verdict", "SAFE")
        data.setdefault("confidence_score", 0)
        data.setdefault("analysis_summary", "")
        data.setdefault("forensic_indicators", {
            "linguistic_flags": [],
            "visual_anomalies": [],
            "behavioral_contradictions": []
        })
        data.setdefault("extracted_entities", {
            "impersonated_target": None,
            "scammer_identifiers": [],
            "malicious_urls": []
        })
        data.setdefault("recommended_action", "FLAG_FOR_HUMAN_REVIEW")
        return data
    except json.JSONDecodeError:
        # Fallback to old schema parsing
        try:
            data = json.loads(raw)
            # map old to new
            verdict_map = {"scam": "HIGH_RISK", "suspicious": "SUSPICIOUS", "safe": "SAFE"}
            old_verdict = data.get("verdict", "safe").lower()
            new_verdict = verdict_map.get(old_verdict, "SAFE")
            confidence = int(data.get("confidence", 0) * 100)
            reason = data.get("reason", "")
            indicators = data.get("indicators", [])
            return {
                "verdict": new_verdict,
                "confidence_score": confidence,
                "analysis_summary": reason,
                "forensic_indicators": {
                    "linguistic_flags": indicators,
                    "visual_anomalies": [],
                    "behavioral_contradictions": []
                },
                "extracted_entities": {
                    "impersonated_target": None,
                    "scammer_identifiers": [],
                    "malicious_urls": []
                },
                "recommended_action": "FLAG_FOR_HUMAN_REVIEW"
            }
        except Exception:
            log.warning("Failed to parse Reka response: %s", raw[:200])
            return {
                "verdict": "SAFE",
                "confidence_score": 0,
                "analysis_summary": raw.strip(),
                "forensic_indicators": {
                    "linguistic_flags": [],
                    "visual_anomalies": [],
                    "behavioral_contradictions": []
                },
                "extracted_entities": {
                    "impersonated_target": None,
                    "scammer_identifiers": [],
                    "malicious_urls": []
                },
                "recommended_action": "FLAG_FOR_HUMAN_REVIEW"
            }


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message
    text = msg.text

    status = await msg.reply_text("Analysing text — please wait…")

    try:
        urls = _extract_urls(text)
        # Flash analysis on text
        raw_flash = await scan_text(text)
        flash_parsed = _parse_reka_response_new(raw_flash)
        conf = float(flash_parsed.get("confidence_score", 0))
        needs_core = 30 <= conf <= 70  # ambiguous range & potential false positives

        # Core analysis on text if ambiguous
        core_parsed = None
        if needs_core:
            log.info(
                "Flash confidence %.2f triggers core analysis for text",
                conf,
            )
            raw_core = await scan_text_core(text)
            core_parsed = _parse_reka_response_new(raw_core)

        # Link analysis: if URLs present and flash ambiguous, run core on each URL
        link_results: List[Dict[str, Any]] = []
        if urls and needs_core:
            log.info(
                "Flash confidence %.2f triggers core analysis for %d URL(s)",
                conf,
                len(urls),
            )
            for url in urls:
                try:
                    raw_link = await scan_text_core(url)
                    link_results.append(_parse_reka_response_new(raw_link))
                except Exception as e:  # pragma: no cover - network errors
                    log.exception("Core analysis failed for URL %s", url)
                    link_results.append(
                        {
                            "verdict": "SAFE",
                            "confidence_score": 0,
                            "analysis_summary": f"Core analysis error: {e}",
                            "forensic_indicators": {
                                "linguistic_flags": [],
                                "visual_anomalies": [],
                                "behavioral_contradictions": []
                            },
                            "extracted_entities": {
                                "impersonated_target": None,
                                "scammer_identifiers": [],
                                "malicious_urls": []
                            },
                            "recommended_action": "FLAG_FOR_HUMAN_REVIEW"
                        }
                    )

        # Combine verdicts: choose highest risk among flash text, core text (if any), and link cores
        def risk_level(res: Dict[str, Any]) -> int:
            v = res.get("verdict", "SAFE").upper()
            return {"SAFE": 0, "SUSPICIOUS": 1, "HIGH_RISK": 2}.get(v, 0)

        candidates = [flash_parsed]
        if core_parsed is not None:
            candidates.append(core_parsed)
        candidates.extend(link_results)
        final_res = max(candidates, key=risk_level)

        # Build a combined raw JSON for formatter (new schema)
        combined = {
            "verdict": final_res.get("verdict"),
            "confidence_score": final_res.get("confidence_score"),
            "analysis_summary": final_res.get("analysis_summary"),
            "forensic_indicators": final_res.get("forensic_indicators"),
            "extracted_entities": final_res.get("extracted_entities"),
            "recommended_action": final_res.get("recommended_action"),
            # Debug info
            "flash_verdict": flash_parsed.get("verdict"),
            "flash_confidence": flash_parsed.get("confidence_score"),
            "has_core": core_parsed is not None,
            "urls_checked": urls,
            "link_count": len(link_results)
        }
        import json as _json
        final_raw = _json.dumps(combined, ensure_ascii=False)
        await status.edit_text(format_text_verdict(final_raw))

    except Exception as e:
        log.exception("text handler failed")
        await status.edit_text(
            f"Sorry, something went wrong analysing that message.\n\n"
            f"Error: `{type(e).__name__}: {e}`"
        )
