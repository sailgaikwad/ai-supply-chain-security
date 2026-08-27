from typing import List, Dict, Any, Tuple, Optional
import logging

logger = logging.getLogger(__name__)

def classify_score(score: int) -> str:
    """Classify the risk score into a category based on predefined thresholds.

    Project‑defined thresholds (not NIST mandated):
        0‑19   SAFE
        20‑39  LOW
        40‑59  MEDIUM
        60‑79  HIGH
        80‑100 CRITICAL
    """
    if score < 20:
        return "SAFE"
    elif score < 40:
        return "LOW"
    elif score < 60:
        return "MEDIUM"
    elif score < 80:
        return "HIGH"
    else:
        return "CRITICAL"

# --- Likelihood contribution mappings ---
_STATIC_LIKELIHOOD_MAP = {
    "shell_execution": 8,
    "arbitrary_code_execution": 12,
    "network_operation": 6,
    "system_access": 7,
    "persistence": 9,
    "credential_access": 10,
    "obfuscation": 5,
    "suspicious_pattern": 4,
}

_DYNAMIC_LIKELIHOOD_SEVERITY = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 60,
}

_IMPACT_SEVERITY_MAP = {
    "LOW": 20,
    "MEDIUM": 40,
    "HIGH": 70,
    "CRITICAL": 90,
}

def _cvss_to_likelihood(cvss_score: float) -> int:
    """Map a CVSS base score (0‑10) to a 0‑100 likelihood contribution."""
    return int(min(max(cvss_score, 0.0), 10.0) * 10)

def _confidence_from_evidence(static_cnt: int, dynamic_available: bool, dynamic_cnt: int, dep_cnt: int) -> str:
    """Derive a confidence level from the breadth of evidence sources.

    LOW: only one source (static OR dynamic OR dependency)
    MEDIUM: two sources
    HIGH: three or more sources
    """
    sources = sum([static_cnt > 0, dynamic_available, dep_cnt > 0])
    if sources == 1:
        return "LOW"
    elif sources == 2:
        return "MEDIUM"
    else:
        return "HIGH"

def calculate_unified_risk(
    static_findings: List[Dict[str, Any]],
    dep_findings: List[Dict[str, Any]],
    dynamic_result: Optional[Dict[str, Any]] = None,
    artifact_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Calculate a unified risk assessment using a likelihood‑impact model.

    Returns a dictionary with the following keys:
        likelihood_score (0‑100)
        impact_score (0‑100)
        risk_score (0‑100)
        classification (project‑defined)
        confidence (LOW/MEDIUM/HIGH)
        explanation (human‑readable summary)
        evidence_summary (raw evidence collections)
        component_assessment (break‑down per component)
    """
    # -------------------------------------------------------------------
    # Likelihood aggregation
    # -------------------------------------------------------------------
    likelihood_score = 0
    for f in static_findings:
        cat = f.get("category", "").lower()
        likelihood_score += _STATIC_LIKELIHOOD_MAP.get(cat, 3)

    for df in dep_findings:
        cvss = df.get("cvss_base_score")
        if cvss is not None:
            try:
                likelihood_score += _cvss_to_likelihood(float(cvss))
                continue
            except Exception:
                pass
        sev = df.get("severity", "").upper()
        if sev == "CRITICAL":
            likelihood_score += 30
        elif sev == "HIGH":
            likelihood_score += 20
        elif sev == "MEDIUM":
            likelihood_score += 10
        elif sev == "LOW":
            likelihood_score += 5
        else:
            likelihood_score += 5

    dynamic_available = False
    dynamic_findings_cnt = 0
    if dynamic_result:
        dynamic_available = dynamic_result.get("success", False)
        if dynamic_available:
            sec_findings = dynamic_result.get("analysis", {}).get("security_findings", [])
            if isinstance(sec_findings, list):
                dynamic_findings_cnt = len(sec_findings)
                for f in sec_findings:
                    sev = f.get("severity", "").upper()
                    likelihood_score += _DYNAMIC_LIKELIHOOD_SEVERITY.get(sev, 10)
    likelihood_score = min(max(likelihood_score, 0), 100)

    # -------------------------------------------------------------------
    # Impact aggregation
    # -------------------------------------------------------------------
    impact_score = 0
    for f in static_findings:
        sev = f.get("severity", "").upper()
        impact_score += _IMPACT_SEVERITY_MAP.get(sev, 10)

    for df in dep_findings:
        cvss = df.get("cvss_base_score")
        if cvss is not None:
            try:
                impact_score += int(float(cvss) * 10)
                continue
            except Exception:
                pass
        sev = df.get("severity", "").upper()
        impact_score += _IMPACT_SEVERITY_MAP.get(sev, 10)

    if dynamic_available:
        dyn_sev = dynamic_result.get("dynamic_severity", "UNKNOWN").upper()
        impact_score += _IMPACT_SEVERITY_MAP.get(dyn_sev, 0)
    impact_score = min(max(impact_score, 0), 100)

    # -------------------------------------------------------------------
    # Combined risk score (project‑defined formula)
    # -------------------------------------------------------------------
    risk_score = int((likelihood_score * impact_score) / 100)
    risk_score = min(max(risk_score, 0), 100)
    classification = classify_score(risk_score)

    # -------------------------------------------------------------------
    # Confidence heuristic
    # -------------------------------------------------------------------
    confidence = _confidence_from_evidence(
        static_cnt=len(static_findings),
        dynamic_available=dynamic_available,
        dynamic_cnt=dynamic_findings_cnt,
        dep_cnt=len(dep_findings),
    )

    # -------------------------------------------------------------------
    # Explanation & summary
    # -------------------------------------------------------------------
    parts = []
    if static_findings:
        parts.append(f"Static analysis yielded {len(static_findings)} finding(s).")
    if dep_findings:
        parts.append(f"Dependency scan identified {len(dep_findings)} vulnerable package(s).")
    if dynamic_available:
        if dynamic_findings_cnt:
            parts.append(f"Dynamic sandbox observed {dynamic_findings_cnt} suspicious behaviour(s).")
        else:
            parts.append("Dynamic sandbox executed without observable suspicious behavior.")
    else:
        parts.append("Dynamic analysis was unavailable or failed.")
    explanation = " ".join(parts) if parts else "No evidence collected."

    evidence_summary = {
        "static_findings": static_findings,
        "dependency_findings": dep_findings,
        "dynamic_findings": (
            dynamic_result.get("analysis", {}).get("security_findings", []) if dynamic_result else []
        ),
    }

    component_assessment = {
        "static": {
            "finding_count": len(static_findings),
            "likelihood_contribution": sum(_STATIC_LIKELIHOOD_MAP.get(f.get("category", "").lower(), 3) for f in static_findings),
            "impact_contribution": sum(_IMPACT_SEVERITY_MAP.get(f.get("severity", "").upper(), 10) for f in static_findings),
        },
        "dynamic": {
            "available": dynamic_available,
            "finding_count": dynamic_findings_cnt,
            "likelihood_contribution": sum(
                _DYNAMIC_LIKELIHOOD_SEVERITY.get(f.get("severity", "").upper(), 10) for f in evidence_summary["dynamic_findings"]
            ),
            "impact_contribution": _IMPACT_SEVERITY_MAP.get(dynamic_result.get("dynamic_severity", "UNKNOWN").upper(), 0) if dynamic_available else 0,
        },
        "dependencies": {
            "available": bool(dep_findings),
            "vulnerability_count": len(dep_findings),
            "cvss_information": [df.get("cvss_base_score") for df in dep_findings if df.get("cvss_base_score")],
            "likelihood_contribution": sum(
                _cvss_to_likelihood(float(df.get("cvss_base_score"))) if df.get("cvss_base_score") else 0 for df in dep_findings
            ),
            "impact_contribution": sum(_IMPACT_SEVERITY_MAP.get(df.get("severity", "").upper(), 10) for df in dep_findings),
        },
    }

    return {
        "likelihood_score": likelihood_score,
        "impact_score": impact_score,
        "risk_score": risk_score,
        "classification": classification,
        "confidence": confidence,
        "security_findings_present": dynamic_findings_cnt > 0,
        "vulnerability_risk": component_assessment["static"]["likelihood_contribution"] + component_assessment["dependencies"]["likelihood_contribution"],
        "behavioral_risk": component_assessment["dynamic"]["likelihood_contribution"],
        "explanation": explanation,
        "evidence_summary": evidence_summary,
        "component_assessment": component_assessment,
    }

# Legacy wrapper – retains original API used by existing code and tests.
def calculate_risk(findings: List[Dict[str, Any]], dep_findings: List[Dict[str, Any]] = None) -> Tuple[int, str, str]:
    """Legacy risk calculation used by tests.

    Calculates risk score by summing static finding score contributions and adding a
    contribution based on dependency severity. Severity contribution mapping:
        CRITICAL and HIGH -> 30 points
        MEDIUM -> 10 points
        LOW -> 5 points
    """
    if dep_findings is None:
        dep_findings = []
    static_score = sum(f.get("score_contribution", 0) for f in findings)
    severity_map = {"CRITICAL": 30, "HIGH": 30, "MEDIUM": 10, "LOW": 5}
    dep_score = sum(severity_map.get(d.get("severity", "").upper(), 0) for d in dep_findings)
    total_score = static_score + dep_score
    total_score = min(max(total_score, 0), 100)
    classification = classify_score(total_score)
    explanation = f"Static score {static_score} + dependency score {dep_score}"
    return total_score, classification, explanation
