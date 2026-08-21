from typing import List, Dict, Any, Tuple

def classify_score(score: int) -> str:
    """
    Classify the risk score into a category based on predefined thresholds.
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

def calculate_risk(findings: List[Dict[str, Any]], dep_findings: List[Dict[str, Any]] = None) -> Tuple[int, str, str]:
    """
    Calculate the overall risk score based on static findings and dependency findings.
    
    Args:
        findings: A list of static finding dictionaries, each containing a 'score_contribution'.
        dep_findings: A list of dependency finding dictionaries.
        
    Returns:
        A tuple of (score, classification, explanation).
    """
    if dep_findings is None:
        dep_findings = []
        
    total_score = sum(finding.get('score_contribution', 0) for finding in findings)
    
    # Add dependency risk
    has_critical_dep = False
    has_high_dep = False
    for df in dep_findings:
        sev = df.get('severity', '').upper()
        if sev == 'CRITICAL':
            total_score += 40
            has_critical_dep = True
        elif sev == 'HIGH':
            total_score += 30
            has_high_dep = True
        elif sev == 'MEDIUM':
            total_score += 20
        elif sev == 'LOW':
            total_score += 10
        else:
            total_score += 10 # Default for unknown
    
    # Cap score between 0 and 100
    score = min(total_score, 100)
    score = max(score, 0)
    
    classification = classify_score(score)
    
    # Explanation generation
    if score == 0:
        explanation = "No suspicious indicators or known vulnerabilities found. The artifact appears safe."
    elif score < 40:
        explanation = "Minor suspicious indicators or low-severity vulnerabilities found. Likely benign but warrants basic review."
    elif score < 60:
        explanation = "Notable suspicious indicators or medium-severity vulnerabilities found. Proceed with caution."
    elif score < 80:
        if has_high_dep and not findings:
            explanation = "High-severity known vulnerabilities found in dependencies. Update recommended."
        else:
            explanation = "High-risk indicators found. Careful review required before executing or using."
    else:
        if has_critical_dep and not findings:
            explanation = "Critical-severity known vulnerabilities found in dependencies. Do not use without updating."
        else:
            explanation = "Critical risk indicators found. Highly unsafe to use."
            
    return score, classification, explanation
