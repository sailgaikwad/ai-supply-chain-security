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

def calculate_risk(findings: List[Dict[str, Any]]) -> Tuple[int, str, str]:
    """
    Calculate the overall risk score based on findings.
    
    Args:
        findings: A list of finding dictionaries, each containing a 'score_contribution'.
        
    Returns:
        A tuple of (score, classification, explanation).
    """
    total_score = sum(finding.get('score_contribution', 0) for finding in findings)
    
    # Cap score between 0 and 100
    score = min(total_score, 100)
    score = max(score, 0)
    
    classification = classify_score(score)
    
    if score == 0:
        explanation = "No suspicious indicators found. The artifact appears safe based on heuristic rules."
    elif score < 40:
        explanation = "Minor suspicious indicators found. Likely benign but warrants basic review."
    elif score < 60:
        explanation = "Notable suspicious indicators found. Proceed with caution and review findings."
    elif score < 80:
        explanation = "High-risk indicators found. Careful review required before executing or using."
    else:
        explanation = "Critical risk indicators found. Highly likely to be malicious or extremely unsafe."
        
    return score, classification, explanation
