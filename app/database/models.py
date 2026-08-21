from dataclasses import dataclass
from typing import Optional
import datetime

@dataclass
class ScanModel:
    id: Optional[int]
    artifact_id: int
    timestamp: datetime.datetime
    risk_score: int
    classification: str

@dataclass
class FindingModel:
    id: Optional[int]
    scan_id: int
    category: str
    severity: str
    description: str
    evidence: str
    score_contribution: int
