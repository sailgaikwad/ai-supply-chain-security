import datetime
from dataclasses import dataclass

@dataclass
class Artifact:
    """
    Represents an uploaded software or AI artifact for analysis.
    """
    filename: str
    file_path: str
    size: int
    timestamp: datetime.datetime
    sha256: str
    artifact_type: str
    inventory: dict = None
