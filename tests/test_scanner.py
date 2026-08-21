import os
import tempfile
import datetime
from app.scanner.artifact import Artifact
from app.scanner.hashing import calculate_sha256
from app.scanner.risk_engine import calculate_risk, classify_score
from app.scanner.static_analysis import analyze_directory
from app.database.sqlite import init_db, get_metrics

def test_calculate_sha256():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        temp_path = f.name
        
    try:
        hash_val = calculate_sha256(temp_path)
        # sha256 of "test data"
        assert hash_val == "916f0027a575074ce72a331777c3478d6513f786a591bd892da1a577bf2335f9"
    finally:
        os.unlink(temp_path)

def test_risk_classification():
    assert classify_score(10) == "SAFE"
    assert classify_score(30) == "LOW"
    assert classify_score(50) == "MEDIUM"
    assert classify_score(70) == "HIGH"
    assert classify_score(90) == "CRITICAL"

def test_calculate_risk():
    findings = [
        {"score_contribution": 30, "category": "test", "evidence": "1"},
        {"score_contribution": 40, "category": "test", "evidence": "2"}
    ]
    dep_findings = [
        {"severity": "HIGH"}
    ]
    score, classification, explanation = calculate_risk(findings, dep_findings)
    # 30 + 40 + 30 (high) = 100
    assert score == 100
    assert classification == "CRITICAL"

def test_static_analysis():
    with tempfile.TemporaryDirectory() as temp_dir:
        src_dir = os.path.join(temp_dir, "src")
        os.makedirs(src_dir)
        temp_path = os.path.join(src_dir, "test_malicious.py")
        with open(temp_path, "w") as f:
            f.write("import os\n\nos.system('echo test')")
        
        findings = analyze_directory(temp_dir)
        assert len(findings) > 0
        categories = [f['category'] for f in findings]
        assert "System Access" in categories # From import os
        assert "Shell Execution" in categories # From os.system()
        # Verify relative file_path is recorded
        file_paths = [f['file_path'] for f in findings]
        assert os.path.join("src", "test_malicious.py") in file_paths

def test_database():
    init_db()
    metrics = get_metrics()
    assert isinstance(metrics['artifacts_scanned'], int)
