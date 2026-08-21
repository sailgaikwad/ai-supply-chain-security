import os
import tempfile
import json
from unittest.mock import patch, MagicMock
from app.scanner.dependency_analysis import extract_dependencies, run_osv_scanner, scan_dependencies

def test_extract_dependencies():
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = os.path.join(temp_dir, "requirements.txt")
        with open(temp_path, 'w', encoding='utf-8') as f:
            f.write("requests==2.25.0\nflask\n# comment\n-e .\n")
            
        count = extract_dependencies(temp_path)
        assert count == 2 # requests and flask

@patch('app.scanner.dependency_analysis.subprocess.run')
def test_run_osv_scanner(mock_run):
    mock_result = MagicMock()
    mock_result.stdout = json.dumps({
        "results": [{
            "packages": [{
                "package": {"name": "requests", "version": "2.25.0"},
                "vulnerabilities": [{
                    "id": "CVE-2021-X",
                    "summary": "Mock vulnerability",
                    "database_specific": {"severity": "HIGH"}
                }]
            }]
        }]
    })
    mock_run.return_value = mock_result
    
    findings = run_osv_scanner("mock_reqs.txt")
    
    assert len(findings) == 1
    assert findings[0]["package_name"] == "requests"
    assert findings[0]["vulnerability_id"] == "CVE-2021-X"
    assert findings[0]["severity"] == "HIGH"
    
@patch('app.scanner.dependency_analysis.find_manifests')
def test_scan_dependencies_no_manifest(mock_find):
    mock_find.return_value = []
    
    available, count, findings = scan_dependencies("/tmp/mock")
    
    assert available is False
    assert count == 0
    assert len(findings) == 0

@patch('app.scanner.dependency_analysis.subprocess.run')
def test_run_osv_scanner_v2(mock_run):
    mock_result = MagicMock()
    mock_result.stdout = json.dumps({
        "results": [{
            "packages": [{
                "package": {"name": "requests", "version": "2.19.0"},
                "vulnerabilities": [{
                    "id": "PYSEC-2018-28",
                    "summary": "Mock summary",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]
                }],
                "groups": [{
                    "ids": ["PYSEC-2018-28"],
                    "max_severity": "7.5"
                }]
            }]
        }]
    })
    mock_result.returncode = 0
    mock_run.return_value = mock_result
    
    findings = run_osv_scanner("mock_reqs.txt")
    
    assert len(findings) == 1
    assert findings[0]["package_name"] == "requests"
    assert findings[0]["severity"] == "HIGH"

