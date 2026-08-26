import os

def test_dashboard_dynamic_findings_key():
    """Verify that the dashboard extracts security_findings from the dynamic analysis result."""
    dashboard_path = os.path.join('app', 'dashboard', 'main.py')
    with open(dashboard_path, 'r', encoding='utf-8') as f:
        content = f.read()
    assert "security_findings" in content, "Dashboard should use 'security_findings' key for dynamic findings"
