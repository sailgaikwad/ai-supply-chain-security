import os
import tempfile
import json
from unittest.mock import patch, MagicMock
from app.sandbox.sandbox_dispatcher import dispatch_artifact

def test_dispatch_invalid_file():
    result = dispatch_artifact("/non/existent/file.zip")
    assert result["success"] is False
    assert "Artifact does not exist" in result["error"]

def test_dispatch_directory():
    with tempfile.TemporaryDirectory() as temp_dir:
        result = dispatch_artifact(temp_dir)
        assert result["success"] is False
        assert "Artifact is not a regular file" in result["error"]

@patch('app.sandbox.sandbox_dispatcher.check_connectivity')
def test_dispatch_no_connectivity(mock_check):
    mock_check.return_value = False
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        temp_path = f.name
        
    try:
        result = dispatch_artifact(temp_path)
        assert result["success"] is False
        assert "is unreachable" in result["error"]
    finally:
        os.unlink(temp_path)

@patch('app.sandbox.sandbox_dispatcher.check_connectivity')
@patch('app.sandbox.sandbox_dispatcher.subprocess.run')
def test_dispatch_scp_failure(mock_run, mock_check):
    mock_check.return_value = True
    
    # Mock SCP failing
    mock_res = MagicMock()
    mock_res.returncode = 1
    mock_res.stderr = "Permission denied"
    mock_run.return_value = mock_res
    
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        temp_path = f.name
        
    try:
        result = dispatch_artifact(temp_path)
        assert result["success"] is False
        assert "Failed to SCP" in result["error"]
    finally:
        os.unlink(temp_path)

@patch('app.sandbox.sandbox_dispatcher.check_connectivity')
@patch('app.sandbox.sandbox_dispatcher.subprocess.run')
@patch('app.sandbox.sandbox_dispatcher.open', new_callable=MagicMock, create=True)
def test_dispatch_success(mock_open, mock_run, mock_check):
    mock_check.return_value = True
    
    # Mock all subprocess calls returning success
    mock_res = MagicMock()
    mock_res.returncode = 0
    # Simulate the orchestrator printing the JOB_ID
    mock_res.stdout = "Job       : 20260826_091951_behavior-test\nResults   : /home/researcher/ai-lab/jobs/20260826_091951_behavior-test/results\n"
    mock_run.return_value = mock_res
    
    # Mock the retrieved JSON payload
    mock_file = MagicMock()
    mock_file.__enter__.return_value.read.return_value = json.dumps({
        "risk": {
            "score": 25,
            "severity": "MEDIUM"
        },
        "findings": ["network_communication"]
    })
    mock_open.return_value = mock_file

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"test data")
        temp_path = f.name

    try:
        result = dispatch_artifact(temp_path)
        assert result["success"] is True
        assert result["dynamic_score"] == 25
        assert result["dynamic_severity"] == "MEDIUM"
        assert result["analysis"]["findings"] == ["network_communication"]
        assert result["job_id"] == "20260826_091951_behavior-test"
        
        # Verify the SCP pull command was constructed correctly
        # The SCP pull should be the 3rd subprocess.run call (mkdir, scp push, ssh exec, scp pull)
        # Wait, there are 4 calls total. The last call is the SCP pull.
        scp_pull_call = mock_run.call_args_list[-1]
        scp_cmd_args = scp_pull_call[0][0]
        remote_path_arg = scp_cmd_args[-2] # e.g. "researcher@10.10.10.20:/home/researcher/ai-lab/jobs/20260826_091951_behavior-test/results/analysis_v3.json"
        
        assert "20260826_091951_behavior-test" in remote_path_arg
        assert "/results/analysis_v3.json" in remote_path_arg
        
    finally:
        os.unlink(temp_path)
