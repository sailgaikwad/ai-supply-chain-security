import os
import sys
import subprocess
import json
import uuid
import datetime
import logging

# Ensure the project root is in the Python path if run from CLI
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.scanner.hashing import calculate_sha256

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

SANDBOX_IP = "10.10.10.20"
SANDBOX_USER = "researcher"
REMOTE_INCOMING_DIR = "/home/researcher/ai-lab/incoming/"
REMOTE_ORCHESTRATOR = "/home/researcher/ai-lab/orchestrator/orchestrator_v1.py"
REMOTE_RESULT_FILE = "analysis_v3.json"
SSH_OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]

def check_connectivity() -> bool:
    """Checks if the sandbox IP is reachable using ping."""
    try:
        # Cross-platform ping check (-n for Windows, -c for Linux)
        param = '-n' if sys.platform.startswith('win') else '-c'
        cmd = ["ping", param, "1", "-w", "2" if sys.platform.startswith('win') else "2", SANDBOX_IP]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
        return result.returncode == 0
    except Exception as e:
        logger.error(f"Failed to execute ping: {e}")
        return False

def dispatch_artifact(artifact_path: str) -> dict:
    """
    Submits an artifact to the isolated Ubuntu sandbox via SSH/SCP.
    Returns a structured dictionary with the dynamic analysis results.
    """
    job_id = str(uuid.uuid4())
    base_result = {
        "success": False,
        "job_id": job_id,
        "artifact": os.path.basename(artifact_path) if artifact_path else "",
        "sha256": None,
        "dynamic_score": 0,
        "dynamic_severity": "UNKNOWN",
        "analysis": {},
        "result_path": None,
        "error": None
    }
    
    # 1. Validate artifact exists
    if not artifact_path or not os.path.exists(artifact_path):
        base_result["error"] = "Artifact does not exist."
        return base_result
        
    if not os.path.isfile(artifact_path):
        base_result["error"] = "Artifact is not a regular file."
        return base_result
        
    # 2. Calculate SHA-256
    try:
        base_result["sha256"] = calculate_sha256(artifact_path)
    except Exception as e:
        base_result["error"] = f"Failed to hash artifact: {e}"
        return base_result
        
    # 3. Verify connectivity
    if not check_connectivity():
        base_result["error"] = f"Sandbox VM at {SANDBOX_IP} is unreachable."
        return base_result
        
    remote_target = f"{SANDBOX_USER}@{SANDBOX_IP}"
    filename = os.path.basename(artifact_path)
    remote_artifact_path = f"{REMOTE_INCOMING_DIR}{filename}"
    remote_json_path = f"{REMOTE_INCOMING_DIR}{REMOTE_RESULT_FILE}"
    
    try:
        # Create remote directory (just in case) and remove any old analysis_v3.json
        # Also clean up any potential leftover files for this run
        ssh_cmd = ["ssh"] + SSH_OPTIONS + [remote_target, f"mkdir -p {REMOTE_INCOMING_DIR} && rm -f {remote_json_path}"]
        subprocess.run(ssh_cmd, capture_output=True, text=True, check=False)
        
        # 4. Transfer the artifact via SCP
        scp_cmd = ["scp"] + SSH_OPTIONS + [artifact_path, f"{remote_target}:{remote_artifact_path}"]
        scp_res = subprocess.run(scp_cmd, capture_output=True, text=True, check=False)
        if scp_res.returncode != 0:
            base_result["error"] = f"Failed to SCP artifact to sandbox: {scp_res.stderr.strip()}"
            return base_result
            
        # 5 & 6 & 7. Execute Orchestrator via SSH
        exec_cmd = ["ssh"] + SSH_OPTIONS + [remote_target, "python3", REMOTE_ORCHESTRATOR, remote_artifact_path]
        exec_res = subprocess.run(exec_cmd, capture_output=True, text=True, check=False)
        if exec_res.returncode != 0:
            # We don't necessarily abort if exit code isn't 0, but it might indicate orchestrator failure.
            # We'll rely on the JSON existence as the ultimate success check, but log the error.
            logger.warning(f"Orchestrator returned non-zero exit code: {exec_res.stderr.strip()}")
            
        # Extract JOB_ID from orchestrator output
        if exec_res.stdout.strip():
            for line in exec_res.stdout.split('\n'):
                line = line.strip()
                if line.startswith("Job") and ":" in line:
                    # Parse 'Job       : 20260826_091951_behavior-test'
                    job_id = line.split(":", 1)[1].strip()
                    base_result["job_id"] = job_id
                    break
                
        # Construct the remote JSON path using the actual JOB_ID
        remote_json_path = f"/home/researcher/ai-lab/jobs/{job_id}/results/analysis_v3.json"
            
        # 8 & 9. Retrieve JSON result back to Kali
        # Prepare local storage path
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        sandbox_results_dir = os.path.join(base_dir, "data", "sandbox_results")
        os.makedirs(sandbox_results_dir, exist_ok=True)
        
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        local_result_name = f"dynamic_{job_id}_{timestamp}.json"
        local_result_path = os.path.join(sandbox_results_dir, local_result_name)
        
        scp_pull_cmd = ["scp"] + SSH_OPTIONS + [f"{remote_target}:{remote_json_path}", local_result_path]
        scp_pull_res = subprocess.run(scp_pull_cmd, capture_output=True, text=True, check=False)
        if scp_pull_res.returncode != 0:
            base_result["error"] = f"Failed to retrieve JSON from sandbox: {scp_pull_res.stderr.strip()}"
            return base_result
            
        # 10. Store and parse the dynamic result
        with open(local_result_path, 'r', encoding='utf-8') as f:
            analysis_data = json.load(f)
            
        base_result["success"] = True
        base_result["result_path"] = local_result_path
        base_result["analysis"] = analysis_data
        
        # Safely extract score and severity from JSON
        base_result["dynamic_score"] = analysis_data.get("dynamic_score", 0)
        base_result["dynamic_severity"] = analysis_data.get("severity", "UNKNOWN")
        
        return base_result
        
    except json.JSONDecodeError as e:
        base_result["error"] = f"Failed to parse analysis_v3.json: {e}"
        return base_result
    except Exception as e:
        base_result["error"] = f"Unexpected error during dynamic dispatch: {e}"
        return base_result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sandbox_dispatcher.py <artifact_path>")
        sys.exit(1)
        
    path = sys.argv[1]
    print(f"Dispatching artifact {path} to Sandbox {SANDBOX_IP}...")
    result = dispatch_artifact(path)
    print(json.dumps(result, indent=2))
