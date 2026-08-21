import os
import subprocess
import json
import re
from typing import List, Dict, Any, Tuple

SUPPORTED_MANIFESTS = [
    "requirements.txt",
    "requirements-dev.txt",
    "Pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "uv.lock",
    "pylock.toml"
]

class UnionFind:
    def __init__(self):
        self.parent = {}
    def find(self, item):
        if self.parent.setdefault(item, item) != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]
    def union(self, a, b):
        root_a = self.find(a)
        root_b = self.find(b)
        if root_a != root_b:
            self.parent[root_a] = root_b

def deduplicate_vulnerabilities(raw_findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    # Step 1: Group by package and version
    groups = {}
    for finding in raw_findings:
        key = (finding['package_name'], finding['package_version'])
        groups.setdefault(key, []).append(finding)
        
    deduped = []
    
    for key, findings in groups.items():
        uf = UnionFind()
        
        # Link all IDs for each finding
        for finding in findings:
            all_ids = set(finding.get('aliases', []))
            all_ids.add(finding['vulnerability_id'])
            all_ids_list = list(all_ids)
            if not all_ids_list:
                continue
            first_id = all_ids_list[0]
            for other_id in all_ids_list[1:]:
                uf.union(first_id, other_id)
                
        # Group findings by root
        root_to_findings = {}
        for finding in findings:
            v_id = finding['vulnerability_id']
            root = uf.find(v_id)
            root_to_findings.setdefault(root, []).append(finding)
            
        # For each group, pick one canonical finding and merge aliases
        for root, group in root_to_findings.items():
            # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW > UNKNOWN)
            sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
            group.sort(key=lambda x: sev_rank.get(x['severity'], 0), reverse=True)
            
            canonical = group[0]
            
            # Gather all aliases from the group
            all_aliases = set()
            for f in group:
                all_aliases.add(f['vulnerability_id'])
                for a in f.get('aliases', []):
                    all_aliases.add(a)
                    
            # Remove canonical ID from aliases list
            if canonical['vulnerability_id'] in all_aliases:
                all_aliases.remove(canonical['vulnerability_id'])
                
            canonical['aliases'] = sorted(list(all_aliases))
            deduped.append(canonical)
            
    return deduped

def find_manifests(directory: str) -> List[str]:
    """Find supported dependency manifests in a directory."""
    manifests = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file in SUPPORTED_MANIFESTS:
                manifests.append(os.path.join(root, file))
    return manifests

def extract_dependencies(manifest_path: str) -> int:
    """
    Very basic parsing to extract the number of dependencies.
    This is mostly for the dashboard metric.
    """
    count = 0
    filename = os.path.basename(manifest_path)
    
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        if filename in ["requirements.txt", "requirements-dev.txt"]:
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('-'):
                    count += 1
        elif filename in ["Pipfile.lock", "poetry.lock", "uv.lock", "pylock.toml", "pyproject.toml"]:
            # Simple heuristic for TOML/JSON-like structures
            for line in lines:
                if "==" in line or "version =" in line or '"version":' in line:
                    count += 1
    except Exception:
        pass
        
    return count

def run_osv_scanner(manifest_path: str) -> List[Dict[str, Any]]:
    """
    Run OSV-Scanner securely using subprocess and parse the JSON output.
    Returns a list of structured vulnerability findings.
    """
    findings = []
    
    try:
        # Run osv-scanner as a controlled subprocess with a timeout
        # Try modern OSV-Scanner v2.x / v1.9+ syntax first
        cmd = ['osv-scanner', 'scan', '--format', 'json', '--lockfile', manifest_path]
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
            timeout=30
        )
        
        # If stdout is empty, it might be an older version (e.g. v1.4) that doesn't support 'scan' subcommand
        if not result.stdout and result.returncode != 0:
            cmd = ['osv-scanner', '--json', '-L', manifest_path]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                check=False,
                timeout=30
            )
            
        if not result.stdout:
            return findings
            
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return findings
            
        results = data.get('results', [])
        for res in results:
            packages = res.get('packages', [])
            for pkg in packages:
                pkg_info = pkg.get('package', {})
                pkg_name = pkg_info.get('name', 'Unknown')
                pkg_version = pkg_info.get('version', 'Unknown')
                
                # Extract groups for max_severity in v2.x JSON
                groups = pkg.get('groups', [])
                id_to_severity_score = {}
                for g in groups:
                    max_sev = g.get('max_severity')
                    if max_sev:
                        try:
                            score = float(max_sev)
                            for v_id in g.get('ids', []):
                                id_to_severity_score[v_id] = score
                        except ValueError:
                            pass
                
                vulns = pkg.get('vulnerabilities', [])
                for vuln in vulns:
                    vuln_id = vuln.get('id', 'Unknown')
                    aliases = vuln.get('aliases', [])
                    summary = vuln.get('summary', 'No summary provided')
                    
                    # Extract severity
                    severity = "UNKNOWN"
                    
                    # 1. Try to get severity from database_specific (e.g. GHSA)
                    db_specific = vuln.get('database_specific', {})
                    if 'severity' in db_specific:
                        severity = db_specific['severity'].upper()
                    
                    # 2. Try to get it from CVSS score via groups (OSV-Scanner v2.x feature)
                    if severity == "UNKNOWN" and vuln_id in id_to_severity_score:
                        score = id_to_severity_score[vuln_id]
                        if score >= 9.0: severity = "CRITICAL"
                        elif score >= 7.0: severity = "HIGH"
                        elif score >= 4.0: severity = "MEDIUM"
                        elif score > 0.0: severity = "LOW"
                    
                    # 3. Default fallback
                    if severity == "UNKNOWN":
                        severity = "HIGH"
                        
                    findings.append({
                        "package_name": pkg_name,
                        "package_version": pkg_version,
                        "vulnerability_id": vuln_id,
                        "aliases": aliases,
                        "severity": severity,
                        "summary": summary,
                        "fixed_version": "",
                        "source": "OSV-Scanner",
                        "evidence": f"Found in {os.path.basename(manifest_path)}"
                    })
                    
    except FileNotFoundError:
        # OSV-Scanner is not installed
        pass
    except Exception:
        # Broad catch for unexpected subprocess errors
        pass
        
    return findings

def scan_dependencies(extract_dir: str) -> Tuple[bool, int, List[Dict[str, Any]]]:
    """
    Scans a directory for dependencies across all manifests.
    Returns (analysis_available, total_dependencies, findings)
    """
    manifests = find_manifests(extract_dir)
    
    if not manifests:
        return False, 0, []
        
    total_deps = 0
    raw_findings = []
    
    for manifest in manifests:
        total_deps += extract_dependencies(manifest)
        findings = run_osv_scanner(manifest)
        raw_findings.extend(findings)
        
    # Deduplicate findings across multiple manifests and aliases
    deduped_findings = deduplicate_vulnerabilities(raw_findings)
        
    return True, total_deps, deduped_findings
