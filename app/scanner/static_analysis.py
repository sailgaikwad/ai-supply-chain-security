import ast
import re
import os
from typing import List, Dict, Any
from app.scanner.artifact import Artifact

class StaticAnalyzer(ast.NodeVisitor):
    def __init__(self, file_path: str = ""):
        self.file_path = file_path
        self.findings = []
        
    def add_finding(self, category: str, severity: str, description: str, evidence: str, score: int):
        self.findings.append({
            "file_path": self.file_path,
            "category": category,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "score_contribution": score
        })

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                func_name = f"{node.func.value.id}.{node.func.attr}"
            else:
                func_name = node.func.attr
                
        if func_name == "eval":
            self.add_finding("Code Execution", "HIGH", "Use of eval() detected. Can be used for arbitrary code execution.", "eval()", 30)
        elif func_name == "exec":
            self.add_finding("Code Execution", "CRITICAL", "Use of exec() detected. Can be used for arbitrary code execution.", "exec()", 40)
        elif func_name == "os.system":
            self.add_finding("Shell Execution", "HIGH", "Use of os.system() detected. Possible command injection risk.", "os.system()", 30)
        elif func_name.startswith("subprocess."):
            self.add_finding("Shell Execution", "MEDIUM", f"Use of {func_name}() detected. Warrants review for safe shell usage.", f"{func_name}()", 20)
        elif func_name.startswith("requests."):
            self.add_finding("Network Operations", "LOW", "Use of requests module detected for making HTTP calls.", f"{func_name}()", 10)
            
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.check_import(alias.name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        if node.module:
            self.check_import(node.module)
        self.generic_visit(node)
        
    def check_import(self, module_name: str):
        if module_name == "socket":
            self.add_finding("Network Operations", "MEDIUM", "Import of socket module. May indicate establishing network connections.", "import socket", 15)
        elif module_name == "requests":
            self.add_finding("Network Operations", "LOW", "Import of requests module.", "import requests", 5)
        elif module_name in ["os", "subprocess"]:
            self.add_finding("System Access", "LOW", f"Import of {module_name} module.", f"import {module_name}", 5)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            val = node.value
            if "/etc/passwd" in val or "/etc/shadow" in val:
                self.add_finding("Suspicious File Access", "CRITICAL", "Access to sensitive system file.", val, 50)
            elif re.search(r"AKIA[0-9A-Z]{16}", val):
                self.add_finding("Hardcoded Secret", "HIGH", "Possible AWS Access Key ID detected.", val, 40)
            elif "PRIVATE KEY-----" in val:
                self.add_finding("Hardcoded Secret", "HIGH", "Hardcoded Private Key detected.", val, 40)
                
        self.generic_visit(node)

def analyze_directory(directory: str) -> List[Dict[str, Any]]:
    """
    Perform static analysis on all Python files within a directory recursively.
    """
    all_findings = []
    
    for root, dirs, files in os.walk(directory):
        for file in files:
            if not file.endswith('.py'):
                continue
                
            abs_path = os.path.join(root, file)
            # Make the path relative to the extracted directory for the finding report
            rel_path = os.path.relpath(abs_path, directory)
            
            try:
                with open(abs_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    
                tree = ast.parse(content)
                analyzer = StaticAnalyzer(file_path=rel_path)
                analyzer.visit(tree)
                all_findings.extend(analyzer.findings)
            except SyntaxError:
                pass
            except UnicodeDecodeError:
                pass
            except Exception:
                pass
                
    return all_findings

def analyze_artifact(artifact: Artifact) -> List[Dict[str, Any]]:
    """
    Deprecated: Provided for backward compatibility if needed.
    """
    # Create a temporary directory structure mimicking the new flow if necessary, 
    # but practically we will now rely on analyze_directory from main.py.
    # To keep this functioning for single files as before:
    findings = []
    try:
        with open(artifact.file_path, "r", encoding="utf-8") as f:
            content = f.read()
        tree = ast.parse(content)
        analyzer = StaticAnalyzer(file_path=artifact.filename)
        analyzer.visit(tree)
        findings.extend(analyzer.findings)
    except Exception:
        pass
    return findings
