import sqlite3
import os
import datetime
from typing import List, Dict, Any
from app.scanner.artifact import Artifact

# Ensure data directory exists and define DB path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "research.db")

def get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    return sqlite3.connect(DB_PATH)

def init_db():
    """Initialize SQLite database with required tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        file_path TEXT NOT NULL,
        size INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        sha256 TEXT NOT NULL,
        artifact_type TEXT NOT NULL
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        artifact_id INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        classification TEXT NOT NULL,
        FOREIGN KEY(artifact_id) REFERENCES artifacts(id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence TEXT NOT NULL,
        score_contribution INTEGER NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS dependency_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        package_name TEXT NOT NULL,
        package_version TEXT NOT NULL,
        vulnerability_id TEXT NOT NULL,
        severity TEXT NOT NULL,
        summary TEXT NOT NULL,
        fixed_version TEXT,
        source TEXT NOT NULL,
        evidence TEXT NOT NULL,
        FOREIGN KEY(scan_id) REFERENCES scans(id)
    )
    ''')
    
    conn.commit()
    conn.close()

def insert_artifact(artifact: Artifact) -> int:
    """Insert an artifact into the database and return its ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO artifacts (filename, file_path, size, timestamp, sha256, artifact_type)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (artifact.filename, artifact.file_path, artifact.size, 
          artifact.timestamp.isoformat(), artifact.sha256, artifact.artifact_type))
    artifact_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return artifact_id

def insert_scan_result(artifact_id: int, score: int, classification: str, findings: List[Dict[str, Any]]):
    """Insert the scan result and associated findings."""
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    
    cursor.execute('''
        INSERT INTO scans (artifact_id, timestamp, risk_score, classification)
        VALUES (?, ?, ?, ?)
    ''', (artifact_id, now, score, classification))
    scan_id = cursor.lastrowid
    
    for finding in findings:
        cursor.execute('''
            INSERT INTO findings (scan_id, category, severity, description, evidence, score_contribution)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (scan_id, finding['category'], finding['severity'], 
              finding['description'], finding['evidence'], finding['score_contribution']))
              
    conn.commit()
    conn.close()
    return scan_id

def insert_dependency_findings(scan_id: int, dep_findings: List[Dict[str, Any]]):
    """Insert dependency findings associated with a scan."""
    conn = get_connection()
    cursor = conn.cursor()
    for df in dep_findings:
        cursor.execute('''
            INSERT INTO dependency_findings 
            (scan_id, package_name, package_version, vulnerability_id, severity, summary, fixed_version, source, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (scan_id, df['package_name'], df['package_version'], df['vulnerability_id'],
              df['severity'], df['summary'], df['fixed_version'], df['source'], df['evidence']))
              
    conn.commit()
    conn.close()
    
def get_metrics() -> Dict[str, int]:
    """Retrieve summary metrics for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification = 'SAFE'")
    safe = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification IN ('LOW', 'MEDIUM')")
    suspicious = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE classification IN ('HIGH', 'CRITICAL')")
    high_risk = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        "artifacts_scanned": total_scans,
        "safe": safe,
        "suspicious": suspicious,
        "high_risk": high_risk
    }

def get_scan_history() -> List[Dict[str, Any]]:
    """Retrieve scan history for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT a.filename, s.timestamp, s.risk_score, s.classification
        FROM scans s
        JOIN artifacts a ON s.artifact_id = a.id
        ORDER BY s.timestamp DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    
    return [{"filename": r[0], "timestamp": r[1], "score": r[2], "classification": r[3]} for r in rows]

def get_dependency_findings(scan_id: int) -> List[Dict[str, Any]]:
    """Retrieve dependency findings for a given scan ID."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT package_name, package_version, vulnerability_id, severity, summary, fixed_version, source, evidence
        FROM dependency_findings
        WHERE scan_id = ?
    ''', (scan_id,))
    rows = cursor.fetchall()
    conn.close()
    
    return [{
        "package_name": r[0], 
        "package_version": r[1], 
        "vulnerability_id": r[2], 
        "severity": r[3], 
        "summary": r[4], 
        "fixed_version": r[5], 
        "source": r[6], 
        "evidence": r[7]
    } for r in rows]
