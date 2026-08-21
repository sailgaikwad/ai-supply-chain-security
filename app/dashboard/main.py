import streamlit as st
import os
import datetime
import pandas as pd
import plotly.express as px
import sys
import tempfile
import shutil
import subprocess
from dataclasses import asdict

# Ensure the project root is in the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.database.sqlite import init_db, get_metrics, get_scan_history, insert_artifact, insert_scan_result, insert_dependency_findings
from app.scanner.artifact import Artifact
from app.scanner.hashing import calculate_sha256
from app.scanner.static_analysis import analyze_directory
from app.scanner.risk_engine import calculate_risk
from app.scanner.extraction import safe_extract
from app.scanner.dependency_analysis import scan_dependencies
from app.scanner.inventory import inventory_directory

# Check for OSV-Scanner
osv_available = False
try:
    subprocess.run(['osv-scanner', '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    osv_available = True
except FileNotFoundError:
    pass

# Initialize database
init_db()

st.set_page_config(page_title="AI Supply-Chain Security Scanner", layout="wide")

st.title("AI Supply-Chain Security Scanner")
st.markdown("""
Welcome to the **AI Supply-Chain Security Scanner (Version 1.1)**.
This research prototype performs static analysis and dependency scanning on software and AI artifacts to identify heuristic indicators of malicious behavior or supply-chain risks.
""")

if not osv_available:
    st.warning("Dependency vulnerability scanning unavailable: OSV-Scanner is not installed.")

# Dashboard Metrics
st.header("Summary Metrics")
metrics = get_metrics()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Artifacts Scanned", metrics["artifacts_scanned"])
col2.metric("Safe", metrics["safe"])
col3.metric("Suspicious", metrics["suspicious"])
col4.metric("High Risk", metrics["high_risk"])

# Scan New Artifact
st.header("Scan New Artifact")
st.markdown("Upload a file or archive (.zip, .tar, .tgz, .whl) from your local machine to perform a static scan. *Uploaded files will not be executed.*")

uploaded_file = st.file_uploader("Select an artifact", type=None)

if uploaded_file is not None:
    # Save the file to a temporary location to process it
    # Ensure data/uploads directory exists
    uploads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    
    file_path = os.path.join(uploads_dir, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
        
    # Calculate original hash BEFORE extraction
    sha256_hash = calculate_sha256(file_path)
    file_size = os.path.getsize(file_path)
    scan_timestamp = datetime.datetime.now(datetime.timezone.utc)
    _, ext = os.path.splitext(uploaded_file.name)
    artifact_type = ext if ext else "unknown"
    
    if st.button("Start Static Scan"):
        with st.spinner("Analyzing artifact..."):
            
            with tempfile.TemporaryDirectory() as extract_dir:
                
                # 1. Extraction
                is_archive = artifact_type in ['.zip', '.tar', '.gz', '.tgz', '.whl']
                extraction_rejected = False
                rejection_reason = ""
                
                if is_archive:
                    extract_res = safe_extract(file_path, extract_dir)
                    if not extract_res.success:
                        extraction_rejected = True
                        rejection_reason = extract_res.reason
                else:
                    # Single file ingestion
                    dest = os.path.join(extract_dir, uploaded_file.name)
                    shutil.copy2(file_path, dest)
                
                if extraction_rejected:
                    st.error(f"ARCHIVE REJECTED\nReason: {rejection_reason}")
                else:
                    # 2. Inventory
                    inv = inventory_directory(extract_dir)
                    
                    artifact = Artifact(
                        filename=uploaded_file.name,
                        file_path=file_path,
                        size=file_size,
                        timestamp=scan_timestamp,
                        sha256=sha256_hash,
                        artifact_type=artifact_type,
                        inventory=asdict(inv)
                    )
                    
                    artifact_id = insert_artifact(artifact)
                    
                    st.subheader("Artifact Overview")
                    st.text(f"Filename: {artifact.filename}")
                    st.text(f"SHA-256: {artifact.sha256}")
                    st.text(f"Size: {artifact.size} bytes")
                    st.text(f"Type: {artifact.artifact_type}")
                    st.text(f"Timestamp: {artifact.timestamp.isoformat()}")
                    st.text(f"Total Files: {inv.total_files}")
                    st.text(f"Python Files: {inv.python_files}")
                    st.text(f"Dependency Manifests: {inv.dependency_manifests}")
                    
                    # 3. Automatic Analysis Discovery
                    findings = []
                    dep_findings = []
                    analysis_available = False
                    total_deps = 0
                    
                    static_coverage = "skipped"
                    dep_coverage = "skipped"
                    
                    if inv.python_files > 0:
                        findings = analyze_directory(extract_dir)
                        static_coverage = "completed"
                        
                    if inv.dependency_manifests > 0 or inv.lockfiles > 0:
                        analysis_available, total_deps, dep_findings = scan_dependencies(extract_dir)
                        dep_coverage = "completed"
                        
                    st.subheader("Analysis Coverage")
                    st.write(f"**Static Analysis:** {static_coverage}")
                    st.write(f"**Dependency Analysis:** {dep_coverage}")
                    
                    # 4. Calculate Risk
                    score, classification, explanation = calculate_risk(findings, dep_findings)
                    
                    # 5. Store Scan Results
                    scan_id = insert_scan_result(artifact_id, score, classification, findings)
                    if dep_findings:
                        insert_dependency_findings(scan_id, dep_findings)
                    
                    st.success("Scan Complete!")
                    st.subheader("Scan Results")
                    st.write(f"**Risk Score:** {score} / 100")
                    st.write(f"**Classification:** {classification}")
                    st.write(f"**Explanation:** {explanation}")
                    
                    st.info("⚠️ This is a heuristic analysis and does NOT definitively prove that an artifact is malicious.")
                    
                    st.subheader("DEPENDENCY ANALYSIS")
                    st.write(f"**Dependency analysis available:** {'Yes' if analysis_available else 'No'}")
                    if analysis_available:
                        st.write(f"**Dependencies discovered:** {total_deps}")
                        st.write(f"**Vulnerable dependencies count:** {len(dep_findings)}")
                        
                        if dep_findings:
                            st.write("**Dependency Findings Table**")
                            df_dep = pd.DataFrame(dep_findings)
                            cols_dep = ['package_name', 'package_version', 'vulnerability_id', 'aliases', 'severity', 'summary', 'fixed_version', 'source', 'evidence']
                            df_dep = df_dep[[c for c in cols_dep if c in df_dep]]
                            st.dataframe(df_dep)
                            
                            severity_counts = df_dep['severity'].value_counts().reset_index()
                            severity_counts.columns = ['severity', 'count']
                            fig_dep = px.bar(severity_counts, x='severity', y='count', title='Dependency Vulnerabilities by Severity')
                            st.plotly_chart(fig_dep)
                        else:
                            st.write("No vulnerable dependencies found.")
                    
                    st.subheader("STATIC CODE FINDINGS")
                    if findings:
                        df_findings = pd.DataFrame(findings)
                        # Reorder columns to show file_path clearly
                        cols = ['file_path', 'category', 'severity', 'description', 'evidence', 'score_contribution']
                        df_findings = df_findings[[c for c in cols if c in df_findings]]
                        st.dataframe(df_findings)
                        
                        fig = px.pie(df_findings, values='score_contribution', names='category', title='Risk Score Breakdown by Category')
                        st.plotly_chart(fig)
                    else:
                        st.write("No suspicious indicators found in static analysis.")

st.header("Scan History")
history = get_scan_history()
if history:
    df_history = pd.DataFrame(history)
    st.dataframe(df_history)
else:
    st.write("No scans completed yet.")
