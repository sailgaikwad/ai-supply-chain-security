import streamlit as st
import os
import datetime
import pandas as pd
import plotly.express as px
import sys

# Ensure the project root is in the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from app.database.sqlite import init_db, get_metrics, get_scan_history, insert_artifact, insert_scan_result
from app.scanner.artifact import Artifact
from app.scanner.hashing import calculate_sha256
from app.scanner.static_analysis import analyze_artifact
from app.scanner.risk_engine import calculate_risk

# Initialize database
init_db()

st.set_page_config(page_title="AI Supply-Chain Security Scanner", layout="wide")

st.title("AI Supply-Chain Security Scanner")
st.markdown("""
Welcome to the **AI Supply-Chain Security Scanner (Version 1)**.
This research prototype performs static analysis on software and AI artifacts to identify heuristic indicators of malicious behavior or supply-chain risks.
""")

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
st.markdown("Upload a file from your local machine to perform a static scan. *Uploaded files will not be executed.*")

uploaded_file = st.file_uploader("Select an artifact", type=None)

if uploaded_file is not None:
    # Save the file to a temporary location to process it
    # Ensure data/uploads directory exists
    uploads_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "uploads")
    os.makedirs(uploads_dir, exist_ok=True)
    
    file_path = os.path.join(uploads_dir, uploaded_file.name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.getbuffer())
        
    st.subheader("Artifact Information")
    
    # Calculate hash and other details
    sha256_hash = calculate_sha256(file_path)
    file_size = os.path.getsize(file_path)
    scan_timestamp = datetime.datetime.now(datetime.timezone.utc)
    _, ext = os.path.splitext(uploaded_file.name)
    artifact_type = ext if ext else "unknown"
    
    artifact = Artifact(
        filename=uploaded_file.name,
        file_path=file_path,
        size=file_size,
        timestamp=scan_timestamp,
        sha256=sha256_hash,
        artifact_type=artifact_type
    )
    
    st.text(f"Filename: {artifact.filename}")
    st.text(f"Size: {artifact.size} bytes")
    st.text(f"SHA-256: {artifact.sha256}")
    st.text(f"Type: {artifact.artifact_type}")
    st.text(f"Timestamp: {artifact.timestamp.isoformat()}")
    
    if st.button("Start Static Scan"):
        with st.spinner("Analyzing artifact..."):
            # Insert artifact to DB
            artifact_id = insert_artifact(artifact)
            
            # Analyze
            findings = analyze_artifact(artifact)
            
            # Calculate Risk
            score, classification, explanation = calculate_risk(findings)
            
            # Store Scan Results
            insert_scan_result(artifact_id, score, classification, findings)
            
            st.success("Scan Complete!")
            st.subheader("Scan Results")
            st.write(f"**Risk Score:** {score} / 100")
            st.write(f"**Classification:** {classification}")
            st.write(f"**Explanation:** {explanation}")
            
            st.info("⚠️ This is a heuristic analysis and does NOT definitively prove that an artifact is malicious.")
            
            if findings:
                st.subheader("Findings")
                df_findings = pd.DataFrame(findings)
                st.dataframe(df_findings)
                
                # Basic Plotly Visualization
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
