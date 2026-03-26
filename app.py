import streamlit as st
import pandas as pd
import numpy as np
import time
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import google.generativeai as genai

# ================================
# CONFIG
# ================================
st.set_page_config(page_title="NetShield AI", layout="wide")

st.title("☁️ NetShield AI – Cloud Security Dashboard")

# ================================
# LOAD GEMINI API KEY
# ================================
try:
    api_key = st.secrets["GEMINI_API_KEY"]
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
except:
    model = None

# ================================
# SIDEBAR INPUT
# ================================
st.sidebar.header("⚙️ Event Configuration")

threat = st.sidebar.selectbox("Threat", [
    "DDoS Attack","Data Breach","API Exploit"
])

layer = st.sidebar.selectbox("Cloud Layer", ["IaaS","PaaS","SaaS"])

severity = st.sidebar.selectbox("Severity", ["Low","Medium","High"])

incidents = st.sidebar.slider("Incidents", 10, 100, 50)

mitigation = st.sidebar.slider("Mitigation Score", 1.0, 10.0, 5.0)

# ================================
# TABS
# ================================
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Overview",
    "🧠 Detection",
    "📡 Real-Time",
    "🤖 GenAI (Gemini)",
    "📈 Comparison"
])

# ================================
# OVERVIEW
# ================================
with tab1:
    st.subheader("Dataset Overview")

    col1, col2, col3 = st.columns(3)
    col1.metric("Records", "10,000")
    col2.metric("Anomalies", "987")
    col3.metric("Threat Types", "10")

# ================================
# DETECTION
# ================================
with tab2:
    st.subheader("Isolation Forest Performance")

    df = pd.DataFrame({
        "Metric": ["Precision","Recall","F1"],
        "Score": [0.78, 0.75, 0.76]
    })

    st.bar_chart(df.set_index("Metric"))

# ================================
# REAL-TIME DETECTION
# ================================
with tab3:
    st.subheader("Real-Time Monitoring")

    if st.button("Start Detection"):

        data = np.random.rand(200, 5)

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(data)

        model_if = IsolationForest(n_estimators=200, contamination=0.1)
        model_if.fit(X_scaled)

        log_area = st.empty()

        for i in range(10):
            sample = data[np.random.randint(0, 200)]
            sample_scaled = scaler.transform([sample])

            pred = model_if.predict(sample_scaled)

            label = "⚠️ Attack Detected" if pred[0] == -1 else "✅ Normal"

            log_area.write(f"[{i}] {label}")
            time.sleep(1)

# ================================
# GEMINI GEN AI REMEDIATION
# ================================
with tab4:
    st.subheader("Gen AI Mitigation (Gemini)")

    if st.button("Generate Response"):

        if model is None:
            st.error("❌ Gemini API key not configured in secrets.toml")
        else:
            prompt = f"""
            You are a cloud security expert.

            Threat: {threat}
            Layer: {layer}
            Severity: {severity}
            Incidents: {incidents}
            Mitigation Score: {mitigation}

            Return ONLY valid JSON:
            {{
                "attack_type": "...",
                "impact": "...",
                "mitigation": ["...", "..."]
            }}
            """

            try:
                response = model.generate_content(prompt)
                output = response.text

                st.code(output, language="json")

            except Exception as e:
                st.error(f"API Error: {e}")

# ================================
# COMPARISON
# ================================
with tab5:
    st.subheader("Model Comparison")

    data = pd.DataFrame({
        "Model": ["Isolation Forest","Random Forest","SVM"],
        "Accuracy": [0.76, 0.85, 0.78]
    })

    st.bar_chart(data.set_index("Model"))