import streamlit as st
import pandas as pd
import numpy as np
import joblib
from tensorflow.keras.models import load_model
import time
import plotly.express as px
import plotly.graph_objects as go

# --- Page Configuration ---
st.set_page_config(
    page_title="Neo SOC Agent",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Custom CSS ---
def load_css():
    st.markdown("""
    <style>
        /* General Body and Font Styling */
        @import url('https://fonts.googleapis.com/css2?family=Source+Code+Pro:wght@400;600&family=Roboto:wght@400;700&display=swap');
        
        body { font-family: 'Roboto', sans-serif; color: #e0e0e0; }
        .title-text { color: #00ffcc; text-shadow: 0 0 10px rgba(0, 255, 204, 0.7); }
        h1, h2, h3 { color: #00ffcc; }

        /* Metric Box Styling */
        .metric-box {
            background-color: #1a1a1a; padding: 20px; border-radius: 10px; text-align: center;
            box-shadow: 0 0 10px rgba(0, 255, 204, 0.4); border: 1px solid rgba(0, 255, 204, 0.3);
            transition: all 0.3s ease-in-out; height: 100%; display: flex; flex-direction: column; justify-content: center;
        }
        .metric-box:hover { box-shadow: 0 0 20px rgba(0, 255, 204, 0.8); transform: translateY(-5px); border-color: #00ffcc; }
        .metric-title { font-size: 1rem; color: #a0a0a0; margin-bottom: 8px; }
        .metric-value { font-size: 2rem; font-weight: 600; color: #ffffff; }

        /* Alert Card Styling */
        .alert-card {
            background: linear-gradient(145deg, #1e1e1e, #141414); border-left: 7px solid;
            border-radius: 10px; padding: 20px; margin-bottom: 15px; box-shadow: 0 10px 20px rgba(0,0,0,0.2);
        }
        .alert-card-critical { border-left-color: #ff4d4d; }
        .alert-card-high { border-left-color: #ff9a4d; }
        .alert-card-medium { border-left-color: #ffd700; }
        .alert-card-benign { border-left-color: #4dff4d; }
        .xai-header { color: #00ffcc; font-weight: 600; }
        .agent-list { list-style: none; padding-left: 0; }
        .agent-list li { background-color: rgba(0, 255, 204, 0.05); border-left: 3px solid #00ffcc; padding: 5px 10px; margin-bottom: 5px; border-radius: 3px; }
    </style>
    """, unsafe_allow_html=True)

# --- BACKEND: Model Loading & Prediction ---
@st.cache_resource
def load_prediction_assets():
    """Loads ALL models and preprocessing assets from disk."""
    classifier_model = load_model('soc_model.h5')
    autoencoder_model = load_model('autoencoder_model.h5')
    scaler = joblib.load('scaler.pkl')
    model_columns = joblib.load('model_columns.pkl')
    return classifier_model, autoencoder_model, scaler, model_columns

def predict_alert(alert_data, classifier, autoencoder, scaler, model_columns):
    """Uses the Hybrid AI Engine for detection."""
    df_alert = pd.DataFrame([alert_data]); df_alert = pd.get_dummies(df_alert).reindex(columns=model_columns, fill_value=0)
    scaled_alert = scaler.transform(df_alert)

    # 1. Known Threat Score (from your original model)
    prediction_proba = classifier.predict(scaled_alert, verbose=0)[0][0]
    
    # 2. Zero-Day Score (from the Autoencoder)
    reconstruction = autoencoder.predict(scaled_alert, verbose=0)
    reconstruction_error = np.mean(np.power(scaled_alert - reconstruction, 2), axis=1)[0]
    # Normalize error to a 0-1 score for easier interpretation (values are empirical)
    zero_day_score = min(reconstruction_error * 50, 1.0) 

    # Determine risk level based on the HIGHER of the two scores
    final_score = max(prediction_proba, zero_day_score)
    risk_level = "Benign"
    if final_score > 0.9: risk_level = "Critical"
    elif final_score > 0.7: risk_level = "High"
    elif final_score > 0.4: risk_level = "Medium"
    
    justification = f"Known Threat Score: {prediction_proba:.2%}. Zero-Day Novelty Score: {zero_day_score:.2%}. Final verdict is based on the highest of these two scores."
    action = "Log for audit."
    if risk_level == "Critical": action = "AUTOMATED RESPONSE: Isolate endpoint and flag for Tier-2 review."
    elif risk_level == "High": action = "AUTOMATED RESPONSE: Flag for high-priority human review."
    
    return {"risk_level": risk_level, "anomaly_score": prediction_proba, "zero_day_score": zero_day_score,
            "summary": f"{alert_data.get('service', 'N/A')} event ({alert_data.get('protocol_type', 'N/A')})",
            "justification": justification, "recommended_action": action, "status": "Awaiting Review", "feedback": None}

# --- ADVANCED FEATURE SIMULATION ---
def get_agent_task_force(alert_data, result):
    task_force = []; task_force.append({"agent": "📊 Log Analysis Agent", "finding": f"Parsed event from service: '{alert_data.get('service', 'N/A')}' with flag '{alert_data.get('flag', 'N/A')}'."})
    protocol = alert_data.get('protocol_type', 'unknown'); service = alert_data.get('service', 'unknown')
    if protocol in ['tcp', 'udp']: task_force.append({"agent": "🌐 Network Traffic Agent", "finding": f"Analyzed L4 protocol: {protocol.upper()}. Source Bytes: {alert_data.get('src_bytes', 0)}, Dest Bytes: {alert_data.get('dst_bytes', 0)}."})
    if service in ['ftp_data', 'http'] and alert_data.get('dst_bytes', 0) > 10000: task_force.append({"agent": "📦 Data Exfiltration Agent", "finding": f"Flagged high outbound traffic ({alert_data.get('dst_bytes', 0)} bytes) on a common exfil service."})
    if alert_data.get('serror_rate', 0) > 0.5 or alert_data.get('rerror_rate', 0) > 0.5: task_force.append({"agent": "🛡️ DoS Detection Agent", "finding": f"Detected high error rate: {alert_data.get('serror_rate', 0):.0%} SYN errors, {alert_data.get('rerror_rate', 0):.0%} REJ errors."})
    if service == 'ssh' or alert_data.get('num_failed_logins', 0) > 0: task_force.append({"agent": "🔑 Brute Force Agent", "finding": f"Detected {alert_data.get('num_failed_logins', 0)} failed login attempts."})
    task_force.append({"agent": "🔍 Explainability Agent", "finding": f"Correlated {len(task_force)} agent findings to generate final justification based on the hybrid engine's scores."})
    return task_force

def get_causal_chain(alert_data, risk_level):
    if risk_level == "Critical": return ["Initial Access (Anomalous Connection)", "Execution (High Error Rate)", "Impact (Potential DoS)"]
    if risk_level == "High": return ["Reconnaissance (High Host Count)", "Credential Access (Failed Logins)", "Lateral Movement (Attempted)"]
    if risk_level == "Medium": return ["Discovery (Uncommon Service)", "Collection (High Byte Count)"]
    return ["Benign Activity (Normal Pattern)"]

# --- UI RENDERING FUNCTIONS ---
def display_sidebar():
    with st.sidebar:
        st.title("🛡️ AI SOC Analyst Agent"); st.header("Neo Agents"); st.caption("Amrita Vishwa VidyaPeetham"); st.markdown("---")
        st.subheader("Hackathon Theme"); st.info("Agentic AI – Adaptive AI agents for autonomous defenses."); st.markdown("---")
        if 'model_confidence' in st.session_state: st.metric("🤖 Model Confidence (Simulated)", f"{st.session_state.model_confidence:.4%}", f"+{st.session_state.feedback_count} feedback points")
        st.markdown("---"); st.title("Operation Mode")

def display_header_and_kpis(stats):
    st.markdown('<h1 class="title-text">AI Security Operations Center</h1>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)
    with col1: st.markdown(f'<div class="metric-box"><div class="metric-title">Total Events Processed</div><div class="metric-value">{stats["Total"]}</div></div>', unsafe_allow_html=True)
    with col2: st.markdown(f'<div class="metric-box"><div class="metric-title">🚨 Critical Threats</div><div class="metric-value">{stats["Critical"]}</div></div>', unsafe_allow_html=True)
    with col3: st.markdown(f'<div class="metric-box"><div class="metric-title">🟠 High-Risk Alerts</div><div class="metric-value">{stats["High"]}</div></div>', unsafe_allow_html=True)
    with col4: st.markdown(f'<div class="metric-box"><div class="metric-title">⚪ Benign Events Filtered</div><div class="metric-value">{stats["Benign"]}</div></div>', unsafe_allow_html=True)

def display_causal_chain_graph(stages, chart_key):
    fig = go.Figure()
    for i, stage in enumerate(stages):
        fig.add_trace(go.Scatter(x=[i], y=[0], mode='markers+text', text=[stage], textposition='bottom center', marker=dict(size=20, color='#00ffcc'), showlegend=False))
        if i > 0: fig.add_annotation(x=i-1, y=0, ax=i, ay=0, xref='x', yref='y', axref='x', ayref='y', showarrow=True, arrowhead=2, arrowsize=1.5, arrowwidth=2, arrowcolor="#00ffcc")
    fig.update_layout(showlegend=False, plot_bgcolor='rgba(0,0,0,0)', paper_bgcolor='rgba(0,0,0,0)',
                      xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.5, len(stages)-0.5]),
                      yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-0.5, 0.5]),
                      height=150, margin=dict(l=0, r=0, t=0, b=0))
    st.plotly_chart(fig, use_container_width=True, key=chart_key)

def display_threat_card(index, result, original_alert_data):
    severity_class = f"alert-card-{result['risk_level'].lower()}"
    with st.container():
        st.markdown(f'<div class="alert-card {severity_class}">', unsafe_allow_html=True)
        
        # --- NEW: Display the Hybrid AI scores side-by-side ---
        score_col1, score_col2 = st.columns(2)
        score_col1.metric("Known Threat Score", f"{result['anomaly_score']:.2%}")
        # Highlight if Zero-Day score is the primary driver of the alert
        if result['zero_day_score'] > result['anomaly_score'] and result['risk_level'] not in ['Benign']:
             score_col2.metric("Novelty Score (Zero-Day)", f"{result['zero_day_score']:.2%}", "🔥 High Novelty")
        else:
            score_col2.metric("Novelty Score (Zero-Day)", f"{result['zero_day_score']:.2%}")

        st.markdown(f"""
            <div style="font-size: 1.2rem; font-weight: 600;">[{result['risk_level']}] Event ID: {index} | {result['summary']}</div>
            <p style="margin-top: 10px;"><span class="xai-header">📄 Explainable AI Justification:</span> {result['justification']}</p>
            <p style="font-style: italic;"><span class="xai-header">💡 AI Recommendation:</span> {result['recommended_action']}</p>
        """, unsafe_allow_html=True)
        with st.expander("Show Advanced Analysis"):
            st.markdown("**convocated Agent Task Force:**")
            task_force = get_agent_task_force(original_alert_data, result)
            for agent_info in task_force:
                col1, col2 = st.columns([1, 2]); col1.markdown(f"**{agent_info['agent']}**"); col2.info(agent_info['finding'])
            st.markdown("** Causal Chain Analysis:**"); chain = get_causal_chain(original_alert_data, result['risk_level'])
            display_causal_chain_graph(chain, chart_key=f"causal_chain_{index}")
        st.markdown("** Human-in-the-Loop Feedback:**")
        if result['status'] == 'Awaiting Review':
            c1, c2, c3 = st.columns([1, 1, 4])
            if c1.button("✅ Approve", key=f"approve_{index}", use_container_width=True):
                result['status'] = "Action Approved"; result['feedback'] = "Positive"; st.session_state.model_confidence += 0.0001; st.session_state.feedback_count += 1; st.rerun()
            if c2.button("❌ Reject", key=f"reject_{index}", use_container_width=True):
                result['status'] = "Action Rejected"; result['feedback'] = "Negative"; st.session_state.feedback_count += 1; st.rerun()
        else:
            if result['feedback'] == "Positive": st.success(f"✅ Feedback Recorded: Analyst approved action. Model confidence increased.")
            else: st.warning(f"❌ Feedback Recorded: Analyst rejected action. Awaiting model retraining cycle.")
        st.markdown('</div>', unsafe_allow_html=True)

# --- MAIN APP LOGIC ---
load_css(); display_sidebar()

if 'is_running' not in st.session_state:
    st.session_state.is_running = False; st.session_state.current_index = 0; st.session_state.results = []
    st.session_state.stats = {"Total": 0, "Critical": 0, "High": 0, "Medium": 0, "Benign": 0}
    st.session_state.model_confidence = 0.9978; st.session_state.feedback_count = 0; st.session_state.alert_queue = None

try:
    classifier_model, autoencoder_model, scaler, model_columns = load_prediction_assets()
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
        'su_attempted', 'num_root', 'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login', 'is_guest_login', 'count', 'srv_count',
        'serror_rate', 'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'class', 'difficulty'
    ]
except Exception as e:
    st.error(f"Fatal Error loading model assets: {e}"); st.stop()

mode = st.sidebar.radio("Choose how to use the agent:", ("Autonomous SOC Simulation", "Analyze Custom File"))

if mode == "Autonomous SOC Simulation":
    if st.session_state.alert_queue is None:
        try:
            df_test = pd.read_csv(r'C:\Users\samee\OneDrive\Desktop\ai_agent\NSL_KDD_Test.csv', header=None, names=columns)
            st.session_state.alert_queue = df_test.sample(frac=1).reset_index(drop=True).drop(['class', 'difficulty'], axis=1)
            st.info("Simulation data loaded and shuffled for dynamic demonstration.")
        except FileNotFoundError:
            st.error("Error: 'NSL_KDD_Test.csv' not found. Please check the path."); st.stop()

    alert_queue = st.session_state.alert_queue
    st.sidebar.header("🕹️ Simulation Controls")
    if st.sidebar.button("▶️ Start", type="primary", use_container_width=True): st.session_state.is_running = True; st.rerun()
    if st.sidebar.button("⏹️ Stop", use_container_width=True): st.session_state.is_running = False; st.rerun()
    if st.sidebar.button("🔄 Reset", use_container_width=True): st.session_state.clear(); st.rerun()

    display_header_and_kpis(st.session_state.stats); st.markdown("---"); st.header("🔴 Live Threat Feed")
    feed_placeholder = st.container()

    if st.session_state.is_running:
        if st.session_state.current_index < len(alert_queue):
            idx = st.session_state.current_index; alert_data = alert_queue.loc[idx].to_dict()
            analysis = predict_alert(alert_data, classifier_model, autoencoder_model, scaler, model_columns)
            st.session_state.stats["Total"] += 1; st.session_state.stats[analysis["risk_level"]] += 1
            st.session_state.results.insert(0, (idx, analysis, alert_data)); st.session_state.current_index += 1
        else:
            st.success("✅ Alert queue fully processed."); st.session_state.is_running = False
    with feed_placeholder:
        if not st.session_state.results: st.info("Agent is idle. Press 'Start' to begin simulation.")
        else:
            for index, result, original_data in st.session_state.results:
                display_threat_card(index, result, original_data)
    if st.session_state.is_running: time.sleep(1.5); st.rerun()

elif mode == "Analyze Custom File":
    st.title("🔎 Analyze Custom Alert Feed"); st.info("Upload a CSV file with alerts in the NSL-KDD format (without headers).")
    uploaded_file = st.file_uploader("Upload your alert file", type=["csv", "txt"])
    if uploaded_file is not None:
        try:
            df_custom = pd.read_csv(uploaded_file, header=None, names=columns)
            st.subheader("Uploaded Data Preview"); st.dataframe(df_custom.head())
            if st.button(f"Process and Analyze {len(df_custom)} Events", type="primary", use_container_width=True):
                with st.spinner("Analyzing..."):
                    results = []; stats = {"Total": 0, "Critical": 0, "High": 0, "Medium": 0, "Benign": 0}
                    df_to_process = df_custom.drop(['class', 'difficulty'], axis=1, errors='ignore')
                    for index, row in df_to_process.iterrows():
                        analysis = predict_alert(row.to_dict(), classifier_model, autoencoder_model, scaler, model_columns)
                        results.append((index, analysis, row.to_dict())); stats[analysis["risk_level"]] += 1; stats["Total"] += 1
                st.subheader("Analysis Complete!"); display_header_and_kpis(stats); st.markdown("---"); st.header("📄 Detailed Report")
                for index, result, original_data in results:
                    display_threat_card(index, result, original_data)
        except Exception as e:
            st.error(f"Failed to process file. Error: {e}")

st.markdown("---"); st.caption("© Neo Agents | Amrita Vishwa VidyaPeetham | AI SOC Analyst Agent")