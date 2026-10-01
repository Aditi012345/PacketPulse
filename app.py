# app.py
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

from utils.model_loader import load_model
from utils.predictions import predict_with_model
from utils.live_flow_predictor import run_capture_and_predict
from utils.cicids_flow_features import FEATURE_COLUMNS

st.set_page_config(page_title="SentinelNet IDS", layout="wide")

# ---------------- Load models (cached) ----------------
@st.cache_resource
def load_resources():
    scaler = load_model("models/nsl_kdd_scaler.pkl") if os.path.exists("models/nsl_kdd_scaler.pkl") else None
    return scaler

scaler = load_resources()

FEATURE_COLUMNS_NSL_KDD = [
    'duration',
 'src_bytes',
 'dst_bytes',
 'land',
 'wrong_fragment',
 'urgent',
 'num_failed_logins',
 'logged_in',
 'root_shell',
 'su_attempted',
 'num_root',
 'num_file_creations',
 'num_shells',
 'num_access_files',
 'is_guest_login',
 'count',
 'srv_count',
 'same_srv_rate',
 'diff_srv_rate',
 'srv_diff_host_rate',
 'dst_host_count',
 'dst_host_srv_count',
 'dst_host_diff_srv_rate',
 'dst_host_same_src_port_rate',
 'dst_host_srv_diff_host_rate',
 'dst_host_srv_serror_rate',
 'dst_host_srv_rerror_rate',
 'protocol_type_icmp',
 'protocol_type_tcp',
 'protocol_type_udp',
 'service_IRC',
 'service_X11',
 'service_Z39_50',
 'service_aol',
 'service_auth',
 'service_bgp',
 'service_courier',
 'service_csnet_ns',
 'service_ctf', 'service_daytime', 'service_discard', 'service_domain', 'service_domain_u',
 'service_echo', 'service_eco_i', 'service_ecr_i', 'service_efs', 'service_exec', 'service_finger',
 'service_ftp', 'service_ftp_data', 'service_gopher', 'service_harvest', 'service_hostnames',
 'service_http', 'service_http_2784', 'service_http_443', 'service_http_8001',
 'service_imap4', 'service_iso_tsap', 'service_klogin', 'service_kshell', 'service_ldap',
 'service_link', 'service_login', 'service_mtp', 'service_name', 'service_netbios_dgm',
 'service_netbios_ns', 'service_netbios_ssn', 'service_netstat', 'service_nnsp',
 'service_nntp', 'service_ntp_u', 'service_other', 'service_pm_dump', 'service_pop_2',
 'service_pop_3', 'service_printer', 'service_private', 'service_red_i', 'service_remote_job',
 'service_rje', 'service_shell', 'service_smtp', 'service_sql_net', 'service_ssh',
 'service_sunrpc', 'service_supdup', 'service_systat', 'service_telnet', 'service_tftp_u',
 'service_tim_i', 'service_time', 'service_urh_i', 'service_urp_i',
 'service_uucp', 'service_uucp_path', 'service_vmnet', 'service_whois',
 'flag_OTH', 'flag_REJ', 'flag_RSTO', 'flag_RSTOS0', 'flag_RSTR',
 'flag_S0', 'flag_S1', 'flag_S2', 'flag_S3', 'flag_SF', 'flag_SH'
]

FEATURE_COLUMNS_CICIDS = FEATURE_COLUMNS

# Model list for CSV mode
MODELS_NSL_KDD = {
    "Decision Tree": "models/nsl_kdd_decision_tree.pkl",
    "Random Forest": "models/nsl_kdd_random_forest.pkl",
    "SVM": "models/nsl_kdd_svm.pkl",
    "XGBoost": "models/nsl_kdd_xgboost.pkl"
}

MODELS_CIC_IDS = {
    "CatBoost": "models/cicids_catboost.pkl",
    "Decision Tree": "models/cicids_decision_tree.pkl",
    "LightGBM": "models/cicids_lightgbm.pkl",
    "Random Forest": "models/cicids_random_forest.pkl",
    "XGBoost": "models/cicids_xgboost.pkl"
}

DATASET_FEATURES = {
    "NSL_KDD": FEATURE_COLUMNS_NSL_KDD,
    "CICIDS": FEATURE_COLUMNS_CICIDS,
}

DATASET_MODELS = {
    "NSL_KDD": MODELS_NSL_KDD,
    "CICIDS": MODELS_CIC_IDS,
}

DATASET_METRICS_IMAGES = {
    "NSL_KDD": "assets/NSL_KDD_Metrics.jpeg",
    "CICIDS": "assets/CICIDS_Metrics.jpeg",
}


def plot_verdict_bar(n_benign, n_threat, title="Prediction Summary"):
    """Bar chart with benign in green and attacks/threats in red."""
    fig, ax = plt.subplots(figsize=(3, 3))
    labels = ["Normal", "Attack"]
    values = [n_benign, n_threat]
    colors = ["green", "red"]
    ax.bar(labels, values, color=colors)
    ax.set_ylabel("Count")
    ax.set_title(title)
    for i, v in enumerate(values):
        ax.text(i, v, str(v), ha="center", va="bottom")
    fig.tight_layout()
    return fig


# ---------------- UI ----------------
st.title("🔐 SentinelNet IDS — Real-Time Intrusion Detection")

if "selected_mode" not in st.session_state:
    st.session_state.selected_mode = None

mode_col1, mode_col2 = st.columns(2)
with mode_col1:
    with st.container(border=True):
        st.markdown("### 🟢 Live Predicting (Real-Time)")
        st.write("Sniff live traffic and score reconstructed flows on the fly.")
        if st.button("Select Live Mode", use_container_width=True):
            st.session_state.selected_mode = "Live Predicting (Real-Time)"

with mode_col2:
    with st.container(border=True):
        st.markdown("### 📁 CSV Predicting (Offline)")
        st.write("Upload a dataset CSV and score it against a trained model.")
        if st.button("Select CSV Mode", use_container_width=True):
            st.session_state.selected_mode = "CSV Predicting (Offline)"

mode = st.session_state.selected_mode
st.markdown("---")

# ---------------- WELCOME / INFO ----------------
if mode is None:
    st.markdown("## Welcome to SentinelNet IDS 👋")
    st.markdown(
        "SentinelNet IDS is a network intrusion detection dashboard that lets you "
        "score network traffic for **benign vs. attack** behaviour using trained "
        "machine-learning models, either live off the wire or offline from a CSV file."
    )

    info_col1, info_col2 = st.columns(2)
    with info_col1:
        st.markdown("#### 🟢 Live Predicting (Real-Time)")
        st.markdown(
            "- Sniffs live packets off your network interface for a duration you choose\n"
            "- Reconstructs bidirectional flows from the raw capture\n"
            "- Scores each flow with the CICIDS XGBoost model\n"
            "- Reports counts of normal vs. attack flows with a live chart"
        )
    with info_col2:
        st.markdown("#### 📁 CSV Predicting (Offline)")
        st.markdown(
            "- Choose between the **NSL-KDD** or **CICIDS** feature schema\n"
            "- See the exact feature columns your CSV must contain, plus a downloadable template\n"
            "- Compare available models by their performance metrics\n"
            "- Pick a model and upload a CSV to get instant predictions and a results chart"
        )

    st.info("Pick **Live Predicting** or **CSV Predicting** above to get started.")

# ---------------- LIVE MODE ----------------
elif mode == "Live Predicting (Real-Time)":
    st.subheader("Live Network Protection")
    col1, col2 = st.columns([1, 3])

    with col1:
        capture_seconds = st.number_input(
            "Capture duration (seconds)", min_value=1, max_value=60, value=10, step=1
        )
        start_btn = st.button("START LIVE DETECTION", use_container_width=True)

    with col2:
        status_box = st.empty()
        results_box = st.empty()
        chart_box = st.empty()

    if start_btn:
        status_box.info(f"Capturing traffic for {capture_seconds} seconds... generate traffic (open YouTube / ping google.com).")
        n_packets, n_flows, n_benign, n_threat, scored = run_capture_and_predict(int(capture_seconds))

        status_box.success(f"Captured {n_packets} packets — reconstructed {n_flows} flows")

        results_box.markdown(f"""
            <div style="text-align:center; padding:20px;">
                <h2>Live Threat Report</h2>
                <h1 style="color:red;">⚠ {n_threat} Attack Flows Detected</h1>
                <h3 style="color:lightgreen;">✔ {n_benign} Normal Flows</h3>
            </div>
        """, unsafe_allow_html=True)

        fig = plot_verdict_bar(n_benign, n_threat, title="Live Capture Verdicts")
        chart_box.pyplot(fig, use_container_width=False)
        if not scored.empty:
            display = scored.rename(columns={
                "Flow Duration": "Duration (µs)",
                "Total Fwd Packets": "Fwd Pkts",
                "Total Backward Packets": "Bwd Pkts",
                "threat_probability": "Threat Probability",
                "verdict": "Verdict",
            }).drop(columns=["prediction"])

            col_cfg = {
                "Threat Probability": st.column_config.ProgressColumn(
                    "Threat Probability", min_value=0.0, max_value=1.0, format="%.2f"
                )
            }

            flagged = display[display["Verdict"] == "THREAT"].sort_values(
                "Threat Probability", ascending=False
            )

            st.markdown("#### 🚨 Flagged Flows")
            if flagged.empty:
                st.success("No threats detected in this capture.")
            else:
                st.dataframe(flagged, column_config=col_cfg, use_container_width=True, hide_index=True)

            with st.expander(f"All {len(display)} flows"):
                st.dataframe(
                    display.sort_values("Threat Probability", ascending=False),
                    column_config=col_cfg, use_container_width=True, hide_index=True,
                )

# ---------------- CSV MODE ----------------
else:
    st.subheader("Offline CSV Analysis")

    if "selected_dataset" not in st.session_state:
        st.session_state.selected_dataset = None

    card_col1, card_col2 = st.columns(2)
    with card_col1:
        with st.container(border=True):
            st.markdown("### 📊 NSL_KDD")
            st.write("Classic NSL-KDD intrusion detection dataset.")
            if st.button("Select NSL_KDD", use_container_width=True):
                st.session_state.selected_dataset = "NSL_KDD"

    with card_col2:
        with st.container(border=True):
            st.markdown("### 📊 CICIDS")
            st.write("CICIDS flow-based intrusion detection dataset.")
            if st.button("Select CICIDS", use_container_width=True):
                st.session_state.selected_dataset = "CICIDS"

    dataset = st.session_state.selected_dataset

    if dataset:
        st.markdown("---")
        st.subheader(f"Selected Dataset: {dataset}")

        feature_columns = DATASET_FEATURES[dataset]

        # Required feature columns
        st.markdown("#### Required Feature Columns")
        FEATURES_PER_ROW = 6
        for i in range(0, len(feature_columns), FEATURES_PER_ROW):
            row_features = feature_columns[i:i + FEATURES_PER_ROW]
            row_cols = st.columns(FEATURES_PER_ROW)
            for col, feat_name in zip(row_cols, row_features):
                with col:
                    st.markdown(f"`{feat_name}`")

        sample_csv = pd.DataFrame(columns=feature_columns).to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Sample Empty CSV",
            data=sample_csv,
            file_name=f"{dataset.lower()}_sample_template.csv",
            mime="text/csv",
        )

        # Model performance metrics (image asset)
        st.markdown("#### Model Comparison")
        metrics_image_path = DATASET_METRICS_IMAGES[dataset]
        if os.path.exists(metrics_image_path):
            st.image(metrics_image_path, use_container_width=True)
        else:
            st.warning(f"Metrics image not found at {metrics_image_path}")

        available_models = list(DATASET_MODELS[dataset].keys())

        # Choose model as cards
        st.markdown("#### Choose Model")
        model_key = f"selected_model_{dataset}"
        if model_key not in st.session_state or st.session_state[model_key] not in available_models:
            st.session_state[model_key] = available_models[0] if available_models else None

        if available_models:
            model_cols = st.columns(len(available_models))
            for col, model_name in zip(model_cols, available_models):
                with col:
                    with st.container(border=True):
                        st.markdown(f"**{model_name}**")
                        is_selected = st.session_state[model_key] == model_name
                        btn_label = "✅ Selected" if is_selected else "Select"
                        if st.button(btn_label, key=f"model_btn_{dataset}_{model_name}", use_container_width=True):
                            st.session_state[model_key] = model_name
        else:
            st.warning("No models available for this dataset.")

        model_choice = st.session_state[model_key]
        if model_choice:
            st.markdown(f"**Chosen Model:** `{model_choice}`")

        st.markdown("#### Upload Data for Prediction")
        uploaded = st.file_uploader("Upload CSV File", type=["csv"], key=f"uploader_{dataset}")

        if uploaded and st.button("Run Prediction"):
            df = pd.read_csv(uploaded)
            st.write("Preview:", df.head())

            models_dict = DATASET_MODELS[dataset]
            model_path = models_dict.get(model_choice)

            if model_path is None or not os.path.exists(model_path):
                st.error(f"Model file not found for '{model_choice}'")
            else:
                model = load_model(model_path)

                X = df[feature_columns].fillna(0)
                if dataset == "NSL_KDD" and scaler is not None:
                    X_in = scaler.transform(X)
                else:
                    X_in = X.values

                preds = predict_with_model(model, X_in)

                n_threat = int(sum(preds))
                n_benign = len(preds) - n_threat

                st.success(f"Detected {n_threat} attacks out of {len(preds)} rows")

                fig = plot_verdict_bar(n_benign, n_threat, title=f"{dataset} — {model_choice} Verdicts")
                st.pyplot(fig, use_container_width=False)