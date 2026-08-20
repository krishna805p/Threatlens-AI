from __future__ import annotations

import pickle
import subprocess
import sys
import json
from dataclasses import asdict
from pathlib import Path

import pandas as pd
import streamlit as st
try:
    import plotly.express as px
    import plotly.graph_objects as go
except Exception:  # pragma: no cover - optional at runtime
    px = None
    go = None
try:
    from streamlit_autorefresh import st_autorefresh
except Exception:  # pragma: no cover - optional at runtime
    def st_autorefresh(*args, **kwargs):
        return None

from feature_extraction import append_trusted_domain
from gemini_assistant import generate_security_explanation
from integrations.gmail_analysis import GmailEmailAnalyzer
from integrations.gmail_service import GmailIntegrationError, GmailService
from log_utils import LOGS_FILE
from model import CybercrimeDetectionSystem
from pipeline.repository import InMemoryEventRepository
from pipeline.service import DetectionPipeline


BASE_DIR = Path(__file__).resolve().parent
MODEL_FILE = BASE_DIR / "models" / "detector.pkl"


@st.cache_resource(show_spinner=False)
def load_or_train_system() -> CybercrimeDetectionSystem:
    if MODEL_FILE.exists():
        with MODEL_FILE.open("rb") as model_file:
            system = pickle.load(model_file)
        if getattr(system, "is_trained", False):
            return system

    subprocess.run([sys.executable, "training/train.py"], cwd=BASE_DIR, check=True)
    with MODEL_FILE.open("rb") as model_file:
        return pickle.load(model_file)


def render_prediction_card(result) -> None:
    public_level = {
        "High": "High Risk",
        "Medium": "Suspicious",
        "Low": "Safe",
        "High Risk": "High Risk",
        "Suspicious": "Suspicious",
        "Safe": "Safe",
    }.get(result.risk_level, result.risk_level)
    color = {
        "High": "#ef4444",
        "Medium": "#f59e0b",
        "Low": "#22c55e",
        "High Risk": "#ef4444",
        "Suspicious": "#f59e0b",
        "Safe": "#22c55e",
    }.get(result.risk_level, "#3b82f6")
    st.markdown(
        f"""
        <div style="padding:1rem;border-radius:16px;background:#0f172a;color:white;">
            <div style="font-size:1.25rem;font-weight:700;">{result.prediction}</div>
            <div style="margin-top:0.4rem;">Risk Level:
                <span style="background:{color};padding:0.25rem 0.65rem;border-radius:999px;font-weight:700;">
                    {public_level}
                </span>
            </div>
            <div style="margin-top:0.35rem;">Risk Score: {result.risk_score}/10</div>
            <div style="margin-top:0.35rem;">ML Probability: {result.probability:.2%}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_explainability(result) -> None:
    st.subheader("Explainable Output")
    debug = result.debug or {}

    st.write(f"ML probability: `{result.probability:.2%}`")

    rule_triggers = debug.get("rule_triggers", [])
    if rule_triggers:
        st.write("Rule triggers:")
        for trigger in rule_triggers[:5]:
            st.write(f"- {trigger.get('reason', trigger.get('rule_name', 'Rule triggered'))}")
    else:
        st.write("Rule triggers: `None`")

    api_result = debug.get("api_result") or debug.get("reputation", {}).get("api_result")
    reputation = debug.get("reputation", {})
    if api_result:
        st.write(
            "API result: `{}` | confidence: `{:.2f}` | fallback used: `{}`".format(
                api_result.get("verdict", "unknown"),
                float(api_result.get("confidence_score", 0.0)),
                api_result.get("fallback_used", False),
            )
        )
    elif reputation.get("status") in {"safe_override", "malicious_override"}:
        st.write(f"API result: `{reputation.get('status')}`")
    else:
        st.write("API result: `No API verdict available`")

    nlp_detector = debug.get("nlp_detector", {})
    if nlp_detector:
        st.write(
            "NLP patterns detected: `{}` | scam probability: `{:.2%}`".format(
                ", ".join(nlp_detector.get("detected_patterns", [])) or "None",
                float(nlp_detector.get("scam_probability", 0.0)),
            )
        )
    else:
        st.write("NLP patterns detected: `None`")

    explanation_lines = []
    if rule_triggers:
        explanation_lines.append(rule_triggers[0].get("reason", "Rule engine triggered"))
    if result.probability >= 0.75:
        explanation_lines.append("High ML probability")
    elif result.probability >= 0.55:
        explanation_lines.append("Elevated ML probability")
    if api_result and api_result.get("verdict") == "malicious":
        explanation_lines.append("API flagged malicious")
    if nlp_detector.get("detected_patterns"):
        explanation_lines.append(f"NLP patterns: {', '.join(nlp_detector.get('detected_patterns', [])[:3])}")

    if explanation_lines:
        st.info(f"{result.risk_level} because: " + "; ".join(explanation_lines))


def metrics_frame(system: CybercrimeDetectionSystem) -> pd.DataFrame:
    rows = []
    for source, info in system.metrics.items():
        report = info.get("report", {})
        rows.append(
            {
                "Source": source.upper(),
                "Accuracy": round(info.get("accuracy", 0.0), 4),
                "Precision": round(report.get("threat", {}).get("precision", 0.0), 4),
                "Recall": round(report.get("threat", {}).get("recall", 0.0), 4),
                "F1": round(report.get("threat", {}).get("f1-score", 0.0), 4),
                "CV F1": round(info.get("cross_validation", {}).get("mean", 0.0), 4),
            }
        )
    return pd.DataFrame(rows)


def pie_data(predictions: pd.Series) -> pd.DataFrame:
    counts = predictions.value_counts().rename_axis("label").reset_index(name="count")
    return counts


def inject_custom_css() -> None:
    st.markdown(
        """
        <style>
            .stApp {
                background:
                    radial-gradient(circle at top right, rgba(59, 130, 246, 0.12), transparent 25%),
                    radial-gradient(circle at top left, rgba(34, 197, 94, 0.08), transparent 20%),
                    linear-gradient(180deg, #08111f 0%, #0b1728 45%, #0f172a 100%);
                color: #e2e8f0;
            }
            .block-container {
                padding-top: 1.6rem;
                padding-bottom: 2rem;
            }
            div[data-testid="stMetric"] {
                background: rgba(15, 23, 42, 0.72);
                border: 1px solid rgba(148, 163, 184, 0.18);
                padding: 1rem;
                border-radius: 18px;
                box-shadow: 0 14px 32px rgba(8, 15, 28, 0.28);
            }
            .monitor-card {
                background: rgba(15, 23, 42, 0.76);
                border: 1px solid rgba(148, 163, 184, 0.14);
                border-radius: 18px;
                padding: 1rem 1.1rem;
                box-shadow: 0 14px 30px rgba(8, 15, 28, 0.22);
                margin-bottom: 0.8rem;
            }
            .monitor-label {
                color: #93c5fd;
                font-size: 0.82rem;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                font-weight: 700;
                margin-bottom: 0.35rem;
            }
            .detail-panel {
                background: rgba(15, 23, 42, 0.78);
                border: 1px solid rgba(148, 163, 184, 0.16);
                border-radius: 18px;
                padding: 1rem 1.15rem;
                box-shadow: 0 14px 30px rgba(8, 15, 28, 0.22);
            }
            .risk-pill {
                display: inline-block;
                padding: 0.26rem 0.72rem;
                border-radius: 999px;
                font-weight: 700;
                font-size: 0.85rem;
                margin-bottom: 0.8rem;
            }
            .risk-pill.high {
                background: rgba(239, 68, 68, 0.18);
                color: #fca5a5;
                border: 1px solid rgba(239, 68, 68, 0.34);
            }
            .risk-pill.suspicious {
                background: rgba(245, 158, 11, 0.18);
                color: #fde68a;
                border: 1px solid rgba(245, 158, 11, 0.34);
            }
            .risk-pill.safe {
                background: rgba(34, 197, 94, 0.18);
                color: #86efac;
                border: 1px solid rgba(34, 197, 94, 0.34);
            }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_logs() -> list[dict[str, object]]:
    if not LOGS_FILE.exists():
        return []

    try:
        with LOGS_FILE.open("r", encoding="utf-8") as logs_file:
            payload = json.load(logs_file)
    except (OSError, json.JSONDecodeError):
        return []

    if isinstance(payload, dict):
        payload = [payload]
    if not isinstance(payload, list):
        return []

    normalized_logs: list[dict[str, object]] = []
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        normalized_logs.append(
            {
                "timestamp": str(entry.get("timestamp", "")),
                "input": str(entry.get("input", "")),
                "risk": str(entry.get("risk", "Unknown")),
                "score": float(entry.get("score", 0.0) or 0.0),
                "ml_prob": float(entry.get("ml_prob", 0.0) or 0.0),
                "reasons": entry.get("reasons", []) if isinstance(entry.get("reasons", []), list) else [str(entry.get("reasons", ""))],
            }
        )
    return normalized_logs


def logs_frame(logs: list[dict[str, object]]) -> pd.DataFrame:
    if not logs:
        return pd.DataFrame(columns=["timestamp", "input", "risk", "score", "ml_prob", "reasons"])

    frame = pd.DataFrame(logs)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    frame = frame.sort_values("timestamp", ascending=False).reset_index(drop=True)
    frame["timestamp"] = frame["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S").fillna("")
    frame["reasons"] = frame["reasons"].apply(lambda value: ", ".join(value) if isinstance(value, list) else str(value))
    return frame


def filter_logs(logs_df: pd.DataFrame, selected_risk: str) -> pd.DataFrame:
    if logs_df.empty or selected_risk == "All":
        return logs_df
    return logs_df[logs_df["risk"] == selected_risk].reset_index(drop=True)


def render_live_alerts(logs: list[dict[str, object]]) -> None:
    st.subheader("Live Alerts")
    if not logs:
        st.info("No live logs available yet. Threat events from `logs.json` will appear here automatically.")
        return

    for entry in reversed(logs[-5:]):
        risk = str(entry.get("risk", "Unknown"))
        if risk == "High Risk":
            indicator = "🔴 High Risk"
        elif risk == "Suspicious":
            indicator = "🟡 Suspicious"
        else:
            indicator = "🟢 Safe"
        message = (
            f"{indicator}\n\n{entry.get('timestamp', 'Unknown time')} | Score: {entry.get('score', 0):.1f} | "
            f"ML: {float(entry.get('ml_prob', 0.0)):.2%}\n\n{entry.get('input', '')}\n\n"
            f"Reasons: {', '.join(entry.get('reasons', [])) or 'No reasons recorded.'}"
        )
        if risk == "High Risk":
            st.error(message)
        elif risk == "Suspicious":
            st.warning(message)
        else:
            st.success(message)


def render_system_stats(logs_df: pd.DataFrame) -> None:
    total_scans = len(logs_df)
    high_risk_count = int((logs_df["risk"] == "High Risk").sum()) if not logs_df.empty else 0
    safe_count = int((logs_df["risk"] == "Safe").sum()) if not logs_df.empty else 0
    suspicious_count = int((logs_df["risk"] == "Suspicious").sum()) if not logs_df.empty else 0

    total_col, high_col, safe_col, suspicious_col = st.columns(4)
    total_col.metric("Total Scans", total_scans)
    high_col.metric("High Risk Count", high_risk_count)
    safe_col.metric("Safe Count", safe_count)
    suspicious_col.metric("Suspicious Count", suspicious_count)


def render_plotly_charts(logs_df: pd.DataFrame) -> None:
    st.subheader("Threat Analytics")
    if logs_df.empty:
        st.info("Charts will appear here as soon as `logs.json` contains scan activity.")
        return

    if px is None or go is None:
        st.warning("Plotly is not installed, so analytics charts cannot be rendered right now.")
        return

    chart_left, chart_middle, chart_right = st.columns(3)

    risk_counts = logs_df["risk"].value_counts().reindex(["Safe", "Suspicious", "High Risk"], fill_value=0)
    pie_fig = go.Figure(
        data=[
            go.Pie(
                labels=risk_counts.index.tolist(),
                values=risk_counts.values.tolist(),
                hole=0.52,
                marker=dict(colors=["#22c55e", "#f59e0b", "#ef4444"]),
                textinfo="label+percent",
            )
        ]
    )
    pie_fig.update_layout(
        title="Risk Distribution",
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    chart_left.plotly_chart(pie_fig, use_container_width=True)

    bar_fig = px.bar(
        x=risk_counts.index.tolist(),
        y=risk_counts.values.tolist(),
        color=risk_counts.index.tolist(),
        color_discrete_map={"Safe": "#22c55e", "Suspicious": "#f59e0b", "High Risk": "#ef4444"},
        labels={"x": "Risk Category", "y": "Detections"},
        title="Risk Category Counts",
    )
    bar_fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=50, b=10),
        showlegend=False,
    )
    chart_middle.plotly_chart(bar_fig, use_container_width=True)

    trend_df = logs_df.copy()
    trend_df["timestamp"] = pd.to_datetime(trend_df["timestamp"], errors="coerce")
    trend_df = trend_df.dropna(subset=["timestamp"])
    trend_df["time_bucket"] = trend_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    trend_df = trend_df.groupby("time_bucket").size().reset_index(name="detections")
    line_fig = px.line(
        trend_df,
        x="time_bucket",
        y="detections",
        markers=True,
        title="Detection Trend Over Time",
        labels={"time_bucket": "Timestamp", "detections": "Detections"},
    )
    line_fig.update_traces(line_color="#38bdf8", marker_color="#38bdf8")
    line_fig.update_layout(
        template="plotly_dark",
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    chart_right.plotly_chart(line_fig, use_container_width=True)


def render_scan_history(logs_df: pd.DataFrame) -> None:
    if logs_df.empty:
        st.info("No scan history available yet.")
        return
    st.dataframe(logs_df, use_container_width=True)


def render_detailed_view(logs_df: pd.DataFrame) -> dict[str, object] | None:
    if logs_df.empty:
        st.info("No log entries available for detailed inspection.")
        return None

    options = [
        f"{row.timestamp} | {row.risk} | {str(row.input)[:70]}"
        for row in logs_df.itertuples(index=False)
    ]
    selected_option = st.selectbox("Select a logged scan", options)
    selected_index = options.index(selected_option)
    selected_entry = logs_df.iloc[selected_index]
    risk_value = str(selected_entry["risk"])
    pill_class = "high" if risk_value == "High Risk" else "suspicious" if risk_value == "Suspicious" else "safe"

    st.markdown(
        f"""
        <div class="detail-panel">
            <div class="monitor-label">Detailed Analysis</div>
            <div class="risk-pill {pill_class}">{risk_value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write(f"Input: `{selected_entry['input']}`")
    st.write(f"Risk Level: `{risk_value}`")
    st.write(f"Score: `{float(selected_entry['score']):.1f}`")
    st.write(f"ML Probability: `{float(selected_entry['ml_prob']):.2%}`")
    st.write("Reasons:")
    reasons = [item.strip() for item in str(selected_entry["reasons"]).split(",") if item.strip()]
    for reason in reasons:
        st.write(f"- {reason}")
    return {
        "source": "history",
        "input": str(selected_entry["input"]),
        "risk_level": risk_value,
        "risk_score": float(selected_entry["score"]),
        "ml_probability": float(selected_entry["ml_prob"]),
        "reasons": reasons,
    }


def detection_context(result, input_value: str) -> dict[str, object]:
    return {
        "source": result.source,
        "input": input_value,
        "prediction": result.prediction,
        "risk_level": result.risk_level,
        "risk_score": result.risk_score,
        "ml_probability": result.probability,
        "reasons": result.reasons[:5],
        "rule_triggers": (result.debug or {}).get("rule_triggers", [])[:5],
        "nlp_result": (result.debug or {}).get("nlp_detector", {}),
    }


def render_security_assistant(context: dict[str, object] | None) -> None:
    st.markdown("### AI Security Assistant")
    st.caption("Optional Gemini explanations. The local detection result remains the security authority.")
    if not context:
        st.info("Analyze an item or select a scan in Details to ask the assistant about that detection.")
        return

    context_key = f"{context.get('input')}|{context.get('risk_score')}|{context.get('risk_level')}"
    if st.session_state.get("assistant_context_key") != context_key:
        st.session_state.assistant_context_key = context_key
        st.session_state.assistant_history = []

    suggestions = [
        "Why was this detected as risky?",
        "Explain this threat in simple terms.",
        "What should I do now?",
        "What suspicious patterns were detected?",
        "How could an attacker use this type of attack?",
    ]
    columns = st.columns(2)
    for index, suggestion in enumerate(suggestions):
        if columns[index % 2].button(suggestion, key=f"assistant-suggestion-{index}"):
            st.session_state.assistant_question = suggestion

    question = st.text_area(
        "Ask about this detection",
        key="assistant_question",
        placeholder="Ask a security question about the selected detection.",
        height=90,
    )
    if st.button("Explain This Detection", type="secondary"):
        question = question.strip() or "Explain this detection and recommend safe next steps."
        history = st.session_state.get("assistant_history", [])
        try:
            api_key = st.secrets.get("GEMINI_API_KEY")
            model = st.secrets.get("GEMINI_MODEL")
        except Exception:
            api_key = model = None
        answer = generate_security_explanation(context, question, history, api_key=api_key, model=model)
        st.session_state.assistant_history = history + [{"question": question, "answer": answer}]

    for exchange in st.session_state.get("assistant_history", []):
        st.markdown(f"**You:** {exchange['question']}")
        st.markdown(f"**AI Security Assistant:** {exchange['answer']}")


def render_gmail_security(system: CybercrimeDetectionSystem) -> None:
    """Optional local Gmail reader; Gmail data never enters the general JSON history."""
    st.markdown("### Gmail Security")
    st.caption("Read-only Gmail access. Messages are scanned only when you request it.")
    gmail = GmailService()
    status = gmail.status()
    if not status["credentials_configured"]:
        st.info("Gmail is not configured. Add a local `credentials.json` OAuth client file to enable it.")
        return
    if not status["connected"]:
        st.warning("Gmail is not connected.")
        if st.button("Connect Gmail", key="gmail-connect"):
            try:
                profile = gmail.authenticate_gmail()
                st.session_state.gmail_profile = profile
                st.success(f"Connected: {profile['email_address']}")
            except GmailIntegrationError as exc:
                st.error(str(exc))
        return

    profile = st.session_state.get("gmail_profile")
    if profile:
        st.success(f"Gmail connected: {profile.get('email_address', 'authorized account')}")
    else:
        st.success("Gmail connected")

    scan_limit = st.number_input("Recent messages to load", min_value=1, max_value=50, value=20, key="gmail-scan-limit")
    if st.button("Load Recent Emails", key="gmail-load-recent"):
        try:
            st.session_state.gmail_messages = gmail.list_messages(int(scan_limit))
        except GmailIntegrationError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Gmail messages could not be loaded. Reconnect Gmail and try again.")

    messages = st.session_state.get("gmail_messages", [])
    if not messages:
        return
    options = [f"{item['sender']} — {item['subject'] or '(no subject)'}" for item in messages]
    selected_index = st.selectbox("Select a Gmail message", range(len(messages)), format_func=lambda index: options[index], key="gmail-message-select")
    selected_summary = messages[selected_index]
    if st.button("Load Email Details", key="gmail-load-details"):
        try:
            st.session_state.gmail_selected_email = asdict(gmail.get_message(str(selected_summary["message_id"])))
        except GmailIntegrationError as exc:
            st.error(str(exc))
        except Exception:
            st.error("Gmail message could not be loaded.")

    email_data = st.session_state.get("gmail_selected_email")
    if not email_data or email_data.get("message_id") != selected_summary["message_id"]:
        return
    st.caption(f"From: {email_data['sender']} | Received: {email_data.get('received_timestamp') or 'Unknown'}")
    st.write(f"URLs found: {len(email_data['urls'])} | Attachments: {len(email_data['attachments'])}")
    with st.expander("Email details", expanded=False):
        st.write(email_data["body"] or "No readable text body was available.")
        if email_data["attachments"]:
            st.dataframe(pd.DataFrame(email_data["attachments"]), use_container_width=True)

    if st.button("Analyze Email", type="primary", key="gmail-analyze"):
        try:
            repository = st.session_state.get("gmail_event_repository")
            if repository is None:
                repository = InMemoryEventRepository()
                st.session_state.gmail_event_repository = repository
            analyzer = GmailEmailAnalyzer(system, DetectionPipeline(system, repository), repository)
            from integrations.gmail_service import EmailInput, GmailAttachment

            email = EmailInput(
                **{
                    **email_data,
                    "attachments": [GmailAttachment(**item) for item in email_data["attachments"]],
                }
            )
            event, duplicate = analyzer.analyze(email)
            st.session_state.gmail_analysis_event = event
            st.info("This Gmail message was already analyzed in this session." if duplicate else "Email analysis complete.")
        except Exception:
            st.error("Email analysis could not be completed. The existing detector remains available.")

    event = st.session_state.get("gmail_analysis_event")
    if event and event.get("metadata", {}).get("gmail_message_id") == email_data["message_id"]:
        assessment = event.get("assessment") or {}
        st.subheader("Gmail Threat Assessment")
        st.write(f"Risk: **{assessment.get('risk_level', 'Unknown')}** | Score: **{assessment.get('risk_score', 0)}** | Confidence: **{assessment.get('confidence', 0):.0%}**")
        for reason in assessment.get("reasons", []):
            st.write(f"- {reason}")
        url_results = assessment.get("metadata", {}).get("urls", [])
        if url_results:
            st.dataframe(pd.DataFrame(url_results), use_container_width=True)


def main() -> None:
    st.set_page_config(page_title="Cybercrime Detection Dashboard", layout="wide")
    st_autorefresh(interval=3000, key="dashboard-live-refresh")
    inject_custom_css()
    st.title("Cybercrime Detection Dashboard")
    st.caption("Hybrid detection system using ML, rule engine, and reputation checks.")

    system = load_or_train_system()
    logs = load_logs()
    logs_df = logs_frame(logs)

    left, middle, right = st.columns(3)
    left.metric("Email Accuracy", f"{system.metrics.get('email', {}).get('accuracy', 0):.2%}")
    middle.metric("SMS Accuracy", f"{system.metrics.get('sms', {}).get('accuracy', 0):.2%}")
    right.metric("URL Accuracy", f"{system.metrics.get('url', {}).get('accuracy', 0):.2%}")
    st.metric("Text Accuracy", f"{system.metrics.get('text', {}).get('accuracy', 0):.2%}")

    st.markdown("### Monitoring Overview")
    filter_col, _ = st.columns([1, 4])
    selected_risk = filter_col.selectbox("Risk Filter", ["All", "High Risk", "Suspicious", "Safe"])
    filtered_logs_df = filter_logs(logs_df, selected_risk)
    filtered_logs = filtered_logs_df.to_dict(orient="records")

    render_system_stats(filtered_logs_df)
    render_plotly_charts(filtered_logs_df)

    monitor_tab, history_tab, details_tab = st.tabs(["Dashboard", "History", "Details"])
    with monitor_tab:
        render_live_alerts(filtered_logs)
    with history_tab:
        st.subheader("Scan History")
        render_scan_history(filtered_logs_df)
    with details_tab:
        st.subheader("Detailed Analysis View")
        history_context = render_detailed_view(filtered_logs_df)

    render_gmail_security(system)

    st.markdown("### Analysis Tools")

    tab1, tab2, tab3, tab4 = st.tabs(["Single Scan", "Batch Analysis", "Model Analytics", "Feature Insights"])

    with tab1:
        source = st.selectbox("Source", ["url", "email", "sms", "text"], format_func=str.upper)
        content = st.text_area("Input", height=220, placeholder="Paste URL, email body, or SMS text here.")
        if "single_scan_result" not in st.session_state:
            st.session_state.single_scan_result = None
        if st.button("Analyze Item", type="primary"):
            try:
                st.session_state.single_scan_result = system.analyze(source, content)
            except ValueError as exc:
                st.error(str(exc))
                st.session_state.single_scan_result = None

        result = st.session_state.single_scan_result
        if result is not None:
            render_prediction_card(result)
            render_explainability(result)
            st.subheader("Top Reasons")
            for reason in result.reasons[:3]:
                st.write(f"- {reason}")
            if result.debug.get("rule_triggers"):
                st.subheader("Rule Triggers")
                st.dataframe(pd.DataFrame(result.debug["rule_triggers"]), use_container_width=True)
            if source == "url" and content.strip():
                if st.button("Report False Positive / Trust This Domain"):
                    try:
                        trusted_domain = append_trusted_domain(content)
                        if system.url_predictor is not None:
                            system.url_predictor.reputation_checker.whitelist.add(trusted_domain)
                            if system.url_bundle is not None:
                                system.url_bundle.feature_extractor.trusted_domains = sorted(
                                    set(system.url_bundle.feature_extractor.trusted_domains) | {trusted_domain}
                                )
                        st.success(
                            f"Added `{trusted_domain}` to `trusted_domains.csv`. Future URL checks will treat it as trusted."
                        )
                        st.session_state.single_scan_result = system.analyze(source, content)
                    except ValueError as exc:
                        st.error(str(exc))
            if result.debug:
                with st.expander("Explainability / Debug"):
                    st.json(result.debug, expanded=False)

    with tab2:
        st.write("Upload a CSV for batch scanning. Recommended columns are `source, content`, but common alternatives like `url`, `text`, `message`, `body`, or `link` are also accepted.")
        batch_source = st.selectbox(
            "Default source for single-column files",
            ["url", "email", "sms", "text"],
            format_func=str.upper,
            key="batch-source",
        )
        sample_batch = pd.DataFrame(
            [
                {"source": "url", "content": "https://web.whatsapp.com/"},
                {"source": "email", "content": "Urgent, verify your payroll account at http://secure-payroll-check.com"},
                {"source": "sms", "content": "You won a reward. Claim now and share OTP immediately."},
                {"source": "text", "content": "Kindly send your bank OTP immediately to unlock your reward."},
            ]
        )
        st.download_button(
            "Download Sample Batch Template",
            sample_batch.to_csv(index=False).encode("utf-8"),
            file_name="sample_batch_template.csv",
            mime="text/csv",
        )

        uploaded = st.file_uploader("Upload CSV", type=["csv"], key="batch-upload")
        if uploaded is not None:
            batch_df = pd.read_csv(uploaded)
            if batch_df.empty:
                st.warning("Uploaded CSV is empty. Please upload a file with at least one row.")
            st.dataframe(batch_df.head(10), use_container_width=True)
            if st.button("Run Batch Scan"):
                try:
                    results_df = system.analyze_batch(batch_df, default_source=batch_source)
                    st.dataframe(results_df, use_container_width=True)
                    threat_rate = (results_df["prediction"].eq("Threat").mean() * 100) if not results_df.empty else 0
                    st.metric("Threat Rate", f"{threat_rate:.2f}%")
                    pie_df = pie_data(results_df["prediction"])
                    st.subheader("Threat vs Safe Pie Chart")
                    st.vega_lite_chart(
                        pie_df,
                        {
                            "mark": {"type": "arc", "innerRadius": 40},
                            "encoding": {
                                "theta": {"field": "count", "type": "quantitative"},
                                "color": {"field": "label", "type": "nominal"},
                                "tooltip": [{"field": "label"}, {"field": "count"}],
                            },
                        },
                        use_container_width=True,
                    )
                    st.download_button(
                        "Download Results",
                        results_df.to_csv(index=False).encode("utf-8"),
                        file_name="cybercrime_batch_results.csv",
                        mime="text/csv",
                    )
                except Exception as exc:
                    st.error(f"Batch scan failed: {exc}")
                    st.info("Use columns like `source, content` or upload a single-column CSV and choose the default source above.")

    with tab3:
        comparison_df = metrics_frame(system)
        st.subheader("Model Comparison")
        st.dataframe(comparison_df, use_container_width=True)
        st.bar_chart(comparison_df.set_index("Source")[["Accuracy", "Precision", "Recall", "F1"]])

        st.subheader("Threat vs Safe Mix")
        mix_df = pd.DataFrame(
            [
                {"source": source.upper(), "safe": metrics["class_distribution"].get("safe", 0), "threat": metrics["class_distribution"].get("threat", 0)}
                for source, metrics in system.metrics.items()
            ]
        )
        st.bar_chart(mix_df.set_index("source"))

    with tab4:
        url_metrics = system.metrics.get("url", {})
        feature_importance = pd.DataFrame(url_metrics.get("feature_importance", []))
        if not feature_importance.empty:
            st.subheader("Top URL Feature Importances")
            st.bar_chart(feature_importance.set_index("feature"))
        comparison = pd.DataFrame(url_metrics.get("model_comparison", []))
        if not comparison.empty:
            st.subheader("URL Model Comparison")
            st.dataframe(comparison, use_container_width=True)
            st.bar_chart(comparison.set_index("model")[["accuracy", "precision", "recall", "f1"]])

    manual_context = detection_context(result, content) if result is not None else None
    render_security_assistant(manual_context or history_context)


if __name__ == "__main__":
    main()
