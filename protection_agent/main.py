from __future__ import annotations

import sys
import threading
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from .api_client import BackendApiClient
    from .clipboard_monitor import ClipboardMonitor
    from .config import AgentConfig
    from .nlp_model import NLPModel
    from .notifier import DesktopNotifier
    from .tray_app import TrayApplication
except ImportError:
    from api_client import BackendApiClient
    from clipboard_monitor import ClipboardMonitor
    from config import AgentConfig
    from nlp_model import NLPModel
    from notifier import DesktopNotifier
    from tray_app import TrayApplication
from log_utils import build_log_entry


class CybercrimeProtectionAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        self.notifier = DesktopNotifier(config.app_name)
        self.api_client = BackendApiClient(config)
        self.nlp_model = NLPModel(config)
        self.nlp_model.load_or_train()
        self.clipboard_monitor = ClipboardMonitor(config, self._handle_clipboard_content)
        self._lock = threading.Lock()
        self._last_notified_signature = ""

    def start_monitoring(self) -> None:
        self.clipboard_monitor.start()

    def stop_monitoring(self) -> None:
        self.clipboard_monitor.stop()

    def shutdown(self) -> None:
        self.stop_monitoring()

    def status_text(self) -> str:
        state = "ON" if self.clipboard_monitor.is_running else "OFF"
        return f"Clipboard monitoring is {state}. Backend: {self.config.backend_predict_url}"

    def show_status_notification(self) -> None:
        self.notifier.show(self.config.app_name, self.status_text())

    def _handle_clipboard_content(self, clipboard_text: str, extracted_url: str | None) -> None:
        input_data = extracted_url or clipboard_text
        self.process_input(input_data=input_data, raw_text=clipboard_text, extracted_url=extracted_url)

    def process_input(self, input_data: str, raw_text: str, extracted_url: str | None = None) -> None:
        result = self._predict_input(input_data=input_data, raw_text=raw_text, extracted_url=extracted_url)
        if result is None:
            return
        print(f"[ProtectionAgent] RESULT: {result}")
        self.log_to_dashboard(result)
        self.trigger_alert(result)

    def _predict_input(self, input_data: str, raw_text: str, extracted_url: str | None = None) -> dict | None:
        if extracted_url:
            prediction = self.api_client.predict_url(extracted_url)
            if prediction is None:
                print(f"[ProtectionAgent] API failure while checking URL: {extracted_url}")
                return None
            return build_log_entry(
                input_value=extracted_url,
                risk=prediction.risk_level,
                score=prediction.risk_score,
                ml_prob=prediction.ml_probability,
                reasons=prediction.reasons,
            )

        text = raw_text.strip()
        if not text:
            return

        prediction = self.nlp_model.analyze_text(text)
        if prediction.scam_probability >= self.config.nlp_alert_threshold:
            risk_level = "High Risk"
        elif prediction.scam_probability >= 0.45:
            risk_level = "Suspicious"
        else:
            risk_level = "Safe"

        return build_log_entry(
            input_value=text,
            risk=risk_level,
            score=round(prediction.scam_probability * 10, 2),
            ml_prob=prediction.scam_probability,
            reasons=[
                "Local NLP scam detector analyzed copied text.",
                f"Predicted label: {prediction.label}",
            ],
        )

    def log_to_dashboard(self, result: dict) -> None:
        self.api_client.log_to_dashboard(result)

    def trigger_alert(self, result: dict) -> None:
        if result["risk"].lower() != "high risk":
            return

        signature = result.get("input", "")
        with self._lock:
            if signature == self._last_notified_signature:
                return
            self._last_notified_signature = signature

        primary_reason = result.get("reasons", ["Dangerous content detected"])[0]
        message = (
            f"{result.get('input', '')}\n"
            f"Risk: {result.get('risk', 'Unknown')} ({float(result.get('score', 0.0)):.1f}/10)\n"
            f"{primary_reason}"
        )
        print(f"[ProtectionAgent] ALERT TRIGGER: {message}")
        self.notifier.show("Cyber Alert", message, popup=True)


def main() -> None:
    config = AgentConfig()
    controller = CybercrimeProtectionAgent(config)
    if config.start_monitoring_on_launch:
        controller.start_monitoring()
    TrayApplication(controller).run()


if __name__ == "__main__":
    main()
