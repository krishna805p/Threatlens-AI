from __future__ import annotations

from typing import Dict, List

from api_checker import URLReputationChecker
from feature_extraction import COMMON_SAFE_TLDS, EXTENDED_TRUSTED_DOMAINS, SUSPICIOUS_KEYWORDS, is_valid_url, prepare_model_features
from model_training import URLModelBundle
from rule_engine import RuleEngine
from scoring_engine import RiskScoringEngine


class URLPredictor:
    def __init__(self, bundle: URLModelBundle) -> None:
        self.bundle = bundle
        merged_trusted_domains = set(getattr(bundle.feature_extractor, "trusted_domains", []))
        merged_trusted_domains.update(EXTENDED_TRUSTED_DOMAINS)
        self.bundle.feature_extractor.trusted_domains = sorted(merged_trusted_domains)
        self.rule_engine = RuleEngine()
        self.reputation_checker = URLReputationChecker(whitelist=self.bundle.feature_extractor.trusted_domains)
        self.scoring_engine = RiskScoringEngine()

    def __setstate__(self, state):
        self.__dict__.update(state)
        merged_trusted_domains = set(getattr(self.bundle.feature_extractor, "trusted_domains", []))
        merged_trusted_domains.update(EXTENDED_TRUSTED_DOMAINS)
        self.bundle.feature_extractor.trusted_domains = sorted(merged_trusted_domains)
        if not hasattr(self, "rule_engine"):
            self.rule_engine = RuleEngine()
        self.reputation_checker = URLReputationChecker(whitelist=self.bundle.feature_extractor.trusted_domains)
        if not hasattr(self, "scoring_engine"):
            self.scoring_engine = RiskScoringEngine()

    def predict(self, url: str) -> Dict[str, object]:
        if not str(url or "").strip():
            raise ValueError("Input is empty. Please enter a URL to analyze.")
        if not is_valid_url(url):
            raise ValueError("Invalid URL format. Please enter a valid HTTP or HTTPS URL.")

        features = self.bundle.feature_extractor.extract(url)
        registered_domain = str(features["registered_domain"])
        reputation = self.reputation_checker.check(url, registered_domain)
        if reputation["status"] == "safe_override":
            return {
                "prediction": "Safe",
                "probability": 0.01,
                "risk_score": 0,
                "risk_level": "Safe",
                "reasons": reputation["reasons"][:3],
                "debug": {
                    "features": features,
                    "decision_reason": "Trusted domain override",
                    "model_probability": 0.01,
                    "rule_triggers": [],
                    "reputation": reputation,
                    "ml_model": self.bundle.model_name,
                },
            }

        encoded = self.bundle.vectorizer.transform([prepare_model_features(features)])
        probability = float(self.bundle.classifier.predict_proba(encoded)[0][self._positive_class_index()])
        rule_result = self.rule_engine.evaluate(features)
        api_score = 1.0 if reputation["status"] in {"api_malicious_override", "malicious_override"} else max(0.0, reputation["score_adjustment"] / 6.0)
        scoring = self.scoring_engine.score(
            ml_probability=probability,
            rule_score=rule_result["rule_score"],
            api_score=api_score,
            nlp_score=0,
        )
        final_score = scoring["risk_score"]
        benign_profile = self._is_benign_https_profile(features, rule_result, reputation, probability)

        if reputation["status"] == "malicious_override":
            prediction = "Threat"
        elif reputation["status"] == "api_malicious_override":
            prediction = "Threat"
            final_score = 10
        elif benign_profile:
            prediction = "Safe"
            final_score = min(final_score, 3)
        else:
            prediction = scoring["decision"] if probability < 0.55 else "Threat"

        reasons = self._build_explanations(features, probability, rule_result, reputation)[:3]
        if benign_profile:
            reasons = ["Benign HTTPS/common-domain profile reduced false-positive risk."] + reasons
        decision_reason = reasons[0] if reasons else "Hybrid score decision"

        return {
            "prediction": prediction,
            "probability": probability,
            "risk_score": int(final_score),
            "risk_level": self._risk_level(int(final_score)),
            "reasons": reasons or ["No strong phishing indicators were detected."],
            "debug": {
                "features": features,
                "decision_reason": decision_reason,
                "model_probability": probability,
                "scoring_components": scoring["components"],
                "rule_score": rule_result["rule_score"],
                "rule_triggers": rule_result["triggered_rules"],
                "reputation": reputation,
                "api_result": reputation.get("api_result"),
                "ml_model": self.bundle.model_name,
            },
        }

    def _build_explanations(
        self,
        features: Dict[str, object],
        probability: float,
        rule_result: Dict[str, object],
        reputation: Dict[str, object],
    ) -> List[str]:
        reasons: List[str] = []
        if reputation["reasons"]:
            reasons.extend(reputation["reasons"])
        reasons.extend(rule_result["reasons"])
        if probability >= 0.75:
            reasons.append("Machine learning model assigned a high phishing probability.")
        elif probability >= 0.55:
            reasons.append("Machine learning model assigned a moderately elevated phishing probability.")
        if int(features["suspicious_keyword_count"]) > 0:
            matched_keywords = [keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in str(features["url"]).lower()]
            reasons.append(f"Suspicious keywords present: {', '.join(matched_keywords[:5])}.")
        if not reasons:
            reasons.append("No critical phishing indicators detected across ML, rules, or reputation checks.")
        return reasons

    @staticmethod
    def _is_benign_https_profile(
        features: Dict[str, object],
        rule_result: Dict[str, object],
        reputation: Dict[str, object],
        probability: float,
    ) -> bool:
        return (
            reputation["status"] == "neutral"
            and int(features.get("uses_https", 0)) == 1
            and int(features.get("has_ip_address", 0)) == 0
            and int(features.get("suspicious_keyword_count", 0)) == 0
            and str(features.get("tld", "")).lower() in COMMON_SAFE_TLDS
            and int(rule_result.get("rule_score", 0)) <= 1
            and float(probability) < 0.72
        )

    @staticmethod
    def _risk_level(score: int) -> str:
        if score >= 8:
            return "High Risk"
        if score >= 4:
            return "Suspicious"
        return "Safe"

    def _positive_class_index(self) -> int:
        if hasattr(self.bundle.classifier, "classes_"):
            classes = list(self.bundle.classifier.classes_)
            if "threat" in classes:
                return classes.index("threat")
        return self.bundle.class_labels.index("threat")
