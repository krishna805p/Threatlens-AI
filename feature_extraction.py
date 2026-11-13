from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List
from urllib.parse import urlparse

import tldextract


SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "secure",
    "update",
    "bank",
    "signin",
    "account",
    "password",
    "wallet",
    "otp",
    "pay",
    "billing",
    "confirm",
]

BASE_DIR = Path(__file__).resolve().parent
TRUSTED_DOMAINS_FILE = BASE_DIR / "config" / "trusted_domains.csv"

TRUSTED_DOMAINS = [
    "google.com",
    "whatsapp.com",
    "amazon.com",
    "microsoft.com",
    "facebook.com",
]

def load_trusted_domains() -> List[str]:
    if not TRUSTED_DOMAINS_FILE.exists():
        return []

    trusted_domains: List[str] = []
    try:
        raw_lines = TRUSTED_DOMAINS_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []

    for raw_line in raw_lines:
        value = raw_line.strip().rstrip(".").lower()
        if not value or value.startswith("#") or value == "domain":
            continue
        trusted_domains.append(value)
    return trusted_domains


def append_trusted_domain(url_or_domain: str) -> str:
    normalized_value = str(url_or_domain or "").strip().lower()
    if not normalized_value:
        raise ValueError("URL or domain is empty.")

    candidate = normalized_value
    if "://" in candidate or "/" in candidate:
        candidate = get_registered_domain(normalize_url(candidate))

    candidate = candidate.strip().rstrip(".").lower()
    if not candidate:
        raise ValueError("Could not extract a valid registered domain.")

    existing_domains = set(load_trusted_domains())
    if candidate in existing_domains:
        return candidate

    lines = ["domain", *sorted(existing_domains | {candidate})]
    TRUSTED_DOMAINS_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return candidate


EXTENDED_TRUSTED_DOMAINS = sorted(set(TRUSTED_DOMAINS + [
    "youtube.com",
    "youtu.be",
    "github.com",
    "apple.com",
    "linkedin.com",
    "wikipedia.org",
    "openai.com",
    "spotify.com",
    "fancode.com",
    "examly.io",
    "lpu.in",
    "telegram.org",
    "slack.com",
    "discord.com",
    "coursera.org",
    "geeksforgeeks.org",
    "hackerrank.com",
    "leetcode.com",
    "codechef.com",
    "docs.google.com",
    "drive.google.com",
    "grammarly.com",
    "blitz.cloud",
] + load_trusted_domains()))

COMMON_SAFE_TLDS = {"com", "org", "edu", "gov", "net", "co", "in"}
SPECIAL_CHAR_PATTERN = re.compile(r"[@\-_?&=%#+]")
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None, cache_dir=None)
MODEL_FEATURE_KEYS = [
    "tld",
    "url_length",
    "hostname_length",
    "registered_domain_length",
    "path_length",
    "query_length",
    "dot_count",
    "subdomain_count",
    "slash_count",
    "digit_count",
    "digit_ratio",
    "special_char_count",
    "at_symbol_count",
    "hyphen_count",
    "underscore_count",
    "percent_count",
    "question_count",
    "ampersand_count",
    "equals_count",
    "uses_https",
    "has_ip_address",
    "has_special_chars",
    "suspicious_keyword_count",
    "has_suspicious_keyword",
    "trusted_domain",
    "domain_age_days_mock",
    "popularity_score_mock",
    "hostname_entropy",
    "path_entropy",
]


def normalize_url(url: str) -> str:
    cleaned = str(url or "").strip()
    if not cleaned:
        return ""
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"http://{cleaned}"
    return cleaned


def is_valid_url(raw_url: str) -> bool:
    raw_value = str(raw_url or "").strip()
    if not raw_value or any(char.isspace() for char in raw_value):
        return False
    normalized = normalize_url(raw_url)
    if not normalized:
        return False
    parsed = safe_urlparse(normalized)
    hostname = parsed.netloc.split("@")[-1].split(":")[0].lower()
    if not hostname or hostname == "invalid.local":
        return False
    if parsed.scheme not in {"http", "https"}:
        return False
    return True


def safe_urlparse(url: str):
    try:
        return urlparse(url)
    except ValueError:
        return urlparse("http://invalid.local")


def get_domain_parts(url: str) -> tuple[str, str, str]:
    try:
        extracted = EXTRACTOR(url)
        subdomain = extracted.subdomain.lower()
        domain = extracted.domain.lower()
        suffix = extracted.suffix.lower()
    except Exception:
        subdomain, domain, suffix = "", "", ""
    return subdomain, domain, suffix


def get_registered_domain(url: str) -> str:
    subdomain, domain, suffix = get_domain_parts(url)
    if domain and suffix:
        return f"{domain}.{suffix}"
    return domain or suffix or ""


def get_hostname(url: str) -> str:
    parsed = safe_urlparse(url)
    return parsed.netloc.split("@")[-1].split(":")[0].lower()


def is_ip_host(hostname: str) -> bool:
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@dataclass
class URLFeatureExtractor:
    trusted_domains: List[str] = field(default_factory=lambda: list(EXTENDED_TRUSTED_DOMAINS))

    def is_trusted_domain(self, registered_domain: str) -> bool:
        clean_domain = str(registered_domain or "").strip().rstrip(".").lower()
        if "://" in clean_domain or "/" in clean_domain:
            clean_domain = get_registered_domain(normalize_url(clean_domain))

        merged_trusted_domains = {domain.strip().rstrip(".").lower() for domain in EXTENDED_TRUSTED_DOMAINS}
        merged_trusted_domains.update(domain.strip().rstrip(".").lower() for domain in load_trusted_domains())
        merged_trusted_domains.update(domain.strip().rstrip(".").lower() for domain in self.trusted_domains)

        if clean_domain in merged_trusted_domains:
            return True

        extracted_reg = get_registered_domain(f"http://{clean_domain}")
        if extracted_reg and extracted_reg in merged_trusted_domains:
            if clean_domain == extracted_reg or clean_domain.endswith(f".{extracted_reg}"):
                return True

        return False

    def mock_domain_age_days(self, registered_domain: str, suspicious_keyword_count: int) -> int:
        if self.is_trusted_domain(registered_domain):
            return 3650
        if suspicious_keyword_count >= 2:
            return 45
        if registered_domain.endswith(".gov") or registered_domain.endswith(".edu"):
            return 2500
        return 720

    def mock_popularity_score(self, registered_domain: str, tld: str) -> int:
        if self.is_trusted_domain(registered_domain):
            return 98
        if tld in COMMON_SAFE_TLDS:
            return 62
        return 28

    def extract(self, raw_url: str) -> Dict[str, object]:
        url = normalize_url(raw_url)
        hostname = get_hostname(url)
        subdomain, domain, suffix = get_domain_parts(url)
        registered_domain = get_registered_domain(url)
        parsed = safe_urlparse(url)
        path = parsed.path or ""
        query = parsed.query or ""
        special_chars = SPECIAL_CHAR_PATTERN.findall(url)
        suspicious_keyword_count = sum(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS)

        feature_map: Dict[str, object] = {
            "url": url,
            "hostname": hostname,
            "domain_name": domain,
            "registered_domain": registered_domain,
            "subdomain": subdomain,
            "tld": suffix or "unknown",
            "url_length": len(url),
            "hostname_length": len(hostname),
            "registered_domain_length": len(registered_domain),
            "path_length": len(path),
            "query_length": len(query),
            "dot_count": url.count("."),
            "number_of_dots": url.count("."),
            "subdomain_count": len([part for part in subdomain.split(".") if part]) if subdomain else 0,
            "slash_count": url.count("/"),
            "digit_count": sum(character.isdigit() for character in url),
            "digit_ratio": sum(character.isdigit() for character in url) / max(len(url), 1),
            "special_char_count": len(special_chars),
            "special_character_count": len(special_chars),
            "at_symbol_count": url.count("@"),
            "hyphen_count": url.count("-"),
            "underscore_count": url.count("_"),
            "percent_count": url.count("%"),
            "question_count": url.count("?"),
            "ampersand_count": url.count("&"),
            "equals_count": url.count("="),
            "uses_https": int(parsed.scheme == "https"),
            "has_ip_address": int(is_ip_host(hostname)),
            "has_special_chars": int(bool(special_chars)),
            "suspicious_keyword_count": suspicious_keyword_count,
            "has_suspicious_keyword": int(suspicious_keyword_count > 0),
            "trusted_domain": int(self.is_trusted_domain(registered_domain)),
            "domain_in_whitelist": int(self.is_trusted_domain(registered_domain)),
            "domain_age_days_mock": self.mock_domain_age_days(registered_domain, suspicious_keyword_count),
            "popularity_score_mock": self.mock_popularity_score(registered_domain, suffix or "unknown"),
            "hostname_entropy": round(shannon_entropy(hostname), 4),
            "entropy": round(shannon_entropy(hostname), 4),
            "path_entropy": round(shannon_entropy(path), 4),
        }
        return feature_map


def prepare_model_features(extracted_features: Dict[str, object]) -> Dict[str, object]:
    return {key: extracted_features[key] for key in MODEL_FEATURE_KEYS}
