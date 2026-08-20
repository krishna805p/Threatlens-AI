# Platform Architecture Plan

## Scope and compatibility rule

This document is an architecture plan for evolving the project into an **AI-Powered Multi-Source Cyber Threat Detection, Intelligence and Endpoint Monitoring Platform**. It does not implement a new detector, change a score, retrain a model, change an API response, or move a compatibility-sensitive module.

The deployed `models/detector.pkl` pickle imports the following modules by their current root-level names: `api_checker`, `feature_extraction`, `model`, `model_training`, `nlp_detector`, `nlp_engine`, `predictor`, `rule_engine`, and `scoring_engine`. Those files must stay in place until a deliberate, tested model migration is performed.

## Pipeline foundation now present

The initial, lightweight pipeline foundation is implemented in `pipeline/` without changing the existing detection path:

- `contracts.py` defines `SecurityEvent`, `ThreatAssessment`, event states, enrichment states, and priorities.
- `normalization.py` provides shared transport validation for the current `url`, `email`, `sms`, and `text` sources.
- `service.py` wraps the existing `CybercrimeDetectionSystem` and carries its exact risk score, probability, reasons, and rule triggers into an event assessment.
- `repository.py` provides a bounded, lock-protected in-memory repository. It is intentionally separate from `logs.json`; a durable SQLite/PostgreSQL repository can replace it later.
- `queue.py` provides a replaceable bounded priority-queue contract with timeouts, capped retries, and per-worker circuit breakers. No worker is started because no deep-analysis module exists yet.
- `backend_api.py` adds opt-in `POST /api/v1/events` and `GET /api/v1/events/{event_id}`. Existing `/predict`, `/log`, and other endpoints are unchanged.

The new event endpoint performs the existing local fast detection synchronously, then returns the initial event. Future deep enrichment belongs in registered background workers, not in this request path.

## Current architecture

```text
Browser extension / Windows protection agent / Streamlit manual scan
                              |
                              v
                    FastAPI (`backend_api.py`)
                              |
                              v
        `CybercrimeDetectionSystem` (`model.py`)
          | URL ML + features + rules + reputation
          | Email/SMS/text TF-IDF + NLP indicators
          v
      `DetectionResult` + existing risk score and reasons
          |                         |
          v                         v
  JSON scan history          Streamlit dashboard
  (`logs/logs.json`)         (`dashboard.py`)
```

Existing components:

- `backend_api.py` preserves `/health`, `/analyze`, `/predict`, `/feedback/false-positive`, `/log`, and `/batch`.
- `model.py` owns the runtime multi-source pipeline and the current `DetectionResult` structure.
- `predictor.py`, `feature_extraction.py`, `rule_engine.py`, `scoring_engine.py`, and `api_checker.py` form the URL analysis path.
- `nlp_detector.py` and `nlp_engine.py` support textual threat signals.
- `log_utils.py` writes compatible local JSON history used by the dashboard and protection agent.
- `chrome_extension/` and `protection_agent/` remain independent clients of the existing API/logging contract.
- `gemini_assistant.py` is an optional, user-invoked explanation layer only; it is not a classifier and is not part of the detection path.

## Target modular architecture

The future structure should add stable boundaries while retaining a legacy compatibility layer during migration:

```text
project/
├── backend/                         # Added only as new API modules are implemented
│   ├── api/
│   │   ├── routes/                   # future detect, intelligence, incident routes
│   │   └── dependencies.py
│   ├── detectors/
│   │   ├── phishing/                 # adapters to the existing root modules first
│   │   ├── email/                    # planned
│   │   ├── scam/                     # planned
│   │   ├── file/                     # planned; static inspection only
│   │   ├── malware/                  # planned; deeper executable static analysis
│   │   ├── endpoint/                 # planned
│   │   └── network/                  # planned
│   ├── intelligence/                 # planned provider interfaces and implementations
│   ├── risk/                         # planned unified-risk adapter
│   ├── services/                     # planned event/logging/storage services
│   ├── schemas/                      # planned shared public result/event schemas
│   └── main.py                       # future versioned API application
├── dashboard/                        # future Streamlit views/components when a safe UI split is needed
├── compatibility/                    # future adapters only; never duplicate detector logic
├── models/                           # current detector.pkl remains here
├── training/                         # current optional training workflow remains here
├── chrome_extension/                 # unchanged client
├── protection_agent/                 # unchanged client
├── tests/
│   ├── unit/                         # planned detector/risk/intelligence tests
│   └── integration/                  # planned API/dashboard/agent contract tests
├── backend_api.py                    # existing API compatibility entry point
├── dashboard.py                      # existing UI compatibility entry point
└── [existing root detector modules]  # retained while detector.pkl relies on them
```

Do not create empty packages merely to resemble this tree. Create each package together with its first real module and focused tests.

## Common contracts for future modules

All new detectors should return a shared `ThreatAssessment` contract before reaching the unified risk layer:

```text
ThreatAssessment
├── threat_type        # phishing, email, scam, file, malware, endpoint, network
├── source             # url, email, sms, clipboard, file, process, connection
├── risk_level
├── risk_score
├── confidence
├── indicators         # structured machine-readable evidence
├── reasons            # safe human-readable explanation
├── metadata           # non-sensitive detector-specific facts
└── timestamp
```

The current `DetectionResult` remains unchanged. A future phishing adapter converts it to `ThreatAssessment`; this permits new modules to use the contract without forcing a risky rewrite.

Future persistent records should use a separate `SecurityEvent` contract:

```text
SecurityEvent
├── event_id, timestamp, source, input_type, input_reference
├── threat_type, severity, confidence, indicators
├── assessment
└── status             # new, investigating, resolved
```

`input_reference` must be a safe reference, hash, or redacted value when raw content is sensitive. Continue using the JSON log format until a storage migration is designed and tested. A later repository can implement a storage interface with SQLite locally and PostgreSQL in deployment.

## Detector and intelligence boundaries

| Boundary | Responsibility | Status |
| --- | --- | --- |
| Phishing | Existing URL ML, features, rules, reputation, risk scoring | Existing; preserve |
| Email | Sender/subject/body analysis, URL reuse, attachment metadata | Planned |
| Scam | SMS/chat/clipboard NLP and URL reuse | Planned |
| File | Hash, type, size, entropy, metadata, strings; never execute input | Planned |
| Malware | Executable/PE static analysis only, separate from general file checks | Planned |
| Endpoint | Process/startup/file/browser/clipboard signals with least privilege | Planned |
| Network | Connection/DNS/domain anomalies and reputation signals | Planned |
| Password | Local strength/entropy/common-password checks; never persist or send plaintext | Planned |
| Intelligence | Provider interface for URL/domain/IP/hash/feed lookups | Planned |

Future `ThreatIntelProvider` implementations should expose `check_url`, `check_domain`, `check_ip`, and `check_hash`. Detectors consume provider results through that interface, so VirusTotal, Google Safe Browsing, or other providers remain replaceable. Existing URL reputation code remains unchanged until it is intentionally adapted.

## Unified risk and assistant boundaries

The future risk engine consumes weighted evidence rather than blindly averaging values:

```text
Detector assessments + local ML/NLP + rules + intelligence + behavioural signals
                                  |
                                  v
                       Unified risk assessment
                                  |
                  ┌───────────────┴────────────────┐
                  v                                v
          Security event/incidents          Optional AI explanation
```

The current phishing risk calculation remains authoritative for existing requests. A future unified-risk adapter must initially preserve that output exactly, then add other evidence only for new detector types. AI explanation services receive only a completed assessment; they never classify, override, or alter its score.

## API and dashboard migration path

Keep the current endpoints and their response fields unchanged. Add future versioned endpoints alongside them only when their underlying detectors exist:

```text
/api/v1/detect/url, /api/v1/detect/text, /api/v1/detect/email, /api/v1/detect/file
/api/v1/detect/password, /api/v1/endpoint/events, /api/v1/network/events
/api/v1/intelligence, /api/v1/incidents, /api/v1/health
```

The existing Streamlit dashboard remains the live interface. Its later SOC-style sections can be Overview, Threats, Threat Intelligence, Incidents, AI Security Assistant, and System Monitoring. Each section should consume shared assessment/event contracts, not detector-private structures.

## Safe implementation order

1. Add schemas and a phishing adapter with unit/contract tests; compare every converted result to the original result.
2. Add versioned API routes while retaining `/predict`, `/log`, and existing agent/extension configuration.
3. Add event-storage abstraction, then an opt-in SQLite migration with JSON-log import tooling.
4. Add one new detector at a time with static, privacy-preserving inputs and focused tests.
5. Add dashboard views only for modules that return real assessments.

At every step: validate input, redact sensitive values in logs, use environment variables for credentials, never execute uploaded files, and maintain least privilege for endpoint monitoring.

## Files moved, removed, and created by this architecture task

- Moved: none. Root detector modules deliberately remain in place for pickle compatibility.
- Removed: none.
- Created: this `ARCHITECTURE.md` design document.
