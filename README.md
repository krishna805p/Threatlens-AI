# AI-Based Cybercrime Detection System

This project detects cybercrime threats from three different data sources:

- Email content
- URLs
- SMS messages

It combines machine learning and rule-based risk signals to classify each input as `Safe` or `Threat`, estimate a threat probability, and explain why the item was flagged.

## Features

- Multi-page SOC Threat Intelligence Dashboard built with React.js, Vite, and Tailwind CSS
- Email classifier trained on phishing and ham email datasets
- SMS classifier trained on bundled sample SMS fraud data
- URL classifier trained on engineered URL structure features
- Batch CSV analysis for project demonstrations
- Risk score, risk level, and explanation panel for every prediction

## Project Layout

- `frontend/` — React.js + Vite SOC dashboard Single Page Application.
- `backend_api.py` / `main.py` — FastAPI API service entry point (`http://127.0.0.1:8000`).
- Root prediction modules — retained at the top level because the saved `detector.pkl` references their module names while loading.
- `models/detector.pkl` — trained runtime model.
- `config/trusted_domains.csv` — editable trusted-domain configuration.
- `logs/` — local scan history; ignored by Git.
- `chrome_extension/` — browser extension.
- `protection_agent/` — Windows clipboard-monitoring agent.
- `training/` — optional retraining script, source datasets, and generated training artifacts; datasets and artifacts are ignored by Git.
- `tests/` - unit and pipeline tests.

## Platform Architecture

The current phishing product is the stable foundation for a broader cybersecurity platform. The planned modular expansion, compatibility constraints, and safe implementation order are documented in [ARCHITECTURE.md](ARCHITECTURE.md). This plan does not alter the current detector or its API contracts.

## Training Data

Raw datasets are intentionally excluded from Git so the repository stays small and does not include large training files. They are only needed when running `python training/train.py`; the included trained model is enough to run the application.

## How To Run

1. Install Python backend dependencies:

```powershell
pip install -r requirements.txt
```

2. Start the FastAPI backend server (`http://127.0.0.1:8000`):

```powershell
python main.py
```

3. Install React frontend dependencies and start the Vite dev server (`http://localhost:5173`):

```powershell
cd frontend
npm install
npm run dev
```

## Optional Gmail Security (local development)

Gmail is an explicit, read-only input source. It is not polled automatically and it never stores a Gmail password. To enable it locally:

1. In Google Cloud Console, create/select a project, enable the Gmail API, configure the OAuth consent screen, and create an OAuth client of type **Desktop app**.
2. Download the OAuth client JSON and place it at `.secrets/credentials.json` in the project root. This file is ignored by Git.
3. Install the root requirements and start the app. In **Gmail Security**, select **Connect Gmail** and complete Google authorization in the browser.
4. The local refresh token is stored at `.secrets/gmail_token.json`, also ignored by Git. The only requested scope is `https://www.googleapis.com/auth/gmail.readonly`.

The installed-app OAuth callback uses a local browser and loopback server, so this implementation is for local development. Do not upload `credentials.json` or a refresh token to Streamlit Community Cloud. A production deployment needs a separately designed web-server OAuth flow and secure server-side token store.

## Batch Input Format

Upload a CSV file with these columns:

```csv
source,content
email,"Urgent, verify your account at http://secure-payroll-check.com"
sms,"You won a reward. Claim now and share OTP immediately."
url,"https://www.wikipedia.org"
```

## Suggested Project Title

AI-Based Cybercrime Detection System Using Multi-Source Data (Email, URL, SMS)

## Suggested Abstract

This project presents an AI-based cybercrime detection system that analyzes multiple digital communication sources, including emails, URLs, and SMS messages, to identify possible cyber threats. The system uses machine learning models trained on phishing and legitimate communication data, along with feature engineering for suspicious URL patterns. A unified dashboard allows users to perform single-message analysis and batch detection through CSV uploads. The model produces threat predictions, probability scores, risk levels, and interpretable reasons for each result, making it useful for cyber awareness, academic demonstration, and early threat screening.
