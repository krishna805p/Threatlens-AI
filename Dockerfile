# ThreatLens AI — Production Backend Dockerfile
# Base: Debian-based Python 3.11 Slim (Minimal footprint, ₹0 budget compatible)
FROM python:3.11-slim

# Prevent Python from writing .pyc files and enable unbuffered standard I/O
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    DISTILBERT_PYTHON_BIN=/usr/local/bin/python

WORKDIR /app

# Install system dependencies (curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch and Transformers first (isolated layer, saves ~2.5GB vs CUDA)
RUN pip install --no-cache-dir --timeout 300 --retries 10 torch --index-url https://download.pytorch.org/whl/cpu \
    && pip install --no-cache-dir --timeout 300 --retries 10 transformers

# Copy requirements and install exact production backend dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --timeout 300 --retries 10 -r requirements.txt

# Create runtime directories for persistent volume mounts (.secrets and logs)
RUN mkdir -p /app/.secrets /app/logs /app/models /app/config \
    /app/training/gmail_classifier/outputs/phase_2_7_commercial

# Copy production backend source files
COPY backend_api.py main.py model.py predictor.py scoring_engine.py rule_engine.py \
     feature_extraction.py api_checker.py log_utils.py nlp_detector.py nlp_engine.py \
     gemini_assistant.py model_training.py ./

# Copy configuration and trained model artifacts
COPY config/ config/
COPY models/detector.pkl models/detector.pkl
COPY pipeline/ pipeline/
COPY integrations/ integrations/

# Copy DistilBERT worker script and verified Phase 2.7 commercial best_checkpoint
COPY training/gmail_classifier/outputs/phase_2_7_commercial/distilbert_worker.py \
     training/gmail_classifier/outputs/phase_2_7_commercial/distilbert_worker.py
COPY training/gmail_classifier/outputs/phase_2_7_commercial/best_checkpoint/ \
     training/gmail_classifier/outputs/phase_2_7_commercial/best_checkpoint/

# Expose backend port
EXPOSE 8000

# Health check using existing FastAPI /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8000}/health || exit 1

# Start production Uvicorn server bound to 0.0.0.0 and dynamic container PORT
CMD ["sh", "-c", "uvicorn backend_api:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]
