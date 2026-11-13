"""Backend system loader and initialization module."""

from __future__ import annotations

import pickle
import subprocess
import sys
from pathlib import Path
from typing import Any

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_FILE = BASE_DIR / "models" / "detector.pkl"


def load_or_train_system() -> Any:
    """Backend-safe system loader without Streamlit UI dependencies."""
    if MODEL_FILE.exists():
        with MODEL_FILE.open("rb") as model_file:
            system = pickle.load(model_file)
        if getattr(system, "is_trained", False):
            return system

    subprocess.run([sys.executable, "training/train.py"], cwd=BASE_DIR, check=True)
    with MODEL_FILE.open("rb") as model_file:
        return pickle.load(model_file)
