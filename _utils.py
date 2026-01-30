import os
from dataclasses import dataclass
from pathlib import Path

import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials

from _logger import setup_logger

load_dotenv()

logger = setup_logger(__name__)


@dataclass(frozen=True)
class AppConfig:
    # Remote Config
    firebase_key_path: str
    firebase_bucket: str
    firebase_collection: str = "infected_files"

    # Local Path Config
    uploaded_archive: Path = Path(os.getenv("UPLOAD_PATH", "uploaded_archive"))
    virus_samples_dir: Path = Path(os.getenv("SAMPLES_PATH", "generated_samples"))
    template_virus_path: Path = Path(
        os.getenv("TEMPLATE_VIRUS_PATH", "static/virus.exe")
    )


def load_config() -> AppConfig:
    key_path = os.getenv("FIREBASE_KEY_PATH")
    bucket = os.getenv("FIREBASE_BUCKET")

    if not key_path or not bucket:
        raise ValueError("Missing FIREBASE_KEY_PATH or FIREBASE_BUCKET in .env")

    config = AppConfig(firebase_key_path=key_path, firebase_bucket=bucket)

    return config


def get_firebase_app(config: AppConfig):
    """Singleton-like firebase app initialization."""
    if not firebase_admin._apps:
        cred = credentials.Certificate(config.firebase_key_path)
        return firebase_admin.initialize_app(
            cred, {"storageBucket": config.firebase_bucket}
        )
    return firebase_admin.get_app()
