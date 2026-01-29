import argparse
import os
import shutil
import firebase_admin
from firebase_admin import credentials, firestore, storage
from _logger import setup_logger
from _utils import AppConfig, load_config


config: AppConfig = load_config()

logger = setup_logger(__name__)


def clean_local():
    logger.info("Starting local cleanup...")

    if os.path.exists(config.uploaded_archive):
        logger.debug(f"Deleting folder {config.uploaded_archive}...")
        shutil.rmtree(config.uploaded_archive)
        logger.info(f"Successfully deleted folder {config.uploaded_archive}")
    else:
        logger.warning(f"Local directory {config.uploaded_archive} does not exist, skipping.")

    if os.path.exists(config.virus_samples_dir):
        logger.debug(f"Deleting folder {config.virus_samples_dir}...")
        shutil.rmtree(config.virus_samples_dir)
        logger.info(f"Successfully deleted folder {config.virus_samples_dir}")
    else:
        logger.warning(f"Local directory {config.virus_samples_dir} does not exist, skipping.")


def clean_cloud():
    logger.info("Starting cloud cleanup (Storage + Firestore)...")

    # Initialize Firebase app if not already initialized
    if not firebase_admin._apps:
        cred = credentials.Certificate(config.firebase_key_path)
        firebase_admin.initialize_app(cred, {"storageBucket": config.firebase_bucket})

    db = firestore.client()
    bucket = storage.bucket()

    # 1. Clean Firestore
    docs = db.collection(config.firebase_collection).stream()
    deleted_count = 0
    for doc in docs:
        doc.reference.delete()
        deleted_count += 1
    logger.info(f"Deleted {deleted_count} documents from Firestore.")

    # 2. Clean Storage
    blobs = bucket.list_blobs(prefix="repo/")
    deleted_blobs = 0
    for blob in blobs:
        blob.delete()
        deleted_blobs += 1
    logger.info(f"Deleted {deleted_blobs} files from Storage.")


if __name__ == "__main__":
    clean_local()

    parser = argparse.ArgumentParser(description="Clean local and cloud resources.")
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Also clean cloud resources (Storage + Firestore)",
    )
    args = parser.parse_args()
    if args.cloud:
        clean_cloud()
    else:
        logger.info("Cloud cleanup skipped. Use --cloud flag to enable.")
    
    logger.info("Cleanup process completed.")
