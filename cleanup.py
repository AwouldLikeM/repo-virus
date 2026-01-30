import argparse
import os
import shutil
from firebase_admin import firestore, storage
from _logger import setup_logger
from _utils import AppConfig, get_firebase_app, load_config


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
    get_firebase_app(config)

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


    parser = argparse.ArgumentParser(description="Clean local and cloud resources.")
    parser.add_argument(
        "--cloud",
        action="store_true",
        help="Also clean cloud resources (Storage + Firestore)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Also clean local resources (uploaded_archive and generated_samples folders)",
    )
    args = parser.parse_args()
    if args.cloud:
        clean_cloud()
    else:
        logger.info("Cloud cleanup skipped. Use --cloud flag to enable.")

    if args.local:
        clean_local()
    else:
        logger.info("Local cleanup skipped. Use --local flag to enable.")
    # if neither flag is provided, clean both
    if not args.cloud and not args.local:
        clean_local()
        clean_cloud()
    logger.info("Cleanup process completed.")
