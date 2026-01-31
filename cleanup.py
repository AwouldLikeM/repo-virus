import argparse
import os
import shutil
import firebase_admin
from firebase_admin import credentials, firestore, storage
from _logger import setup_logger
from _utils import AppConfig, load_config, get_firebase_app # Pamiętaj o imporcie get_firebase_app z utils!

config: AppConfig = load_config()
logger = setup_logger(__name__)

def clean_local():
    logger.info("Starting local cleanup...")
    
    paths_to_clean = [config.uploaded_archive, config.virus_samples_dir]
    
    for path in paths_to_clean:
        if os.path.exists(path):
            try:
                shutil.rmtree(path)
                logger.info(f"Deleted folder: {path}")
            except Exception as e:
                logger.warning(f"Failed to delete {path}: {e}")
        else:
            logger.debug(f"Path not found (skipping): {path}")

def delete_firestore_collection_in_batches(db, collection_name, batch_size=400):
    """Efficiently deletes documents using WriteBatch."""
    coll_ref = db.collection(collection_name)
    total_deleted = 0
    
    while True:
        # Pobieramy tylko referencje (szybciej niż całe dokumenty)
        docs = list(coll_ref.limit(batch_size).stream())
        deleted_count = len(docs)
        
        if deleted_count == 0:
            break
            
        batch = db.batch()
        for doc in docs:
            batch.delete(doc.reference)
            
        batch.commit()
        total_deleted += deleted_count
        logger.info(f"  ...committed batch delete of {deleted_count} documents.")
        
    logger.info(f"Total documents deleted from Firestore: {total_deleted}")

def clean_cloud():
    logger.info("Starting CLOUD cleanup...")

    # Używamy helpera z _utils (DRY!)
    get_firebase_app(config)

    db = firestore.client()
    bucket = storage.bucket()

    # 1. Clean Firestore (Batch)
    logger.info("Cleaning Firestore...")
    delete_firestore_collection_in_batches(db, config.firebase_collection)

    # 2. Clean Storage (Batch)
    logger.info("Cleaning Storage...")
    blobs = list(bucket.list_blobs(prefix="repo/"))
    
    if blobs:
        # bucket.delete_blobs usuwa listę w jednym żądaniu (znacznie szybciej)
        # Uwaga: API Google czasem ma limit na ilość w jednym requeście, 
        # ale biblioteka pythonowa zazwyczaj to obsługuje pod spodem.
        # Dla bezpieczeństwa można to też dzielić na chunki, ale przy <10k plików zadziała.
        chunks = [blobs[i:i + 100] for i in range(0, len(blobs), 100)]
        total_blobs = 0
        for chunk in chunks:
            bucket.delete_blobs(chunk)
            total_blobs += len(chunk)
            logger.info(f"  ...deleted chunk of {len(chunk)} files from Storage.")
    else:
        logger.info("Storage is already empty.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Clean resources with BATCH operations.")
    parser.add_argument("--cloud", action="store_true", help="Clean cloud resources")
    parser.add_argument("--local", action="store_true", help="Clean local folders")
    
    args = parser.parse_args()

    # Domyślnie czyścimy wszystko, jeśli nie podano flag
    if not args.cloud and not args.local:
        clean_local()
        clean_cloud()
    else:
        if args.local: clean_local()
        if args.cloud: clean_cloud()
        
    logger.info("Cleanup completed.")