import os
import shutil
import sys
import firebase_admin
from firebase_admin import credentials, firestore, storage

from dotenv import load_dotenv

load_dotenv()

KEY_PATH = os.getenv("FIREBASE_KEY_PATH")
BUCKET_NAME = os.getenv("FIREBASE_BUCKET")

# Walidacja konfiguracji
if not KEY_PATH or not BUCKET_NAME:
    print("[ERROR] Brak konfiguracji w pliku .env!")
    print("Upewnij się, że zdefiniowałeś FIREBASE_KEY_PATH i FIREBASE_BUCKET.")
    sys.exit(1)


LOCAL_DIR = "generated_samples"


def clean_local():
    if os.path.exists("uploaded_archive"):
        shutil.rmtree("uploaded_archive")
        print("[+] Usunięto lokalny katalog uploaded_archive")

    if os.path.exists(LOCAL_DIR):
        shutil.rmtree(LOCAL_DIR)
        print(f"[+] Usunięto lokalny katalog {LOCAL_DIR}")
    else:
        print(f"[-] Lokalny katalog {LOCAL_DIR} nie istnieje.")


def clean_cloud():
    print("[!] Rozpoczynam czyszczenie chmury (Storage + Firestore)...")

    # Inicjalizacja (jeśli nie jest zainicjowana)
    if not firebase_admin._apps:
        cred = credentials.Certificate(KEY_PATH)
        firebase_admin.initialize_app(cred, {"storageBucket": BUCKET_NAME})

    db = firestore.client()
    bucket = storage.bucket()

    # 1. Czyszczenie Firestore
    # Pobieramy wszystkie dokumenty z kolekcji
    docs = db.collection("infected_files").stream()
    deleted_count = 0
    for doc in docs:
        doc.reference.delete()
        deleted_count += 1
    print(f"  -> Usunięto {deleted_count} dokumentów z Firestore.")

    # 2. Czyszczenie Storage
    blobs = bucket.list_blobs(prefix="repo/")
    deleted_blobs = 0
    for blob in blobs:
        blob.delete()
        deleted_blobs += 1
    print(f"  -> Usunięto {deleted_blobs} plików ze Storage.")


if __name__ == "__main__":
    # Zawsze czyść lokalnie
    clean_local()

    # Czyść chmurę tylko jeśli podano flagę
    if "--cloud" in sys.argv:
        try:
            clean_cloud()
            print("[SUCCESS] Środowisko wyczyszczone całkowicie.")
        except Exception as e:
            print(f"[ERROR] Błąd podczas czyszczenia chmury: {e}")
            print("Sprawdź czy masz uprawnienia admina w pliku JSON.")
    else:
        print(
            "[INFO] Wyczyszczono tylko lokalnie. Użyj 'python cleanup.py --cloud' aby wyczyścić też Firebase."
        )
