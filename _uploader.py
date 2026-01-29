import firebase_admin
from firebase_admin import credentials, firestore, storage
import os
import shutil
import pefile
import random
import argparse
import sys
from dotenv import load_dotenv

load_dotenv()

KEY_PATH = os.getenv("FIREBASE_KEY_PATH")
BUCKET_NAME = os.getenv("FIREBASE_BUCKET")

# Walidacja konfiguracji
if not KEY_PATH or not BUCKET_NAME:
    print("[ERROR] Brak konfiguracji w pliku .env!")
    print("Upewnij się, że zdefiniowałeś FIREBASE_KEY_PATH i FIREBASE_BUCKET.")
    sys.exit(1)

# Reszta kodu bez zmian...
# INPUT_DIR = ...

# Foldery (Wzorzec Inbox/Archive)
INPUT_DIR = "generated_samples"  # Tu generator wrzuca pliki
ARCHIVE_DIR = "uploaded_archive"  # Tu trafiają po wysłaniu
# Inicjalizacja Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate(KEY_PATH)
    firebase_admin.initialize_app(cred, {"storageBucket": BUCKET_NAME})

db = firestore.client()
bucket = storage.bucket()


def decode_safe(data):
    """Pomocnicza funkcja do dekodowania bajtów na tekst"""
    if isinstance(data, str):
        return data.strip()
    if not data:
        return ""
    try:
        # Najpierw próbujemy UTF-8 (typowe dla kluczy)
        return data.decode("utf-8").strip("\x00").strip()
    except:
        try:
            # Potem UTF-16 (typowe dla wartości w Windows resources)
            return data.decode("utf-16le").strip("\x00").strip()
        except:
            return str(data)  # Fallback


def extract_pe_metadata(filepath):
    print(f"  [DEBUG] Analiza głęboka PE dla: {os.path.basename(filepath)}")
    meta = {
        "is_pe_valid": False,
        "machine_type": "Unknown",
        "timestamp": None,
        "company_name": "Unknown",
        "file_description": "",
        "file_version": "",
        "product_name": "",
        "product_version": "",
        "copyright": "",
    }

    pe = None
    try:
        pe = pefile.PE(filepath)
        meta["is_pe_valid"] = True

        # 1. Architektura
        if pe.FILE_HEADER.Machine == 0x014C:
            meta["machine_type"] = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0x8664:
            meta["machine_type"] = "x64 (64-bit)"

        # 2. Timestamp
        meta["timestamp"] = pe.FILE_HEADER.TimeDateStamp

        # 3. StringFileInfo (Poprawiona iteracja dla nowszych wersji pefile)
        if hasattr(pe, "FileInfo"):
            # FileInfo to lista list struktur
            for file_info_list in pe.FileInfo:
                for file_info in file_info_list:
                    if hasattr(file_info, "StringTable"):
                        for st in file_info.StringTable:
                            for entry_key, entry_val in st.entries.items():
                                s_key = decode_safe(entry_key)
                                s_val = decode_safe(entry_val)
                                if s_key == "CompanyName":
                                    meta["company_name"] = s_val[:1000]
                                elif s_key == "FileDescription":
                                    meta["file_description"] = s_val[:1000]
                                elif s_key == "FileVersion":
                                    meta["file_version"] = s_val
                                elif s_key == "ProductName":
                                    meta["product_name"] = s_val
                                elif s_key == "ProductVersion":
                                    meta["product_version"] = s_val
                                elif s_key == "LegalCopyright":
                                    meta["copyright"] = s_val

    except Exception as e:
        print(f"  [!] Błąd parsowania PE: {e}")
    finally:
        if pe:
            pe.close()

    return meta


def parse_arguments():
    """Konfiguracja parsera argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(
        description="Narzędzie do analizy PE i synchronizacji z Firebase Storage/Firestore.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Grupa: Źródła danych
    paths = parser.add_argument_group("Ścieżki lokalne")
    paths.add_argument(
        "-i",
        "--input",
        default="generated_samples",
        help="Folder wejściowy z plikami do przetworzenia",
    )
    paths.add_argument(
        "-a",
        "--archive",
        default="uploaded_archive",
        help="Folder, do którego trafią przetworzone pliki",
    )

    # Grupa: Firebase (pobiera z .env jako default, ale pozwala nadpisać)
    fb = parser.add_argument_group("Konfiguracja Firebase")
    fb.add_argument(
        "--key",
        default=os.getenv("FIREBASE_KEY_PATH"),
        help="Ścieżka do pliku JSON z kluczem Firebase",
    )
    fb.add_argument(
        "--bucket", default=os.getenv("FIREBASE_BUCKET"), help="Nazwa Storage Bucket"
    )

    # Grupa: Opcje działania
    opts = parser.add_argument_group("Opcje wykonania")
    opts.add_argument(
        "--dry-run",
        action="store_true",
        help="Analiza plików bez wysyłania ich do chmury",
    )
    opts.add_argument(
        "--verbose", action="store_true", help="Wyświetlaj szczegółowe logi debugowania"
    )

    return parser.parse_args()


def parse_arguments():
    """Konfiguracja parsera argumentów wiersza poleceń."""
    parser = argparse.ArgumentParser(
        description="Narzędzie do analizy PE i synchronizacji z Firebase Storage/Firestore.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    # Grupa: Źródła danych
    paths = parser.add_argument_group("Ścieżki lokalne")
    paths.add_argument(
        "-i",
        "--input",
        default="generated_samples",
        help="Folder wejściowy z plikami do przetworzenia",
    )
    paths.add_argument(
        "-a",
        "--archive",
        default="uploaded_archive",
        help="Folder, do którego trafią przetworzone pliki",
    )

    # Grupa: Firebase (pobiera z .env jako default, ale pozwala nadpisać)
    fb = parser.add_argument_group("Konfiguracja Firebase")
    fb.add_argument(
        "--key",
        default=os.getenv("FIREBASE_KEY_PATH"),
        help="Ścieżka do pliku JSON z kluczem Firebase",
    )
    fb.add_argument(
        "--bucket", default=os.getenv("FIREBASE_BUCKET"), help="Nazwa Storage Bucket"
    )

    # Grupa: Opcje działania
    opts = parser.add_argument_group("Opcje wykonania")
    opts.add_argument(
        "--dry-run",
        action="store_true",
        help="Analiza plików bez wysyłania ich do chmury",
    )
    opts.add_argument(
        "--verbose", action="store_true", help="Wyświetlaj szczegółowe logi debugowania"
    )

    return parser.parse_args()


def process_files(args):
    """Główna pętla, teraz przyjmuje obiekt args."""

    # Walidacja krytycznych parametrów
    if not args.key or not args.bucket:
        print("[ERROR] Brak klucza Firebase lub nazwy Bucketu!")
        print("Podaj je przez argumenty (--key, --bucket) lub w pliku .env")
        sys.exit(1)

    # Inicjalizacja Firebase (tylko jeśli nie dry-run)
    if not args.dry_run:
        if not firebase_admin._apps:
            cred = credentials.Certificate(args.key)
            firebase_admin.initialize_app(cred, {"storageBucket": args.bucket})
        db = firestore.client()
        bucket = storage.bucket()
    else:
        print("[INFO] Tryb DRY-RUN: Pliki nie zostaną wysłane.")

    if not os.path.exists(args.archive):
        os.makedirs(args.archive)

    if not os.path.exists(args.input):
        print(f"[ERROR] Brak folderu {args.input}.")
        return

    files = [f for f in os.listdir(args.input) if f.endswith((".exe", ".bin", ".dll"))]
    if not files:
        print("Brak plików do przetworzenia.")
        return

    print(f"[*] Przetwarzanie {len(files)} plików z folderu: {args.input}...")

    for filename in files:
        src_path = os.path.join(args.input, filename)
        dst_path = os.path.join(args.archive, filename)

        if args.verbose:
            print(f"\n[DEBUG] Processing: {filename}")

        # --- Analiza PE ---
        file_size = os.path.getsize(src_path)
        pe_meta = extract_pe_metadata(src_path)

        if args.dry_run:
            print(f"  [DRY] Wykryto: {pe_meta['company_name']} | Rozmiar: {file_size}b")
            continue
        # KROK 2: Upload do Storage
        blob = bucket.blob(f"repo/{filename}")
        try:
            blob.upload_from_filename(src_path)
            blob.make_public()
            download_url = blob.public_url
        except Exception as e:
            print(f"  [ERROR] Błąd uploadu Storage: {e}")
            continue  # Przechodzimy do następnego pliku

        # KROK 3: Zapis do Firestore (z Rollbackiem)
        try:
            # Logika biznesowa tagów
            risk_level = random.randint(1, 100)
            tags = []

            # Jeśli firma to "Unknown" lub puste, to podejrzane
            if pe_meta["company_name"] in ["Unknown", ""]:
                tags.append("unsigned")
                risk_level += 10

            if "Microsoft" in pe_meta["company_name"]:
                tags.append("spoofing_attempt")
                risk_level += 20

            if risk_level > 80:
                tags.append("critical")
                status = "quarantined"
            elif risk_level > 50:
                tags.append("suspicious")
                status = "flagged"
            else:
                tags.append("unverified")
                status = "active"

            doc_data = {
                "filename": filename,
                "url": download_url,
                "uploaded_at": firestore.SERVER_TIMESTAMP,
                "status": status,
                "static_metadata": {
                    "size_bytes": file_size,
                    "file_type": "PE32 Executable",
                    "architecture": pe_meta["machine_type"],
                    "compiled_timestamp": pe_meta["timestamp"],
                    "detected_company": pe_meta["company_name"],
                    "product_name": pe_meta["product_name"],
                    "product_version": pe_meta["product_version"],
                    "file_description": pe_meta["file_description"],
                    "file_version": pe_meta["file_version"],
                    "copyright": pe_meta["copyright"],
                },
                "dynamic_metadata": {
                    "risk_score": risk_level,
                    "tags": tags,
                    "analyst_notes": "",
                },
            }

            db.collection("infected_files").document(filename).set(doc_data)
            print("  -> Firestore: Zapisano pomyślnie.")

            # KROK 4: Archiwizacja (tylko jak wszystko się udało)
            if os.path.exists(dst_path):
                os.remove(dst_path)
            shutil.move(src_path, dst_path)
            print("  -> Plik zarchiwizowany.")

        except Exception as e:
            # ROLLBACK! Baza padła -> usuwamy plik ze Storage
            print(f"  [CRITICAL ERROR] Błąd zapisu do Firestore: {e}")
            print("  [ROLLBACK] Usuwanie pliku ze Storage dla spójności danych...")
            try:
                blob.delete()
                print("  [ROLLBACK] Sukces. System czysty.")
            except Exception as delete_error:
                print(
                    f"  [FATAL] Nie udało się cofnąć zmian w Storage! Ręczna interwencja wymagana: {delete_error}"
                )

    print("\n[SUCCESS] Koniec pracy batcha.")


if __name__ == "__main__":
    args = parse_arguments()
    process_files(args)
