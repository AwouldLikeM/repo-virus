import argparse
import hashlib
import os
import shutil
import sys
import random
import firebase_admin
import pefile
from firebase_admin import credentials, firestore, storage

# Local modules
from _logger import setup_logger
from _utils import AppConfig, get_firebase_app, load_config

config: AppConfig = load_config()
logger = setup_logger(__name__)


def robust_decode(data) -> str:
    """
    Advanced Heuristic Decoder.
    Specifically targets the 'odd-byte offset' bug in patched SYS/CPL files.
    """
    if not data:
        return ""

    # If it's already a string, it might be 'Pre-Mangled' by pefile's internal guess
    # We convert it back to raw bytes to perform a proper alignment check
    if isinstance(data, str):
        raw_bytes = data.encode("utf-16le", errors="ignore")
    else:
        raw_bytes = data

    def is_mojibake(text: str) -> bool:
        """Heuristic: Version/Company strings shouldn't be 100% CJK/High-plane chars."""
        if not text:
            return False
        # Count characters that fall into the 'CJK' or 'Common Mojibake' range
        bad_chars = sum(1 for c in text if "\u2000" <= c <= "\u9fff")
        return (bad_chars / len(text)) > 0.3 if len(text) > 0 else False

    def clean(b_data):
        try:
            return b_data.decode("utf-16le").split("\x00")[0].strip()
        except:
            return None

    # 1. Try standard Alignment
    attempt1 = clean(raw_bytes)
    if attempt1 and not is_mojibake(attempt1):
        return attempt1

    # 2. Try Offset Alignment (The '⸳㤹' Fix)
    # We skip the first byte because the padding shift caused a phase-offset
    attempt2 = clean(raw_bytes[1:])
    if attempt2 and not is_mojibake(attempt2):
        return attempt2

    # 3. Last resort fallbacks
    try:
        return raw_bytes.decode("utf-8", errors="ignore").split("\x00")[0].strip()
    except:
        return str(data).strip()


def get_file_hash(path: str) -> str:
    sha256_hash = hashlib.sha256()
    with open(path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def extract_pe_metadata(filepath: str, original_filename: str) -> dict:
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
        "file_type": "Unknown Binary",
        "file_extension": os.path.splitext(original_filename)[1].lower(),
    }

    try:
        pe = pefile.PE(filepath)
        meta["is_pe_valid"] = True

        if pe.FILE_HEADER.Machine == 0x014C:
            meta["machine_type"] = "x86 (32-bit)"
        elif pe.FILE_HEADER.Machine == 0x8664:
            meta["machine_type"] = "x64 (64-bit)"
        meta["timestamp"] = pe.FILE_HEADER.TimeDateStamp

        if hasattr(pe, "FileInfo"):
            for file_info_list in pe.FileInfo:
                for file_info in file_info_list:
                    if hasattr(file_info, "StringTable"):
                        for st in file_info.StringTable:
                            for key, val in st.entries.items():
                                s_key = robust_decode(key)
                                s_val = robust_decode(val)

                                # Map keys correctly
                                if s_key == "CompanyName":
                                    meta["company_name"] = s_val
                                elif s_key == "FileDescription":
                                    meta["file_description"] = s_val
                                elif s_key == "FileVersion":
                                    meta["file_version"] = s_val
                                elif s_key == "ProductName":
                                    meta["product_name"] = s_val
                                elif s_key == "ProductVersion":
                                    meta["product_version"] = s_val
                                elif s_key == "LegalCopyright":
                                    meta["copyright"] = s_val

        # Smart Labeling
        if pe.is_driver() or meta["file_extension"] == ".sys":
            meta["file_type"] = "System Driver (SYS)"
        elif meta["file_extension"] == ".cpl":
            meta["file_type"] = "Control Panel Applet (CPL)"
        elif pe.is_dll():
            meta["file_type"] = "Dynamic Link Library (DLL)"
        else:
            meta["file_type"] = "Executable (EXE)"

        pe.close()
    except Exception as e:
        logger.warning(f"Metadata Extraction Error for {original_filename}: {e}")
    return meta


def process_files(args):
    # Setup Firebase
    if not args.dry_run:
        get_firebase_app(config)
        db = firestore.client()
        bucket = storage.bucket()

    input_dir = args.input or config.virus_samples_dir
    archive_dir = args.archive or config.uploaded_archive
    os.makedirs(archive_dir, exist_ok=True)

    files = [
        f
        for f in os.listdir(input_dir)
        if f.lower().endswith((".exe", ".dll", ".sys", ".cpl"))
    ]

    if not files:
        logger.info(f"Scanning directory: {os.path.abspath(input_dir)}")
        logger.warning(
            "No matching files found. Check your input directory or file extensions."
        )
        return

    for filename in files:
        src_path = os.path.join(input_dir, filename)
        file_hash = get_file_hash(src_path)
        pe_meta = extract_pe_metadata(src_path, filename)

        if args.dry_run or args.verbose:
            logger.info(f"--- [FILE ANALYSIS: {filename}] ---")
            logger.info(f"  Company: {pe_meta['company_name']}")
            logger.info(f"  Version: {pe_meta['file_version']}")
            logger.info(f"  ProdVer: {pe_meta['product_version']}")
            if args.dry_run:
                continue

        # Dynamic Metadata Logic (Restored)
        risk_level = random.randint(1, 100)
        tags = ["automated_upload"]
        if "Microsoft" in pe_meta["company_name"]:
            tags.append("spoofing_attempt")
            risk_level += 20
        status = "quarantined" if risk_level > 80 else "active"

        try:
            # FIRST UPLOAD FILE TO STORAGE
            blob = bucket.blob(f"repo/{file_hash}.bin")
            blob.upload_from_filename(src_path)
            blob.make_public()

            doc_data = {
                "filename": file_hash,
                "original_filename": filename,
                "url": blob.public_url,
                "uploaded_at": firestore.SERVER_TIMESTAMP,
                "status": status,
                "static_metadata": {
                    "size_bytes": os.path.getsize(src_path),
                    "file_type": pe_meta["file_type"],
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
                    "analyst_notes": f"Batch upload. Type: {pe_meta['file_type']}",
                },
            }
            # THEN CREATE FIRESTORE DOCUMENT with METADATA
            db.collection(config.firebase_collection).document(file_hash).set(doc_data)
            shutil.move(src_path, os.path.join(archive_dir, filename))
            logger.info(f"Success: {filename} uploaded as {file_hash[:8]}.bin")

        except Exception as e:
            logger.error(f"Failed to process {filename}: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input")
    parser.add_argument("-a", "--archive")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    process_files(parser.parse_args())
