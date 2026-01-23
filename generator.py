import pefile
import os
import random
import uuid
import argparse
import sys

# --- KONFIGURACJA STAŁA ---
INPUT_TEMPLATE = os.path.join("static", "virus.exe")
OUTPUT_DIR = "generated_samples"

# Placeholdery
PLACEHOLDERS = {
    "COMPANY":  "COMPANY_NAME_PLACEHOLDER_FOR_PATCHING_PAD_PAD_PAD_PAD_PAD",
    "DESC":     "FILE_DESCRIPTION_PLACEHOLDER_FOR_PATCHING_PAD_PAD_PAD_PAD",
    "COPY":     "COPYRIGHT_HOLDER_PLACEHOLDER_FOR_PATCHING_PAD_PAD_PAD_PAD",
    "PROD_NAME":"PRODUCT_NAME_PLACEHOLDER_FOR_PATCHING_PAD_PAD_PAD_PAD_PAD",
    "FILE_VER": "FILE_VER_PLACEHOLDER_PAD_PAD_PAD",
    "PROD_VER": "PROD_VER_PLACEHOLDER_PAD_PAD_PAD"
}

MANIFEST_PLACEHOLDER = "MANIFEST_DESCRIPTION_PLACEHOLDER_FOR_XML_PATCHING_PAD_PAD_PAD"

DATA_POOL = {
    "companies": ["Microsoft Windows System", "NVIDIA Corporation", "XMR Miner Group", "DarkWeb Solutions", "Unknown Publisher", ""],
    "descriptions": ["Host Process for Windows Services", "Runtime Broker", "Critical Security Patch KB4023", "Trojan.Win32.Generic Payload", "Remote Access Tool (RAT) Server", "WannaCry Decryptor", ""],
    "products": ["Windows Operating System", "GeForce Driver Update", "Bitcoin Wallet Injector", "Network Sniffer v2.0", ""],
    "copyrights": ["(C) Microsoft Corporation", "Copyright (C) 2024", "Hacked by Anonymous", ""]
}

def generate_random_ver():
    return f"{random.randint(1,10)}.{random.randint(0,99)}.{random.randint(0,9999)}.{random.randint(0,9999)}"

def patch_data(raw_data, placeholder_str, new_value, is_utf16=True):
    encoding = "utf-16le" if is_utf16 else "utf-8"
    search_bytes = placeholder_str.encode(encoding)
    
    if search_bytes not in raw_data:
        return raw_data

    if new_value:
        new_bytes = new_value.encode(encoding)
    else:
        new_bytes = b"" 

    max_len = len(search_bytes)
    if len(new_bytes) > max_len:
        new_bytes = new_bytes[:max_len]

    padding = b'\x00' * (max_len - len(new_bytes))
    final_bytes = new_bytes + padding

    return raw_data.replace(search_bytes, final_bytes, 1)

def main():
    # --- PARSOWANIE ARGUMENTÓW ---
    parser = argparse.ArgumentParser(description="Generator próbek wirusów (PE format).")
    parser.add_argument("--count", type=int, default=11, help="Liczba plików do wygenerowania (domyślnie 11)")
    parser.add_argument("--max-size", type=float, default=1.0, help="Maksymalny rozmiar pliku w MB (domyślnie 1.0)")
    args = parser.parse_args()

    count = args.count
    max_size_bytes = int(args.max_size * 1024 * 1024)

    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    if not os.path.exists(INPUT_TEMPLATE):
        print(f"BŁĄD: Brak pliku {INPUT_TEMPLATE}")
        sys.exit(1)

    try:
        pe = pefile.PE(INPUT_TEMPLATE)
        base_raw_data = pe.write()
        pe.close()
    except Exception as e:
        print(f"BŁĄD PEfile: {e}")
        sys.exit(1)

    base_size = len(base_raw_data)
    if base_size > max_size_bytes:
        print(f"BŁĄD: Szablon ({base_size} B) jest większy niż limit ({max_size_bytes} B)!")
        sys.exit(1)

    print(f"[*] Generowanie {count} próbek (Limit: {args.max_size} MB)...")

    for i in range(count):
        current_data = base_raw_data
        
        # 1. Losowanie metadanych
        vals = {
            "COMPANY":   random.choice(DATA_POOL["companies"]),
            "DESC":      random.choice(DATA_POOL["descriptions"]),
            "COPY":      random.choice(DATA_POOL["copyrights"]),
            "PROD_NAME": random.choice(DATA_POOL["products"]),
            "FILE_VER":  generate_random_ver() if random.random() > 0.2 else "",
            "PROD_VER":  generate_random_ver() if random.random() > 0.2 else ""
        }
        if "Microsoft" in vals["COMPANY"]: vals["COPY"] = "(C) Microsoft Corporation"

        # 2. Patchowanie
        for key, placeholder in PLACEHOLDERS.items():
            current_data = patch_data(current_data, placeholder, vals[key])
        
        manifest_val = vals["DESC"] if vals["DESC"] else "Application"
        current_data = patch_data(current_data, MANIFEST_PLACEHOLDER, manifest_val, is_utf16=False)

        # 3. ZMIANA ROZMIARU (Overlay) z uwzględnieniem LIMITU
        current_size = len(current_data)
        available_space = max_size_bytes - current_size
        
        if available_space > 0:
            # Losujemy rozmiar overlayu: od 1KB do dostępnego miejsca
            # Używamy min() żeby nie przekroczyć limitu
            max_add = min(available_space, 512 * 1024) # Nie dodawaj więcej niż 512KB chyba że limit pozwala
            if max_add > 1024:
                extra_size = random.randint(1024, max_add)
                overlay_data = os.urandom(extra_size)
                current_data += overlay_data

        # 4. Zapis
        unique_suffix = uuid.uuid4().hex[:6]
        ext = random.choice([".exe", ".dll", ".bin"])
        filename = f"sample_{unique_suffix}{ext}"
        filepath = os.path.join(OUTPUT_DIR, filename)

        with open(filepath, "wb") as f:
            f.write(current_data)
        
        final_size_mb = len(current_data) / (1024 * 1024)
        print(f"[+] {filename} | {final_size_mb:.2f} MB | Desc: '{vals['DESC']}'")

    print("\n[OK] Zakończono.")

if __name__ == "__main__":
    main()