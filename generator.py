import os
import random
import uuid
import argparse
import shutil
import pefile
from _logger import setup_logger
from _utils import AppConfig, load_config

config: AppConfig = load_config()
logger = setup_logger(__name__)

#########################################
# CONFIGURATION & POOLS
#########################################

# XML Manifest is outside the standard string table, so we define it manually.
MANIFEST_PLACEHOLDER = "MANIFEST_DESCRIPTION_PLACEHOLDER_FOR_XML_PATCHING_PAD_PAD_PAD"

# Probability that a metadata field (other than filename) is wiped empty (0.01 - 0.30)
EMPTY_FIELD_PROBABILITY = 0.13  

DATA_POOL = {
    "companies": ["Microsoft Windows System", "NVIDIA Corporation", "XMR Miner Group", "DarkWeb Solutions", "Unknown Publisher", "Valve Corp.", "Realtek Semiconductor", "Adobe Systems Incorporated"],
    "descriptions": ["Host Process for Windows Services", "Runtime Broker", "Critical Security Patch KB4023", "Trojan.Win32.Generic Payload", "Remote Access Tool (RAT) Server", "WannaCry Decryptor", "System Configuration Utility", "Local Security Authority Process"],
    "products": ["Windows Operating System", "GeForce Driver Update", "Bitcoin Wallet Injector", "Network Sniffer v2.0", "Steam Client Service", "Realtek HD Audio", "Adobe Acrobat Update"],
    "copyrights": ["(C) Microsoft Corporation", "Copyright (C) 2024", "Hacked by Anonymous", "All rights reserved.", "(C) NVIDIA Corp.", "© 2023 Valve Corporation"],
    "viruses": [
        "ILOVEYOU", "Mydoom", "Stuxnet", "Conficker", "Storm Worm", 
        "Sasser", "Netsky", "Zeus", "CryptoLocker", "Emotet", 
        "Ryuk", "Petya", "NotPetya", "WannaCry", "Code Red", 
        "Nimda", "Melissa", "Slammer", "Blaster", "Morris"
    ],
    "generic": ["Core system library.", "Optimized for x64 architecture.", "Do not modify.", "Internal build 4092.", "Patch Level 3."]
}

#########################################
# UTILITIES
#########################################

def generate_random_version() -> str:
    """Generates a random version string (e.g., 4.12.90.1)."""
    depth = random.randint(2, 4)
    ranges = [(1, 10), (0, 99), (0, 9999), (0, 9999)]
    return ".".join([str(random.randint(l, h)) for l, h in ranges[:depth]])

def get_value_for_key(key: str, filename: str) -> str:
    """
    Decides what value to put into a metadata field based on its Key name.
    """
    key_lower = key.lower()
    
    # 1. Filename consistency (Critical for realism, rarely empty)
    if "internalname" in key_lower or "originalfilename" in key_lower:
        # Small chance to be empty, but usually matches filename
        if random.random() < 0.05: return "" 
        return filename
    
    # 2. Random Chance to be Empty (The 1% - 30% rule)
    if random.random() < EMPTY_FIELD_PROBABILITY:
        return ""

    # 3. Mapped pools
    if "company" in key_lower:
        return random.choice(DATA_POOL["companies"])
    if "description" in key_lower:
        return random.choice(DATA_POOL["descriptions"])
    if "copyright" in key_lower:
        return random.choice(DATA_POOL["copyrights"])
    if "productname" in key_lower:
        return random.choice(DATA_POOL["products"])
    if "comments" in key_lower:
        return random.choice(DATA_POOL["generic"])
    if "version" in key_lower: 
        return generate_random_version()
    
    # 4. Fallback
    return random.choice(DATA_POOL["generic"])

def extract_placeholders_from_template(template_path: str):
    """
    Scans the template using ROBUST decoding logic (from test.py) 
    to find ALL placeholder values in the StringTable.
    """
    found_placeholders = []
    
    try:
        pe = pefile.PE(template_path)
        if not hasattr(pe, 'FileInfo'):
            return []

        for file_info in pe.FileInfo:
            for file_info_item in file_info:
                if hasattr(file_info_item, 'StringTable'):
                    for st in file_info_item.StringTable:
                        for key, value in st.entries.items():
                            
                            # --- ROBUST DECODING LOGIC START ---
                            # 1. Decode Key
                            s_key = key.decode('utf-8', 'ignore') if isinstance(key, bytes) else str(key)
                            
                            s_value = ""
                            if isinstance(value, bytes):
                                # Alignment Fix: check if byte shift fixes 'Chinese' chars
                                try:
                                    temp_val = value.decode('utf-16le').strip('\x00')
                                    # If it looks like CJK (Chinese) but shouldn't be
                                    if any('\u4e00' <= c <= '\u9fff' for c in temp_val):
                                         s_value = value[1:].decode('utf-16le').strip('\x00')
                                    else:
                                         s_value = temp_val
                                except:
                                    s_value = value.decode('utf-8', 'ignore').strip('\x00')
                            else:
                                # If pefile returned a string, it might be corrupted (Mojibake)
                                s_value = str(value).strip('\x00')
                                if any('\u4e00' <= c <= '\u9fff' for c in s_value):
                                    try:
                                        # Re-encode to raw and try to fix alignment
                                        raw = s_value.encode('utf-16le', errors='ignore')
                                        s_value = raw.decode('utf-16le', errors='ignore').strip('\x00')
                                    except: pass
                            # --- ROBUST DECODING LOGIC END ---

                            # Only keep it if it looks like one of our long placeholders
                            # (Contains "PLACEHOLDER" or is very long)
                            if "PLACEHOLDER" in s_value or len(s_value) > 20:
                                found_placeholders.append((s_key, s_value))
        pe.close()
    except Exception as e:
        logger.warning(f"Metadata extraction failed for {template_path}: {e}")
        
    return found_placeholders

#########################################
# CORE LOGIC
#########################################

def generate_virus_sample(template_path: str, output_path: str, max_size: int, filename: str) -> None:
    HEADER_BUFFER_SIZE = 10 * 1024 * 1024 
    
    # --- PHASE 1: DISCOVERY ---
    placeholders_to_patch = extract_placeholders_from_template(template_path)
    
    # --- PHASE 2: PATCHING ---
    with open(template_path, "rb") as f_in, open(output_path, "wb") as f_out:
        header_data = bytearray(f_in.read(HEADER_BUFFER_SIZE))
        
        for key_name, placeholder_str in placeholders_to_patch:
            
            new_value = get_value_for_key(key_name, filename)
            
            # Encode the placeholder exactly as we expect it in the binary (UTF-16LE)
            p_bytes = placeholder_str.encode('utf-16le')
            
            offset = header_data.find(p_bytes)
            
            if offset != -1:
                # Pad with nulls to match EXACT length
                padded_value = new_value.encode('utf-16le').ljust(len(p_bytes), b'\0')
                
                # Truncate if new value is somehow longer than placeholder (safety)
                if len(padded_value) > len(p_bytes):
                    padded_value = padded_value[:len(p_bytes)]
                    if len(padded_value) % 2 != 0: # Ensure even byte length
                         padded_value = padded_value[:-1] + b'\0'

                header_data[offset : offset + len(p_bytes)] = padded_value
            else:
                logger.debug(f"Could not find bytes for placeholder: {key_name} in {template_path}")

        # Patch Manifest (Manual)
        manifest_bytes = MANIFEST_PLACEHOLDER.encode('utf-8')
        manifest_offset = header_data.find(manifest_bytes)
        if manifest_offset != -1:
            desc = random.choice(DATA_POOL["descriptions"])
            padded_manifest = desc.encode('utf-8').ljust(len(manifest_bytes), b' ')
            header_data[manifest_offset : manifest_offset + len(manifest_bytes)] = padded_manifest

        f_out.write(header_data)
        shutil.copyfileobj(f_in, f_out, length=1024*1024) 

        # --- PHASE 3: PADDING ---
        current_size = f_out.tell() 
        if current_size < max_size:
            random_final_size = random.randint(current_size, max_size)
            padding_needed = random_final_size - current_size
            while padding_needed > 0:
                write_size = min(padding_needed, 1024 * 1024)
                f_out.write(random.randbytes(write_size))
                padding_needed -= write_size

def validate_max_size(value):
    ivalue = int(value)
    if ivalue < 13: raise argparse.ArgumentTypeError(f"Max size {ivalue}KB is too small.")
    return ivalue

def main():
    parser = argparse.ArgumentParser(description="Universal PE Generator.")
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--output-dir", type=str, default="generated_samples")
    parser.add_argument("--max-size", type=validate_max_size, default=512)
    args = parser.parse_args()

    max_size_bytes = args.max_size * 1024
    os.makedirs(args.output_dir, exist_ok=True)
    
    TEMPLATES = {
        "exe": "static/virus.exe",
        "dll": "static/System.Net.dll",
        "sys": "static/nvvad64v.sys",
        "cpl": "static/irprops.cpl"
    }
    
    logger.info(f"Starting generation of {args.count} samples...")

    for i in range(args.count):
        try:
            ext = random.choice(list(TEMPLATES.keys()))
            template_path = TEMPLATES[ext]
            
            if not os.path.exists(template_path):
                logger.warning(f"Template not found: {template_path}. Skipping.")
                continue

            virus_name = random.choice(DATA_POOL["viruses"])
            unique_filename = f"{virus_name}_{uuid.uuid4().hex[:4]}.{ext}"
            output_path = os.path.join(args.output_dir, unique_filename)
            
            generate_virus_sample(template_path, output_path, max_size_bytes, unique_filename)
            logger.info(f"Generated: {unique_filename}")
            
        except Exception as e:
            logger.error(f"Failed to generate sample {i}: {e}")

if __name__ == "__main__":
    main()