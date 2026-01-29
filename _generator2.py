
import os
import random
import uuid
import argparse

import shutil
from _logger import setup_logger
from _utils import AppConfig, load_config


config: AppConfig = load_config()

logger = setup_logger(__name__)
#########################################
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
#########################################

def generate_random_string(length: int) -> str:
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(letters) for i in range(length))

def generate_random_version() -> str:
    """
    Generates a random version string with a random depth (2 to 4 parts).
    Example outputs: "4.12", "9.82.1452", or "1.0.8421.55"
    """
    # Decide how many segments the version has (e.g., 2 to 4)
    depth = random.randint(2, 4)
    
    # Define the ranges for each potential segment
    # Major, Minor, Patch, Build
    ranges = [
        (1, 10),    # Major
        (0, 99),    # Minor
        (0, 9999),  # Patch
        (0, 9999)   # Build
    ]
    
    # Generate segments based on the selected depth
    version_parts = [str(random.randint(low, high)) for (low, high) in ranges[:depth]]
    
    return ".".join(version_parts)
    


# ... existing imports and constants ...

def generate_virus_sample(template_path: str, output_path: str, max_size: int):
    # 1. Define a safe buffer size for headers (e.g., 10MB)
    # Most PE headers/resources are well within the first few MBs.
    HEADER_BUFFER_SIZE = 10 * 1024 * 1024 
    
    updates = {
        "COMPANY": random.choice(DATA_POOL["companies"]),
        "DESC": random.choice(DATA_POOL["descriptions"]),
        "PROD_NAME": random.choice(DATA_POOL["products"]),
        "COPY": random.choice(DATA_POOL["copyrights"]),
        "FILE_VER": generate_random_version() if random.random() > 0.4 else "",
        "PROD_VER": generate_random_version() if random.random() > 0.36 else "",
    }

    with open(template_path, "rb") as f_in, open(output_path, "wb") as f_out:
        # --- PHASE 1: Process the Header (In Memory) ---
        
        # Read only the beginning of the file
        header_data = bytearray(f_in.read(HEADER_BUFFER_SIZE))
        
        # Patch the binary using placeholders
        for key, placeholder_str in PLACEHOLDERS.items():
            if key not in updates:
                continue
            
            new_val = updates[key]
            p_bytes = placeholder_str.encode('utf-8')
            
            # Find the placeholder in the header buffer
            offset = header_data.find(p_bytes)
            
            if offset != -1:
                # Pad new value to match EXACT placeholder length
                padded_value = new_val.encode('utf-8').ljust(len(p_bytes), b'\0')
                header_data[offset : offset + len(p_bytes)] = padded_value
            else:
                # Depending on strictness, you might just log this
                # logger.debug(f"Placeholder {placeholder_str} not found in first 10MB.")
                pass

        # Write the modified header to the new file
        f_out.write(header_data)

        # --- PHASE 2: Stream the Rest (Disk to Disk) ---
        
        # Determine how much is left in the source file
        # We perform a buffered copy so we never hold huge data in RAM
        shutil.copyfileobj(f_in, f_out, length=1024*1024) 

        # --- PHASE 3: Randomized Padding ---
        
        # Check current size of the new file (Header + Original Content)
        current_size = f_out.tell() 
        limit_size = max_size  # The hard limit passed in args
        
        # Only pad if we have room to grow
        if current_size < limit_size:
            # Pick a random final size between the current size and the limit
            random_final_size = random.randint(current_size, limit_size)
            
            padding_needed = random_final_size - current_size
            
            # Write padding in chunks (memory safe)
            chunk_size = 1024 * 1024  # 1MB chunks
            while padding_needed > 0:
                write_size = min(padding_needed, chunk_size)
                f_out.write(random.randbytes(write_size))
                padding_needed -= write_size
                
        elif current_size > limit_size:
            logger.warning(f"Base file ({current_size} bytes) is already larger than max_size ({limit_size} bytes). Skipping padding.")
                
def generate_virus_sample2(base_data: bytes, max_size: int) -> bytes:
    sample_data = bytearray(base_data)
    
    updates = {
        "COMPANY": random.choice(DATA_POOL["companies"]),
        "DESC": random.choice(DATA_POOL["descriptions"]),
        "PROD_NAME": random.choice(DATA_POOL["products"]),
        "COPY": random.choice(DATA_POOL["copyrights"]),
        "FILE_VER": generate_random_version() if random.random() > 0.4 else "",
        "PROD_VER": generate_random_version() if random.random() > 0.36 else "",
    }
    
    # Patch the binary using placeholders
    for key, placeholder_str in PLACEHOLDERS.items():
        if key not in updates:
            continue
            
        new_val = updates[key]
        
        # Binary strings in PE resources are often UTF-16LE, 
        # but if you embedded them as ASCII/UTF-8 placeholders:
        p_bytes = placeholder_str.encode('utf-8')
        
        # Find the placeholder in the binary
        offset = sample_data.find(p_bytes)
        
        if offset != -1:
            # Pad the new value with null bytes to match EXACT placeholder length
            # This is critical: if you change the length, the PE file corrupts.
            padded_value = new_val.encode('utf-8').ljust(len(p_bytes), b'\0')
            
            # Slice and dice the bytearray
            sample_data[offset : offset + len(p_bytes)] = padded_value
        else:
            # Log a warning if a placeholder is missing
            print(f"Warning: Placeholder {placeholder_str} not found in base data.")

    # 3. Handle Padding (Max Size requirement)
    # If the file is smaller than max_size, we append random junk or nulls
    current_size_kb = len(sample_data) // 1024
    if current_size_kb < max_size:
        padding_needed = (max_size * 1024) - len(sample_data)
        sample_data.extend(random.randbytes(padding_needed))

    return bytes(sample_data)

def validate_max_size(value):
    """Custom validator to check minimum size requirements."""
    ivalue = int(value)
    # can't be lower than 13KB
    if ivalue < 13:
        raise argparse.ArgumentTypeError(f"Max size {ivalue}KB is too small. Minimum is 13KB.")
    return ivalue

def main():
    parser = argparse.ArgumentParser(
        description="Generate fake PE files with randomized metadata.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # --help
    )
    
    parser.add_argument(
        "--count", 
        type=int, 
        default=10, 
        help="Number of fake PE files to generate."
    )
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="generated_samples", 
        help="Directory to save generated PE files."
    )
    parser.add_argument(
        "--max-size", 
        type=validate_max_size,
        default=512,
        help="Maximum size of generated PE files in KB (Min: 13)."
    )

    args = parser.parse_args()
    max_size_bytes = args.max_size * 1024
    
    logger.debug(f"Max size: {args.max_size}KB ({max_size_bytes} bytes).")
    
    # check if output dir exists
    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)
    # check if template virus exists
    template_virus_path = config.template_virus_path
    if not os.path.isfile(template_virus_path):
        raise FileNotFoundError(f"Template virus file not found at {template_virus_path}")
    
# NO LONGER READING BASE_DATA HERE
    
    for i in range(args.count):
        try:
            # Generate a unique filename for the output
            unique_name = f"virus_sample_{uuid.uuid4().hex[:8]}.exe"
            output_path = os.path.join(output_dir, unique_name)
            
            # Pass paths, not bytes
            generate_virus_sample(template_virus_path, output_path, max_size_bytes)
            
            logger.info(f"Generated sample {i+1}/{args.count} at {output_path}")
        except Exception as e:
            logger.error(f"Failed to generate sample {i}: {e}")
            
if __name__ == "__main__":
    main()