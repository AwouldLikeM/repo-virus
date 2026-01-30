import os
import pefile

def print_all_pe_metadata(file_path):
    try:
        # Load the PE file
        pe = pefile.PE(file_path)
        print(f"--- Analyzing: {file_path} ---")
        count = 0 # count how many metadata entries we print
        # Check if the file has Version Information
        if not hasattr(pe, 'FileInfo'):
            print("No Version Information (FileInfo) found in this file.")
            return

        # Iterate through the FileInfo structures
        for file_info_list in pe.FileInfo:
            # Each file_info_list can contain StringFileInfo or VarFileInfo
            for file_info in file_info_list:
                
                # We specifically want the StringTable where the metadata lives
                if hasattr(file_info, 'StringTable'):
                    for string_table in file_info.StringTable:
                        print(f"\n[StringTable: {string_table.LangID.decode('utf-8', 'ignore')}]")
                        
                        # Dynamically iterate through all available keys and values
                        # This avoids hardcoding keys like 'CompanyName'
                        for key, value in string_table.entries.items():
                            s_key = key.decode('utf-8', 'ignore') if isinstance(key, bytes) else str(key)
                            count += 1
                            if isinstance(value, bytes):
                                # The "Alignment Fix": if the bytes look wrong, try shifting by 1 byte
                                try:
                                    s_value = value.decode('utf-16le').strip('\x00')
                                    # Check if it contains mostly Chinese chars despite being an English resource
                                    if any('\u4e00' <= c <= '\u9fff' for c in s_value):
                                        s_value = value[1:].decode('utf-16le').strip('\x00')
                                except:
                                    s_value = value.decode('utf-8', 'ignore').strip('\x00')
                            else:
                                # If pefile already converted it to a string incorrectly
                                s_value = str(value).strip('\x00')
                                if any('\u4e00' <= c <= '\u9fff' for c in s_value):
                                    try:
                                        # Re-encode to raw and try to fix alignment
                                        raw = s_value.encode('utf-16le', errors='ignore')
                                        s_value = raw.decode('utf-16le', errors='ignore').strip('\x00')
                                    except: pass

                            print(f"{s_key:25}: {s_value}")

        # Basic Header Metadata (Bonus)
        print("\n--- Basic Header Info ---")
        machine = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
        print(f"{'Architecture':25}: {machine}")
        print(f"{'TimeDateStamp':25}: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"{'Metadata Entries Count':25}: {count}")
    except FileNotFoundError:
        print(f"Error: The file at {file_path} was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        if 'pe' in locals():
            pe.close()

if __name__ == "__main__":
    target_folder = "static\\"

    for filename in os.listdir(target_folder):
        if filename.lower().endswith(('.exe', '.dll', '.sys', '.cpl')):
            file_path = os.path.join(target_folder, filename)
            print_all_pe_metadata(file_path)
            print("="*50)