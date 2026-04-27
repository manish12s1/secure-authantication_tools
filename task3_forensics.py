import os
import hashlib
import shutil
import datetime
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False
    print("[WARNING] Pillow not installed - EXIF disabled")

# SETTINGS
# ============================================================
QUARANTINE_VAULT = "/home/manish/QUARANTINE_VAULT"
SCAN_LOG_FILE    = "/home/manish/scan_log.txt"
CHUNK_SIZE       = 4096

# KNOWN MALWARE SIGNATURES
 
KNOWN_BAD_SIGNATURES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
        "name"        : "EmptyFile.Trojan",
        "type"        : "Trojan",
        "severity"    : "HIGH",
        "description" : "Empty file used as malware placeholder"
    },
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": {
        "name"        : "HelloWorld.Spyware",
        "type"        : "Spyware",
        "severity"    : "MEDIUM",
        "description" : "Monitors and steals keystrokes"
    },
    "5994471abb01112afcc18159f6cc74b4f511b99806da59b3caf5a9c173cacfc5": {
        "name"        : "Backdoor.RAT.Generic",
        "type"        : "Backdoor",
        "severity"    : "CRITICAL",
        "description" : "Remote Access Trojan"
    },
    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": {
        "name"        : "Password.Stealer",
        "type"        : "Stealer",
        "severity"    : "CRITICAL",
        "description" : "Steals saved passwords"
    },
}

# Simple MD5-based signatures for quick test scan (user-requested add-on)
MD5_MALWARE_SIGNATURES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
}
 
# FILE MAGIC BYTES - Real file signature validation
# Detects true file type regardless of extension 
FILE_MAGIC_BYTES = {
    b'\xff\xd8\xff'       : "JPEG Image",
    b'\x89PNG\r\n\x1a\n' : "PNG Image",
    b'GIF87a'             : "GIF Image",
    b'GIF89a'             : "GIF Image",
    b'%PDF'               : "PDF Document",
    b'PK\x03\x04'        : "ZIP Archive",
    b'\x1f\x8b'          : "GZIP Archive",
    b'MZ'                 : "Windows EXE",
    b'\x7fELF'           : "Linux ELF Binary",
}


 
# FUNCTION 1: Validate real file type using magic bytes 
def check_file_signature(file_path):
    
   # Read first 8 bytes of file and compare to known magic bytes.This detects files pretending to be something they are not.For example a virus renamed as image.jpg
    try:
        with open(file_path, "rb") as f:
            header = f.read(8)

        for magic, file_type in FILE_MAGIC_BYTES.items():
            if header.startswith(magic):
                return file_type

        return "Unknown or Text File"

    except Exception as e:
        return "Cannot read: " + str(e)

#  Calculate SHA-256 hash using chunks
 
def calculate_sha256(file_path):
    """
    Calculate SHA-256 hash of file using 4096 byte chunks.
    Chunk reading is memory safe for large files.
    Returns hex string or None if failed.
    """
    if not os.path.exists(file_path):
        print("  [ERROR] File not found: " + file_path)
        return None

    if not os.path.isfile(file_path):
        print("  [ERROR] Not a valid file")
        return None

    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                sha256.update(chunk)

        return sha256.hexdigest()

    except PermissionError:
        print("  [SKIP] Permission denied: " + file_path)
        return None

    except Exception as e:
        print("  [ERROR] Hashing failed: " + str(e))
        return None


 # calculting    md5 hash
def calculate_md5(filepath):
    try:
        with open(filepath, "rb") as file:
            return hashlib.md5(file.read()).hexdigest()
    except Exception:
        return None

# qucck  single md   file  scan 
def scan_file(filepath):
    file_hash = calculate_md5(filepath)

    if file_hash in MD5_MALWARE_SIGNATURES:
        print(f"[CRITICAL] Malware detected: {filepath}")
        return True

    print(f"[*] Clean: {filepath}")
    return False


 # checking  bad  signniture  using sha256 hash
def check_signature(file_hash):

    #Compare file hash against known malware signatures.Returns malware info dict if match found.
    if not file_hash:
        return None

    for known_hash, info in KNOWN_BAD_SIGNATURES.items():
        if file_hash.lower() == known_hash.lower():
            return info

    return None


 # gps dms  into decimal conversion    Convert GPS from Degrees Minutes Seconds to decimal.Handles both tuple and IFDRational number formats.South and West values become negative decimal numbers.
def gps_to_decimal(coords, ref):
    
    try:
        values = []
        for c in coords:
            if hasattr(c, 'numerator'):
                values.append(float(c.numerator) / float(c.denominator))
            elif hasattr(c, 'real'):
                values.append(float(c))
            else:
                values.append(float(c))

        degrees = values[0]
        minutes = values[1]
        seconds = values[2]

        decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)

        if ref in ["S", "W"]:
            decimal = -decimal

        return round(decimal, 6)

    except Exception:
        return None


 
 #Extract EXIF metadata from image files
 
def extract_exif(file_path):
 
    if not PILLOW_AVAILABLE:
        print("  [EXIF] Pillow not installed - skipping")
        return None

    image_ext = [".jpg", ".jpeg", ".png", ".tiff", ".bmp"]
    file_ext  = os.path.splitext(file_path)[1].lower()

    if file_ext not in image_ext:
        print("  [EXIF] Not an image - skipping EXIF extraction")
        return None

    if not os.path.exists(file_path):
        print("  [EXIF] File not found")
        return None

    try:
        img      = Image.open(file_path)
        exif_raw = img._getexif()

        if not exif_raw:
            print("  [EXIF] No metadata found in this image")
            return None

        all_tags = {}
        for tag_id, value in exif_raw.items():
            tag_name           = TAGS.get(tag_id, str(tag_id))
            all_tags[tag_name] = value

        print("\n  " + "=" * 50)
        print("  EXIF METADATA REPORT")
        print("  " + "=" * 50)

        # Image basic information
        print("\n  [IMAGE INFO]")
        print("  Format     : " + str(img.format))
        print("  Dimensions : " + str(img.size[0]) + " x " + str(img.size[1]))
        print("  Mode       : " + str(img.mode))

        # Camera make and model
        print("\n  [CAMERA INFO]")
        camera_tags  = ["Make", "Model", "Software", "LensModel"]
        found_camera = False
        for tag in camera_tags:
            if tag in all_tags:
                print("  " + tag + " : " + str(all_tags[tag]))
                found_camera = True
        if not found_camera:
            print("  No camera information found")

        # Date photo was taken
        print("\n  [DATE TAKEN]")
        date_tags  = ["DateTimeOriginal", "DateTime", "DateTimeDigitized"]
        found_date = False
        for tag in date_tags:
            if tag in all_tags:
                print("  " + tag + " : " + str(all_tags[tag]))
                found_date = True
                break
        if not found_date:
            print("  No date information found")

        # GPS location
        print("\n  [GPS LOCATION]")
        if "GPSInfo" in all_tags:
            gps_raw  = all_tags["GPSInfo"]
            gps_data = {}

            for gps_id, gps_val in gps_raw.items():
                gps_name           = GPSTAGS.get(gps_id, str(gps_id))
                gps_data[gps_name] = gps_val

            lat = None
            lon = None
            alt = None

            if "GPSLatitude" in gps_data:
                lat = gps_to_decimal(
                    gps_data["GPSLatitude"],
                    gps_data.get("GPSLatitudeRef", "N")
                )

            if "GPSLongitude" in gps_data:
                lon = gps_to_decimal(
                    gps_data["GPSLongitude"],
                    gps_data.get("GPSLongitudeRef", "E")
                )

            if "GPSAltitude" in gps_data:
                try:
                    alt = round(float(gps_data["GPSAltitude"]), 2)
                except:
                    alt = None

            if lat is not None and lon is not None:
                print("  Latitude   : " + str(lat) + " decimal degrees")
                print("  Longitude  : " + str(lon) + " decimal degrees")
                if alt is not None:
                    print("  Altitude   : " + str(alt) + " meters")
                print("  Google Map : https://maps.google.com/?q="
                      + str(lat) + "," + str(lon))
                print("  OSM Map    : https://www.openstreetmap.org/?mlat="
                      + str(lat) + "&mlon=" + str(lon))
            else:
                print("  GPS data found but coordinates incomplete")

        else:
            print("  No GPS data found in this image")

        print("  " + "=" * 50)
        return all_tags

    except Exception as e:
        print("  [EXIF] Failed to read metadata: " + str(e))
        return None


 
#   Write quarantine event to log file
 
def write_log(original, vault_path, malware_info, timestamp):
  
    try:
        with open(SCAN_LOG_FILE, "a") as log:
            log.write("=" * 50 + "\n")
            log.write("Time        : " + timestamp + "\n")
            log.write("Original    : " + original + "\n")
            log.write("Quarantined : " + vault_path + "\n")
            log.write("Malware     : " + malware_info["name"] + "\n")
            log.write("Type        : " + malware_info["type"] + "\n")
            log.write("Severity    : " + malware_info["severity"] + "\n")
            log.write("Description : " + malware_info["description"] + "\n\n")

        print("  Log Updated : " + SCAN_LOG_FILE)

    except Exception as e:
        print("  [ERROR] Log write failed: " + str(e))


 
#   Move malicious file to quarantine vault
 
def quarantine_file(file_path, malware_info):
 
    if not os.path.exists(file_path):
        print("  [ERROR] File not found for quarantine")
        return False

    try:
        timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        original    = os.path.basename(file_path)
        mal_type    = malware_info.get("type", "UNKNOWN")
        new_name    = timestamp + "_" + mal_type + "_" + original
        destination = os.path.join(QUARANTINE_VAULT, new_name)

        shutil.move(file_path, destination)

        print("  [QUARANTINED] File moved to vault")
        print("  Original     : " + original)
        print("  Vault Name   : " + new_name)
        print("  Vault Path   : " + destination)

        write_log(file_path, destination, malware_info, timestamp)
        return True

    except Exception as e:
        print("  [ERROR] Quarantine failed: " + str(e))
        return False

#   Show quarantine vault contents
 
def show_vault():
   # """Display all files currently in quarantine vault."""
    print("\n" + "=" * 55)
    print("  QUARANTINE VAULT")
    print("  Path: " + QUARANTINE_VAULT)
    print("=" * 55)

    if not os.path.exists(QUARANTINE_VAULT):
        print("  Vault does not exist yet")
        return

    files = os.listdir(QUARANTINE_VAULT)

    if not files:
        print("  Vault is empty")
        return

    print("  Total Files : " + str(len(files)))
    print("-" * 55)

    for i, filename in enumerate(files, 1):
        file_path = os.path.join(QUARANTINE_VAULT, filename)
        file_size = os.path.getsize(file_path)
        print("  " + str(i) + ". " + filename)
        print("     Size : " + str(file_size) + " bytes")

    print("=" * 55)

 
#  : Scan a single file completely
 
def scan_single_file(file_path):
    """
    Run complete static forensic scan on a single file.
    Steps: file signature check, SHA-256 hash,
    malware signature check, EXIF extraction for images,
    quarantine if infected.
    """
    print("\n" + "=" * 55)
    print("  SCANNING FILE")
    print("=" * 55)
    print("  File : " + os.path.basename(file_path))
    print("  Path : " + file_path)
    print("-" * 55)

    if not os.path.exists(file_path):
        print("  [ERROR] File does not exist")
        return "error"

    if not os.path.isfile(file_path):
        print("  [ERROR] Path is not a file")
        return "error"

    # Step 1: Validate real file type using magic bytes
    real_type = check_file_signature(file_path)
    print("  Real Type : " + real_type)

    # Step 2: Calculate SHA-256 hash
    print("\n  [HASHING]")
    file_hash = calculate_sha256(file_path)

    if not file_hash:
        print("  [SKIP] Cannot hash this file")
        return "skipped"

    print("  SHA-256 : " + file_hash)

    # Step 3: Check against malware signatures
    print("\n  [SIGNATURE CHECK]")
    malware_info = check_signature(file_hash)

    # Step 4: EXIF/GPS forensic extraction (for image files) before quarantine
    # so metadata is still accessible even if file is moved
    extract_exif(file_path)

    if malware_info:
        print("  *** MALWARE DETECTED ***")
        print("  Name     : " + malware_info["name"])
        print("  Type     : " + malware_info["type"])
        print("  Severity : " + malware_info["severity"])
        print("  Details  : " + malware_info["description"])

        # Step 5: Quarantine the malicious file
        print("\n  [QUARANTINE]")
        success = quarantine_file(file_path, malware_info)
        if success:
            print("  [ACTION] Infected file isolated in quarantine vault")
            return "infected"

        print("  [ERROR] Malware detected but quarantine failed")
        return "skipped"

    print("  [CLEAN] No malware detected - file is safe")
    return "clean"

 
#   Scan entire folder automatically
# 
def scan_folder(folder_path):
    
    print("\n" + "#" * 55)
    print("  FOLDER SCAN STARTED")
    print("  Target : " + folder_path)
    print("#" * 55)

    if not os.path.exists(folder_path):
        print("[ERROR] Folder not found: " + folder_path)
        return

    if not os.path.isdir(folder_path):
        print("[ERROR] Not a valid folder")
        return

    total_scanned  = 0
    total_clean    = 0
    total_infected = 0
    total_skipped  = 0

    quarantine_resolved = str(Path(QUARANTINE_VAULT).resolve())

    for root, dirs, files in os.walk(folder_path):
        root_resolved = str(Path(root).resolve())

        # Prevent descending into quarantine vault
        dirs[:] = [
            d for d in dirs
            if str((Path(root) / d).resolve()) != quarantine_resolved
        ]

        # Skip current root itself if it is the quarantine vault
        if root_resolved == quarantine_resolved:
            continue

        for filename in files:
            file_path = os.path.join(root, filename)
            result    = scan_single_file(file_path)

            total_scanned += 1

            if result == "clean":
                total_clean += 1
            elif result == "infected":
                total_infected += 1
            elif result == "skipped":
                total_skipped += 1
            elif result == "error":
                total_skipped += 1

    # Print final summary
    print("\n" + "=" * 55)
    print("  FOLDER SCAN COMPLETE - SUMMARY")
    print("=" * 55)
    print("  Total Scanned  : " + str(total_scanned))
    print("  Clean Files    : " + str(total_clean))
    print("  Infected       : " + str(total_infected))
    print("  Skipped/Error  : " + str(total_skipped))
    print("  Quarantine     : " + QUARANTINE_VAULT)
    print("  Log File       : " + SCAN_LOG_FILE)
    print("=" * 55)


 
# FUNCTION 11: Show scan log file contents
 
def show_log():
    """Display contents of the scan log file."""
    print("\n" + "=" * 55)
    print("  SCAN LOG FILE")
    print("  Path: " + SCAN_LOG_FILE)
    print("=" * 55)

    if not os.path.exists(SCAN_LOG_FILE):
        print("  No log file found yet")
        print("  Log is created when malware is detected")
        return

    try:
        with open(SCAN_LOG_FILE, "r") as log:
            content = log.read()

        if content.strip():
            print(content)
        else:
            print("  Log file is empty")

    except Exception as e:
        print("  [ERROR] Cannot read log: " + str(e))

    print("=" * 55)


 
# MAIN MENU
 
def main():
    

    # Setup quarantine vault on startup
    if not os.path.exists(QUARANTINE_VAULT):
        os.makedirs(QUARANTINE_VAULT)
        print("[SETUP] Quarantine vault created!")

    print("\n" + "#" * 55)
    print("  TASK 3: MALWARE ANALYSIS AND FORENSICS TOOL")
    print("  Static File Scanner with Quarantine System")
    print("#" * 55)

    while True:
        print("\n" + "=" * 45)
        print("  MAIN MENU")
        print("=" * 45)
        print("  1. Scan Single File")
        print("  2. Scan Entire Folder")
        print("  3. Show Quarantine Vault")
        print("  4. Show Scan Log")
        print("  5. Exit")
        print("  6. Quick MD5 Test Scan (fake_virus.txt)")
        print("=" * 45)

        choice = input("  Choose (1-6): ").strip()

        if choice == "1":
            path = input("  Enter file path: ").strip()
            if path:
                scan_single_file(path)
            else:
                print("  [ERROR] No path entered")

        elif choice == "2":
            folder = input("  Enter folder path: ").strip()
            if folder:
                scan_folder(folder)
            else:
                print("  [ERROR] No folder path entered")

        elif choice == "3":
            show_vault()

        elif choice == "4":
            show_log()

        elif choice == "5":
            print("\n  Goodbye! Stay secure.")
            break

        elif choice == "6":
            scan_file("fake_virus.txt")



if __name__ == "__main__":
    main()