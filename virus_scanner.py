import requests
import hashlib
import argparse
from config import API_KEY  # Import API key from config.py

# Function to compute SHA-256 hash of a file
def get_file_hash(file_path):
    """Generate SHA-256 hash of the given file."""
    sha256_hash = hashlib.sha256()
    
    try:
        with open(file_path, "rb") as f:
            byte_block = f.read(4096)  # Read first chunk
            while byte_block:  # Continue until empty
                sha256_hash.update(byte_block)
                byte_block = f.read(4096)  # Read next chunk
        
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found.")
        return None

    return sha256_hash.hexdigest()

# Function to check file hash on VirusTotal
def scan_file(file_path):
    """Check if the file has been scanned by VirusTotal."""
    file_hash = get_file_hash(file_path)
    if not file_hash:
        return

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": API_KEY}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        result = response.json()
        stats = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

        print(f"\n🔍 Scan Results for '{file_path}':")
        print(f"✅ Harmless: {stats.get('harmless', 0)}")
        print(f"❗ Malicious: {stats.get('malicious', 0)}")
        print(f"⚠ Suspicious: {stats.get('suspicious', 0)}")

        if stats.get("malicious", 0) > 0:
            print("🚨 WARNING: This file is flagged as malicious!")
        else:
            print("✅ This file appears safe.")
    elif response.status_code == 404:
        print("🔍 No previous scan found. Consider uploading the file for scanning.")
    else:
        print(f"❌ Error: {response.json()}")

# Function to upload file if no hash exists in VirusTotal database
def upload_and_scan(file_path):
    """Upload a file to VirusTotal for scanning if no previous results exist."""
    url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": API_KEY}

    try:
        with open(file_path, "rb") as file:
            files = {"file": file}
            response = requests.post(url, headers=headers, files=files)

        if response.status_code == 200:
            scan_result = response.json()
            analysis_id = scan_result.get("data", {}).get("id", "")
            print(f"✅ File uploaded successfully! Scan ID: {analysis_id}")
            print("⏳ Scan in progress... Check results on VirusTotal.")
            print(f"🔗 View Results: https://www.virustotal.com/gui/file/{analysis_id}")
        else:
            print("❌ Upload failed:", response.text)
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found.")

# Adding argparse to accept file path and flags from command line
def main():
    parser = argparse.ArgumentParser(description="VirusTotal Scanner with Flags")
    
    parser.add_argument("file", help="Path to the file to scan")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--scan", action="store_true", help="Scan the file using its hash")
    group.add_argument("-u", "--upload", action="store_true", help="Upload the file and scan it if not found in VirusTotal")

    args = parser.parse_args()

    if args.scan:
        scan_file(args.file)
    elif args.upload:
        upload_and_scan(args.file)

if __name__ == "__main__":
    main()