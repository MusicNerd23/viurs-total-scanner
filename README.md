# 🔍 VirusTotal Scanner

[![GitHub Repo](https://img.shields.io/badge/GitHub-Repo-blue?logo=github)](https://github.com/MusicNerd23/viurs-total-scanner)
![GitHub last commit](https://img.shields.io/github/last-commit/MusicNerd23/viurs-total-scanner)
![GitHub stars](https://img.shields.io/github/stars/MusicNerd23/viurs-total-scanner?style=social)
![GitHub issues](https://img.shields.io/github/issues/MusicNerd23/viurs-total-scanner)
![GitHub license](https://img.shields.io/github/license/MusicNerd23/viurs-total-scanner)

A simple command-line tool that checks files against the **VirusTotal database** to detect potential threats.  
It allows you to **scan a file using its hash** or **upload a file for scanning** if no prior results exist.

---

## 🚀 Features
✅ Scan files against **VirusTotal** using SHA-256 hash.  
✅ Upload files to VirusTotal for scanning (if not previously analyzed).  
✅ Uses **argparse** for command-line flexibility.  

---

## ⚙️ Installation

### 1️⃣ Clone the Repository
```bash
git clone https://github.com/MusicNerd23/viurs-total-scanner.git
cd viurs-total-scanner
```

### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🔑 Setting Up Your API Key
To use the VirusTotal API, you must obtain an **API key** from [VirusTotal](https://www.virustotal.com/gui/join).  

### 📌 Where to Place the API Key
1. Create a new file in the project directory named **`config.py`**  
   *(If it doesn’t exist, create it manually.)*  
2. Open **`config.py`** and add the following line:
   ```python
   API_KEY = "your_virustotal_api_key"
   ```
3. Save the file.

⚠️ **Do NOT share your API key publicly!**  

---

## 📄 Usage
Run the script with the appropriate flag:  

### 🔍 Scan a File Using Its Hash
```bash
python scanner.py -s path/to/file
```
✅ This checks if the file **already exists in VirusTotal**.  

**Example:**
```bash
python scanner.py -s eicar.com
```

---

### 📤 Upload a File and Scan
```bash
python scanner.py -u path/to/file
```
✅ This **uploads the file** to VirusTotal for analysis **if no prior scan exists**.

**Example:**
```bash
python scanner.py -u eicar.com
```

---

## 🔗 Example Output
```
🔍 Scan Results for 'eicar.com':
✅ Harmless: 2
❗ Malicious: 50
⚠ Suspicious: 0
🚨 WARNING: This file is flagged as malicious!
```

If the file is not found:
```
🔍 No previous scan found. Uploading for scanning...
✅ File uploaded successfully! Scan ID: abcd1234xyz
🔗 View Results: https://www.virustotal.com/gui/file/abcd1234xyz
```

---

## 🔐 Security Best Practices
- **Do not upload sensitive or proprietary files** to VirusTotal.
- Always **review AI-generated code** for security risks before using it in production.

---

## 🤝 Contributing
Pull requests are welcome! If you have suggestions or improvements, feel free to contribute.

---

## 📜 License
This project is licensed under the **MIT License**.