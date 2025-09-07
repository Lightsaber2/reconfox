# ReconFox 🦊
A Lightweight & Stealthy Web Vulnerability Scanner

---

## 📌 Overview
ReconFox is a simple yet powerful **web vulnerability scanner** built with Python.  
It automates the detection of common web security issues while staying **stealth-aware** to reduce noise and avoid detection.

⚠️ **Disclaimer**  
This tool is for **educational and authorized penetration testing only**.  
The author is **not responsible** for any misuse or illegal activity. Always ensure you have **explicit permission** before scanning.

---

## ✨ Features
- 🔍 **Port Scanning & Banner Grabbing**
- 🛡️ **SQL Injection Detection**
- 💻 **XSS Detection**
- 🔄 **Open Redirect Checks**
- 📑 **Security Headers Analysis**
- 🌐 **CORS Misconfiguration Checks**
- 📂 **Directory Listing Detection**
- 🕷️ **Stealth-Aware Web Crawler**
- 📊 **JSON Export of Results**
- ⚡ **Stealth Mode** (rotating headers, randomized delays, retries)

---

## 📂 Project Structure

```
reconfox/
│── main.py              # Main entry point
│── scanner/             # Scanner modules
│   ├── __init__.py
│   ├── http_client.py
│   ├── port_scan.py
│   ├── banner_grab.py
│   ├── sql_injection.py
│   ├── xss.py
│   ├── headers.py
│   ├── redirect.py
│   ├── cors.py
│   ├── dirlisting.py
│   ├── crawler.py
│── results/             # Scan results
│── requirements.txt     # Python dependencies
│── README.md            # Project documentation
│── LICENSE              # Open-source license
│── .gitignore           # Ignore cache, results, venv
```

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/Lightsaber2/reconfox.git
cd reconfox

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic Scan
```bash
python main.py --target [target domain or IP]
```

### Save Results as JSON
```bash
python main.py --target [target domain or IP] -j
```

### Enable Stealth Mode
```bash
python main.py --target [target domain or IP] --stealth --delay-min 1 --delay-max 3 --threads 2
```

### Enable the fast mode
```bash
python main.py --target [target domain or IP] --fast --only-modules sqli,xss,headers --threads 10 -j
```

---

## 📊 Example Output

```
=== Final Scan Report ===

High Findings (1):
   - Port 21 open

Medium Findings (6):
   - Server version exposed in banner
   - Content-Security-Policy missing
   - X-Frame-Options missing
   - X-Content-Type-Options missing
   - Strict-Transport-Security missing
   - Directory listing enabled at /admin/

Info Findings (9):
   - No SQLi detected
   - No XSS detected
   - No Open Redirect
   - No CORS headers
   - Discovered URL: https://discoveredurl.com
```

---

## 🛡️ Legal Disclaimer
ReconFox is intended for **educational purposes** and **authorized penetration testing only**.  
You are **responsible** for ensuring compliance with all applicable laws.  
Unauthorized use against systems without permission is strictly prohibited.

---

## 📜 License
This project is licensed under the [MIT License](LICENSE).

---

👨‍💻 Developed by **Lightsaber2**
