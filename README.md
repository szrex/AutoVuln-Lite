# 🔍 AutoVuln-Lite  
A lightweight, fast, and offline-capable **CPE → CVE Vulnerability Scanner** built using Python and Nmap.

AutoVuln-Lite performs:

- ✔ Nmap service/version scanning  
- ✔ XML parsing of scan results  
- ✔ Service → CPE fingerprinting  
- ✔ CPE → CVE matching using NVD JSON 2.0  
- ✔ Clean structured vulnerability reporting  

This is a simplified version of a full vulnerability assessment engine.

---

## ⚡ Features

- 🚀 **Fast scanning** using predefined Nmap profiles  
- 📄 **XML parser** to extract port/service/product data  
- 🧠 **Smart CPE estimator** for matching service names  
- 🛡 **Offline CVE lookup** using NVD JSON 2.0 dataset  
- 📦 **Zero external API calls** (fully local)  
- 📝 **Readable, clean vulnerability output**  
- 💡 Perfect for learning cybersecurity automation  

---

## 📁 Project Structure

```
AutoVuln-Lite/
 │── config/
 │     └── scan_profiles.json
 │── data/
 │     └── nvd/            (Place NVD JSON files here)
 │── parser/
 │     └── xml_parser.py
 │── cpe_mapper/
 │     └── cpe_mapper.py
 │── cve_mapper/
 │     └── cve_mapper.py
 │── scanner/
 │     └── scan_runner.py
 │── requirements.txt
 │── README.md
```

---

## 🛠 Installation

### 1️⃣ Clone the repository

```
git clone https://github.com/szrex/AutoVuln-Lite.git
cd AutoVuln-Lite
```

### 2️⃣ Create & activate virtual environment

```
python -m venv venv
.\venv\Scripts\activate
```

### 3️⃣ Install dependencies

```
pip install -r requirements.txt
```

---

## 📥 Download NVD Database (Required)

AutoVuln-Lite requires local NVD JSON 2.0 feeds.

Download them from:  
👉 https://nvd.nist.gov/vuln/data-feeds#JSON_FEED

Then place the files here:

```
data/nvd/
```

Example:

```
data/nvd/nvdcve-2.0-2023.json
data/nvd/nvdcve-2.0-2024.json
data/nvd/nvdcve-2.0-2025.json
```

That's all — no API keys, no networking, fully offline.

---

## ▶️ Usage

Run the scanner:

```
python scanner/scan_runner.py
```

Enter:

- Target IP/CIDR  
- Scan profile (fast / full_tcp / lab_udp)

The tool will:

1. Run Nmap  
2. Parse XML  
3. Detect service & version  
4. Predict CPE  
5. Match CVEs  
6. Print final vulnerability report  

---

## 🧪 Example Output

```
IP:        192.168.1.7
Port:      135
Service:   msrpc
Product:   Microsoft Windows RPC
CPE:       cpe:/a:microsoft:microsoft_rpc
CVEs:
   - CVE-2022-XXXXX (High, CVSS 8.2)
   - CVE-2021-YYYYY (Medium, CVSS 6.5)
------------------------------------------------------------
```

---

## 📍 Limitations

- Requires local NVD dataset  
- CPE inference is approximate  
- Designed for learning & research, not production use  

---

## 🧠 Future Enhancements

- AI-assisted vulnerability prioritization  
- ExploitDB / Metasploit mapping  
- PDF reporting  
- Web UI  
- Offline exploit simulation  

---

## ⭐ Support the project

Give the repo a ⭐ if you like the project!  
Contributions and suggestions are welcome.

