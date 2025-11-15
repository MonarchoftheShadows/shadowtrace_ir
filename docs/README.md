# ShadowTrace-IR: Digital Forensics & Incident Response Console

**Version:** 1.0.0  
**Purpose:** Legitimate defensive cybersecurity, malware triage, and post-incident analysis
![ShadowTrace](https://github.com/user-attachments/assets/598dcb7f-e927-4c5f-ade0-66d133d6ee80)

---

## ⚠️ Important Notice

**ShadowTrace-IR is designed exclusively for defensive cybersecurity purposes:**

- ✅ Security researchers analyzing suspicious files from incidents
- ✅ Blue teams conducting post-infection forensics
- ✅ Threat analysts performing safe triage of unknown samples
- ✅ Compliance teams documenting evidence safely

**This tool is NOT intended for:**

- ❌ Circumventing detection systems
- ❌ Modifying or weaponizing malware
- ❌ Assisting malicious activity
- ❌ Any offensive security operations

---

## 🚀 Quick Start

### Installation

1. **Clone or download the project:**
```bash
   git clone https://github.com/MonarchoftheShadows/ShadowTrace.git
   cd shadowtrace_ir/
```

2. **Install dependencies:**
```bash
   pip install -r requirements.txt
   
   #Alternative: Install in virtual environment (recommended)
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   
```

3. **Optional: Install system dependencies:**
   - **exiftool** (for enhanced metadata extraction):
```bash
     # Ubuntu/Debian
     sudo apt-get install libimage-exiftool-perl
     
     # macOS
     brew install exiftool
```

### Running ShadowTrace-IR
```bash
python run.py
```

---

## 📋 Features

### 1. **File Analysis & Hashing**
- Compute MD5, SHA1, and SHA256 hashes
- Extract file size, timestamps, and MIME type
- For forensic archival and integrity verification

### 2. **Metadata Extraction**
- Extract document metadata (EXIF, PDF info, Office properties)
- Understand file provenance and history
- Uses `exiftool` when available

### 3. **String Extraction & IOC Discovery**
- Extract ASCII and UTF-16 strings
- Automatically identify potential IOCs:
  - Domain names
  - URLs
  - IP addresses
  - Email addresses

### 4. **PE/Executable Inspection**
- **Read-only** structural analysis of PE files
- View imported DLLs and functions
- Analyze sections and entropy
- Check security features (ASLR, DEP)
- **Purpose:** Malware classification and transparency, NOT reverse engineering

### 5. **YARA Rule Scanning**
- Load custom YARA rules
- Scan files for pattern matches
- View matched rules and tags
- Essential for malware detection

### 6. **OSINT Hash Lookups**
- Query file hashes (never uploads files) against:
  - **VirusTotal** - Multi-engine malware scanning
  - **HybridAnalysis** - Sandbox analysis reports
  - **AlienVault OTX** - Threat intelligence platform

### 7. **Forensic Report Generation**
- Generate comprehensive reports in:
  - **JSON** - Machine-readable format
  - **Markdown** - Documentation-friendly format
  - **Plain Text** - Universal compatibility

---

## 🔐 API Key Configuration

ShadowTrace-IR **never embeds API keys in code**. All keys are stored securely in `config.yaml`.

### Adding API Keys

1. Launch ShadowTrace-IR
2. Navigate to: **Settings & API Keys → Add/Update API Key**
3. Select the service and enter your key
4. Keys are saved locally in `config.yaml`

### Obtaining API Keys

- **VirusTotal:** https://www.virustotal.com/gui/join-us
- **HybridAnalysis:** https://www.hybrid-analysis.com/signup
- **AlienVault OTX:** https://otx.alienvault.com/

---

## 📁 Project Structure
```
shadowtrace_ir/
├── run.py                      # Main entry point
├── requirements.txt            # Python dependencies
├── config.yaml                 # Configuration file (API keys stored here)
├── core/
│   ├── __init__.py
│   ├── config_manager.py       # Configuration management
│   ├── ui.py                   # Terminal UI handler
│   └── menu_router.py          # Navigation and routing
├── modules/
│   ├── __init__.py
│   ├── hashing.py              # File hashing module
│   ├── metadata.py             # Metadata extraction
│   ├── strings.py              # String extraction
│   ├── pe_inspection.py        # PE file analysis
│   ├── yara_scan.py            # YARA scanning
│   ├── osint_vt.py             # VirusTotal integration
│   ├── osint_ha.py             # HybridAnalysis integration
│   ├── osint_otx.py            # AlienVault OTX integration
│   └── ioc_extractor.py        # IOC extraction
├── reports/
│   ├── __init__.py
│   └── report_builder.py       # Report generation
└── docs/
    └── README.md               # This file
```

---

## 🛠️ Usage Workflow

### Typical Analysis Workflow:

1. **Select Target File**
   - Choose the suspicious file to analyze

2. **Run File Analysis**
   - Compute hashes and gather basic information

3. **Extract Strings & IOCs**
   - Discover potential indicators of compromise

4. **Inspect PE Structure** (if applicable)
   - Analyze executable structure and imports

5. **Run YARA Scan** (optional)
   - Check against known malware signatures

6. **Perform OSINT Lookup**
   - Query threat intelligence platforms

7. **Generate Report**
   - Document findings in your preferred format

---

## 🔒 Security & Privacy

### Data Handling:
- **No file uploads:** OSINT modules only submit file hashes, never actual files
- **Local processing:** All analysis happens on your machine
- **API key security:** Keys stored locally, never transmitted except to authenticated services

### Best Practices:
- Always analyze suspicious files in isolated environments
- Use virtual machines or sandboxes for unknown samples
- Never run unknown executables on production systems
- Regularly update YARA rules from trusted sources

---

## 📚 Dependencies

### Python Libraries:
- `rich` - Terminal UI framework
- `pyyaml` - Configuration management
- `requests` - HTTP client for OSINT APIs
- `pefile` - PE file parsing
- `yara-python` - YARA rule engine
- `python-magic` - MIME type detection

### Optional System Tools:
- `exiftool` - Enhanced metadata extraction

---

## 🤝 Contributing

This tool is designed for the defensive security community. Contributions that enhance forensic capabilities, improve accuracy, or add legitimate analysis features are welcome.

**Please ensure all contributions:**
- Maintain defensive/forensic focus
- Include appropriate documentation
- Follow security best practices
- Do not enable malicious use cases

---

## 📄 License

This tool is provided for legitimate cybersecurity defense and incident response purposes only.

---

## ⚖️ Legal & Ethical Use

**Users must:**
- Comply with all applicable laws and regulations
- Only analyze files they have authorization to examine
- Use findings responsibly and ethically
- Not use this tool to facilitate malicious activity

**Remember:** This tool is for defense, not offense. Use it wisely and responsibly.

---

## 🆘 Support & Documentation

For questions, issues, or feature requests:
- Review this documentation thoroughly
- Check configuration settings in `config.yaml`
- Ensure all dependencies are properly installed
- Verify API keys are correctly configured
- Issues: Report bugs and request features via GitHub Issues or Report security issues privately to RealEnemyintheMirror@proton.me
---

**ShadowTrace-IR - Empowering Defensive Security Through Transparency**

*Stay vigilant. Stay defensive. Stay secure.*


