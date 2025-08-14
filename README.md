# 🖧 ARP Network Scanner

A Python-based **ARP network scanner** that discovers devices on your local network by sending broadcast requests and collecting replies.

---

## 📌 Features
- Scans a target subnet for active hosts
- Displays each device’s **IP** and **MAC** address
- Supports **JSON** output for scripting
- Optional interface selection
- Beginner-friendly, heavily commented code

---

## 🛠 Requirements
- **Python 3.8+**
- **Scapy** (`pip install scapy`)
- **Root/Administrator privileges** to send low-level packets
- **Linux** / **macOS** recommended (Windows works with Npcap installed)

---

## 📂 Installation
```bash
# Clone this repository
git clone https://github.com/yAyushKoul24/network_scanner.git
cd network_scanner

# Create a virtual environment
python3 -m venv .venv
# Activate:
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
