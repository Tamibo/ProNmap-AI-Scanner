# Network Scanner + AI Analysis

This is a personal project I developed to explore how Generative AI can be integrated into daily security workflows. The goal was to take raw, technical data from an Nmap scan and automatically turn it into something more meaningful—a structured security report with actual context.

## Why I built this
As part of my Cyber Security studies, I noticed that interpreting Nmap results can sometimes be time-consuming, especially when dealing with multiple services. I wanted to see if I could use Python to bridge the gap between scanning a target and understanding its risk profile in plain English.

## How it works
The script runs a professional Nmap scan (using service and version detection) and then feeds that specific output into the Gemini AI API. The AI isn't just summarizing; it's looking at the versions and port states to suggest potential vulnerabilities and practical remediation steps.

## Main Features
* **Automated Recon:** Uses the Nmap engine to find open ports and identify service versions.
* **Smart Reporting:** Generates a Markdown report that includes risk scores and "next steps" for a security analyst.
* **Flexible Modes:** Includes options for stealthy scans or more aggressive version detection depending on the lab environment.
* **Clean Data:** Outputs everything to JSON so it's easy to track or pipe into other tools later.

## Quick Start
1. **Clone the repo:** `git clone https://github.com/YOUR_USER/ProNmap-AI-Scanner.git`
2. **Setup:** Add your API key to a `.env` file (`GOOGLE_API_KEY=your_key`).
3. **Install:** `pip install -r requirements.txt`
4. **Run it:** `python3 nmap_scanner.py <target_ip>`

---
*Note: This tool was created for educational purposes in a controlled lab environment. Always ensure you have explicit permission before scanning any network.*
