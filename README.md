# Network Scanner with Automated Analysis

This is a script I developed during my cyber security course to automate the process of network reconnaissance and result interpretation. It uses Nmap to scan a target and then utilizes the Gemini API to analyze the findings.

I built this because I wanted to find a way to quickly identify the most critical risks in a scan without manually looking up every service version. The tool helps in categorizing vulnerabilities and suggesting immediate remediation steps.

How it works:
- It performs a service and version detection scan using Nmap.
- The results are parsed and sent to a Generative AI model.
- A report is generated that highlights open ports, service risks, and a prioritized action plan.

I used Python for the logic, Nmap for the scanning engine, and environment variables to keep the API keys secure.

To use this project:
1. Clone the repository.
2. Add your API key to a .env file.
3. Run the script: python3 nmap_scanner.py <target_ip>

Note: This was created for educational purposes. Always ensure you have permission before scanning any target.
