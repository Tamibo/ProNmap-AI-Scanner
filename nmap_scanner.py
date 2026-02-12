#!/usr/bin/env python3
"""
ProNmap V2.0 - Professional Nmap Scanner with AI Analysis
Author: Cyber Security Student Portfolio
"""

import warnings
# משתיק אזהרות מערכת לא רלוונטיות (כדי לשמור על לוג נקי)
warnings.simplefilter("ignore")

import sys
import os
import json  # חדש: מאפשר שמירת נתונים בפורמט שקל לקרוא בקוד
import ipaddress
from datetime import datetime
import argparse # חדש: מאפשר ניהול ארגומנטים מתקדם בשורת הפקודה

# בדיקה שהספריות הנדרשות מותקנות
try:
    import nmap
    from dotenv import load_dotenv
    import google.generativeai as genai
    import colorama
    from colorama import Fore, Style, init
    # אתחול צבעים (autoreset=True מונע מהצבע "לזלוג" לשורות הבאות)
    init(autoreset=True, strip=False)
except ImportError as e:
    print(f"Error: Missing library. {e}")
    print("Run: pip3 install python-nmap python-dotenv google-generativeai colorama")
    sys.exit(1)

# ==========================================
# קבועים ועיצוב
# ==========================================

BANNER = f"""{Fore.CYAN}
    ____             _   __                     
   / __ \_________  / | / /___ ___  ____ _____  
  / /_/ / ___/ __ \/  |/ / __ `__ \/ __ `/ __ \ 
 / ____/ /  / /_/ / /|  / / / / / / /_/ / /_/ / 
/_/   /_/   \____/_/ |_/_/ /_/ /_/\__,_/ .___/  
                                      /_/       
{Style.RESET_ALL}{Fore.YELLOW}Professional Nmap Scanner & AI Analysis Tool{Style.RESET_ALL}
"""

class ProNmapScanner:
    def __init__(self, api_key_env="GOOGLE_API_KEY"):
        """אתחול המחלקה: יצירת תיקיות והגדרת ה-AI"""
        self.target = None
        # יצירת תיקייה ייעודית לכל סריקה עם חותמת זמן
        self.results_dir = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(self.results_dir, exist_ok=True)
        self.setup_ai(api_key_env)
    
    def setup_ai(self, key_name):
        """חיבור ל-Gemini API"""
        load_dotenv()
        self.api_key = os.getenv(key_name)
        
        if self.api_key:
            genai.configure(api_key=self.api_key)
            try:
                # מנסים את המודל המהיר והחדש ביותר
                self.model = genai.GenerativeModel('gemini-flash-latest')
                print(f"{Fore.GREEN}[*] AI System Online (Gemini 1.5 Flash){Style.RESET_ALL}")
            except:
                # גיבוי למקרה שהמודל החדש לא זמין
                self.model = genai.GenerativeModel('gemini-pro')
                print(f"{Fore.YELLOW}[!] AI Fallback Mode (Gemini Pro){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!] No API Key found. AI analysis will be disabled.{Style.RESET_ALL}")
    
    def validate_target(self, target):
        """בדיקה שהכתובת שהוזנה היא כתובת IP תקינה"""
        try:
            # הפונקציה הזו זורקת שגיאה אם הכתובת לא חוקית (למשל 999.999.999)
            ipaddress.ip_network(target, strict=False)
            return True
        except ValueError:
            print(f"{Fore.RED}[!] Invalid IP address or range: {target}{Style.RESET_ALL}")
            return False

    def construct_nmap_args(self, mode, ports):
        """בניית פקודת Nmap דינמית לפי בחירת המשתמש"""
        base_args = "-sV" # תמיד נרצה זיהוי גרסאות שירותים
        
        # בחירת מצב סריקה (Stealth vs Aggressive)
        if mode == 'stealth':
            # -T2: איטי ומנומס
            # -sS: סריקת SYN (חצי פתוחה) שלא משלימה לחיצת יד ולכן פחות רועשת
            print(f"{Fore.BLUE}[i] Mode: STEALTH (Slow & Silent){Style.RESET_ALL}")
            return f"{base_args} -T2 -sS -p {ports}"
            
        elif mode == 'aggressive':
            # -T4: מהיר
            # -A: הכל כולל הכל (מערכת הפעלה, סקריפטים, traceroute)
            # --min-rate 1000: שולח לפחות 1000 חבילות בשנייה (רועש מאוד!)
            print(f"{Fore.RED}[i] Mode: AGGRESSIVE (Fast & Loud){Style.RESET_ALL}")
            return f"{base_args} -T4 -A --min-rate 1000 -p {ports}"
            
        else:
            # ברירת מחדל: מאוזן
            print(f"{Fore.GREEN}[i] Mode: NORMAL (Balanced){Style.RESET_ALL}")
            return f"{base_args} -T3 -p {ports}"

    def scan(self, target, ports="1-1000", mode="normal"):
        """ביצוע הסריקה הראשית"""
        if not self.validate_target(target):
            return []
        
        self.target = target
        arguments = self.construct_nmap_args(mode, ports)
        
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"🚀 STARTING SCAN ON: {Fore.YELLOW}{target}")
        print(f"🔧 Arguments: {arguments}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")
        
        nm = nmap.PortScanner()
        results_list = []
        
        try:
            # הרצת הסריקה בפועל
            nm.scan(target, arguments=arguments)
            
            # בדיקה אם המארח בכלל למעלה
            if target not in nm.all_hosts():
                print(f"{Fore.RED}[!] Host is down or blocking ping probes.{Style.RESET_ALL}")
                return []
            
            # מעבר על כל הפרוטוקולים (TCP/UDP)
            for proto in nm[target].all_protocols():
                lport = nm[target][proto].keys()
                for port in sorted(lport):
                    port_data = nm[target][proto][port]
                    state = port_data['state']
                    
                    if state == 'open':
                        # איסוף המידע למבנה נתונים מסודר
                        service_info = {
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": port_data.get('name', 'unknown'),
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', ''),
                            "extra_info": port_data.get('extrainfo', '')
                        }
                        results_list.append(service_info)
                        
                        # הדפסה יפה לטרמינל בזמן אמת
                        print(f"{Fore.GREEN}[+] {port}/{proto} OPEN {Style.RESET_ALL}| "
                              f"{Fore.YELLOW}{service_info['service']} {service_info['product']} {service_info['version']}")

            # שמירת התוצאות
            self.save_results(results_list)
            return results_list

        except Exception as e:
            print(f"{Fore.RED}[!] Critical Scan Error: {e}{Style.RESET_ALL}")
            return []

    def save_results(self, results):
        """שמירת התוצאות ל-TXT ול-JSON"""
        # שמירת JSON (לשימוש עתידי או אינטגרציות)
        json_path = os.path.join(self.results_dir, "scan_raw.json")
        with open(json_path, 'w') as f:
            json.dump(results, f, indent=4)
            
        # שמירת TXT (לקריאה אנושית)
        txt_path = os.path.join(self.results_dir, "scan_log.txt")
        with open(txt_path, 'w') as f:
            f.write(f"SCAN REPORT FOR {self.target}\n")
            f.write(f"DATE: {datetime.now()}\n")
            f.write("-" * 50 + "\n")
            for r in results:
                f.write(f"Port {r['port']}: {r['service']} {r['product']} {r['version']}\n")
        
        print(f"\n{Fore.CYAN}[*] Results saved to folder: {self.results_dir}{Style.RESET_ALL}")

    def ai_analysis(self, results):
        """שליחת הממצאים ל-AI לניתוח סיכונים"""
        if not self.api_key or not results:
            return

        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"🤖 STARTING AI VULNERABILITY ANALYSIS...")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        # המרת רשימת הממצאים לטקסט קריא עבור ה-AI
        scan_summary = json.dumps(results, indent=2)

        prompt = f"""
        You are a Senior Penetration Tester & Security Analyst.
        
        TARGET IP: {self.target}
        SCAN TIME: {datetime.now().strftime('%Y-%m-%d %H:%M')}
        
        Here is the raw JSON output from an Nmap scan:
        {scan_summary}
        
        Your Mission:
        Analyze these findings and create a professional penetration test report.
        
        Structure the report exactly like this:
        1. **Executive Summary**: A 2-sentence overview for management.
        2. **Risk Assessment Table**: List each open port with its Risk Level (Critical/High/Medium/Low).
        3. **Vulnerability Deep Dive**: For high-risk items, explain the specific threat (e.g., "Outdated Apache version vulnerable to RCE"). Mention CVEs if applicable.
        4. **Remediation Plan**: Concrete steps to fix the issues (e.g., "Update OpenSSH to version X", "Disable SMBv1").
        
        Tone: Professional, Action-Oriented, "Hacker-Style".
        """

        try:
            response = self.model.generate_content(prompt)
            
            # הדפסה למסך
            print(f"{Fore.WHITE}{response.text}{Style.RESET_ALL}")
            
            # שמירה לקובץ דוח סופי
            report_path = os.path.join(self.results_dir, "AI_SECURITY_REPORT.md")
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(response.text)
                
            print(f"\n{Fore.GREEN}[*] 📝 AI Report saved successfully to: {report_path}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] AI Analysis Failed: {e}{Style.RESET_ALL}")

def main():
    """הפונקציה הראשית - ניהול ארגומנטים משורת הפקודה"""
    print(BANNER)
    
    # הגדרת הארגומנטים שהתוכנה יודעת לקבל
    parser = argparse.ArgumentParser(description="ProNmap - Advanced Security Scanner")
    parser.add_argument("target", nargs="?", help="Target IP address (e.g., 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    
    # קבוצת ארגומנטים שרק אחד מהם יכול להיבחר (או שקט או רועש)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--stealth", action="store_true", help="Stealth mode (Slow, T2, SYN scan)")
    group.add_argument("--aggressive", action="store_true", help="Aggressive mode (Fast, T4, All scripts)")
    
    args = parser.parse_args()
    
    # אם המשתמש לא הזין כלום, עוברים למצב אינטראקטיבי
    target = args.target
    if not target:
        target = input(f"{Fore.BLUE}🎯 Enter Target IP: {Style.RESET_ALL}").strip()
        
    if not target:
        print(f"{Fore.RED}[!] No target specified. Exiting.{Style.RESET_ALL}")
        sys.exit(1)

    # קביעת המצב הנבחר
    mode = "normal"
    if args.stealth: mode = "stealth"
    if args.aggressive: mode = "aggressive"

    # הרצת התהליך
    scanner = ProNmapScanner()
    results = scanner.scan(target, ports=args.ports, mode=mode)
    
    if results:
        scanner.ai_analysis(results)
    
    print(f"\n{Fore.MAGENTA}✨ Mission Complete.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
