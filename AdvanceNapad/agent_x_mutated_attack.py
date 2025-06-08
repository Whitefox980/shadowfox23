#!/usr/bin/env python3
"""
🔥 SHADOWFOX AGENT X - MUTATED ATTACK EXECUTOR
Precizni striker koji čita mutator rezultate i izvršava napade
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

class AgentX:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.mutated_data = []
        self.attack_results = {
            "mission_info": {},
            "attack_summary": {},
            "successful_attacks": [],
            "failed_attacks": [],
            "interesting_responses": [],
            "reflection_found": [],
            "error_disclosures": [],
            "timing_anomalies": [],
            "statistics": {}
        }
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.attack_results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def load_mutated_data(self):
        """Učitava mutirane podatke iz Centar/mutator_core.json"""
        try:
            with open('Centar/mutator_core.json', 'r') as f:
                mutator_results = json.load(f)
                self.mutated_data = mutator_results.get("mutation_tests", [])
                print(f"🧬 [MUTATOR] Učitano {len(self.mutated_data)} mutiranih payloada")
                
                if not self.mutated_data:
                    print("⚠️  [WARNING] Nema mutiranih podataka za napad!")
                    print("🔧 [FIX] Pokreni Centar/mutator_core.py pre AgentX")
                    exit(1)
                    
        except FileNotFoundError:
            print("❌ [ERROR] Centar/mutator_core.json nije pronađen!")
            print("🔧 [FIX] Pokreni Centar/mutator_core.py pre AgentX")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije na osnovu Meta config"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        
        # Stealth mode konfiguracija
        if self.meta_config.get('stealth_mode', False):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]
            self.session.headers['User-Agent'] = random.choice(user_agents)
            
        self.session.verify = False
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje na osnovu Meta config"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
        else:
            time.sleep(random.uniform(0.1, 0.5))
            
    def execute_attack(self, mutated_payload):
        """Izvršava jedan mutirani napad"""
        endpoint = mutated_payload.get("endpoint")
        method = mutated_payload.get("method", "GET").upper()
        headers = mutated_payload.get("headers", {})
        params = mutated_payload.get("params", {})
        data = mutated_payload.get("data", {})
        payload_info = mutated_payload.get("payload_info", {})
        strategy = mutated_payload.get("mutation_type", "")
        original_payload = mutated_payload.get("original_payload", {})
        payload_value = mutated_payload.get("payload", "UNKNOWN")

        attack_id = hashlib.md5(f"{endpoint}{str(params)}{str(data)}".encode()).hexdigest()[:8]
        print(f"\n🔫 [ATTACK] {attack_id}: {method} {endpoint}")
        print(f"💣 Payload: {payload_value} | Strategy: {strategy} | AI: {mutated_payload.get('ai_score', 'N/A')}")

        request_headers = {**self.session.headers, **headers}
        self.intelligent_delay()

        try:
            start_time = time.time()

            if method == "GET":
                response = self.session.get(endpoint, params={**params, "test": payload_value}, headers=request_headers, timeout=10)
            elif method == "POST":
                response = self.session.post(endpoint, data={**params, "test": payload_value}, headers=request_headers, timeout=10)
            elif method == "PUT":
                response = self.session.put(endpoint, data={**params, "test": payload_value}, headers=request_headers, timeout=10)
            elif method == "DELETE":
                response = self.session.delete(endpoint, params=params, headers=request_headers, timeout=10)
            else:
                response = self.session.request(method, endpoint, data=data, params=params, headers=request_headers, timeout=10)

            end_time = time.time()
            response_time = end_time - start_time

            attack_result = self.analyze_response(attack_id, mutated_payload, response, response_time)

    # BLIND DETEKCIJA
            if "blind" in strategy and response_time > 3.0:
                if "vulnerability_indicators" not in attack_result:
                    attack_result["vulnerability_indicators"] = []
                attack_result["vulnerability_indicators"].append("TIMING_ANOMALY")

    # Evaluator-friendly rezultat (uvek)
            attack_result["injection_results"] = [{
                "payload": mutated_payload.get("payload", ""),
                "parameter": "test",
                "payload_category": mutated_payload.get("mutation_type", "unknown"),
                "vulnerability_indicators": attack_result.get("vulnerability_indicators", [])
            }]
            return attack_result

        except Exception as e:
            error_result = {
                "attack_id": attack_id,
                "status": "FAILED",
                "error": str(e),
                "mutated_payload": mutated_payload,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            print(f"❌ [ATTACK FAILED] {attack_id}: {str(e)}")
            self.attack_results["failed_attacks"].append(error_result)
            return error_result


    def analyze_response(self, attack_id, mutated_payload, response, response_time):
        """Duboka analiza response-a za detekciju ranjivosti"""
        
        # Osnovni response podaci
        result = {
            "attack_id": attack_id,
            "status": "COMPLETED",
            "mutated_payload": mutated_payload,
            "response_analysis": {
                "status_code": response.status_code,
                "content_length": len(response.content),
                "response_time": round(response_time, 3),
                "headers": dict(response.headers),
                "encoding": response.encoding
            },
            "vulnerability_indicators": [],
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        response_text = response.text
        payload_info = mutated_payload.get('payload_info', {})
        original_payload = payload_info.get('payload', '')
        
        # 1. REFLECTION ANALYSIS - Da li je payload reflektovan
        if original_payload and original_payload in response_text:
            reflection_indicator = {
                "type": "PAYLOAD_REFLECTION",
                "severity": "HIGH",
                "description": f"Payload '{original_payload}' je reflektovan u response",
                "location": "response_body"
            }
            result["vulnerability_indicators"].append(reflection_indicator)
            self.attack_results["reflection_found"].append(result)
            print(f"🎯 [REFLECTION] {attack_id}: Payload reflektovan!")
            
        # 2. ERROR DISCLOSURE ANALYSIS
        error_patterns = [
            (r"SQL.*error", "SQL_ERROR_DISCLOSURE"),
            (r"MySQL.*error", "MYSQL_ERROR_DISCLOSURE"),
            (r"PostgreSQL.*error", "POSTGRESQL_ERROR_DISCLOSURE"),
            (r"ORA-\d+", "ORACLE_ERROR_DISCLOSURE"),
            (r"Microsoft.*ODBC", "ODBC_ERROR_DISCLOSURE"),
            (r"Warning.*include", "PHP_INCLUDE_ERROR"),
            (r"Fatal error", "PHP_FATAL_ERROR"),
            (r"Notice.*Undefined", "PHP_UNDEFINED_ERROR"),
            (r"Exception.*at line", "EXCEPTION_DISCLOSURE"),
            (r"Traceback.*most recent call", "PYTHON_TRACEBACK"),
            (r"java\.lang\.", "JAVA_EXCEPTION"),
            (r"System\..*Exception", "DOTNET_EXCEPTION")
        ]
        
        import re
        for pattern, error_type in error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                error_indicator = {
                    "type": "ERROR_DISCLOSURE",
                    "severity": "MEDIUM",
                    "description": f"Detektovan {error_type}",
                    "pattern_matched": pattern
                }
                result["vulnerability_indicators"].append(error_indicator)
                self.attack_results["error_disclosures"].append(result)
                print(f"🔍 [ERROR] {attack_id}: {error_type} detektovan!")
                
        # 3. STATUS CODE ANALYSIS
        if response.status_code == 500:
            server_error = {
                "type": "SERVER_ERROR",
                "severity": "MEDIUM",
                "description": "Server Error 500 - mogući payload uticaj"
            }
            result["vulnerability_indicators"].append(server_error)
            
        elif response.status_code == 403:
            forbidden_error = {
                "type": "ACCESS_FORBIDDEN",
                "severity": "LOW",
                "description": "Access Forbidden - možda dosegnuto zaštićeno područje"
            }
            result["vulnerability_indicators"].append(forbidden_error)
            
        elif response.status_code in [200, 201, 202]:
            if len(response_text) > 0:
                success_indicator = {
                    "type": "SUCCESSFUL_RESPONSE",
                    "severity": "INFO",
                    "description": f"Uspešan response sa {len(response_text)} karaktera"
                }
                result["vulnerability_indicators"].append(success_indicator)
                
        # 4. TIMING ANALYSIS - SQL injection timing attacks
        if response_time > 5.0:
            timing_indicator = {
                "type": "TIMING_ANOMALY",
                "severity": "MEDIUM",
                "description": f"Neobično spor response: {response_time}s - mogući timing attack"
            }
            result["vulnerability_indicators"].append(timing_indicator)
            self.attack_results["timing_anomalies"].append(result)
            print(f"⏱️  [TIMING] {attack_id}: Spor response {response_time}s!")
            
        # 5. CONTENT LENGTH ANALYSIS
        if len(response_text) > 50000:
            large_response = {
                "type": "LARGE_RESPONSE",
                "severity": "LOW",
                "description": f"Veliki response: {len(response_text)} karaktera"
            }
            result["vulnerability_indicators"].append(large_response)
            
        # 6. HEADER ANALYSIS
        suspicious_headers = response.headers.get('X-Debug-Info', '')
        if suspicious_headers:
            debug_header = {
                "type": "DEBUG_HEADER",
                "severity": "LOW",
                "description": f"Debug header pronađen: {suspicious_headers}"
            }
            result["vulnerability_indicators"].append(debug_header)
            
        # Klasifikacija rezultata
        if result["vulnerability_indicators"]:
            high_severity = any(ind["severity"] == "HIGH" for ind in result["vulnerability_indicators"])
            medium_severity = any(ind["severity"] == "MEDIUM" for ind in result["vulnerability_indicators"])
            
            if high_severity:
                self.attack_results["successful_attacks"].append(result)
                print(f"🔥 [SUCCESS] {attack_id}: Visok rizik detektovan!")
            elif medium_severity:
                self.attack_results["interesting_responses"].append(result)
                print(f"⚠️  [INTERESTING] {attack_id}: Srednji rizik detektovan!")
            else:
                # Ni low severity dodajemo u interesting
                self.attack_results["interesting_responses"].append(result)
                
        return result
        
    def run_attacks(self):
        """Pokretanje svih mutiranih napada"""
        print("🔥 AGENT X - POKRETANJE MUTIRANIH NAPADA")
        print("=" * 60)
        
        total_attacks = len(self.mutated_data)
        successful_count = 0
        failed_count = 0
        
        for i, mutated_payload in enumerate(self.mutated_data, 1):
            print(f"\n[{i}/{total_attacks}] Executing attack...")
            
            result = self.execute_attack(mutated_payload)
            
            if result["status"] == "COMPLETED":
                successful_count += 1
            else:
                failed_count += 1
                
        # Generisanje statistike
        stats = {
            "total_attacks": total_attacks,
            "successful_attacks": successful_count,
            "failed_attacks": failed_count,
            "high_risk_findings": len(self.attack_results["successful_attacks"]),
            "interesting_findings": len(self.attack_results["interesting_responses"]),
            "reflections_found": len(self.attack_results["reflection_found"]),
            "error_disclosures": len(self.attack_results["error_disclosures"]),
            "timing_anomalies": len(self.attack_results["timing_anomalies"]),
            "success_rate": round((successful_count / total_attacks) * 100, 2) if total_attacks > 0 else 0,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.attack_results["statistics"] = stats
        self.attack_results["attack_summary"] = {
            "mission_id": self.meta_config.get('mission_id', 'UNKNOWN'),
            "target": self.meta_config.get('target_root', 'UNKNOWN'),
            "total_payloads_executed": total_attacks,
            "vulnerabilities_detected": stats["high_risk_findings"],
            "interesting_responses": stats["interesting_findings"]
        }
        
    def save_results(self):
        """Snimanje rezultata u agent_x_results.json"""
        output_file = "AdvanceNapad/agent_x_results.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.attack_results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka napada"""
        stats = self.attack_results["statistics"]
        print("\n🎯 AGENT X - SAŽETAK NAPADA")
        print("=" * 60)
        print(f"🚀 Ukupno napada: {stats['total_attacks']}")
        print(f"✅ Uspešno: {stats['successful_attacks']}")
        print(f"❌ Neuspešno: {stats['failed_attacks']}")
        print(f"🎯 Stopa uspeha: {stats['success_rate']}%")
        print(f"\n🔥 KRITIČNI NALAZI:")
        print(f"   🎯 Visok rizik: {stats['high_risk_findings']}")
        print(f"   ⚠️  Interesantno: {stats['interesting_findings']}")
        print(f"   🪞 Refleksije: {stats['reflections_found']}")
        print(f"   💥 Error disclosure: {stats['error_disclosures']}")
        print(f"   ⏱️  Timing anomalije: {stats['timing_anomalies']}")
        
        # Prikaz top 3 najuspešnija napada
        if self.attack_results["successful_attacks"]:
            print(f"\n🏆 TOP USPEŠNI NAPADI:")
            for i, attack in enumerate(self.attack_results["successful_attacks"][:3], 1):
                payload_info = attack["mutated_payload"].get("payload_info", {})
                print(f"   {i}. {attack['attack_id']}: {payload_info.get('type', 'UNKNOWN')} - {len(attack['vulnerability_indicators'])} indikatora")
                
        print(f"\n✅ Detaljan izveštaj: AdvanceNapad/agent_x_results.json")
        
    def run(self):
        """Glavna funkcija Agent X-a"""
        print("🦊 SHADOWFOX AGENT X - INICIJALIZACIJA")
        
        # 1. Učitaj Meta config
        self.load_meta_config()
        
        # 2. Učitaj mutirane podatke
        self.load_mutated_data()
        
        # 3. Podesi sesiju
        self.setup_session()
        
        # 4. Pokreni napade
        self.run_attacks()
        
        # 5. Snimi rezultate
        self.save_results()
        
        # 6. Prikaži sažetak
        self.display_summary()

def main():
    agent_x = AgentX()
    agent_x.run()

if __name__ == "__main__":
    main()
