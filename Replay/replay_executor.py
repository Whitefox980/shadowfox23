
#!/usr/bin/env python3
"""
🦊 SHADOWFOX REPLAY AGENT
"IMA DA IH OTVORIMO KAO SIR" - Battle Slogan
Uzima potvrđene rupe, mutira ih, i ponovo testira za finalnu potvrdu exploitabilnosti
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import os
import glob
from urllib.parse import urljoin, urlparse
import argparse
from datetime import datetime
import sys
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowReplayAgent:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.confirmed_hits = []
        self.replay_results = {
            "mission_info": {},
            "battle_slogan": "IMA DA IH OTVORIMO KAO SIR",
            "replay_summary": {},
            "confirmed_exploits": [],
            "mutated_exploits": [],
            "failed_replays": [],
            "ai_analysis": [],
            "confidence_scores": {},
            "statistics": {}
        }
        self.mutation_engine = MutationEngine()
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.replay_results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
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
        self.session.timeout = 15
        
    def intelligent_delay(self):
        """Pametno kašnjenje za stealth mode"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1.5))
        else:
            time.sleep(random.uniform(0.5, 1.0))
            
    def load_confirmed_hits(self, input_folder="Napad"):
        """Učitava sve potvrđene rupe iz Napad/ foldera"""
        print(f"🔍 [REPLAY] Tražim potvrđene hitove u {input_folder}/")
        
        json_files = glob.glob(f"{input_folder}/*.json")
        total_hits = 0
        
        for json_file in json_files:
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    
                # Traži confirmed exploits u različitim formatima
                if isinstance(data, dict):
                    # Format 1: direktno confirmed polje
                    if data.get('confirmed_exploits'):
                        for exploit in data['confirmed_exploits']:
                            exploit['source_file'] = json_file
                            self.confirmed_hits.append(exploit)
                            total_hits += 1
                            
                    # Format 2: lista sa confirmed flagom
                    if isinstance(data.get('results', []), list):
                        for result in data['results']:
                            if result.get('confirmed', False) or result.get('status') == 'confirmed':
                                result['source_file'] = json_file
                                self.confirmed_hits.append(result)
                                total_hits += 1
                                
                    # Format 3: vulnerabilities lista
                    if data.get('vulnerabilities'):
                        for vuln in data['vulnerabilities']:
                            if vuln.get('confirmed', False):
                                vuln['source_file'] = json_file
                                self.confirmed_hits.append(vuln)
                                total_hits += 1
                                
            except Exception as e:
                print(f"⚠️  [WARNING] Greška u {json_file}: {str(e)}")
                
        print(f"✅ [REPLAY] Ukupno potvrđenih hitova: {total_hits}")
        return total_hits > 0
        
    def replay_single_exploit(self, exploit_data):
        """Replay jednog exploita sa originalnim payload-om"""
        url = exploit_data.get('url', '')
        method = exploit_data.get('method', 'GET').upper()
        payload = exploit_data.get('payload', '')
        headers = exploit_data.get('headers', {})
        
        print(f"🎯 [REPLAY] Testiranje: {method} {url}")
        
        try:
            self.intelligent_delay()
            
            # Merge header-a
            request_headers = dict(self.session.headers)
            request_headers.update(headers)
            
            if method == 'GET':
                response = self.session.get(url, headers=request_headers)
            elif method == 'POST':
                data = exploit_data.get('data', payload)
                response = self.session.post(url, data=data, headers=request_headers)
            else:
                response = self.session.request(method, url, headers=request_headers)
                
            # Analiza odgovora
            success_indicators = [
                'error', 'exception', 'stack trace', 'warning',
                'sql', 'mysql', 'oracle', 'postgresql',
                'root:', 'admin', 'debug', 'config',
                '<script>', 'javascript:', 'onerror=',
                'file://', 'http://', 'https://',
                'localhost', '127.0.0.1', '192.168.'
            ]
            
            response_text = response.text.lower()
            success_count = sum(1 for indicator in success_indicators 
                              if indicator in response_text)
            
            replay_result = {
                "original_exploit": exploit_data,
                "replay_timestamp": datetime.now().isoformat(),
                "response_code": response.status_code,
                "response_length": len(response.content),
                "success_indicators": success_count,
                "confirmed": success_count > 0 or response.status_code in [200, 500],
                "response_headers": dict(response.headers),
                "confidence_increase": 0.25 if success_count > 0 else 0
            }
            
            return replay_result
            
        except Exception as e:
            return {
                "original_exploit": exploit_data,
                "error": str(e),
                "confirmed": False,
                "confidence_increase": -0.1
            }
            
    def generate_mutations(self, exploit_data, count=5):
        """Generiše mutacije originalnog exploita"""
        mutations = []
        original_payload = exploit_data.get('payload', '')
        
        if not original_payload:
            return mutations
            
        # Generiši mutacije pomoću MutationEngine
        for i in range(count):
            mutated_payload = self.mutation_engine.mutate_payload(original_payload)
            
            # Kreiraj mutiranu verziju exploita
            mutated_exploit = exploit_data.copy()
            mutated_exploit['payload'] = mutated_payload
            mutated_exploit['mutation_id'] = f"MUT_{i+1}"
            mutated_exploit['original_payload'] = original_payload
            
            mutations.append(mutated_exploit)
            
        return mutations
        
    def replay_with_mutations(self, exploit_data):
        """Replay sa mutiranim payload-ima"""
        print(f"🧬 [MUTATION] Generišem mutacije za exploit...")
        
        mutations = self.generate_mutations(exploit_data, count=7)
        mutation_results = []
        
        for mutation in mutations:
            print(f"   🔬 Testiranje mutacije {mutation['mutation_id']}")
            result = self.replay_single_exploit(mutation)
            result['is_mutation'] = True
            mutation_results.append(result)
            
        # Analiza mutacija
        successful_mutations = [r for r in mutation_results if r.get('confirmed', False)]
        
        return {
            "mutation_count": len(mutations),
            "successful_mutations": len(successful_mutations),
            "mutation_results": mutation_results,
            "best_mutation": max(mutation_results, 
                               key=lambda x: x.get('success_indicators', 0)) if mutation_results else None
        }
        
    def ai_analyze_exploit(self, exploit_data, replay_result, mutation_result=None):
        """AI analiza exploita za severitet i exploitabilnost"""
        
        # Osnovni AI scoring algoritam
        base_score = 1.0
        
        # Analiza payload-a
        payload = exploit_data.get('payload', '').lower()
        
        # XSS indikatori
        if any(xss in payload for xss in ['<script>', 'javascript:', 'onerror', 'onload']):
            base_score += 2.0
            vuln_type = "Cross-Site Scripting (XSS)"
            
        # SQL Injection indikatori
        elif any(sql in payload for sql in ["'", '"', 'union', 'select', 'drop', 'insert']):
            base_score += 2.5
            vuln_type = "SQL Injection"
            
        # SSRF indikatori
        elif any(ssrf in payload for ssrf in ['localhost', '127.0.0.1', 'file://', 'http://']):
            base_score += 3.0
            vuln_type = "Server-Side Request Forgery (SSRF)"
            
        # Path Traversal indikatori
        elif '../' in payload or '..\\' in payload:
            base_score += 2.2
            vuln_type = "Path Traversal"
            
        else:
            vuln_type = "Generic Vulnerability"
            
        # Analiza response-a
        if replay_result.get('success_indicators', 0) > 2:
            base_score += 1.0
            
        # Bonus za mutacije
        if mutation_result and mutation_result.get('successful_mutations', 0) > 0:
            base_score += 0.5
            
        # AI analiza tekst
        ai_analysis = f"""
🧠 AI ANALIZA EXPLOITA:

Tip ranjivosti: {vuln_type}
Početni payload: {exploit_data.get('payload', '')[:100]}...
AI Confidence Score: {base_score:.2f}/5.0

EXPLOITABILNOST:
{'🔴 KRITIČNA' if base_score >= 4.0 else '🟡 SREDNJA' if base_score >= 2.5 else '🟢 NISKA'}

PREPORUKE:
- {'Immedijatno prijaviti H1 kao Critical' if base_score >= 4.0 else 'Prijaviti kao Medium-High severity'}
- {'Testirati na produkciji' if base_score >= 3.0 else 'Dodatno testiranje potrebno'}
"""
        
        if mutation_result and mutation_result.get('best_mutation'):
            best_mut = mutation_result['best_mutation']
            ai_analysis += f"""
🧬 MUTACIJSKA ANALIZA:
Najbolja mutacija: {best_mut.get('original_exploit', {}).get('mutation_id', 'N/A')}
Poboljšanje: {best_mut.get('success_indicators', 0)} indikatora
"""

        return {
            "vulnerability_type": vuln_type,
            "ai_confidence_score": base_score,
            "severity": "CRITICAL" if base_score >= 4.0 else "HIGH" if base_score >= 2.5 else "MEDIUM",
            "exploitability": "HIGH" if base_score >= 3.0 else "MEDIUM",
            "ai_analysis_text": ai_analysis,
            "recommendation": "IMMEDIATE_REPORT" if base_score >= 4.0 else "STANDARD_REPORT"
        }
        
    def run_replay_mission(self, input_folder="Napad"):
        """Glavna replay misija"""
        print("🦊 SHADOWFOX REPLAY AGENT - IMA DA IH OTVORIMO KAO SIR!")
        print("=" * 60)
        
        # 1. Učitaj Meta config
        self.load_meta_config()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Učitaj potvrđene hitove
        if not self.load_confirmed_hits(input_folder):
            print("❌ [ERROR] Nema potvrđenih hitova za replay!")
            return
            
        total_exploits = len(self.confirmed_hits)
        print(f"🎯 [REPLAY] Pokretanje replay misije za {total_exploits} exploita")
        
        # 4. Replay svakog exploita
        for i, exploit in enumerate(self.confirmed_hits, 1):
            print(f"\n🔫 [REPLAY {i}/{total_exploits}] Proces exploita...")
            
            # Original replay
            original_result = self.replay_single_exploit(exploit)
            
            # Mutation replay
            mutation_result = self.replay_with_mutations(exploit)
            
            # AI analiza
            ai_analysis = self.ai_analyze_exploit(exploit, original_result, mutation_result)
            
            # Kombinuj rezultate
            final_result = {
                "exploit_id": f"REPLAY_{i}",
                "original_exploit": exploit,
                "original_result": original_result,
                "mutation_result": mutation_result,
                "ai_analysis": ai_analysis,
                "final_confidence": original_result.get('confidence_increase', 0) + 
                                  (0.5 if mutation_result.get('successful_mutations', 0) > 0 else 0),
                "timestamp": datetime.now().isoformat()
            }
            
            # Kategorizuj rezultat
            if original_result.get('confirmed', False) or mutation_result.get('successful_mutations', 0) > 0:
                if ai_analysis['ai_confidence_score'] >= 3.0:
                    self.replay_results["confirmed_exploits"].append(final_result)
                else:
                    self.replay_results["mutated_exploits"].append(final_result)
            else:
                self.replay_results["failed_replays"].append(final_result)
                
            self.replay_results["ai_analysis"].append(ai_analysis)
            
        # 5. Generiši statistike
        self.generate_replay_statistics()
        
        # 6. Snimi rezultate
        self.save_replay_results()
        
        # 7. Prikaži sažetak
        self.display_replay_summary()
        
    def generate_replay_statistics(self):
        """Generiši replay statistike"""
        stats = {
            "total_replays": len(self.confirmed_hits),
            "confirmed_exploits": len(self.replay_results["confirmed_exploits"]),
            "mutated_exploits": len(self.replay_results["mutated_exploits"]),
            "failed_replays": len(self.replay_results["failed_replays"]),
            "success_rate": 0,
            "average_confidence": 0,
            "critical_vulnerabilities": 0,
            "high_vulnerabilities": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        if stats["total_replays"] > 0:
            stats["success_rate"] = (stats["confirmed_exploits"] + stats["mutated_exploits"]) / stats["total_replays"] * 100
            
        # Analiza severiteta
        for analysis in self.replay_results["ai_analysis"]:
            if analysis["severity"] == "CRITICAL":
                stats["critical_vulnerabilities"] += 1
            elif analysis["severity"] == "HIGH":
                stats["high_vulnerabilities"] += 1
                
        # Prosečna confidence
        confidence_scores = []
        for exploit in self.replay_results["confirmed_exploits"] + self.replay_results["mutated_exploits"]:
            confidence_scores.append(exploit.get("final_confidence", 0))
            
        if confidence_scores:
            stats["average_confidence"] = sum(confidence_scores) / len(confidence_scores)
            
        self.replay_results["statistics"] = stats
        
    def save_replay_results(self):
        """Snimanje replay rezultata"""
        output_file = "Replay/shadow_replay.json"
        
        try:
            os.makedirs("Replay", exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(self.replay_results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Replay rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_replay_summary(self):
        """Prikaz sažetka replay operacije"""
        stats = self.replay_results["statistics"]
        print(f"\n🎯 SHADOWFOX REPLAY - IMA DA IH OTVORIMO KAO SIR!")
        print("=" * 60)
        print(f"🔫 Ukupno replaya: {stats['total_replays']}")
        print(f"✅ Potvrđeni exploiti: {stats['confirmed_exploits']}")
        print(f"🧬 Mutacija exploiti: {stats['mutated_exploits']}")
        print(f"❌ Neuspešni replays: {stats['failed_replays']}")
        print(f"📊 Stopa uspeha: {stats['success_rate']:.1f}%")
        print(f"🧠 Prosečna confidence: {stats['average_confidence']:.2f}")
        print(f"🔴 Kritične ranjivosti: {stats['critical_vulnerabilities']}")
        print(f"🟡 Visoke ranjivosti: {stats['high_vulnerabilities']}")
        
        print(f"\n✅ Kompletni rezultati: Replay/shadow_replay.json")
        
        # Top 3 exploita
        if self.replay_results["confirmed_exploits"]:
            print(f"\n🏆 TOP POTVRĐENI EXPLOITI:")
            for i, exploit in enumerate(self.replay_results["confirmed_exploits"][:3], 1):
                ai_data = exploit["ai_analysis"]
                print(f"   {i}. {ai_data['vulnerability_type']} (Score: {ai_data['ai_confidence_score']:.1f})")


class MutationEngine:
    """Engine za mutaciju payload-a"""
    
    def __init__(self):
        self.xss_mutations = [
            lambda p: p.replace('<script>', '<ScRiPt>'),
            lambda p: p.replace('javascript:', 'JaVaScRiPt:'),
            lambda p: p + '<!---->',
            lambda p: p.replace('"', "'"),
            lambda p: p.replace('=', '%3D'),
            lambda p: f"/*{p}*/"
        ]
        
        self.sql_mutations = [
            lambda p: p.replace("'", "''"),
            lambda p: p.replace(' ', '/**/'),
            lambda p: p.upper(),
            lambda p: p + ' --',
            lambda p: p.replace('union', 'UNION'),
            lambda p: f"({p})"
        ]
        
        self.generic_mutations = [
            lambda p: p + '\x00',
            lambda p: p.replace(' ', '%20'),
            lambda p: p + '\n\r',
            lambda p: p * 2,
            lambda p: p[::-1] if len(p) < 10 else p
        ]
        
    def mutate_payload(self, payload):
        """Mutacija payload-a na osnovu tipa"""
        if not payload:
            return payload
            
        # Detektuj tip payload-a
        payload_lower = payload.lower()
        
        if any(xss in payload_lower for xss in ['<script>', 'javascript:', 'onerror']):
            mutations = self.xss_mutations
        elif any(sql in payload_lower for sql in ["'", 'union', 'select']):
            mutations = self.sql_mutations
        else:
            mutations = self.generic_mutations
            
        # Primeni random mutaciju
        mutation_func = random.choice(mutations)
        
        try:
            return mutation_func(payload)
        except:
            return payload + "_MUTATED"


def main():
    parser = argparse.ArgumentParser(description="ShadowFox Replay Agent")
    parser.add_argument('--input', default='Napad', help='Input folder sa confirmed hits')
    parser.add_argument('--out', default='Replay/shadow_replay.json', help='Output fajl')
    
    args = parser.parse_args()
    
    agent = ShadowReplayAgent()
    agent.run_replay_mission(args.input)

if __name__ == "__main__":
    main()

