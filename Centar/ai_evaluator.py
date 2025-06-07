#!/usr/bin/env python3
"""
🤖 SHADOWFOX AI EVALUATOR - MOŽDANA KORA ANALIZE
Inteligentna analiza attack rezultata i preporuke za unapređenje
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import json
import os
import glob
import time
import re
from collections import defaultdict, Counter
import statistics

class ShadowAIEvaluator:
    def __init__(self):
        self.meta_config = {}
        self.attack_results = []
        self.recon_data = {}
        self.evaluation_results = {
            "mission_info": {},
            "analysis_summary": {},
            "payload_effectiveness": {},
            "parameter_risk_analysis": {},  
            "attack_pattern_analysis": {},
            "improvement_recommendations": [],
            "ai_scoring": {},
            "false_positive_analysis": {},
            "coverage_analysis": {},
            "threat_intelligence": {},
            "statistics": {}
        }
        
        # AI scoring criteria
        self.scoring_weights = {
            "severity_multiplier": {"CRITICAL": 5.0, "HIGH": 4.0, "MEDIUM": 3.0, "LOW": 2.0, "INFO": 1.0},
            "confidence_factors": {
                "sql_error_detected": 0.9,
                "command_output_detected": 0.95,
                "file_content_disclosed": 0.9,
                "payload_reflected": 0.8,
                "template_evaluation": 0.85,
                "status_code_change": 0.6,
                "response_length_anomaly": 0.4,
                "response_time_anomaly": 0.3
            },
            "payload_success_weight": 0.3,
            "parameter_frequency_weight": 0.2,
            "response_consistency_weight": 0.3
        }
        
    def load_dependencies(self):
        """Učitava sve potrebne podatke"""
        try:
            # Meta config
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.evaluation_results["mission_info"] = self.meta_config
                
            # Recon podaci
            if os.path.exists('ShadowRecon/shadow_recon.json'):
                with open('ShadowRecon/shadow_recon.json', 'r') as f:
                    self.recon_data = json.load(f)
                    
            print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
            
        except FileNotFoundError as e:
            print(f"❌ [ERROR] Nedostaje dependency: {str(e)}")
            exit(1)
            
    def load_attack_results(self):
        """Učitava sve .json fajlove iz Napad/ foldera"""
        attack_files = glob.glob("Napad/*.json")
        
        if not attack_files:
            print("❌ [ERROR] Nema attack rezultata u Napad/ folderu!")
            exit(1)
            
        for file_path in attack_files:
            try:
                with open(file_path, 'r') as f:
                    attack_data = json.load(f)
                    attack_data['source_file'] = os.path.basename(file_path)
                    self.attack_results.append(attack_data)
                    print(f"📄 [LOAD] {os.path.basename(file_path)}")
            except Exception as e:
                print(f"❌ [LOAD ERROR] {file_path}: {str(e)}")
                
        print(f"✅ [LOAD] Učitano {len(self.attack_results)} attack rezultata")

    def identify_payload_chains(self):
        """
        Pokušava da detektuje povezane payload-e koji rade zajedno – tzv. chain attack paterni.
        """
        try:
            chains = []
            previous_payload = None
            for attack in self.attack_data:
                current_payload = attack.get("payload", "")
                if previous_payload and previous_payload in current_payload:
                    chains.append({
                        "from": previous_payload,
                        "to": current_payload,
                        "type": "chained"
                    })
                previous_payload = current_payload
            return chains
        except Exception as e:
            return {"error": str(e)} 

    def analyze_payload_effectiveness(self):
        """Analiza efikasnosti payload-a kroz sve attack rezultate"""
        payload_stats = defaultdict(lambda: {
            "total_attempts": 0,
            "successful_hits": 0,
            "vulnerability_types": set(),
            "affected_parameters": set(),
            "success_rate": 0.0,
            "avg_confidence": 0.0,
            "response_patterns": []
        })
        
        for attack_result in self.attack_results:
            injection_results = attack_result.get('injection_results', [])
            
            for injection in injection_results:
                payload = injection.get('payload', '')
                payload_category = injection.get('payload_category', 'unknown')
                vulnerability_indicators = injection.get('vulnerability_indicators', [])
                
                # Stat tracking
                payload_stats[payload]["total_attempts"] += 1
                payload_stats[payload]["affected_parameters"].add(injection.get('parameter', ''))
                
                if vulnerability_indicators:
                    payload_stats[payload]["successful_hits"] += 1
                    for vuln in vulnerability_indicators:
                        payload_stats[payload]["vulnerability_types"].add(vuln.get('type', ''))
                        
                # Response pattern analysis
                response_pattern = {
                    "status_code": injection.get('status_code'),
                    "response_length": injection.get('response_length'),
                    "has_vulnerabilities": len(vulnerability_indicators) > 0
                }
                payload_stats[payload]["response_patterns"].append(response_pattern)
                
        # Calculate effectiveness scores
        effective_payloads = []
        for payload, stats in payload_stats.items():
            if stats["total_attempts"] > 0:
                stats["success_rate"] = stats["successful_hits"] / stats["total_attempts"]
                
                # AI effectiveness score
                effectiveness_score = self.calculate_payload_effectiveness_score(stats)
                stats["ai_effectiveness_score"] = effectiveness_score
                
                # Convert sets to lists for JSON serialization
                stats["vulnerability_types"] = list(stats["vulnerability_types"])
                stats["affected_parameters"] = list(stats["affected_parameters"])
                
                if stats["success_rate"] > 0:
                    effective_payloads.append((payload, stats))
                    
        # Sort by effectiveness
        effective_payloads.sort(key=lambda x: x[1]["ai_effectiveness_score"], reverse=True)
        
        self.evaluation_results["payload_effectiveness"] = {
            "all_payloads": dict(payload_stats),
            "top_effective_payloads": dict(effective_payloads[:20]),
            "payload_categories_performance": self.analyze_category_performance(),
            "recommendations": []
        }
    def map_attack_vectors(self):
        """
        Mapira tipične vektore napada iz payload-a (npr. XSS, SQLi, LFI, RCE...).
        """
        try:
            vectors = {
                "XSS": [],
                "SQLi": [],
                "LFI": [],
                "RCE": [],
                "SSRF": [],
                "Unknown": []
            }

            for attack in self.attack_data:
                payload = attack.get("payload", "").lower()
                if "<script>" in payload or "onerror=" in payload:
                    vectors["XSS"].append(payload)
                elif "select" in payload or "union" in payload:
                    vectors["SQLi"].append(payload)
                elif "../../../../" in payload or "/etc/passwd" in payload:
                    vectors["LFI"].append(payload)
                elif "wget" in payload or "curl" in payload:
                    vectors["RCE"].append(payload)
                elif "http://" in payload or "https://" in payload and "127.0.0.1" in payload:
                    vectors["SSRF"].append(payload)
                else:
                    vectors["Unknown"].append(payload)

            return vectors
        except Exception as e:
            return {"error": str(e)} 

    def calculate_payload_effectiveness_score(self, stats):
        """AI scoring za efikasnost payload-a"""
        base_score = stats["success_rate"] * 10  # 0-10 based on success rate
        
        # Bonus for diversity of vulnerability types
        vuln_diversity_bonus = len(stats["vulnerability_types"]) * 0.5
        
        # Bonus for affecting multiple parameters  
        param_diversity_bonus = len(stats["affected_parameters"]) * 0.3
        
        # Penalty for inconsistent responses
        response_consistency = self.calculate_response_consistency(stats["response_patterns"])
        consistency_bonus = response_consistency * 2
        
        final_score = base_score + vuln_diversity_bonus + param_diversity_bonus + consistency_bonus
        return min(final_score, 10.0)  # Cap at 10
        
    def calculate_response_consistency(self, response_patterns):
        """Kalkulacija konzistentnosti response-a"""
        if len(response_patterns) < 2:
            return 1.0
            
        status_codes = [p["status_code"] for p in response_patterns]
        status_consistency = len(set(status_codes)) / len(status_codes)
        
        return 1.0 - status_consistency  # Higher consistency = higher score
        
    def analyze_category_performance(self):
        """Analiza performansi po kategorijama payload-a"""
        category_performance = defaultdict(lambda: {
            "total_payloads": 0,
            "successful_payloads": 0,
            "avg_success_rate": 0.0,
            "total_vulnerabilities_found": 0,
            "top_payloads": []
        })
        
        for attack_result in self.attack_results:
            injection_results = attack_result.get('injection_results', [])
            
            for injection in injection_results:
                category = injection.get('payload_category', 'unknown')
                payload = injection.get('payload', '')
                vulnerability_indicators = injection.get('vulnerability_indicators', [])
                
                category_performance[category]["total_payloads"] += 1
                
                if vulnerability_indicators:
                    category_performance[category]["successful_payloads"] += 1
                    category_performance[category]["total_vulnerabilities_found"] += len(vulnerability_indicators)
                    
        # Calculate averages
        for category, stats in category_performance.items():
            if stats["total_payloads"] > 0:
                stats["avg_success_rate"] = stats["successful_payloads"] / stats["total_payloads"]
                
        return dict(category_performance)
        
    def analyze_parameter_risk_profiles(self):
        """AI analiza risk profila parametara"""
        parameter_risks = defaultdict(lambda: {
            "total_tests": 0,
            "vulnerabilities_found": 0,
            "vulnerability_types": set(),
            "severity_distribution": defaultdict(int),
            "most_effective_payloads": [],
            "risk_score": 0.0,
            "attack_surface_analysis": {},
            "behavioral_patterns": []
        })
        
        for attack_result in self.attack_results:
            injection_results = attack_result.get('injection_results', [])
            
            for injection in injection_results:
                param_name = injection.get('parameter', '')
                vulnerability_indicators = injection.get('vulnerability_indicators', [])
                payload = injection.get('payload', '')
                
                parameter_risks[param_name]["total_tests"] += 1
                
                if vulnerability_indicators:
                    parameter_risks[param_name]["vulnerabilities_found"] += len(vulnerability_indicators)
                    
                    for vuln in vulnerability_indicators:
                        vuln_type = vuln.get('type', 'Unknown')
                        severity = vuln.get('severity', 'UNKNOWN')
                        
                        parameter_risks[param_name]["vulnerability_types"].add(vuln_type)
                        parameter_risks[param_name]["severity_distribution"][severity] += 1
                        
                        # Track effective payloads
                        if payload not in [p["payload"] for p in parameter_risks[param_name]["most_effective_payloads"]]:
                            parameter_risks[param_name]["most_effective_payloads"].append({
                                "payload": payload,
                                "vulnerability_type": vuln_type,
                                "severity": severity
                            })
                            
        # Calculate AI risk scores
        for param_name, risk_data in parameter_risks.items():
            risk_score = self.calculate_parameter_risk_score(risk_data)
            risk_data["risk_score"] = risk_score
            risk_data["vulnerability_types"] = list(risk_data["vulnerability_types"])
            risk_data["severity_distribution"] = dict(risk_data["severity_distribution"])
            
            # AI-based risk classification
            risk_data["risk_classification"] = self.classify_parameter_risk(risk_score, risk_data)
            
        # Sort by risk score
        sorted_risks = sorted(parameter_risks.items(), key=lambda x: x[1]["risk_score"], reverse=True)
        
        self.evaluation_results["parameter_risk_analysis"] = {
            "all_parameters": dict(parameter_risks),
            "high_risk_parameters": dict(sorted_risks[:10]),
            "risk_distribution": self.analyze_risk_distribution(parameter_risks),
            "attack_surface_summary": self.generate_attack_surface_summary(parameter_risks)
        }
        
    def calculate_parameter_risk_score(self, risk_data):
        """AI kalkulacija risk score-a za parametar"""
        if risk_data["total_tests"] == 0:
            return 0.0
            
        # Base vulnerability rate
        vuln_rate = risk_data["vulnerabilities_found"] / risk_data["total_tests"]
        base_score = vuln_rate * 5  # 0-5 based on vulnerability rate
        
        # Severity weighting
        severity_bonus = 0
        for severity, count in risk_data["severity_distribution"].items():
            if severity in self.scoring_weights["severity_multiplier"]:
                severity_bonus += count * (self.scoring_weights["severity_multiplier"][severity] / 10)
                
        # Diversity bonus (multiple vulnerability types = higher risk)
        diversity_bonus = len(risk_data["vulnerability_types"]) * 0.5
        
        # Frequency bonus (more tests = more confidence)
        frequency_factor = min(risk_data["total_tests"] / 50, 1.0)  # Max bonus at 50+ tests
        
        final_score = (base_score + severity_bonus + diversity_bonus) * (0.5 + frequency_factor * 0.5)
        return min(final_score, 10.0)
        
    def classify_parameter_risk(self, risk_score, risk_data):
        """AI klasifikacija rizika parametra"""
        if risk_score >= 8.0:
            return {
                "level": "CRITICAL",
                "description": "Parametar pokazuje visoku sklonost ka kritičnim ranjivostima",
                "priority": "IMMEDIATE",
                "recommended_actions": [
                    "Hitna manual verifikacija",
                    "Deep payload testing",
                    "Business logic analysis"
                ]
            }
        elif risk_score >= 6.0:
            return {
                "level": "HIGH", 
                "description": "Parametar ima značajne sigurnosne probleme",
                "priority": "HIGH",
                "recommended_actions": [
                    "Extended fuzzing",
                    "Context-specific payloads",
                    "Input validation bypass testing"
                ]
            }
        elif risk_score >= 4.0:
            return {
                "level": "MEDIUM",
                "description": "Parametar pokazuje potencijalne sigurnosne probleme",
                "priority": "MEDIUM", 
                "recommended_actions": [
                    "Targeted payload testing",
                    "Response pattern analysis"
                ]
            }
        else:
            return {
                "level": "LOW",
                "description": "Parametar ima nizak sigurnosni rizik",
                "priority": "LOW",
                "recommended_actions": [
                    "Occasional monitoring",
                    "Business logic testing"
                ]
            }
    def identify_defensive_patterns(self):
        """
        Analizira odgovore servera u cilju otkrivanja zaštitnih mehanizama (WAF, 403, CAPTCHA, itd).
        """
        try:
            defensive_hits = {
                "WAF_detected": 0,
                "403_forbidden": 0,
                "CAPTCHA": 0,
                "Rate_Limit": 0,
                "Unknown": 0
            }

            for attack in self.attack_data:
                response = attack.get("response", "").lower()

                if "access denied" in response or "waf" in response:
                    defensive_hits["WAF_detected"] += 1
                elif "403 forbidden" in response:
                    defensive_hits["403_forbidden"] += 1
                elif "captcha" in response:
                    defensive_hits["CAPTCHA"] += 1
                elif "rate limit" in response or "too many requests" in response:
                    defensive_hits["Rate_Limit"] += 1
                else:
                    defensive_hits["Unknown"] += 1

            return defensive_hits
        except Exception as e:
            return {"error": str(e)}
            
    def analyze_risk_distribution(self, parameter_risks):
        """Analizira raspodelu rizika po nivoima"""
        distribution = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
        for param, risk_data in parameter_risks.items():
            level = risk_data.get("risk_classification", {}).get("level", "LOW")
            if level in distribution:
                distribution[level] += 1
    
        return distribution

    def generate_attack_surface_summary(self, parameter_risks):
        """Generiše kratak rezime attack surface-a"""
        total_params = len(parameter_risks)
        high_risk = sum(1 for r in parameter_risks.values() if r.get("risk_classification", {}).get("level") in ["CRITICAL", "HIGH"])
    
        return {
            "total_parameters": total_params,
            "high_risk_count": high_risk,
            "risk_ratio": round(high_risk / total_params, 2) if total_params else 0.0
        }
    def analyze_attack_patterns(self):
        """Analiza attack paterna i behavior-a"""
        attack_patterns = {
            "temporal_patterns": self.analyze_temporal_patterns(),
            "response_clustering": self.analyze_response_clusters(),
            "payload_chains": self.identify_payload_chains(),
            "attack_vectors": self.map_attack_vectors(),
            "defensive_patterns": self.identify_defensive_patterns()
        }
        
        self.evaluation_results["attack_pattern_analysis"] = attack_patterns
        
    def analyze_temporal_patterns(self):
        """Analiza vremenskih paterna napada"""
        # Implementacija analize vremenskih paterna
        return {
            "peak_vulnerability_times": [],
            "response_time_correlation": {},
            "attack_frequency_analysis": {}
        }

    def analyze_response_clusters(self):
        """
        Analizira odgovore servera i pokušava da klasifikuje sličnosti među njima
        u cilju identifikacije ponašanja zaštita (WAF, redirect, fallback itd.)
        """
        try:
            response_signatures = {}
            for attack in self.attack_data:
                url = attack.get("url")
                status = attack.get("response_status")
                length = attack.get("response_length")
                sig = f"{status}-{length}"
                if sig not in response_signatures:
                    response_signatures[sig] = []
                response_signatures[sig].append(url)
        
            return {
                "cluster_count": len(response_signatures),
                "clusters": response_signatures
            }
        except Exception as e:
            return {"error": str(e)} 
    
    def generate_improvement_recommendations(self):
        """AI generisanje preporuka za unapređenje"""
        recommendations = []
        
        # Payload recommendations
        payload_effectiveness = self.evaluation_results.get("payload_effectiveness", {})
        top_payloads = payload_effectiveness.get("top_effective_payloads", {})
        
        if len(top_payloads) < 10:
            recommendations.append({
                "category": "Payload Expansion",
                "priority": "HIGH",
                "description": "Insufficient effective payloads detected",
                "specific_recommendations": [
                    "Add more context-specific payloads",
                    "Implement custom payload generation",
                    "Focus on application-specific injection vectors"
                ],
                "impact": "Increased vulnerability detection rate"
            })
            
        # Parameter coverage recommendations
        param_analysis = self.evaluation_results.get("parameter_risk_analysis", {})
        high_risk_params = param_analysis.get("high_risk_parameters", {})
        
        if high_risk_params:
            recommendations.append({
                "category": "High-Risk Parameter Focus",
                "priority": "CRITICAL",
                "description": f"Found {len(high_risk_params)} high-risk parameters requiring immediate attention",
                "specific_recommendations": [
                    f"Prioritize manual testing of: {', '.join(list(high_risk_params.keys())[:5])}",
                    "Implement parameter-specific payload customization",
                    "Increase test coverage for high-risk parameters"
                ],
                "impact": "Higher chance of finding critical vulnerabilities"
            })
            
        # Coverage gap analysis
        coverage_gaps = self.identify_coverage_gaps()
        if coverage_gaps:
            recommendations.append({
                "category": "Coverage Improvement",
                "priority": "MEDIUM", 
                "description": "Identified gaps in attack coverage",
                "specific_recommendations": coverage_gaps,
                "impact": "More comprehensive security assessment"
            })
            
        self.evaluation_results["improvement_recommendations"] = recommendations
        
    def identify_coverage_gaps(self):
        """Identifikacija praznina u coverage-u"""
        gaps = []
        
        # Check for missing attack categories
        tested_categories = set()
        for attack_result in self.attack_results:
            for injection in attack_result.get('injection_results', []):
                tested_categories.add(injection.get('payload_category', ''))
                
        expected_categories = {'sqli_basic', 'xss_basic', 'path_traversal', 'command_injection'}
        missing_categories = expected_categories - tested_categories
        
        if missing_categories:
            gaps.append(f"Missing attack categories: {', '.join(missing_categories)}")
            
        return gaps
        
    def calculate_overall_ai_scores(self):
        """AI skoring celog assessment-a"""
        # Mission completeness score
        completeness_factors = {
            "recon_coverage": self.calculate_recon_coverage_score(),
            "attack_comprehensiveness": self.calculate_attack_comprehensiveness_score(),
            "vulnerability_confidence": self.calculate_vulnerability_confidence_score(),
            "payload_effectiveness": self.calculate_overall_payload_effectiveness()
        }
        
        # Weighted average
        weights = {"recon_coverage": 0.2, "attack_comprehensiveness": 0.3, 
                  "vulnerability_confidence": 0.3, "payload_effectiveness": 0.2}
        
        overall_score = sum(completeness_factors[factor] * weights[factor] 
                           for factor in completeness_factors)
        
        ai_scoring = {
            "overall_mission_score": overall_score,
            "completeness_factors": completeness_factors,
            "score_breakdown": weights,
            "mission_grade": self.grade_mission(overall_score),
            "confidence_level": self.calculate_confidence_level(),
            "recommended_next_steps": self.recommend_next_steps(overall_score)
        }
        
        self.evaluation_results["ai_scoring"] = ai_scoring
        
    def grade_mission(self, score):
        """AI grade-ovanje misije"""
        if score >= 9.0:
            return {"grade": "A+", "description": "Exceptional security assessment"}
        elif score >= 8.0:
            return {"grade": "A", "description": "Comprehensive security assessment"}
        elif score >= 7.0:
            return {"grade": "B+", "description": "Good security assessment with minor gaps"}
        elif score >= 6.0:
            return {"grade": "B", "description": "Adequate security assessment"}
        elif score >= 5.0:
            return {"grade": "C", "description": "Basic security assessment with significant gaps"}
        else:
            return {"grade": "F", "description": "Incomplete security assessment"}
            
    def calculate_recon_coverage_score(self):
        """Score za recon coverage"""
        if not self.recon_data:
            return 0.0
            
        recon_stats = self.recon_data.get('statistics', {})
        total_endpoints = recon_stats.get('total_endpoints', 0)
        total_parameters = recon_stats.get('total_parameters', 0)
        
        # Scoring based on discovery depth
        base_score = min(total_endpoints / 20, 1.0) * 5  # Max 5 points for endpoint discovery
        param_score = min(total_parameters / 30, 1.0) * 5  # Max 5 points for parameter discovery
        
        return base_score + param_score
        
    def calculate_attack_comprehensiveness_score(self):
        """Score za attack comprehensiveness"""
        total_tests = sum(len(result.get('injection_results', [])) for result in self.attack_results)
        
        # Scoring based on test volume and diversity
        volume_score = min(total_tests / 500, 1.0) * 7  # Max 7 points for volume
        
        # Category diversity score
        categories_tested = set()
        for result in self.attack_results:
            for injection in result.get('injection_results', []):
                categories_tested.add(injection.get('payload_category', ''))
                
        diversity_score = len(categories_tested) * 0.5  # 0.5 points per category
        
        return volume_score + diversity_score
        
    def calculate_vulnerability_confidence_score(self):
        """Score za confidence u pronađenim ranjivostima"""
        total_vulns = 0
        confidence_sum = 0
        
        for result in self.attack_results:
            for injection in result.get('injection_results', []):
                for vuln in injection.get('vulnerability_indicators', []):
                    total_vulns += 1
                    # Confidence based on vulnerability type and indicators
                    confidence = self.get_vulnerability_confidence(vuln)
                    confidence_sum += confidence
                    
        if total_vulns == 0:
            return 5.0  # Neutral score if no vulnerabilities
            
        avg_confidence = confidence_sum / total_vulns
        return avg_confidence * 10
        
    def get_vulnerability_confidence(self, vulnerability):
        """Confidence score za pojedinačnu ranjivost"""
        vuln_type = vulnerability.get('type', '').lower()
        indicator = vulnerability.get('indicator', '').lower()
        
        # High confidence indicators
        high_confidence_patterns = ['sql error', 'command output', 'file content disclosed']
        if any(pattern in indicator for pattern in high_confidence_patterns):
            return 0.9
            
        # Medium confidence
        medium_confidence_patterns = ['payload reflected', 'template evaluation']
        if any(pattern in indicator for pattern in medium_confidence_patterns):
            return 0.7
            
        # Lower confidence
        return 0.5
        
    def calculate_overall_payload_effectiveness(self):
        """Overall payload effectiveness score"""
        payload_data = self.evaluation_results.get("payload_effectiveness", {})
        top_payloads = payload_data.get("top_effective_payloads", {})
        
        if not top_payloads:
            return 0.0
            
        effectiveness_scores = [payload_info.get("ai_effectiveness_score", 0) 
                              for payload_info in top_payloads.values()]
        
        return statistics.mean(effectiveness_scores) if effectiveness_scores else 0.0
        
    def calculate_confidence_level(self):
        """Calculation of overall confidence level"""
        factors = []
        
        # Volume confidence
        total_tests = sum(len(result.get('injection_results', [])) for result in self.attack_results)
        volume_confidence = min(total_tests / 1000, 1.0)
        factors.append(volume_confidence)
        
        # Diversity confidence  
        categories = set()
        for result in self.attack_results:
            for injection in result.get('injection_results', []):
                categories.add(injection.get('payload_category', ''))
        diversity_confidence = len(categories) / 8  # Expecting 8 categories
        factors.append(diversity_confidence)
        
        # Response consistency confidence
        consistency_scores = []
        for result in self.attack_results:
            injections = result.get('injection_results', [])
            if injections:
                status_codes = [inj.get('status_code') for inj in injections]
                consistency = len(set(status_codes)) / len(status_codes) if status_codes else 1
                consistency_scores.append(1 - consistency)  # Higher consistency = higher confidence
                
        consistency_confidence = statistics.mean(consistency_scores) if consistency_scores else 0.5
        factors.append(consistency_confidence)
        
        overall_confidence = statistics.mean(factors)
        
        if overall_confidence >= 0.8:
            return "HIGH"
        elif overall_confidence >= 0.6:
            return "MEDIUM"
        else:
            return "LOW"
            
    def recommend_next_steps(self, overall_score):
        """AI preporuke za sledeće korake"""
        if overall_score >= 8.0:
            return [
                "Proceed to manual verification of found vulnerabilities",
                "Prepare detailed PoC reports",
                "Consider advanced attack scenarios"
            ]
        elif overall_score >= 6.0:
            return [
                "Expand payload coverage in weak areas",
                "Increase parameter testing depth",
                "Manual verification of high-confidence findings"
            ]
        else:
            return [
                "Significantly expand reconnaissance phase",
                "Increase payload diversity and volume",
                "Review attack methodology and coverage"
            ]
            
    def generate_statistics(self):
        """Generisanje finalne statistike"""
        total_attack_results = len(self.attack_results)
        total_injection_tests = sum(len(result.get('injection_results', [])) for result in self.attack_results)
        total_vulnerabilities = sum(len([inj for inj in result.get('injection_results', []) 
                                       if inj.get('vulnerability_indicators')]) 
                                  for result in self.attack_results)
        
        stats = {
            "evaluation_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_attack_files_analyzed": total_attack_results,
            "total_injection_tests_analyzed": total_injection_tests,
            "total_vulnerabilities_analyzed": total_vulnerabilities,
            "ai_evaluation_version": "ShadowFox AI v1.0",
            "analysis_completeness": "COMPREHENSIVE"
        }
        
        self.evaluation_results["statistics"] = stats
        
    def save_results(self):
        """Snimanje AI evaluation rezultata"""
        output_file = "Centar/ai_evaluator.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.evaluation_results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] AI Evaluation snimljen: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def display_ai_summary(self):
        """Prikaz AI evaluation sažetka"""
        ai_scoring = self.evaluation_results.get("ai_scoring", {})
        stats = self.evaluation_results.get("statistics", {})
        
        print("\n🤖 SHADOWFOX AI EVALUATOR - INTELIGENTNA ANALIZA")
        print("=" * 60)
        print(f"📊 Mission Score: {ai_scoring.get('overall_mission_score', 0):.2f}/10")
        print(f"🎓 Mission Grade: {ai_scoring.get('mission_grade', {}).get('grade', 'N/A')}")
        print(f"🔍 Confidence Level: {ai_scoring.get('confidence_level', 'UNKNOWN')}")
        
        # Payload effectiveness
        payload_eff = self.evaluation_results.get("payload_effectiveness", {})
        top_payloads = payload_eff.get("top_effective_payloads", {})
        print(f"🎯 Top Effective Payloads: {len(top_payloads)}")
        
        # Parameter risks
        param_risks = self.evaluation_results.get("parameter_risk_analysis", {})
        high_risk = param_risks.get("high_risk_parameters", {})
        print(f"⚠️  High-Risk Parameters: {len(high_risk)}")
        
        # Recommendations
        recommendations = self.evaluation_results.get("improvement_recommendations", [])
        print(f"💡 AI Recommendations: {len(recommendations)}")
        
        # Top recommendations
        if recommendations:
            print(f"\n🏆 TOP AI PREPORUKE:")
            for i, rec in enumerate(recommendations[:3], 1):
                print(f"   {i}. [{rec.get('priority', 'UNKNOWN')}] {rec.get('category', 'Unknown')}")
                print(f"      {rec.get('description', 'No description')}")
                
        print(f"\n📈 STATISTIKA:")
        print(f"   • Attack fajlovi analizirani: {stats.get('total_attack_files_analyzed', 0)}")
        print(f"   • Injection testovi analizirani: {stats.get('total_injection_tests_analyzed', 0)}")
        print(f"   • Ranjivosti analizirane: {stats.get('total_vulnerabilities_analyzed', 0)}")
        
        print(f"\n✅ Detaljan AI report: Centar/ai_evaluator.json")
        
    def run_evaluation(self):
        """Glavna AI evaluation operacija"""
        print("🤖 SHADOWFOX AI EVALUATOR - POKRETANJE INTELIGENTNE ANALIZE")
        print("=" * 70)
        
        # 1. Load dependencies
        self.load_dependencies()
        
        # 2. Load svih attack rezultata
        self.load_attack_results()
        
        # 3. Analiza payload effectiveness
        print("🎯 [AI] Analiza payload efikasnosti...")
        self.analyze_payload_effectiveness()
        
        # 4. Parameter risk analysis
        print("⚠️  [AI] Analiza parameter rizika...")
        self.analyze_parameter_risk_profiles()
        
        # 5. Attack pattern analysis
        print("🔍 [AI] Analiza attack paterna...")
        self.analyze_attack_patterns()
        self.generate_improvement_recommendations()
        self.calculate_overall_ai_scores()
        self.generate_statistics()
        self.save_results()
        self.display_ai_summary()
if __name__ == "__main__":
    evaluator = ShadowAIEvaluator()
    evaluator.run_evaluation()
