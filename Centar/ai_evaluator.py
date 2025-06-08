#!/usr/bin/env python3
"""
🧠 SHADOWFOX AI EVALUATOR MODULE - FIXED VERSION
AI analiza napada i scoring sistema
Autor: Whitefox980 | Verzija: 2025.06.06 | PATCH: Agent X Compatibility
"""

import json
import re
import time
from datetime import datetime
import os

class ShadowAIEvaluator:
    def __init__(self):
        self.results = {
            "mission_info": {},
            "evaluation_summary": {},
            "payload_analysis": {},
            "risk_assessment": {},
            "recommendations": [],
            "ai_scoring": {}
        }
        self.meta_config = {}
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            exit(1)
            
    def load_attack_data(self):
        """Učitava podatke iz Agent X rezultata - FIXED VERSION"""
        attack_data = {}
        
        # Pokušaj učitavanje iz različitih lokacija
        possible_files = [
            'AdvanceNapad/agent_x_results.json',
            'Napad/attack_param_fuzz.json',
            'Centar/mutator_core.json'
        ]
        
        for file_path in possible_files:
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as f:
                        data = json.load(f)
                        attack_data[file_path] = data
                        print(f"✅ [LOAD] Učitano: {file_path}")
                except Exception as e:
                    print(f"⚠️  [WARNING] Greška pri čitanju {file_path}: {str(e)}")
                    
        if not attack_data:
            print("❌ [ERROR] Nijedan attack fajl nije pronađen!")
            return {}
            
        return attack_data
        
    def parse_agent_x_results(self, data):
        """Parsiranje Agent X rezultata u standardni format"""
        parsed_results = []
        
        # Agent X format: successful_attacks, failed_attacks, interesting_responses
        if 'successful_attacks' in data:
            for attack in data['successful_attacks']:
                parsed_attack = {
                    "attack_id": attack.get('attack_id', 'UNKNOWN'),
                    "payload": attack.get('mutated_payload', ''),
                    "method": attack.get('method', 'GET'),
                    "url": attack.get('endpoint', ''),
                    "status_code": attack.get('test_result', {}).get('status_code', 0),
                    "response_length": attack.get('test_result', {}).get('content_length', 0),
                    "response_time": attack.get('test_result', {}).get('response_time', 0),
                    "vulnerability_indicators": attack.get('vulnerability_indicators', []),
                    "risk_level": attack.get('risk_level', 'MEDIUM'),
                    "confidence": self.calculate_confidence_from_indicators(
                        attack.get('vulnerability_indicators', [])
                    )
                }
                parsed_results.append(parsed_attack)
                
        # Dodaj i failed_attacks kao LOW risk
        if 'failed_attacks' in data:
            for attack in data['failed_attacks']:
                parsed_attack = {
                    "attack_id": attack.get('attack_id', 'FAILED'),
                    "payload": attack.get('mutated_payload', ''),
                    "method": attack.get('method', 'GET'),
                    "url": attack.get('endpoint', ''),
                    "status_code": attack.get('test_result', {}).get('status_code', 0),
                    "response_length": attack.get('test_result', {}).get('content_length', 0),
                    "response_time": attack.get('test_result', {}).get('response_time', 0),
                    "vulnerability_indicators": [],
                    "risk_level": "LOW",
                    "confidence": 0.1
                }
                parsed_results.append(parsed_attack)
                
        # Dodaj interesting_responses kao MEDIUM risk
        if 'interesting_responses' in data:
            for response in data['interesting_responses']:
                parsed_attack = {
                    "attack_id": response.get('attack_id', 'INTERESTING'),
                    "payload": response.get('mutated_payload', ''),
                    "method": response.get('method', 'GET'),
                    "url": response.get('endpoint', ''),
                    "status_code": response.get('test_result', {}).get('status_code', 0),
                    "response_length": response.get('test_result', {}).get('content_length', 0),
                    "response_time": response.get('test_result', {}).get('response_time', 0),
                    "vulnerability_indicators": response.get('vulnerability_indicators', []),
                    "risk_level": "MEDIUM",
                    "confidence": 0.6
                }
                parsed_results.append(parsed_attack)
                
        return parsed_results
        
    def calculate_confidence_from_indicators(self, indicators):
        """Računanje confidence na osnovu vulnerability indicators"""
        if not indicators:
            return 0.0
            
        confidence = 0.0
        
        # Scoring na osnovu indikatora
        indicator_scores = {
            "ACCESS_FORBIDDEN": 0.9,
            "Error": 0.7,
            "SQL": 0.8,
            "XSS": 0.8,
            "IDOR": 0.9,
            "Path Traversal": 0.8,
            "Command Injection": 0.9,
            "SSRF": 0.8,
            "XXE": 0.7,
            "Deserialization": 0.8
        }
        
        for indicator in indicators:
            indicator_str = str(indicator)
            for pattern, score in indicator_scores.items():
                if pattern.lower() in indicator_str.lower():
                    confidence = max(confidence, score)
                    
        return min(confidence, 1.0)
        
    def ai_payload_analysis(self, parsed_attacks):
        """AI analiza payload-a i njihove efikasnosti"""
        analysis = {
            "total_payloads": len(parsed_attacks),
            "effective_payloads": 0,
            "payload_categories": {},
            "top_payloads": [],
            "pattern_analysis": {}
        }
        
        if not parsed_attacks:
            return analysis
            
        # Kategorisanje payload-a
        categories = {
            "XSS": ["<script", "javascript:", "onerror", "onload", "alert("],
            "SQL_INJECTION": ["'", "UNION", "SELECT", "DROP", "INSERT", "OR 1=1"],
            "PATH_TRAVERSAL": ["../", "..\\", "%2e%2e", "....//"],
            "COMMAND_INJECTION": [";", "&", "|", "`", "$(", "${"],
            "SSRF": ["http://", "https://", "file://", "gopher://"],
            "XXE": ["<!ENTITY", "SYSTEM", "PUBLIC", "<!DOCTYPE"],
            "IDOR": ["id=", "user=", "uid=", "account="],
            "CSRF": ["csrf", "token", "_token", "authenticity"]
        }
        
        for attack in parsed_attacks:

            payload = str(attack.get('payload', '')).lower()
            
            # Confidence > 0.5 = efikasan payload
            if attack.get('confidence', 0) > 0.5:
                analysis["effective_payloads"] += 1
                
            # Kategorisanje
            for category, patterns in categories.items():
                if any(pattern.lower() in payload for pattern in patterns):
                    if category not in analysis["payload_categories"]:
                        analysis["payload_categories"][category] = 0
                    analysis["payload_categories"][category] += 1
                    
        # Top 10 najuspešnijih payload-a
        sorted_attacks = sorted(parsed_attacks, 
                              key=lambda x: x.get('confidence', 0), 
                              reverse=True)
        analysis["top_payloads"] = sorted_attacks[:10]
        
        # Pattern analiza
        analysis["pattern_analysis"] = self.analyze_payload_patterns(parsed_attacks)
        
        return analysis
        
    def analyze_payload_patterns(self, attacks):
        """Analiza pattern-a u uspešnim payload-ima"""
        patterns = {
            "encoding_patterns": {},
            "bypass_techniques": {},
            "common_vectors": {}
        }
        
        effective_attacks = [a for a in attacks if a.get('confidence', 0) > 0.5]
        
        # Encoding pattern-i
        encoding_patterns = [
            "%", "&#", "&amp;", "\\x", "\\u", "\\", 
            "%20", "%3C", "%3E", "%22", "%27"
        ]
        
        for pattern in encoding_patterns:
            count = sum(1 for attack in effective_attacks 
                       if pattern in attack.get('payload', ''))
            if count > 0:
                patterns["encoding_patterns"][pattern] = count
                
        # Bypass tehnike
        bypass_patterns = [
            "/*", "*/", "--", "#", "||", "&&", 
            "eval", "setTimeout", "setInterval"
        ]
        
        for pattern in bypass_patterns:
            count = sum(1 for attack in effective_attacks 
                       if pattern in attack.get('payload', ''))
            if count > 0:
                patterns["bypass_techniques"][pattern] = count
                
        return patterns
        
    def risk_assessment(self, parsed_attacks):
        """CVSS-inspirisan risk assessment"""
        assessment = {
            "overall_risk": "LOW",
            "risk_breakdown": {
                "CRITICAL": 0,
                "HIGH": 0, 
                "MEDIUM": 0,
                "LOW": 0
            },
            "vulnerability_types": {},
            "attack_surface_coverage": 0.0
        }
        
        if not parsed_attacks:
            return assessment
            
        # Računanje risk levels
        for attack in parsed_attacks:
            confidence = attack.get('confidence', 0)
            indicators = attack.get('vulnerability_indicators', [])
            
            # Risk scoring
            risk_level = "LOW"
            if confidence > 0.9 and len(indicators) > 2:
                risk_level = "CRITICAL"
            elif confidence > 0.7 and len(indicators) > 1:
                risk_level = "HIGH"
            elif confidence > 0.5:
                risk_level = "MEDIUM"
                
            assessment["risk_breakdown"][risk_level] += 1
            
            # Vulnerability types
            attack_id = attack.get('attack_id', 'UNKNOWN')
            vuln_type = attack_id.split('_')[0] if '_' in attack_id else attack_id
            if vuln_type not in assessment["vulnerability_types"]:
                assessment["vulnerability_types"][vuln_type] = 0
            assessment["vulnerability_types"][vuln_type] += 1
            
        # Overall risk
        if assessment["risk_breakdown"]["CRITICAL"] > 0:
            assessment["overall_risk"] = "CRITICAL"
        elif assessment["risk_breakdown"]["HIGH"] > 0:
            assessment["overall_risk"] = "HIGH"
        elif assessment["risk_breakdown"]["MEDIUM"] > 0:
            assessment["overall_risk"] = "MEDIUM"
            
        # Attack surface coverage (aproksimacija)
        unique_endpoints = len(set(attack.get('url', '') for attack in parsed_attacks))
        total_attacks = len(parsed_attacks)
        if total_attacks > 0:
            assessment["attack_surface_coverage"] = min(unique_endpoints / max(total_attacks, 1), 1.0)
            
        return assessment
        
    def generate_recommendations(self, payload_analysis, risk_assessment):
        """Generisanje AI preporuka za poboljšanje"""
        recommendations = []
        
        # Payload effectiveness preporuke
        effective_ratio = (payload_analysis.get("effective_payloads", 0) / 
                          max(payload_analysis.get("total_payloads", 1), 1))
        
        if effective_ratio < 0.3:
            recommendations.append({
                "category": "Payload Improvement",
                "priority": "HIGH",
                "description": "Low payload effectiveness detected",
                "specific_recommendations": [
                    "Implement custom payload generation",
                    "Focus on application-specific injection vectors",
                    "Analyze failed payloads for patterns"
                ],
                "impact": "Increased vulnerability detection rate"
            })
            
        # Coverage preporuke
        coverage = risk_assessment.get("attack_surface_coverage", 0)
        if coverage < 0.5:
            recommendations.append({
                "category": "Coverage Improvement", 
                "priority": "MEDIUM",
                "description": "Limited attack surface coverage detected",
                "specific_recommendations": [
                    "Expand endpoint discovery",
                    "Test more parameter combinations",
                    "Include additional attack categories"
                ],
                "impact": "More comprehensive security assessment"
            })
            
        # Missing attack categories
        tested_categories = set(payload_analysis.get("payload_categories", {}).keys())
        all_categories = {"XSS", "SQL_INJECTION", "PATH_TRAVERSAL", "COMMAND_INJECTION", 
                         "SSRF", "XXE", "IDOR", "CSRF"}
        missing_categories = all_categories - tested_categories
        
        if missing_categories:
            recommendations.append({
                "category": "Attack Diversification",
                "priority": "MEDIUM", 
                "description": f"Missing attack categories: {', '.join(missing_categories)}",
                "specific_recommendations": [
                    f"Add {cat} payload templates" for cat in missing_categories
                ],
                "impact": "Broader vulnerability coverage"
            })
            
        return recommendations
        
    def calculate_ai_score(self, payload_analysis, risk_assessment):
        """AI scoring algoritam (0.0 - 5.0)"""
        score_components = {
            "payload_effectiveness": 0.0,
            "vulnerability_confidence": 0.0,
            "attack_diversity": 0.0,
            "coverage_score": 0.0
        }
        
        # Payload effectiveness (0-1.5)
        effective_ratio = (payload_analysis.get("effective_payloads", 0) / 
                          max(payload_analysis.get("total_payloads", 1), 1))
        score_components["payload_effectiveness"] = effective_ratio * 1.5
        
        # Vulnerability confidence (0-2.0)
        risk_weights = {"CRITICAL": 2.0, "HIGH": 1.5, "MEDIUM": 1.0, "LOW": 0.3}
        total_weighted = sum(count * risk_weights.get(level, 0) 
                           for level, count in risk_assessment.get("risk_breakdown", {}).items())
        total_attacks = sum(risk_assessment.get("risk_breakdown", {}).values())
        
        if total_attacks > 0:
            avg_risk_weight = total_weighted / total_attacks
            score_components["vulnerability_confidence"] = min(avg_risk_weight, 2.0)
            
        # Attack diversity (0-1.0)
        categories_tested = len(payload_analysis.get("payload_categories", {}))
        max_categories = 8  # Ukupno kategorija
        score_components["attack_diversity"] = min(categories_tested / max_categories, 1.0)
        
        # Coverage score (0-0.5)
        coverage = risk_assessment.get("attack_surface_coverage", 0)
        score_components["coverage_score"] = coverage * 0.5
        
        # Ukupan AI score
        total_score = sum(score_components.values())
        
        return {
            "total_score": round(total_score, 2),
            "components": score_components,
            "grade": self.score_to_grade(total_score),
            "description": self.score_description(total_score)
        }
        
    def score_to_grade(self, score):
        """Konverzija score u grade"""
        if score >= 4.5:
            return "A+"
        elif score >= 4.0:
            return "A"
        elif score >= 3.5:
            return "B+"
        elif score >= 3.0:
            return "B"
        elif score >= 2.5:
            return "C+"
        elif score >= 2.0:
            return "C"
        elif score >= 1.5:
            return "D+"
        elif score >= 1.0:
            return "D"
        else:
            return "F"
            
    def score_description(self, score):
        """Opis score-a"""
        if score >= 4.0:
            return "Excellent security assessment with high-confidence vulnerabilities"
        elif score >= 3.0:
            return "Good security assessment with moderate vulnerabilities detected"
        elif score >= 2.0:
            return "Basic security assessment - room for improvement"
        else:
            return "Limited security assessment - significant improvements needed"
            
    def save_results(self):
        """Snimanje AI evaluacije u ai_evaluator.json"""
        output_file = "Centar/ai_evaluator.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] AI evaluacija snimljena: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def run_evaluation(self):
        """Glavna AI evaluacija"""
        print("🧠 SHADOWFOX AI EVALUATOR - POKRETANJE ANALIZE")
        print("=" * 60)
        
        # 1. Učitaj Meta config
        self.load_meta_config()
        
        # 2. Učitaj attack podatke
        print("📊 [AI] Učitavanje attack podataka...")
        attack_data = self.load_attack_data()
        
        if not attack_data:
            print("❌ [AI] Nema podataka za analizu!")
            return
            
        # 3. Parsiraj podatke iz različitih izvora
        all_parsed_attacks = []
        for file_path, data in attack_data.items():
            print(f"🔍 [AI] Parsiranje: {file_path}")
            parsed = self.parse_agent_x_results(data)
            all_parsed_attacks.extend(parsed)
            
        print(f"✅ [AI] Ukupno parsiranih napada: {len(all_parsed_attacks)}")
        
        # 4. Payload analiza
        print("🎯 [AI] Payload analiza...")
        payload_analysis = self.ai_payload_analysis(all_parsed_attacks)
        self.results["payload_analysis"] = payload_analysis
        
        # 5. Risk assessment
        print("⚠️  [AI] Risk assessment...")
        risk_assessment = self.risk_assessment(all_parsed_attacks)
        self.results["risk_assessment"] = risk_assessment
        
        # 6. Generisanje preporuka
        print("💡 [AI] Generisanje preporuka...")
        recommendations = self.generate_recommendations(payload_analysis, risk_assessment)
        self.results["recommendations"] = recommendations
        
        # 7. AI scoring
        print("🏆 [AI] AI scoring...")
        ai_score = self.calculate_ai_score(payload_analysis, risk_assessment)
        self.results["ai_scoring"] = ai_score
        
        # 8. Evaluation summary
        self.results["evaluation_summary"] = {
            "timestamp": datetime.now().isoformat(),
            "total_attacks_analyzed": len(all_parsed_attacks),
            "effective_attacks": payload_analysis.get("effective_payloads", 0),
            "overall_risk": risk_assessment.get("overall_risk", "LOW"),
            "ai_score": ai_score.get("total_score", 0.0),
            "ai_grade": ai_score.get("grade", "F"),
            "recommendations_count": len(recommendations)
        }
        
        # 9. Snimanje rezultata
        self.save_results()
        
        # 10. Prikaz sažetka
        self.display_summary()
        
    def display_summary(self):
        """Prikaz sažetka AI evaluacije"""
        summary = self.results["evaluation_summary"]
        scoring = self.results["ai_scoring"]
        
        print("\n🧠 SHADOWFOX AI EVALUATOR - SAŽETAK")
        print("=" * 60)
        print(f"📊 Analizirani napadi: {summary['total_attacks_analyzed']}")
        print(f"🎯 Efikasni napadi: {summary['effective_attacks']}")
        print(f"⚠️  Ukupan rizik: {summary['overall_risk']}")
        print(f"🏆 AI Score: {summary['ai_score']}/5.0 ({summary['ai_grade']})")
        print(f"💡 Preporuke: {summary['recommendations_count']}")
        
        print(f"\n📈 SCORE BREAKDOWN:")
        components = scoring.get("components", {})
        for component, score in components.items():
            print(f"   • {component}: {score:.2f}")
            
        print(f"\n📝 {scoring.get('description', 'N/A')}")
        print(f"\n✅ Rezultati: Centar/ai_evaluator.json")

def main():
    evaluator = ShadowAIEvaluator()
    evaluator.run_evaluation()

if __name__ == "__main__":
    main()
