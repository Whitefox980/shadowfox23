#!/usr/bin/env python3
"""
🦊 SHADOWFOX SSRF/XXE DETECTION PROXY
Proxy lovac koji hvata SSRF/XXE pozive i beleži dokaze
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import http.server
import socketserver
import threading
import json
import time
import hashlib
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import base64
import os

class SSRFDetectionHandler(http.server.BaseHTTPRequestHandler):
    """HTTP handler koji hvata sve zahteve i beleži dokaze"""
    
    def log_request_details(self, method):
        """Detaljno beleženje svih zahteva"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Kreiranje unique ID za ovaj zahtev
        request_id = hashlib.md5(f"{timestamp}{self.client_address[0]}{self.path}".encode()).hexdigest()[:8]
        
        # Sakupljanje svih header-a
        headers = {}
        for header_name, header_value in self.headers.items():
            headers[header_name] = header_value
            
        # Parsiranje URL-a
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        
        # Čitanje body-ja ako postoji
        content_length = int(self.headers.get('Content-Length', 0))
        body = ""
        if content_length > 0:
            try:
                body = self.rfile.read(content_length).decode('utf-8', errors='ignore')
            except:
                body = "[BINARY_DATA]"
        
        # Kreiranje evidence record-a
        evidence = {
            "request_id": request_id,
            "timestamp": timestamp,
            "method": method,
            "path": self.path,
            "full_url": f"http://{self.headers.get('Host', 'unknown')}{self.path}",
            "source_ip": self.client_address[0],
            "source_port": self.client_address[1],
            "headers": headers,
            "query_params": query_params,
            "body": body,
            "user_agent": headers.get('User-Agent', 'Unknown'),
            "referer": headers.get('Referer', 'None'),
            "content_type": headers.get('Content-Type', 'Unknown'),
            "content_length": content_length,
            "vulnerability_type": self.detect_vulnerability_type(),
            "severity": self.assess_severity(),
            "attack_vector": self.identify_attack_vector()
        }
        
        # Dodavanje u globalni log
        SSRFProxy.add_evidence(evidence)
        
        # Console log sa bojama
        print(f"\n🎯 [SSRF DETECTED] {timestamp}")
        print(f"   ID: {request_id}")
        print(f"   Method: {method}")
        print(f"   Source: {self.client_address[0]}:{self.client_address[1]}")
        print(f"   Path: {self.path}")
        print(f"   User-Agent: {headers.get('User-Agent', 'Unknown')[:50]}...")
        print(f"   Type: {evidence['vulnerability_type']}")
        print(f"   Severity: {evidence['severity']}")
        
        if body:
            print(f"   Body: {body[:100]}{'...' if len(body) > 100 else ''}")
            
        return evidence
        
    def detect_vulnerability_type(self):
        """Identifikacija tipa ranjivosti na osnovu zahteva"""
        path_lower = self.path.lower()
        headers = {k.lower(): v for k, v in self.headers.items()}
        
        # XXE detection
        if any(keyword in str(self.headers) for keyword in ['xml', 'application/xml', 'text/xml']):
            return "XXE"
            
        # AWS Metadata SSRF
        if "169.254.169.254" in self.path or "metadata" in path_lower:
            return "AWS_METADATA_SSRF"
            
        # File protocol SSRF
        if self.path.startswith(('file://', '/file:')):
            return "FILE_SSRF"
            
        # FTP SSRF
        if self.path.startswith(('ftp://', '/ftp:')):
            return "FTP_SSRF"
            
        # HTTP SSRF (external)
        if any(domain in path_lower for domain in ['evil.com', 'attacker.com', 'malicious']):
            return "HTTP_SSRF"
            
        # Generic SSRF
        return "GENERIC_SSRF"
        
    def assess_severity(self):
        """Procena težine ranjivosti"""
        vuln_type = self.detect_vulnerability_type()
        
        severity_map = {
            "AWS_METADATA_SSRF": "CRITICAL",
            "FILE_SSRF": "HIGH", 
            "XXE": "HIGH",
            "FTP_SSRF": "MEDIUM",
            "HTTP_SSRF": "MEDIUM",
            "GENERIC_SSRF": "LOW"
        }
        
        return severity_map.get(vuln_type, "LOW")
        
    def identify_attack_vector(self):
        """Identifikacija vektora napada"""
        path_lower = self.path.lower()
        
        if "callback" in path_lower or "webhook" in path_lower:
            return "CALLBACK_SSRF"
        elif "redirect" in path_lower or "url" in path_lower:
            return "REDIRECT_SSRF"
        elif "fetch" in path_lower or "download" in path_lower:
            return "FETCH_SSRF"
        elif "xml" in str(self.headers).lower():
            return "XXE_EXTERNAL_ENTITY"
        else:
            return "DIRECT_SSRF"
    
    def send_success_response(self, evidence):
        """Šalje uspešan odgovor sa dokazom"""
        response_data = {
            "status": "SSRF_DETECTED",
            "evidence_id": evidence["request_id"],
            "timestamp": evidence["timestamp"],
            "message": "ShadowFox SSRF Detection - Evidence Collected",
            "vulnerability_confirmed": True,
            "severity": evidence["severity"],
            "type": evidence["vulnerability_type"]
        }
        
        # Specijalni odgovori za različite tipove napada
        if evidence["vulnerability_type"] == "AWS_METADATA_SSRF":
            response_data["aws_metadata"] = {
                "instance-id": "i-1234567890abcdef0",
                "instance-type": "t2.micro",
                "public-ipv4": "203.0.113.25",
                "security-groups": "sg-903004f8"
            }
        elif evidence["vulnerability_type"] == "FILE_SSRF":
            response_data["file_content"] = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
            
        response_json = json.dumps(response_data, indent=2)
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(response_json)))
        self.send_header('X-ShadowFox-Detection', 'SSRF-Confirmed')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(response_json.encode())
        
    def do_GET(self):
        evidence = self.log_request_details("GET")
        self.send_success_response(evidence)
        
    def do_POST(self):
        evidence = self.log_request_details("POST")
        self.send_success_response(evidence)
        
    def do_PUT(self):
        evidence = self.log_request_details("PUT")
        self.send_success_response(evidence)
        
    def do_DELETE(self):
        evidence = self.log_request_details("DELETE")
        self.send_success_response(evidence)
        
    def do_OPTIONS(self):
        evidence = self.log_request_details("OPTIONS")
        self.send_success_response(evidence)
        
    def log_message(self, format, *args):
        """Potiskuje default HTTP server log"""
        pass

class SSRFProxy:
    """Glavni SSRF Detection Proxy"""
    
    evidence_log = []
    
    def __init__(self, port=8080):
        self.port = port
        self.server = None
        self.meta_config = {}
        self.evidence_file = "Centar/ssrf_detection_proxy.json"
        
    @classmethod
    def add_evidence(cls, evidence):
        """Dodaje dokaz u globalni log"""
        cls.evidence_log.append(evidence)
        
    def load_meta_config(self):
        """Učitava Meta konfiguraciju"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
        except FileNotFoundError:
            print("⚠️  [WARNING] Meta/mission_info.json nije pronađen, koristim default config")
            
    def start_server(self):
        """Pokretanje SSRF Detection Proxy servera"""
        try:
            self.server = socketserver.TCPServer(("", self.port), SSRFDetectionHandler)
            self.server.allow_reuse_address = True
            
            print(f"🦊 SHADOWFOX SSRF PROXY - POKRETANJE")
            print(f"🎯 Listening na portu: {self.port}")
            print(f"🔍 Čeka SSRF/XXE pozive...")
            print(f"📝 Evidence log: {self.evidence_file}")
            print("=" * 60)
            print("💡 PAYLOAD PRIMER:")
            print(f"   http://127.0.0.1:{self.port}/")
            print(f"   http://127.0.0.1:{self.port}/aws-metadata")
            print(f"   http://127.0.0.1:{self.port}/file-read")
            print("=" * 60)
            
            # Pokretanje servera u background thread-u
            server_thread = threading.Thread(target=self.server.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            
            return True
            
        except Exception as e:
            print(f"❌ [ERROR] Proxy server failed: {str(e)}")
            return False
            
    def stop_server(self):
        """Zaustavljanje servera"""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("🛑 [STOP] SSRF Proxy zaustavljen")
            
    def save_evidence(self):
        """Snimanje svih dokaza"""
        evidence_data = {
            "mission_info": self.meta_config,
            "proxy_info": {
                "port": self.port,
                "start_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_detections": len(self.evidence_log)
            },
            "detections": self.evidence_log,
            "statistics": self.generate_statistics()
        }
        
        try:
            os.makedirs(os.path.dirname(self.evidence_file), exist_ok=True)
            with open(self.evidence_file, 'w') as f:
                json.dump(evidence_data, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Evidence snimljen: {self.evidence_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def generate_statistics(self):
        """Generisanje statistike detekcija"""
        if not self.evidence_log:
            return {}
            
        stats = {
            "total_detections": len(self.evidence_log),
            "vulnerability_types": {},
            "severity_distribution": {},
            "source_ips": {},
            "attack_vectors": {},
            "timeline": []
        }
        
        for evidence in self.evidence_log:
            # Vulnerability types
            vuln_type = evidence["vulnerability_type"]
            stats["vulnerability_types"][vuln_type] = stats["vulnerability_types"].get(vuln_type, 0) + 1
            
            # Severity distribution
            severity = evidence["severity"]
            stats["severity_distribution"][severity] = stats["severity_distribution"].get(severity, 0) + 1
            
            # Source IPs
            source_ip = evidence["source_ip"]
            stats["source_ips"][source_ip] = stats["source_ips"].get(source_ip, 0) + 1
            
            # Attack vectors
            vector = evidence["attack_vector"]
            stats["attack_vectors"][vector] = stats["attack_vectors"].get(vector, 0) + 1
            
        return stats
        
    def display_statistics(self):
        """Prikaz statistike u real-time"""
        if not self.evidence_log:
            print("📊 [STATS] Nema detekcija")
            return
            
        stats = self.generate_statistics()
        
        print(f"\n📊 SSRF DETECTION STATISTICS")
        print("=" * 40)
        print(f"🎯 Ukupno detekcija: {stats['total_detections']}")
        
        print(f"\n🔍 Tipovi ranjivosti:")
        for vuln_type, count in stats["vulnerability_types"].items():
            print(f"   • {vuln_type}: {count}")
            
        print(f"\n⚠️  Težina:")
        for severity, count in stats["severity_distribution"].items():
            print(f"   • {severity}: {count}")
            
        print(f"\n🌐 Source IP:")
        for ip, count in stats["source_ips"].items():
            print(f"   • {ip}: {count}")
            
    def interactive_mode(self):
        """Interaktivni režim za monitoring"""
        print("\n🎮 INTERAKTIVNI REŽIM")
        print("Komande: 'stats', 'save', 'quit', 'clear'")
        
        while True:
            try:
                cmd = input("\n🦊 ShadowFox> ").strip().lower()
                
                if cmd == 'stats':
                    self.display_statistics()
                elif cmd == 'save':
                    self.save_evidence()
                elif cmd == 'clear':
                    self.evidence_log.clear()
                    print("🗑️  Evidence log očišćen")
                elif cmd in ['quit', 'exit', 'q']:
                    break
                elif cmd == 'help':
                    print("📋 Komande: stats, save, clear, quit")
                else:
                    print("❓ Nepoznata komanda. Kuraj 'help'")
                    
            except KeyboardInterrupt:
                break
                
        print("\n👋 Izlazim iz interaktivnog režima...")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='ShadowFox SSRF Detection Proxy')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Port za proxy server (default: 8080)')
    parser.add_argument('-i', '--interactive', action='store_true', help='Interaktivni režim')
    parser.add_argument('-d', '--daemon', action='store_true', help='Pokreni kao daemon')
    
    args = parser.parse_args()
    
    proxy = SSRFProxy(port=args.port)
    proxy.load_meta_config()
    
    if proxy.start_server():
        try:
            if args.interactive:
                proxy.interactive_mode()
            elif args.daemon:
                print("🔄 [DAEMON] Proxy radi u pozadini...")
                print("🛑 Ctrl+C za zaustavljanje")
                while True:
                    time.sleep(1)
            else:
                print("🔄 [MONITOR] Monitoring SSRF detekcija...")
                print("🛑 Ctrl+C za zaustavljanje")
                while True:
                    time.sleep(10)
                    if len(proxy.evidence_log) > 0:
                        proxy.display_statistics()
                        
        except KeyboardInterrupt:
            print("\n🛑 [SHUTDOWN] Zaustavljanje proxy servera...")
            proxy.save_evidence()
            proxy.stop_server()
            print("✅ [DONE] ShadowFox SSRF Proxy zaustavljen")
    else:
        print("❌ [FAILED] Proxy server nije mogao da se pokrene")

if __name__ == "__main__":
    main()
