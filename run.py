#!/usr/bin/env python3
"""
🦊 SHADOWFOX CLI ORCHESTRATOR
Centralni komandni centar za sve ShadowFox operacije
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import argparse
import os
import sys
import json
import time
import subprocess
import threading
from datetime import datetime
from pathlib import Path
import http.server
import socketserver
from urllib.parse import urlparse
import webbrowser
from http.server import SimpleHTTPRequestHandler
import socketserver



class ShadowFoxCLI:
    def __init__(self):
        self.version = "2025.06.06"
        self.banner = """
╔═══════════════════════════════════════════════════════════╗
║  🦊 SHADOWFOX TACTICAL BOUNTY SYSTEM v{version}            ║  
║  ═══════════════════════════════════════════════════════  ║
║  Modular AI-Powered Bug Bounty Hunting Platform          ║
║  Created by: Whitefox980 | Status: OPERATIONAL           ║
╚═══════════════════════════════════════════════════════════╝
        """.format(version=self.version)
        
        self.modules = {
            "recon": "ShadowRecon/shadow_recon.py",
            "header_fuzz": "Napad/attack_header_fuzz.py", 
            "param_fuzz": "Napad/attack_param_fuzz.py",
            "mutator": "Centar/mutator_core.py",
            "ai_eval": "Centar/ai_evaluator.py",
            "replay": "Replay/replay_executor.py",
            "poc": "PoC/PoC_Reporter.py",
            "filter": "ShadowRecon/chupko_filter.py"
        }
        
        self.server_port = 8888
        self.server_thread = None
        self.server_running = False
        
    def print_banner(self):
        """Prikaz ShadowFox banner-a"""
        print(self.banner)
        
    def check_structure(self):
        """Provera strukture foldera i fajlova"""
        print("🔍 [CHECK] Provera ShadowFox strukture...")
        
        required_dirs = [
            "Meta", "ShadowRecon", "Napad", "Centar", 
            "Replay", "PoC", "Izlaz"
        ]
        
        required_files = [
            "targets.txt",
            "Meta/mission_info.json"
        ]
        
        missing_dirs = []
        missing_files = []
        
        # Proveri direktorijume
        for dir_name in required_dirs:
            if not os.path.exists(dir_name):
                missing_dirs.append(dir_name)
                
        # Proveri fajlove
        for file_name in required_files:
            if not os.path.exists(file_name):
                missing_files.append(file_name)
                
        if missing_dirs or missing_files:
            print("❌ [ERROR] Nedostaju komponente:")
            for missing_dir in missing_dirs:
                print(f"   📁 mkdir {missing_dir}")
            for missing_file in missing_files:
                print(f"   📄 touch {missing_file}")
            return False
        
        print("✅ [CHECK] ShadowFox struktura kompletna")
        return True
        
    def create_structure(self):
        """Kreiranje osnovne strukture foldera"""
        print("🔧 [SETUP] Kreiranje ShadowFox strukture...")
        
        dirs = [
            "Meta", "ShadowRecon", "Napad", "Centar", 
            "Replay", "PoC", "Izlaz"
        ]
        
        for dir_name in dirs:
            os.makedirs(dir_name, exist_ok=True)
            print(f"📁 [CREATED] {dir_name}/")
            
        # Kreiranje osnovnih fajlova
        if not os.path.exists("targets.txt"):
            with open("targets.txt", "w") as f:
                f.write("# ShadowFox Target URLs\n")
                f.write("# Dodaj mete, jedan URL po liniji\n")
                f.write("https://example.com\n")
            print("📄 [CREATED] targets.txt")
            
        if not os.path.exists("Meta/mission_info.json"):
            template = {
                "mission_id": f"SHADOW_MISSION_{datetime.now().strftime('%Y%m%d')}",
                "target_root": "https://example.com",
                "program": "Example Bug Bounty",
                "scope": ["https://example.com"],
                "default_headers": {
                    "User-Agent": "ShadowFox-Recon/1.0",
                    "Accept": "*/*",
                    "X-HackerOne-Research": "Whitefox980"
                },
                "stealth_mode": True,
                "rate_delay_seconds": 2.5,
                "retry_limit": 3,
                "priority_keywords": ["token", "jwt", "auth", "reset", "session", "email"],
                "avoid_keywords": ["logout", "cancel", "facebook", "linkedin"],
                "ai_score_threshold": 3.1,
                "report_folder": "Izlaz/",
                "log_folder": "Izlaz/"
            }
            
            with open("Meta/mission_info.json", "w") as f:
                json.dump(template, f, indent=2)
            print("📄 [CREATED] Meta/mission_info.json")
            
        print("✅ [SETUP] ShadowFox struktura kreirana")
        
    def run_module(self, module_name, args=None):
        """Pokretanje pojedinačnog modula"""
        if module_name not in self.modules:
            print(f"❌ [ERROR] Nepoznat modul: {module_name}")
            return False
            
        module_path = self.modules[module_name]
        
        if not os.path.exists(module_path):
            print(f"❌ [ERROR] Modul ne postoji: {module_path}")
            return False
            
        print(f"🚀 [RUN] Pokretanje modula: {module_name}")
        print(f"📂 [PATH] {module_path}")
        
        try:
            cmd = [sys.executable, module_path]
            if args:
                cmd.extend(args)
                
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print(f"✅ [SUCCESS] Modul {module_name} završen uspešno")
                if result.stdout:
                    print("📤 [OUTPUT]")
                    print(result.stdout)
                return True
            else:
                print(f"❌ [ERROR] Modul {module_name} neuspešan")
                if result.stderr:
                    print("📥 [ERROR OUTPUT]")
                    print(result.stderr)
                return False
                
        except Exception as e:
            print(f"❌ [EXCEPTION] {str(e)}")
            return False
            
    def run_full_mission(self):
        """Pokretanje kompletne ShadowFox misije"""
        print("🎯 [MISSION] Pokretanje kompletne ShadowFox misije")
        print("=" * 60)
        
        mission_flow = [
            ("recon", "🕷️  Izviđanje i mapiranje mete"),
            ("header_fuzz", "🔥 Header fuzzing napadi"),
            ("param_fuzz", "💥 Parameter fuzzing napadi"), 
            ("mutator", "🧬 Mutacija i evolucija payload-a"),
            ("ai_eval", "🤖 AI analiza ranjivosti"),
            ("replay", "🔄 Replay i potvrda napada"),
            ("poc", "📋 Generisanje PoC izveštaja")
        ]
        
        successful_modules = []
        failed_modules = []
        
        for module_name, description in mission_flow:
            print(f"\n{description}")
            print("-" * 40)
            
            if self.run_module(module_name):
                successful_modules.append(module_name)
                time.sleep(2)  # Kratka pauza između modula
            else:
                failed_modules.append(module_name)
                print(f"⚠️  [WARNING] Modul {module_name} neuspešan, nastavljam...")
                
        # Sažetak misije
        print("\n🏁 [MISSION COMPLETE] Sažetak operacije")
        print("=" * 60)
        print(f"✅ Uspešni moduli: {len(successful_modules)}")
        for module in successful_modules:
            print(f"   • {module}")
            
        if failed_modules:
            print(f"❌ Neuspešni moduli: {len(failed_modules)}")
            for module in failed_modules:
                print(f"   • {module}")
                
        # Proveri da li je PoC generisan
        poc_files = list(Path("Izlaz").glob("*.json"))
        if poc_files:
            print(f"\n📁 [RESULTS] Pronađeni PoC fajlovi:")
            for poc_file in poc_files:
                print(f"   📄 {poc_file}")
    def start_live_server(self):
        """Pokretanje live servera za praćenje napada"""
        if self.server_running:
            print("⚠️ [SERVER] Server već radi")
            return

        print(f"🌐 [SERVER] Pokretanje live servera na portu {self.server_port}")

        try:
            os.chdir("Izlaz")  # folder sa rezultatima
            handler = http.server.SimpleHTTPRequestHandler
            httpd = socketserver.TCPServer(("", self.server_port), handler)

            def run_server():
                self.server_running = True
                print(f"✅ [SERVER] Server pokrenut: http://localhost:{self.server_port}")
                print(f"🧪 [SERVER] Pristup rezultatima: http://localhost:{self.server_port}")
                httpd.serve_forever()

            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()

        # Opcionalno otvori browser
            time.sleep(1)
            webbrowser.open(f"http://localhost:{self.server_port}")

        except Exception as e:
            print(f"❌ [SERVER ERROR] {str(e)}")
            self.server_running = False
    def stop_live_server(self):
        """Zaustavljanje live servera"""
        if not self.server_running:
            print("⚠️  [SERVER] Server nije pokrenut")
            return
            
        print("🛑 [SERVER] Zaustavljanje servera...")
        self.server_running = False
        # Note: SimpleHTTPServer ne može da se zaustavi elegantno
        print("✅ [SERVER] Server zaustavljen")
        
    def show_status(self):
        """Prikaz statusa ShadowFox sistema"""
        print("📊 [STATUS] ShadowFox System Status")
        print("=" * 50)
        
        # Proveri Meta config
        if os.path.exists("Meta/mission_info.json"):
            with open("Meta/mission_info.json", "r") as f:
                meta = json.load(f)
            print(f"🎯 Misija: {meta.get('mission_id', 'UNKNOWN')}")
            print(f"🌐 Meta: {meta.get('target_root', 'UNKNOWN')}")
            print(f"⚙️  Stealth Mode: {meta.get('stealth_mode', False)}")
        else:
            print("❌ Meta konfiguracija nije pronađena")
            
        # Proveri targets.txt
        if os.path.exists("targets.txt"):
            with open("targets.txt", "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            print(f"🎯 Aktivnih meta: {len(targets)}")
            for target in targets[:3]:
                print(f"   • {target}")
            if len(targets) > 3:
                print(f"   ... i {len(targets) - 3} više")
        else:
            print("❌ targets.txt nije pronađen")
            
        # Proveri module
        print(f"\n🔧 Dostupni moduli: {len(self.modules)}")
        for name, path in self.modules.items():
            status = "✅" if os.path.exists(path) else "❌"
            print(f"   {status} {name}: {path}")
            
        # Proveri rezultate
        if os.path.exists("Izlaz"):
            results = list(Path("Izlaz").glob("*.json"))
            print(f"\n📁 Rezultati: {len(results)} fajlova")
            for result in results[-5:]:  # Poslednih 5
                print(f"   📄 {result.name}")
                
        # Server status
        print(f"\n🌐 Live Server: {'🟢 AKTIVAN' if self.server_running else '🔴 NEAKTIVAN'}")
        if self.server_running:
            print(f"   📊 URL: http://localhost:{self.server_port}")
            
    def interactive_menu(self):
        """Interaktivni meni za ShadowFox"""
        while True:
            print("\n🦊 SHADOWFOX INTERACTIVE MENU")
            print("=" * 40)
            print("1. 🕷️  Recon (Izviđanje)")
            print("2. 🔥 Header Fuzzing")
            print("3. 💥 Parameter Fuzzing")
            print("4. 🧬 Mutator Core")
            print("5. 🤖 AI Evaluator")
            print("6. 🔄 Replay Executor")
            print("7. 📋 PoC Reporter")
            print("8. 🎯 Full Mission (All)")
            print("9. 🌐 Start Live Server")
            print("10. 📊 System Status")
            print("0. 🚪 Exit")
            
            choice = input("\n👤 Izbor: ").strip()
            
            if choice == "1":
                self.run_module("recon")
            elif choice == "2":
                self.run_module("header_fuzz")
            elif choice == "3":
                self.run_module("param_fuzz")
            elif choice == "4":
                self.run_module("mutator")
            elif choice == "5":
                self.run_module("ai_eval")
            elif choice == "6":
                self.run_module("replay")
            elif choice == "7":
                self.run_module("poc")
            elif choice == "8":
                self.run_full_mission()
            elif choice == "9":
                self.start_live_server()
            elif choice == "10":
                self.show_status()
            elif choice == "0":
                if self.server_running:
                    self.stop_live_server()
                print("👋 ShadowFox shutdown complete")
                break
            else:
                print("❌ Nepoznat izbor")

def main():
    parser = argparse.ArgumentParser(
        description="🦊 ShadowFox Tactical Bounty System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Primeri korišćenja:
  python3 shadowfox_cli.py --setup          # Kreiranje strukture
  python3 shadowfox_cli.py --check          # Provera strukture
  python3 shadowfox_cli.py --recon          # Pokretanje recon modula
  python3 shadowfox_cli.py --full-mission   # Kompletna misija
  python3 shadowfox_cli.py --server         # Live server za rezultate
  python3 shadowfox_cli.py --interactive    # Interaktivni meni
        """
    )
    
    parser.add_argument("--setup", action="store_true", help="Kreiranje ShadowFox strukture")
    parser.add_argument("--check", action="store_true", help="Provera strukture sistema")
    parser.add_argument("--recon", action="store_true", help="Pokretanje recon modula")
    parser.add_argument("--header-fuzz", action="store_true", help="Header fuzzing")
    parser.add_argument("--param-fuzz", action="store_true", help="Parameter fuzzing")
    parser.add_argument("--mutator", action="store_true", help="Mutator core")
    parser.add_argument("--ai-eval", action="store_true", help="AI evaluator")
    parser.add_argument("--replay", action="store_true", help="Replay executor")
    parser.add_argument("--poc", action="store_true", help="PoC reporter")
    parser.add_argument("--full-mission", action="store_true", help="Kompletna misija")
    parser.add_argument("--server", action="store_true", help="Pokretanje live servera")
    parser.add_argument("--interactive", action="store_true", help="Interaktivni meni")
    parser.add_argument("--status", action="store_true", help="Prikaz statusa sistema")
    parser.add_argument("--port", type=int, default=8888, help="Port za live server")
    
    args = parser.parse_args()
    
    cli = ShadowFoxCLI()
    cli.server_port = args.port
    
    # Ako nema argumenata, prikaži banner i interaktivni meni
    if len(sys.argv) == 1:
        cli.print_banner()
        cli.interactive_menu()
        return
    
    cli.print_banner()
    
    if args.setup:
        cli.create_structure()
    elif args.check:
        cli.check_structure()
    elif args.recon:
        cli.run_module("recon")
    elif args.header_fuzz:
        cli.run_module("header_fuzz")
    elif args.param_fuzz:
        cli.run_module("param_fuzz")
    elif args.mutator:
        cli.run_module("mutator")
    elif args.ai_eval:
        cli.run_module("ai_eval")
    elif args.replay:
        cli.run_module("replay")
    elif args.poc:
        cli.run_module("poc")
    elif args.full_mission:
        cli.run_full_mission()
    elif args.server:
        cli.start_live_server()
        try:
            while cli.server_running:
                time.sleep(1)
        except KeyboardInterrupt:
            cli.stop_live_server()
    elif args.status:
        cli.show_status()
    elif args.interactive:
        cli.interactive_menu()

if __name__ == "__main__":
    main()
