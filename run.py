#!/usr/bin/env python3
"""
ShadowFox CLI Command Center
Advanced Cybersecurity Toolkit Interface
"""

import os
import sys
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path

class ShadowFoxCLI:
    def __init__(self):
        self.version = "2.3.1"
        self.project_name = "ShadowFox"
        self.base_dir = Path(__file__).parent
        self.mission_info = self.load_mission_info()
        
    def load_mission_info(self):
        """Load mission info with fallback"""
        try:
            with open(self.base_dir / "Meta" / "mission_info.json", 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {
                "mission": "Unknown Mission",
                "target": "Not specified",
                "status": "active",
                "created": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
    
    def print_header(self):
        """Print stylized CLI header"""
        print("\n" + "═" * 80)
        print(f"🦊 {self.project_name.upper()} COMMAND CENTER v{self.version} 🦊")
        print("═" * 80)
        print(f"🎯 Mission: {self.mission_info.get('mission', 'Unknown')}")
        print(f"🌐 Target: {self.mission_info.get('target', 'Not specified')}")
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("═" * 80)
    
    def print_menu(self):
        """Display main menu options"""
        menu_items = [
            ("1", "📡", "Recon Scan", "shadow_recon.py"),
            ("2", "🧠", "AI Recon Filter", "chupko_filter.py"),
            ("3", "⚔️", "Fuzz Attack", "Napad/ attacks"),
            ("4", "🧬", "Mutator Core", "mutator_core.py"),
            ("5", "🔁", "Replay Engine", "replay_executor.py"),
            ("6", "🛡️", "SSRF Detection Proxy", "ssrf_detection_proxy.py"),
            ("7", "🤖", "AI Evaluator", "ai_evaluator.py"),
            ("8", "💣", "Advanced AgentX Attack", "agent_x_mutated_attack.py"),
            ("9", "🗂️", "View Reports", "AI, Replay, PoC logs"),
            ("10", "🔄", "GitHub Sync", "pull/push operations"),
            ("11", "📊", "System Analysis", "stats & file analysis"),
            ("0", "🚪", "Exit", "shutdown CLI")
        ]
        
        print("\n┌─────────────────────────────────────────────────────────────┐")
        print("│                      🎮 MAIN MENU                          │")
        print("├─────────────────────────────────────────────────────────────┤")
        
        for num, icon, name, desc in menu_items:
            print(f"│ {num:>2} │ {icon} {name:<20} │ {desc:<25} │")
        
        print("└─────────────────────────────────────────────────────────────┘")
    
    def execute_script(self, script_path, args=None):
        """Execute script with error handling"""
        try:
            cmd = [sys.executable, script_path]
            if args:
                cmd.extend(args)
            
            print(f"\n🚀 Executing: {script_path}")
            print("─" * 50)
            
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=False)
            
            if result.returncode == 0:
                print("─" * 50)
                print("✅ Operation completed successfully!")
            else:
                print("─" * 50)
                print(f"⚠️  Process exited with code: {result.returncode}")
                
        except FileNotFoundError:
            print(f"❌ Error: {script_path} not found!")
        except Exception as e:
            print(f"❌ Error executing {script_path}: {str(e)}")
        
        input("\n📎 Press Enter to continue...")
    
    def recon_scan(self):
        """Execute reconnaissance scan"""
        if (self.base_dir / "ShadowRecon" / "shadow_recon.py").exists():
            self.execute_script("ShadowRecon/shadow_recon.py")
        else:
            print("❌ shadow_recon.py not found in ShadowRecon/")
            input("📎 Press Enter to continue...")
    
    def ai_recon_filter(self):
        """Execute AI recon filtering"""
        if (self.base_dir / "ShadowRecon" / "chupko_filter.py").exists():
            self.execute_script("ShadowRecon/chupko_filter.py")
        else:
            print("❌ chupko_filter.py not found in ShadowRecon/")
            input("📎 Press Enter to continue...")
    
    def fuzz_attack_menu(self):
        """Fuzzing attack submenu"""
        napad_dir = self.base_dir / "Napad"
        if not napad_dir.exists():
            print("❌ Napad directory not found!")
            input("📎 Press Enter to continue...")
            return
        
        # Get all Python attack files
        attack_files = [f for f in napad_dir.glob("attack_*.py")]
        
        if not attack_files:
            print("❌ No attack files found in Napad/")
            input("📎 Press Enter to continue...")
            return
        
        print("\n┌─────────────────────────────────────────────┐")
        print("│           ⚔️  FUZZ ATTACK MENU             │")
        print("├─────────────────────────────────────────────┤")
        
        for i, attack_file in enumerate(attack_files, 1):
            attack_name = attack_file.stem.replace("attack_", "").replace("_", " ").title()
            print(f"│ {i:>2} │ {attack_name:<35} │")
        
        print("│  0 │ Back to Main Menu                   │")
        print("└─────────────────────────────────────────────┘")
        
        try:
            choice = input("\n🎯 Select attack: ").strip()
            if choice == "0":
                return
            
            attack_idx = int(choice) - 1
            if 0 <= attack_idx < len(attack_files):
                self.execute_script(str(attack_files[attack_idx]))
            else:
                print("❌ Invalid selection!")
                input("📎 Press Enter to continue...")
        except (ValueError, IndexError):
            print("❌ Invalid input!")
            input("📎 Press Enter to continue...")
    
    def mutator_core(self):
        """Execute mutator core"""
        if (self.base_dir / "Centar" / "mutator_core.py").exists():
            self.execute_script("Centar/mutator_core.py")
        else:
            print("❌ mutator_core.py not found in Centar/")
            input("📎 Press Enter to continue...")
    
    def replay_engine(self):
        """Execute replay engine"""
        if (self.base_dir / "Replay" / "replay_executor.py").exists():
            self.execute_script("Replay/replay_executor.py")
        else:
            print("❌ replay_executor.py not found in Replay/")
            input("📎 Press Enter to continue...")
    
    def ssrf_detection_proxy(self):
        """SSRF Detection Proxy with mode selection"""
        script_path = self.base_dir / "ssrf_detection_proxy.py"
        if not script_path.exists():
            print("❌ ssrf_detection_proxy.py not found!")
            input("📎 Press Enter to continue...")
            return
        
        print("\n┌─────────────────────────────────────────┐")
        print("│        🛡️  SSRF PROXY MODES            │")
        print("├─────────────────────────────────────────┤")
        print("│ 1 │ Passive Monitoring Mode         │")
        print("│ 2 │ Active Detection Mode           │")
        print("│ 3 │ Advanced Analysis Mode          │")
        print("│ 0 │ Back to Main Menu               │")
        print("└─────────────────────────────────────────┘")
        
        try:
            choice = input("\n🔧 Select mode: ").strip()
            modes = {"1": "passive", "2": "active", "3": "advanced"}
            
            if choice == "0":
                return
            elif choice in modes:
                self.execute_script(str(script_path), ["--mode", modes[choice]])
            else:
                print("❌ Invalid selection!")
                input("📎 Press Enter to continue...")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            input("📎 Press Enter to continue...")
    
    def ai_evaluator(self):
        """Execute AI evaluator"""
        if (self.base_dir / "Centar" / "ai_evaluator.py").exists():
            self.execute_script("Centar/ai_evaluator.py")
        else:
            print("❌ ai_evaluator.py not found in Centar/")
            input("📎 Press Enter to continue...")
    
    def advanced_agentx_attack(self):
        """Execute Advanced AgentX Attack"""
        if (self.base_dir / "AdvanceNapad" / "agent_x_mutated_attack.py").exists():
            self.execute_script("AdvanceNapad/agent_x_mutated_attack.py")
        else:
            print("❌ agent_x_mutated_attack.py not found in AdvanceNapad/")
            input("📎 Press Enter to continue...")
    
    def view_reports(self):
        """View various reports and logs"""
        print("\n┌─────────────────────────────────────────────┐")
        print("│            🗂️  REPORTS VIEWER              │")
        print("├─────────────────────────────────────────────┤")
        print("│ 1 │ AI Evaluation Reports             │")
        print("│ 2 │ Replay Engine Logs               │")
        print("│ 3 │ PoC Reports (JSON, PDF, PNG)     │")
        print("│ 4 │ Attack Logs                      │")
        print("│ 5 │ Recon Logs                       │")
        print("│ 0 │ Back to Main Menu                │")
        print("└─────────────────────────────────────────────┘")
        
        try:
            choice = input("\n📊 Select report type: ").strip()
            
            if choice == "0":
                return
            elif choice == "1":
                self.show_directory_contents("Centar", "*.json")
            elif choice == "2":
                self.show_directory_contents("Replay", "*.json")
            elif choice == "3":
                self.show_directory_contents("PoC", "*")
            elif choice == "4":
                self.show_directory_contents("log", "*.log")
            elif choice == "5":
                self.show_directory_contents("ShadowRecon", "*.json")
            else:
                print("❌ Invalid selection!")
                input("📎 Press Enter to continue...")
        except Exception as e:
            print(f"❌ Error: {str(e)}")
            input("📎 Press Enter to continue...")
    
    def show_directory_contents(self, directory, pattern):
        """Show contents of a directory"""
        dir_path = self.base_dir / directory
        if not dir_path.exists():
            print(f"❌ Directory {directory} not found!")
            input("📎 Press Enter to continue...")
            return
        
        files = list(dir_path.glob(pattern))
        if not files:
            print(f"❌ No files matching {pattern} found in {directory}/")
            input("📎 Press Enter to continue...")
            return
        
        print(f"\n📁 Files in {directory}/:")
        print("─" * 50)
        for i, file in enumerate(files, 1):
            size = file.stat().st_size if file.is_file() else 0
            mod_time = datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
            print(f"{i:>2}. {file.name:<30} ({size:>8} bytes) {mod_time}")
        
        print("─" * 50)
        input("📎 Press Enter to continue...")
    
    def github_sync(self):
        """GitHub synchronization menu"""
        while True:
            os.system("clear")
            print("\n🌀  GITHUB SYNC MENU")
            print("=" * 50)
            print(" 1. Git Status")
            print(" 2. Git Pull (Update from remote)")
            print(" 3. Git Push (Upload changes)")
            print(" 4. Git Add All & Commit")
            print(" 5. Full Sync (Pull → Add → Commit → Push)")
            print(" 6. View Last 5 Commits")
            print(" 7. Reset Changes (Hard Reset)")
            print(" 8. View .gitignore")
            print(" 9. Back to Main Menu")
            print("=" * 50)

            choice = input("🛠  Select git operation: ").strip()

            try:
                if choice == "1":
                    self.run_git_command(["git", "status"])
                elif choice == "2":
                    self.run_git_command(["git", "pull", "origin", "main"])
                elif choice == "3":
                    self.run_git_command(["git", "push", "origin", "main"])
                elif choice == "4":
                    commit_msg = input("✏️  Enter commit message: ").strip() or "Auto commit"
                    self.run_git_command(["git", "add", "."])
                    self.run_git_command(["git", "commit", "-m", commit_msg])
                elif choice == "5":
                    self.full_sync()
                elif choice == "6":
                    self.run_git_command(["git", "log", "--oneline", "-n", "5"])
                elif choice == "7":
                    confirm = input("⚠️  Type 'yes' to hard reset: ").strip().lower()
                    if confirm == "yes":
                        self.run_git_command(["git", "reset", "--hard", "origin/main"])
                    else:
                        print("❎  Cancelled.")
                elif choice == "8":
                    os.system("cat .gitignore" if os.path.exists(".gitignore") else "echo 'No .gitignore file found'")
                elif choice == "9":
                    break
                else:
                    print("❌ Invalid selection!")
            except Exception as e:
                print(f"❌ Git Error: {str(e)}")

            input("⏎ Press Enter to continue...")
    def run_git_command(self, cmd):
        """Execute git command"""
        try:
            print(f"\n🔄 Running: {' '.join(cmd)}")
            print("─" * 50)
            result = subprocess.run(cmd, cwd=self.base_dir, capture_output=False)
            print("─" * 50)
            if result.returncode == 0:
                print("✅ Git operation completed!")
            else:
                print(f"⚠️  Git operation finished with code: {result.returncode}")
        except Exception as e:
            print(f"❌ Git error: {str(e)}")
    
    def full_sync(self):
        """Perform full git synchronization"""
        print("\n🔄 Starting full synchronization...")
        
        # Pull latest changes
        print("\n1️⃣ Pulling latest changes...")
        self.run_git_command(["git", "pull", "origin", "main"])
        
        # Add all files
        print("\n2️⃣ Adding all files...")
        self.run_git_command(["git", "add", "."])
        
        # Commit
        print("\n3️⃣ Committing changes...")
        commit_msg = f"Auto sync from ShadowFox CLI - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        self.run_git_command(["git", "commit", "-m", commit_msg])
        
        # Push
        print("\n4️⃣ Pushing to remote...")
        self.run_git_command(["git", "push", "origin", "main"])
        
        print("\n✅ Full synchronization completed!")
        input("📎 Press Enter to continue...")
    
    def system_analysis(self):
        """Perform system analysis and statistics"""
        print("\n┌─────────────────────────────────────────────┐")
        print("│           📊 SYSTEM ANALYSIS                │")
        print("├─────────────────────────────────────────────┤")
        
        # Count files by type
        stats = {
            "Python files": len(list(self.base_dir.rglob("*.py"))),
            "JSON files": len(list(self.base_dir.rglob("*.json"))),
            "Log files": len(list(self.base_dir.rglob("*.log"))),
            "Text files": len(list(self.base_dir.rglob("*.txt"))),
            "Total directories": len([d for d in self.base_dir.rglob("*") if d.is_dir()]),
            "Total files": len([f for f in self.base_dir.rglob("*") if f.is_file()])
        }
        
        # Count payloads and attacks
        napad_dir = self.base_dir / "Napad"
        if napad_dir.exists():
            stats["Attack files"] = len(list(napad_dir.glob("attack_*.py")))
            stats["Fuzz files"] = len(list(napad_dir.glob("*_fuzz.py")))
        
        # Count recon data
        recon_dir = self.base_dir / "ShadowRecon"
        if recon_dir.exists():
            stats["Recon backups"] = len(list(recon_dir.glob("shadow_recon_backup*.json")))
        
        for key, value in stats.items():
            print(f"│ {key:<25} │ {value:>10} │")
        
        print("├─────────────────────────────────────────────┤")
        
        # Directory sizes
        for dir_name in ["Napad", "ShadowRecon", "Centar", "PoC", "log"]:
            dir_path = self.base_dir / dir_name
            if dir_path.exists():
                size = sum(f.stat().st_size for f in dir_path.rglob("*") if f.is_file())
                size_mb = size / (1024 * 1024)

                print(f"│ {dir_name:<18} │ {size_mb:>8.2f} MB │")
        
        print("└─────────────────────────────────────────────┘")
        input("\n📎 Press Enter to continue...")
    
    def run(self):
        """Main CLI loop"""
        try:
            while True:
                os.system('clear' if os.name == 'posix' else 'cls')
                self.print_header()
                self.print_menu()
                
                choice = input("\n🎯 Enter your choice: ").strip()
                
                if choice == "0":
                    print("\n👋 Goodbye! ShadowFox CLI shutting down...")
                    time.sleep(1)
                    break
                elif choice == "1":
                    self.recon_scan()
                elif choice == "2":
                    self.ai_recon_filter()
                elif choice == "3":
                    self.fuzz_attack_menu()
                elif choice == "4":
                    self.mutator_core()
                elif choice == "5":
                    self.replay_engine()
                elif choice == "6":
                    self.ssrf_detection_proxy()
                elif choice == "7":
                    self.ai_evaluator()
                elif choice == "8":
                    self.advanced_agentx_attack()
                elif choice == "9":
                    self.view_reports()
                elif choice == "10":
                    self.github_sync()
                elif choice == "11":
                    self.system_analysis()
                else:
                    print("\n❌ Invalid choice! Please select a valid option.")
                    time.sleep(2)
                    
        except KeyboardInterrupt:
            print("\n\n🛑 CLI interrupted by user. Shutting down...")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Unexpected error: {str(e)}")
            print("🔄 Restarting CLI...")
            time.sleep(3)
            self.run()

def main():
    """Main entry point"""
    cli = ShadowFoxCLI()
    cli.run()

if __name__ == "__main__":
    main()
