#!/usr/bin/env python3
"""
🦊 SHADOWFOX RECON MODULE
Izviđačka elita - spider, param picker, API catcher
Autor: Whitefox980 | Verzija: 2025.06.06
"""

import requests
import json
import re
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs
from bs4 import BeautifulSoup
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class ShadowRecon:
    def __init__(self):
        self.session = requests.Session()
        self.target_url = "UNKNOWN"
        self.visited_urls = set()


        self.results = {
            "mission_info": {},
            "discovered_endpoints": [],
            "discovered_parameters": {},
            "discovered_headers": [],
            "api_endpoints": [],
            "forms_found": [],
            "js_files": [],
            "potential_vulnerabilities": [],
            "statistics": {}
        }
        try:
            with open("targets.txt", "r") as f:
                targets = [line.strip() for line in f if line.strip()]
                if targets:
                    self.target_url = targets[0]
        except Exception as e:
            print(f"[ERROR] Problem sa učitavanjem mete: {e}")

    def load_meta_config(self):
        """Učitava Meta konfiguraciju misije"""
        try:
            with open('Meta/mission_info.json', 'r') as f:
                self.meta_config = json.load(f)
                self.results["mission_info"] = self.meta_config
                print(f"🧠 [META] Misija: {self.meta_config.get('mission_id', 'UNKNOWN')}")
                print(f"🎯 [META] Meta: {self.meta_config.get('target_root', 'UNKNOWN')}")
        except FileNotFoundError:
            print("❌ [ERROR] Meta/mission_info.json nije pronađen!")
            print("🔧 [FIX] Kreaj Meta/mission_info.json pre pokretanja")
            exit(1)
            
    def setup_session(self):
        """Konfiguracija sesije na osnovu Meta config"""
        headers = self.meta_config.get('default_headers', {})
        self.session.headers.update(headers)
        
        # Stealth mode konfiguracija
        if self.meta_config.get('stealth_mode', False):
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]
            self.session.headers['User-Agent'] = random.choice(user_agents)
            
        self.session.verify = False
        self.session.timeout = 10
        
    def intelligent_delay(self):
        """Pametno kašnjenje na osnovu Meta config"""
        if self.meta_config.get('stealth_mode', False):
            delay = self.meta_config.get('rate_delay_seconds', 2.5)
            time.sleep(delay + random.uniform(0, 1))
        
    def spider_crawl(self, target_url, max_depth=2, current_depth=0):
        """Spider - puzanje kroz sajt i sakupljanje linkova"""
        if current_depth >= max_depth or target_url in self.visited_urls:
            return
            
        self.visited_urls.add(target_url)
        print(f"🕷️  [SPIDER] Depth {current_depth}: {target_url}")
        
        try:
            self.intelligent_delay()
            response = self.session.get(target_url)
            
            # Dodaj endpoint u rezultate
            endpoint_info = {
                "url": target_url,
                "status_code": response.status_code,
                "content_type": response.headers.get('Content-Type', ''),
                "content_length": len(response.content),
                "response_headers": dict(response.headers)
            }
            self.results["discovered_endpoints"].append(endpoint_info)
            
            # Analiza HTML sadržaja
            if 'text/html' in response.headers.get('Content-Type', ''):
                self.analyze_html(target_url, response.text)
                
            # Pokupljaj nove linkove
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all(['a', 'form'], href=True):
                href = link.get('href')
                if href:
                    full_url = urljoin(target_url, href)
                    if self.is_in_scope(full_url):
                        self.spider_crawl(full_url, max_depth, current_depth + 1)
                        
        except Exception as e:
            print(f"❌ [SPIDER ERROR] {target_url}: {str(e)}")
            
    def analyze_html(self, url, html_content):
        """Analiza HTML sadržaja za parametre, forme, JS fajlove"""
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Pokupljaj sve forme
        forms = soup.find_all('form')
        for form in forms:
            form_info = {
                "url": url,
                "method": form.get('method', 'GET').upper(),
                "action": urljoin(url, form.get('action', '')),
                "inputs": []
            }
            
            # Pokupljaj input polja
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    "name": input_tag.get('name'),
                    "type": input_tag.get('type', 'text'),
                    "value": input_tag.get('value', '')
                }
                form_info["inputs"].append(input_info)
                
                # Dodaj parametar u globalnu listu
                param_name = input_tag.get('name')
                if param_name:
                    if param_name not in self.results["discovered_parameters"]:
                        self.results["discovered_parameters"][param_name] = []
                    self.results["discovered_parameters"][param_name].append({
                        "source": "form",
                        "url": url,
                        "type": input_tag.get('type', 'text')
                    })
                    
            self.results["forms_found"].append(form_info)
            
        # Pokupljaj JavaScript fajlove
        js_scripts = soup.find_all('script', src=True)
        for script in js_scripts:
            js_url = urljoin(url, script.get('src'))
            if js_url not in [js['url'] for js in self.results["js_files"]]:
                self.results["js_files"].append({
                    "url": js_url,
                    "source_page": url
                })
                
        # Analiza inline JavaScript za API pozive
        inline_scripts = soup.find_all('script', src=False)
        for script in inline_scripts:
            if script.string:
                self.analyze_javascript(script.string, url)
    def extract_forms(self, url):
        """Skenira form elemente i upisuje ih u results"""
        print(f"📝 [FORMS] Analiziram forme na: {url}")
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")

            for form in forms:
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "get").lower(),
                    "inputs": []
                }

                for field in form.find_all(["input", "textarea", "select"]):
                    form_data["inputs"].append({
                        "name": field.get("name"),
                        "type": field.get("type", field.name),
                        "value": field.get("value", "")
                    })

                self.results["forms_found"].append({
                    "url": url,
                    "form": form_data
                })

            print(f"✅ [FORMS] Pronađeno: {len(forms)}")

        except Exception as e:
            print(f"❌ [FORMS ERROR] {url}: {e}") 

    def analyze_javascript(self, js_content, source_url):
        """Analiza JavaScript koda za API endpoint-e i parametre"""
        # Regex pattern-i za API pozive
        api_patterns = [
            r'fetch\([\'"]([^\'"]+)[\'"]',
            r'\.get\([\'"]([^\'"]+)[\'"]',
            r'\.post\([\'"]([^\'"]+)[\'"]',
            r'ajax\(\s*[\'"]([^\'"]+)[\'"]',
            r'XMLHttpRequest.*open\([\'"][^\'"]?[\'"],\s*[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('http', '/')):
                    full_url = urljoin(source_url, match)
                    if self.is_in_scope(full_url):
                        api_info = {
                            "url": full_url,
                            "source": "javascript",
                            "source_page": source_url,
                            "method": "UNKNOWN"
                        }
                        if api_info not in self.results["api_endpoints"]:
                            self.results["api_endpoints"].append(api_info)
                            
        # Pokupljaj parametre iz JavaScript-a
        param_patterns = [
            r'[\'"](\w+)[\'"]:\s*[\'"]?[^,}]+',
            r'data\.\w+',
            r'params\.\w+',
            r'query\.\w+'
        ]
        
        for pattern in param_patterns:
            matches = re.findall(pattern, js_content)
            for match in matches:
                param_name = match.replace('"', '').replace("'", "").split('.')[0]
                if len(param_name) > 2 and param_name.isalnum():
                    if param_name not in self.results["discovered_parameters"]:
                        self.results["discovered_parameters"][param_name] = []
                    self.results["discovered_parameters"][param_name].append({
                        "source": "javascript",
                        "url": source_url,
                        "type": "unknown"
                    })
    def discover_js_files(self, url):
        """Pronalazi sve JS fajlove sa stranice"""
        print(f"📄 [JS] Tražim <script> fajlove na: {url}")
        try:
            response = self.session.get(url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, "html.parser")
            scripts = soup.find_all("script")

            for script in scripts:
                script_src = script.get("src")
                if script_src:
                    full_url = urljoin(url, script_src)
                    if full_url not in self.results["js_files"]:
                        self.results["js_files"].append(full_url)
                else:
                # inline JS možeš sačuvati kasnije
                    inline_code = script.string
                    if inline_code and len(inline_code) > 20:
                        self.results["js_files"].append({"inline": inline_code[:100] + "..."})

            print(f"✅ [JS] Nađeno fajlova: {len(scripts)}")

        except Exception as e:
            print(f"❌ [JS ERROR] {url}: {e}")
    def discover_params_from_js(self):
        """Analizira JS fajlove i traži parametre koji liče na query, token, auth, data..."""
        print(f"🔍 [PARAM] Parsiram parametre iz JS fajlova...")
        param_patterns = [
            r"[\"']([a-zA-Z0-9_\-]{3,20})[\"']\s*:\s*[\"'][^\"']+[\"']",
            r"[\"'](token|auth|session|apiKey|userId|query)[\"']"
        ]

        for entry in self.results["js_files"]:
            js_url = entry if isinstance(entry, str) else entry.get("inline")
            if not js_url:
                continue

            try:
                if isinstance(entry, str) and js_url.startswith("http"):
                    response = self.session.get(js_url, timeout=10, verify=False)
                    js_content = response.text
                else:
                    js_content = js_url  # inline string već je tu

                for pattern in param_patterns:
                    matches = re.findall(pattern, js_content)
                    for param in matches:
                        if param not in self.results["discovered_parameters"]:
                            self.results["discovered_parameters"][param] = []
                        self.results["discovered_parameters"][param].append({
                            "source": "javascript",
                            "sample": "detected in js"
                        })

            except Exception as e:
                print(f"⚠️ [PARAM ERROR] {js_url}: {e}")

    def analyze_url_parameters(self, target_url):
        """Analiza URL parametara iz prosleđenog target_url"""
        from urllib.parse import urlparse, parse_qs

        parsed = urlparse(target_url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name, values in params.items():
                if param_name not in self.results["discovered_parameters"]:
                    self.results["discovered_parameters"][param_name] = []
                self.results["discovered_parameters"][param_name].append({
                    "source": "url",
                    "url": target_url,
                    "type": "query",
                    "sample_values": values
                })
            
    def security_header_check(self, url):
        """Provera sigurnosnih header-a"""
        try:
            self.intelligent_delay()
            response = self.session.get(url)
            
            security_headers = [
                'Content-Security-Policy',
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Referrer-Policy'
            ]
            
            missing_headers = []
            present_headers = []
            
            for header in security_headers:
                if header in response.headers:
                    present_headers.append({
                        "header": header,
                        "value": response.headers[header]
                    })
                else:
                    missing_headers.append(header)
                    
            self.results["discovered_headers"].append({
                "url": url,
                "missing_security_headers": missing_headers,
                "present_security_headers": present_headers,
                "all_headers": dict(response.headers)
            })
            
            # Sigurnosne ranjivosti na osnovu header-a
            if missing_headers:
                vulnerability = {
                    "type": "Missing Security Headers",
                    "severity": "INFO",
                    "url": url,
                    "details": f"Missing: {', '.join(missing_headers)}"
                }
                self.results["potential_vulnerabilities"].append(vulnerability)
                
        except Exception as e:
            print(f"❌ [HEADER ERROR] {url}: {str(e)}")
            
    def is_in_scope(self, url):
        """Provera da li je URL u opsegu misije"""
        scope = self.meta_config.get('scope', [])
        if not scope:
            return True
            
        for scope_url in scope:
            if url.startswith(scope_url):
                return True
        return False
        
    def filter_interesting_parameters(self):
        """Filtriranje parametara na osnovu Meta config keywords"""
        priority_keywords = self.meta_config.get('priority_keywords', [])
        avoid_keywords = self.meta_config.get('avoid_keywords', [])
        
        filtered_params = {}
        
        for param_name, param_data in self.results["discovered_parameters"].items():
            # Preskače ako sadrži avoid keywords
            if any(avoid in param_name.lower() for avoid in avoid_keywords):
                continue
                
            # Prioritet ako sadrži priority keywords
            priority_score = sum(1 for keyword in priority_keywords 
                               if keyword in param_name.lower())
            
            filtered_params[param_name] = {
                "data": param_data,
                "priority_score": priority_score,
                "interesting": priority_score > 0 or len(param_name) > 3
            }
            
        self.results["discovered_parameters"] = filtered_params
        
    def generate_statistics(self):
        """Generisanje statistike recon operacije"""
        stats = {
            "total_endpoints": len(self.results["discovered_endpoints"]),
            "total_parameters": len(self.results["discovered_parameters"]),
            "total_forms": len(self.results["forms_found"]),
            "total_js_files": len(self.results["js_files"]),
            "total_api_endpoints": len(self.results["api_endpoints"]),
            "potential_vulnerabilities": len(self.results["potential_vulnerabilities"]),
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "urls_visited": len(self.visited_urls)
        }
        
        # Top parametri po prioritetu
        if self.results["discovered_parameters"]:
            sorted_params = sorted(
                self.results["discovered_parameters"].items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            stats["top_priority_parameters"] = [param[0] for param in sorted_params[:10]]
            
        self.results["statistics"] = stats
        
    def save_results(self):
        """Snimanje rezultata u shadow_recon.json"""
        output_file = "ShadowRecon/shadow_recon.json"
        
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Rezultati snimljeni: {output_file}")
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            
    def run_recon(self):
        """Glavna recon operacija"""
        print("🦊 SHADOWFOX RECON - POKRETANJE IZVIĐANJA")
        print("=" * 50)
        
        # 1. Učitaj Meta config
        self.load_meta_config()
        
        # 2. Podesi sesiju
        self.setup_session()
        
        # 3. Analiza URL parametara iz targets.txt
        print("📄 [RECON] Analiza targets.txt...")

        self.analyze_url_parameters(self.meta_config.get("target_root"))
        # 4. Spider crawl
        self.spider_crawl(self.target_url, max_depth=2)
        self.extract_forms(self.target_url)


        self.discover_js_files(self.target_url)
        self.discover_params_from_js()
        self.generate_statistics()
        target_root = self.meta_config.get('target_root')
        if target_root:
            print(f"🕷️  [RECON] Spider crawl: {target_root}")
            self.spider_crawl(target_root, max_depth=3)
            
        # 5. Security header check
        print("🔒 [RECON] Provera sigurnosnih header-a...")
        if target_root:
            self.security_header_check(target_root)
            
        # 6. Filtriranje interesantnih parametara
        print("🎯 [RECON] Filtriranje parametara...")
        self.filter_interesting_parameters()
        
        # 7. Generisanje statistike
        print("📊 [RECON] Generisanje statistike...")
        self.generate_statistics()
        
        # 8. Snimanje rezultata
        self.save_results()
        
        # 9. Prikaz rezultata
        self.display_summary()
        
    def display_summary(self):
        """Prikaz sažetka recon operacije"""
        stats = self.results["statistics"]
        print("\n🎯 SHADOWFOX RECON - SAŽETAK")
        print("=" * 50)
        print(f"📍 Endpoints: {stats['total_endpoints']}")
        print(f"🔍 Parametri: {stats['total_parameters']}")
        print(f"📝 Forme: {stats['total_forms']}")
        print(f"📄 JS fajlovi: {stats['total_js_files']}")
        print(f"🔌 API endpoints: {stats['total_api_endpoints']}")
        print(f"⚠️  Potencijalne ranjivosti: {stats['potential_vulnerabilities']}")
        
        if "top_priority_parameters" in stats:
            print(f"\n🏆 TOP PARAMETRI:")
            for param in stats["top_priority_parameters"][:5]:
                print(f"   • {param}")
                
        print(f"\n✅ Rezultati: ShadowRecon/shadow_recon.json")

def main():
    recon = ShadowRecon()
    recon.run_recon()

if __name__ == "__main__":
    main()
