#!/usr/bin/env python3
"""
🦊 SHADOWFOX FILTER MODULE
Čisti i filtrira shadow_recon.json rezultate - izbacuje smece, ostavlja zlato
Autor: Whitefox980 | Verzija: 2025.06.06 - FIXED
"""

import json
import re
import argparse
from urllib.parse import urlparse, parse_qs
import os

class ShadowFilter:
    def __init__(self):
        self.results = {}
        self.filtered_results = {}
        
        # Definisanje nebitnih ekstenzija
        self.junk_extensions = {
            # Slike
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico', '.webp', '.tiff',
            # CSS/JS assets
            '.css', '.js', '.map', '.min.js', '.min.css',
            # Fontovi
            '.woff', '.woff2', '.ttf', '.eot', '.otf',
            # Dokumenti (obično statični)
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            # Media
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mp3', '.wav', '.ogg',
            # Arhive (obično javno dostupne)
            '.zip', '.rar', '.tar', '.gz', '.7z'
        }
        
        # Nebitni URL pattern-i
        self.junk_patterns = [
            r'/static/',
            r'/assets/',
            r'/images/',
            r'/img/',
            r'/css/',
            r'/js/',
            r'/fonts/',
            r'/media/',
            r'/uploads/',
            r'/cdn-cgi/',
            r'/wp-content/',
            r'/wp-includes/',
            r'/_next/static/',
            r'/node_modules/',
            r'\.well-known/',
            r'/favicon',
            r'/robots\.txt',
            r'/sitemap',
            r'/manifest\.json'
        ]
        
        # Nebitni parametri
        self.junk_parameters = {
            # Tracking i analytics
            'ga', 'utm_source', 'utm_medium', 'utm_campaign', 'utm_content', 'utm_term',
            'gclid', 'fbclid', '_ga', '_gid', 'ref', 'referrer',
            # Cache i verzije
            'v', 'ver', 'version', 'cache', 'timestamp', 't', '_t',
            # UI elementi
            'tab', 'view', 'display', 'show', 'hide', 'expand', 'collapse',
            # Paginacija (obična)
            'page', 'offset', 'limit', 'per_page', 'pagesize',
            # Sortiranje (obično)
            'sort', 'order', 'orderby', 'dir', 'direction'
        }
        
        # Visoko prioritetni parametri (UVEK zadržati)
        self.priority_parameters = {
            # Auth i sesije
            'token', 'jwt', 'auth', 'session', 'sid', 'sessionid', 'auth_token',
            'access_token', 'refresh_token', 'api_key', 'apikey', 'key',
            # User data
            'user', 'userid', 'user_id', 'username', 'email', 'password', 'pass',
            'id', 'uid', 'account', 'profile',
            # Kritični funkcije
            'admin', 'role', 'permission', 'priv', 'privilege', 'level',
            'reset', 'confirm', 'verify', 'activate', 'callback', 'redirect',
            # Potencijalni exploit parametri
            'url', 'path', 'file', 'dir', 'cmd', 'exec', 'eval', 'include',
            'template', 'view', 'page', 'module', 'action', 'method'
        }
        
    def load_recon_results(self, filepath="ShadowRecon/shadow_recon.json"):
        """Učitavanje shadow_recon.json rezultata"""
        try:
            with open(filepath, 'r') as f:
                self.results = json.load(f)
            print(f"📂 [LOAD] Učitano: {filepath}")
            return True
        except FileNotFoundError:
            print(f"❌ [ERROR] Fajl nije pronađen: {filepath}")
            return False
        except json.JSONDecodeError:
            print(f"❌ [ERROR] Neispravan JSON format: {filepath}")
            return False
            
    def is_junk_url(self, url):
        """Provera da li je URL nebitaν (slika, CSS, itd.)"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Proveri ekstenziju
        for ext in self.junk_extensions:
            if path.endswith(ext):
                return True
                
        # Proveri pattern-e
        for pattern in self.junk_patterns:
            if re.search(pattern, path, re.IGNORECASE):
                return True
                
        return False
        
    def score_endpoint(self, endpoint):
        """Ocenjivanje endpoint-a na osnovu relevantnosti"""
        score = 0
        url = endpoint.get('url', '')
        status_code = endpoint.get('status_code', 0)
        content_type = endpoint.get('content_type', '')
        
        # Negativni poeni za junk
        if self.is_junk_url(url):
            return -100
            
        # Pozitivni poeni za relevantne status kodove
        if status_code == 200:
            score += 10
        elif status_code in [301, 302, 307, 308]:
            score += 5
        elif status_code == 403:
            score += 15  # Potencijalno interesantan - zabranjen pristup
        elif status_code == 401:
            score += 20  # Auth required - vrlo interesantan
        elif status_code == 500:
            score += 8   # Server error - može biti koristan
            
        # Pozitivni poeni za API endpoint-e
        if '/api/' in url.lower():
            score += 25
        if '/v1/' in url.lower() or '/v2/' in url.lower():
            score += 15
            
        # Pozitivni poeni za dinamičke endpoint-e
        if '?' in url:  # Ima parametre
            score += 10
        if '/admin' in url.lower():
            score += 30
        if '/login' in url.lower() or '/auth' in url.lower():
            score += 25
            
        # Pozitivni poeni za JSON/XML odgovore
        if 'json' in content_type.lower():
            score += 15
        elif 'xml' in content_type.lower():
            score += 10
            
        return score
        
    def score_parameter(self, param_name, param_data):
        """Ocenjivanje parametra na osnovu relevantnosti"""
        score = 0
        param_lower = param_name.lower()
        
        # Visoki prioritet parametri
        for priority_param in self.priority_parameters:
            if priority_param in param_lower:
                score += 50
                break
                
        # Negativni poeni za junk parametre
        if param_lower in [jp.lower() for jp in self.junk_parameters]:
            return -50
            
        # Pozitivni poeni na osnovu dužine i složenosti
        if len(param_name) >= 3:
            score += 5
        if len(param_name) >= 6:
            score += 5
            
        # Pozitivni poeni za parametre sa više izvora
        if isinstance(param_data, dict) and 'data' in param_data:
            sources = len(param_data['data'])
            score += sources * 3
            
        # Pozitivni poeni za priority_score iz recon-a
        if isinstance(param_data, dict) and 'priority_score' in param_data:
            score += param_data['priority_score'] * 10
            
        return score
        
    def filter_endpoints(self, max_count=100):
        """Filtriranje i ocenjivanje endpoint-a"""
        endpoints = self.results.get('discovered_endpoints', [])
        
        print(f"🔍 [FILTER] Filtriranje {len(endpoints)} endpoint-a...")
        
        # Oceni sve endpoint-e
        scored_endpoints = []
        for endpoint in endpoints:
            score = self.score_endpoint(endpoint)
            if score > -50:  # Zadrži samo relevantne
                scored_endpoints.append({
                    'score': score,
                    'data': endpoint
                })
                
        # Sortiraj po oceni i uzmi top N
        scored_endpoints.sort(key=lambda x: x['score'], reverse=True)
        filtered_endpoints = [ep['data'] for ep in scored_endpoints[:max_count]]
        
        print(f"✅ [FILTER] Zadržano {len(filtered_endpoints)}/{len(endpoints)} endpoint-a")
        return filtered_endpoints
        
    def filter_parameters(self, max_count=50):
        """Filtriranje i ocenjivanje parametara sa deduplication"""
        parameters = self.results.get('discovered_parameters', {})
        
        print(f"🔍 [FILTER] Filtriranje {len(parameters)} parametara...")
        
        # Debug: prikaz prvih nekoliko parametara
        param_names = list(parameters.keys())[:5]
        print(f"🔍 [DEBUG] Primeri parametara: {param_names}")
        
        # Deduplikacija - grupiši parametre po URL-ovima
        deduplicated_params = {}
        for param_name, param_data in parameters.items():
            # Uzmi samo jedinstvene URL-ove za svaki parametar
            if isinstance(param_data, dict) and 'data' in param_data:
                unique_urls = []
                seen_urls = set()
                for entry in param_data['data']:
                    url = entry.get('url', '')
                    if url not in seen_urls:
                        unique_urls.append(entry)
                        seen_urls.add(url)
                
                # Sačuvaj samo ako ima manje od 100 duplikata
                if len(param_data['data']) > 100 and len(unique_urls) < 5:
                    print(f"🗑️  [DEDUP] Preskačem '{param_name}' - {len(param_data['data'])} duplikata")
                    continue
                    
                # Ažuriraj param_data sa unique URL-ovima
                new_param_data = param_data.copy()
                new_param_data['data'] = unique_urls
                deduplicated_params[param_name] = new_param_data
            else:
                deduplicated_params[param_name] = param_data
        
        print(f"🔍 [DEDUP] Nakon deduplication-a: {len(deduplicated_params)} parametara")
        
        # Oceni parametre
        scored_parameters = []
        for param_name, param_data in deduplicated_params.items():
            score = self.score_parameter(param_name, param_data)
            
            # Debug za prvi parametar
            if len(scored_parameters) == 0:
                print(f"🔍 [DEBUG] Parametar '{param_name}' - score: {score}")
            
            # Strožiji filter - povećaj threshold
            if score > 0:  # Samo pozitivni score
                scored_parameters.append({
                    'score': score,
                    'name': param_name,
                    'data': param_data
                })
            
        print(f"🔍 [DEBUG] Nakon scoring-a: {len(scored_parameters)} parametara")
                
        # Sortiraj po oceni i uzmi top N
        scored_parameters.sort(key=lambda x: x['score'], reverse=True)
        filtered_parameters = {}
        for param in scored_parameters[:max_count]:
            filtered_parameters[param['name']] = param['data']
            
        print(f"✅ [FILTER] Zadržano {len(filtered_parameters)}/{len(parameters)} parametara")
        return filtered_parameters
        
    def filter_forms(self, max_count=20):
        """Filtriranje formi - zadrži samo relevantne"""
        forms = self.results.get('forms_found', [])
        
        print(f"🔍 [FILTER] Filtriranje {len(forms)} formi...")
        
        scored_forms = []
        for form in forms:
            score = 0
            action_url = form.get('action', '')
            inputs = form.get('inputs', [])
            
            # Pozitivni poeni za auth forme
            if any(keyword in action_url.lower() for keyword in ['login', 'auth', 'signin', 'register']):
                score += 30
                
            # Pozitivni poeni za forme sa password poljima
            if any(inp.get('type') == 'password' for inp in inputs):
                score += 25
                
            # Pozitivni poeni za forme sa file upload-om
            if any(inp.get('type') == 'file' for inp in inputs):
                score += 20
                
            # Pozitivni poeni za POST forme
            if form.get('method', '').upper() == 'POST':
                score += 10
                
            # Pozitivni poeni za broj input polja
            score += min(len(inputs) * 2, 15)
            
            if score > 5:  # Zadrži samo relevantne
                scored_forms.append({
                    'score': score,
                    'data': form
                })
                
        # Sortiraj po oceni i uzmi top N
        scored_forms.sort(key=lambda x: x['score'], reverse=True)
        filtered_forms = [form['data'] for form in scored_forms[:max_count]]
        
        print(f"✅ [FILTER] Zadržano {len(filtered_forms)}/{len(forms)} formi")
        return filtered_forms
        
    def filter_js_files(self, max_count=30):
        """Filtriranje JS fajlova - ukloni minified i biblioteke"""
        js_files = self.results.get("js_files", [])
        print(f"🔍 [FILTER] Filtriranje {len(js_files)} JS fajlova...")

        filtered_js = []
        for js_file in js_files:
            url = js_file['url'] if isinstance(js_file, dict) and 'url' in js_file else js_file
            
            # Skip ako nije string
            if not isinstance(url, str):
                continue

            # Preskači minified fajlove
            if '.min.js' in url:
                continue

            # Preskači poznate biblioteke
            libraries = ['jquery', 'bootstrap', 'angular', 'react', 'vue', 'lodash', 'moment']
            if any(lib in url.lower() for lib in libraries):
                continue

            # Preskači CDN linkove
            if any(cdn in url.lower() for cdn in ['cdnjs', 'googleapis', 'jsdelivr']):
                continue

            filtered_js.append(js_file)

        # Ograniči broj
        filtered_js = filtered_js[:max_count]

        print(f"✅ [FILTER] Zadržano {len(filtered_js)}/{len(js_files)} JS fajlova")
        return filtered_js
        
    def update_statistics(self, original_stats):
        """Ažuriranje statistike nakon filtriranja"""
        new_stats = original_stats.copy()
        new_stats.update({
            'filtered_endpoints': len(self.filtered_results.get('discovered_endpoints', [])),
            'filtered_parameters': len(self.filtered_results.get('discovered_parameters', {})),
            'filtered_forms': len(self.filtered_results.get('forms_found', [])),
            'filtered_js_files': len(self.filtered_results.get('js_files', [])),
            'filter_timestamp': __import__('time').strftime("%Y-%m-%d %H:%M:%S"),
            'filter_applied': True
        })
        return new_stats
        
    def run_filter(self, max_endpoints=100, max_parameters=50, max_forms=20, max_js=30):
        """Glavna filter operacija"""
        print("🦊 SHADOWFOX FILTER - ČIŠĆENJE REZULTATA")
        print("=" * 50)
        
        if not self.results:
            print("❌ [ERROR] Nema učitanih rezultata!")
            return False
            
        # Kopiraj osnovne podatke
        self.filtered_results = {
            'mission_info': self.results.get('mission_info', {}),
            'api_endpoints': self.results.get('api_endpoints', []),  # Zadrži sve API endpoint-e
            'potential_vulnerabilities': self.results.get('potential_vulnerabilities', []),
            'discovered_headers': self.results.get('discovered_headers', [])
        }
        
        # Filtriraj glavne kategorije
        self.filtered_results['discovered_endpoints'] = self.filter_endpoints(max_endpoints)
        self.filtered_results['discovered_parameters'] = self.filter_parameters(max_parameters)
        self.filtered_results['forms_found'] = self.filter_forms(max_forms)
        self.filtered_results['js_files'] = self.filter_js_files(max_js)
        
        # Ažuriraj statistiku
        original_stats = self.results.get('statistics', {})
        self.filtered_results['statistics'] = self.update_statistics(original_stats)
        
        return True
        
    def save_filtered_results(self, output_file="ShadowRecon/shadow_recon.json"):
        """Snimavanje filtriranih rezultata (prepisuje originalni fajl)"""
        try:
            # Backup originalnog fajla
            if os.path.exists(output_file):
                backup_file = output_file.replace('.json', '_backup.json')
                os.rename(output_file, backup_file)
                print(f"💾 [BACKUP] Backup kreiran: {backup_file}")
            
            # Snimi filtrirane rezultate
            with open(output_file, 'w') as f:
                json.dump(self.filtered_results, f, indent=2, ensure_ascii=False)
            print(f"💾 [SAVE] Filtrirani rezultati snimljeni: {output_file}")
            return True
        except Exception as e:
            print(f"❌ [SAVE ERROR] {str(e)}")
            return False
            
    def display_filter_summary(self):
        """Prikaz sažetka filtriranja"""
        original_stats = self.results.get('statistics', {})
        filtered_stats = self.filtered_results.get('statistics', {})
        
        print("\n🎯 SHADOWFOX FILTER - SAŽETAK")
        print("=" * 50)
        
        categories = [
            ('Endpoints', 'total_endpoints', 'filtered_endpoints'),
            ('Parametri', 'total_parameters', 'filtered_parameters'),
            ('Forme', 'total_forms', 'filtered_forms'),
            ('JS fajlovi', 'total_js_files', 'filtered_js_files')
        ]
        
        for name, orig_key, filt_key in categories:
            orig_count = original_stats.get(orig_key, 0)
            filt_count = filtered_stats.get(filt_key, 0)
            if orig_count > 0:
                percentage = (filt_count / orig_count) * 100
                print(f"📊 {name}: {orig_count} → {filt_count} ({percentage:.1f}%)")
                
        print(f"\n✅ Filtrirani rezultati: ShadowRecon/shadow_recon.json")
        print(f"💾 Backup: ShadowRecon/shadow_recon_backup.json")

def main():
    parser = argparse.ArgumentParser(description="ShadowFox Filter - Čisti recon rezultate")
    parser.add_argument("--endpoints", type=int, default=100, help="Max broj endpoint-a (default: 100)")
    parser.add_argument("--parameters", type=int, default=50, help="Max broj parametara (default: 50)")
    parser.add_argument("--forms", type=int, default=20, help="Max broj formi (default: 20)")
    parser.add_argument("--js", type=int, default=30, help="Max broj JS fajlova (default: 30)")
    parser.add_argument("--input", type=str, default="ShadowRecon/shadow_recon.json", help="Input fajl")
    
    args = parser.parse_args()
    
    filter_tool = ShadowFilter()
    
    # Učitaj rezultate
    if not filter_tool.load_recon_results(args.input):
        return
        
    # Pokreni filtriranje
    if filter_tool.run_filter(args.endpoints, args.parameters, args.forms, args.js):
        # Snimi rezultate
        filter_tool.save_filtered_results()
        # Prikaži sažetak
        filter_tool.display_filter_summary()
    else:
        print("❌ [ERROR] Filtriranje neuspešno!")

if __name__ == "__main__":
    main()
