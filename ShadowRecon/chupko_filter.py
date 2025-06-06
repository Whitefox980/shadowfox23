import json
import os

class ChupkoFilter:
    def __init__(self, input_path='ShadowRecon/shadow_recon.json', output_path='ShadowRecon/filtered_recon.json'):
        self.input_path = input_path
        self.output_path = output_path
        self.data = {}

    def load_recon(self):
        if not os.path.isfile(self.input_path):
            print(f"[❌] Čupko ne vidi fajl: {self.input_path}")
            return False
        with open(self.input_path, 'r') as f:
            self.data = json.load(f)
        return True

    def is_interesting(self, item):
        try:
            url = item.get("url", "") if isinstance(item, dict) else str(item)
            ignore_ext = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.svg', '.css', '.ico']
            if any(url.lower().endswith(ext) for ext in ignore_ext):
                return False
            if 'logout' in url or 'signout' in url:
                return False
            return True
        except Exception as e:
            print(f"[⚠️] Greška u proveri is_interesting: {str(e)}")
            return False
    def filter_data(self):
        filtered = {
            "forms": [],
            "js_files": [],
            "discovered_params": {}
        }

        # Filter forms
        filtered["forms"] = [form for form in self.data.get("forms", []) if self.is_interesting(form.get("action", ""))]

        # Filter JS files
        filtered["js_files"] = [js for js in self.data.get("js_files", []) if self.is_interesting(js)]

        # Filter params
        for param, meta in self.data.get("discovered_params", {}).items():
            url = meta.get("source", "")
            if self.is_interesting(url):
                filtered["discovered_params"][param] = meta

        with open(self.output_path, 'w') as f:
            json.dump(filtered, f, indent=2)

        print(f"[✅] Čupko filtrirao rezultate → {self.output_path}")

    def run(self):
        if self.load_recon():
            self.filter_data()

if __name__ == "__main__":
    f = ChupkoFilter()
    if f.load_recon():
        f.filter_data()
