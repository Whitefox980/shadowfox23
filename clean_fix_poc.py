import json

input_path = "PoC/shadowfox_prototype_pollution_poc_20250608_154711.json"
output_path = "PoC/shadowfox_cleaned_poc.json"

with open(input_path, "r") as f:
    raw = json.load(f)

valid = []
for idx, line in enumerate(raw):
    if isinstance(line, str) and line.strip():
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and obj.get("vulnerable") is True:
                valid.append(obj)
        except json.JSONDecodeError as e:
            print(f"[!] Invalid JSON at index {idx}: {e}")

with open(output_path, "w") as f:
    json.dump(valid, f, indent=2)

print(f"[✅] Spašeno {len(valid)} PoC zapisa u: {output_path}")
