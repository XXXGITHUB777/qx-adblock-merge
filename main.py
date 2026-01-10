import requests
import pytz
import re
import os
from datetime import datetime

OUTPUT_FILENAME = "block.list"

REMOTE_URLS = [
    "https://ghproxy.net/https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
    "https://ghproxy.net/https://raw.githubusercontent.com/limbopro/Adblock4limbo/main/Adblock4limbo.list",
    "https://ghproxy.net/https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/filter/filter.list",
    "https://ghproxy.net/https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/QuanX/Adblock/All/filter/allAdBlock.list",
    "https://ghproxy.net/https://raw.githubusercontent.com/VirgilClyne/GetSomeFries/main/ruleset/HTTPDNS.Block.list",
    "https://ghproxy.net/https://raw.githubusercontent.com/async-smith8845bn/QuantumultX_config/main/ClashRuleSet/List/ip/banhttpdns.conf",
    "https://ghproxy.net/https://raw.githubusercontent.com/enriquephl/QuantumultX_config/main/filters/NoMalwares.conf",
    "https://ghproxy.net/https://raw.githubusercontent.com/SukkaLab/ruleset.skk.moe/master/List/non_ip/reject-no-drop.conf"
]

def clean_line(line):
    line = re.split(r'(#|;|//)', line)[0]
    line = line.strip().strip("'").strip('"')
    return line

def fetch_and_merge_rules():
    unique_rules = {} 
    source_stats = {} 
    
    headers = {
        'User-Agent': 'Quantumult%20X/1.0.30 (iPhone; iOS 16.0; Scale/3.00)',
    }
    
    print(f"--- Processing {len(REMOTE_URLS)} Sources ---")

    for url in REMOTE_URLS:
        if "AWAvenue" in url: name = "秋风"
        elif "limbopro" in url: name = "毒奶"
        elif "fmz200" in url: name = "FMZ200"
        elif "zirawell" in url: name = "Zirawell"
        elif "VirgilClyne" in url: name = "HTTPDNS(Virgil)"
        elif "async-smith" in url: name = "HTTPDNS(IP)"
        elif "NoMalwares" in url: name = "Malware"
        elif "SukkaLab" in url: name = "Sukka"
        else: name = "Unknown"
            
        print(f"Fetching: {name} ...", end="")
        
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.encoding = 'utf-8'
            
            if resp.status_code != 200:
                print(f" [Failed] HTTP {resp.status_code}")
                source_stats[name] = 0
                continue

            lines = resp.text.splitlines()
            current_count = 0
            
            for line in lines:
                line = clean_line(line)
                if not line or line.startswith(('[', '<', '!', 'no-alert', 'payload:')):
                    continue

                if ',' in line:
                    parts = [p.strip() for p in line.split(',')]
                else:
                    parts = line.split()

                if len(parts) < 2: continue

                rule_type = parts[0].upper()
                if rule_type == "-" and len(parts) > 2:
                    rule_type = parts[1].upper()
                    target = parts[2]
                    parts = parts[1:]
                else:
                    target = parts[1]
                
                if rule_type == "DOMAIN": rule_type = "HOST"
                if rule_type == "DOMAIN-SUFFIX": rule_type = "HOST-SUFFIX"
                if rule_type == "DOMAIN-KEYWORD": rule_type = "HOST-KEYWORD"
                
                policy = "reject"
                if len(parts) >= 3:
                    potential_policy = parts[2].lower()
                    if potential_policy not in ['no-resolve']: 
                         policy = potential_policy
                
                if "reject" in policy: policy = "reject"
                
                if rule_type not in ["HOST", "HOST-SUFFIX", "HOST-KEYWORD", "IP-CIDR", "IP-CIDR6", "USER-AGENT"]:
                    continue

                unique_key = f"{rule_type},{target}".lower()
                
                if unique_key not in unique_rules:
                    final_rule = f"{rule_type},{target},{policy}"
                    unique_rules[unique_key] = final_rule
                    current_count += 1
            
            source_stats[name] = current_count
            print(f" [OK: {current_count}]")
            
        except Exception as e:
            print(f" [Error] {e}")
            source_stats[name] = 0

    return list(unique_rules.values()), source_stats

def sort_priority(line):
    if line.startswith("HOST,"): return 1
    if line.startswith("HOST-SUFFIX,"): return 2
    if line.startswith("IP-CIDR"): return 3
    return 10

def get_old_rule_count(filepath):
    if not os.path.exists(filepath):
        return 0, False
    
    count = 0
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith(('#', ';', '//')):
                    count += 1
        return count, True
    except Exception:
        return 0, False

def main():
    rules, stats = fetch_and_merge_rules()
    
    if len(rules) == 0:
        exit(1)

    sorted_rules = sorted(rules, key=sort_priority)
    current_count = len(sorted_rules)

    old_count, file_exists = get_old_rule_count(OUTPUT_FILENAME)
    
    diff_val = current_count - old_count
    diff_msg = ""
    
    if not file_exists:
        diff_msg = "(Init)"
        console_msg = "New File"
    else:
        if diff_val > 0:
            diff_msg = f"(+{diff_val})"
            console_msg = f"Increased {diff_val}"
        elif diff_val < 0:
            diff_msg = f"({diff_val})"
            console_msg = f"Decreased {abs(diff_val)}"
        else:
            diff_msg = "(0)"
            console_msg = "No Change"

    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock All-in-One",
        f"# Updated: {now}",
        f"# Total: {current_count} {diff_msg}",
        f"#"
    ]
    for n, c in stats.items():
        header.append(f"# {n}: {c}")
    header.append("")
    
    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        
    print(f"Done. Saved to {OUTPUT_FILENAME}")
    print(f"Total: {current_count} | {console_msg}")

if __name__ == "__main__":
    main()
