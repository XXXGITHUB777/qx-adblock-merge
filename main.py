import requests
import pytz
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# === 配置区域 ===
OUTPUT_FILENAME = "block.list"
MAX_WORKERS = 8
TIMEOUT = 30

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

# === 修正的核心：全类型映射 ===
# 左边是源文件可能出现的写法，右边是 QX 的标准写法
TYPE_MAP = {
    # 1. 兼容 Surge / Clash / Loon 格式
    "DOMAIN": "host",
    "DOMAIN-SUFFIX": "host-suffix",
    "DOMAIN-KEYWORD": "host-keyword",
    "IP-CIDR": "ip-cidr",
    "IP-CIDR6": "ip6-cidr",
    "USER-AGENT": "user-agent",
    
    # 2. 保留 QX 原生格式 (上次漏了这些，导致原生规则被删)
    "HOST": "host",
    "HOST-SUFFIX": "host-suffix",
    "HOST-KEYWORD": "host-keyword",
    "HOST-WILDCARD": "host-wildcard",
    "IP6-CIDR": "ip6-cidr",
    "GEOIP": "geoip",
    "IP-ASN": "ip-asn"
}

def get_source_name(url):
    if "AWAvenue" in url: return "秋风"
    if "limbopro" in url: return "毒奶"
    if "fmz200" in url: return "FMZ200"
    if "zirawell" in url: return "Zirawell"
    if "VirgilClyne" in url: return "HTTPDNS(Virgil)"
    if "async-smith" in url: return "HTTPDNS(IP)"
    if "NoMalwares" in url: return "Malware"
    if "Sukka" in url: return "Sukka"
    return "Unknown"

def fetch_single_url(url):
    name = get_source_name(url)
    rules_found = []
    
    headers = {
        'User-Agent': 'Quantumult%20X/1.5.0 (iPhone; iOS 17.0; Scale/3.00)',
    }
    
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        if resp.status_code != 200:
            print(f"❌ [{name}] HTTP {resp.status_code}")
            return name, []
        
        resp.encoding = 'utf-8'
        lines = resp.text.splitlines()
        
        for line in lines:
            line = re.split(r'(#|;|//)', line)[0].strip()
            if not line: continue
            if line.startswith(('[', '<', '!', 'no-alert', 'payload:')): continue

            # 兼容逗号或空格分隔
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
            else:
                parts = line.split()

            if len(parts) < 2: continue

            raw_type = parts[0].upper()
            
            # 处理 "payload: - DOMAIN-SUFFIX,xxx"
            if raw_type == "-" and len(parts) > 2:
                raw_type = parts[1].upper()
                target = parts[2]
            else:
                target = parts[1]

            qx_type = TYPE_MAP.get(raw_type)
            
            # 如果类型不在白名单，跳过
            if not qx_type:
                continue
            
            target = target.strip("'").strip('"')

            # 强制策略 reject
            # IP 类规则强制加 no-resolve
            if qx_type in ["ip-cidr", "ip6-cidr"]:
                rule = f"{qx_type}, {target}, reject, no-resolve"
            else:
                rule = f"{qx_type}, {target}, reject"
            
            rules_found.append(rule)
            
        print(f"✅ [{name}] Parsed {len(rules_found)}")
        return name, rules_found

    except Exception as e:
        print(f"❌ [{name}] Error: {e}")
        return name, []

def rule_sort_key(rule):
    # 按照 QX 建议的匹配开销顺序排序
    parts = rule.split(',')
    rtype = parts[0].strip()
    
    priority = 100
    if rtype == "host-suffix": priority = 1
    elif rtype == "host-keyword": priority = 2
    elif rtype == "host": priority = 3
    elif rtype == "host-wildcard": priority = 4
    elif rtype == "user-agent": priority = 5
    elif rtype.startswith("ip"): priority = 6
    elif rtype == "geoip": priority = 7
    
    return priority

def main():
    print(f"--- Starting Download ({MAX_WORKERS} threads) ---")
    
    all_rules_set = set()
    source_stats = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_single_url, url): url for url in REMOTE_URLS}
        for future in as_completed(futures):
            name, rules = future.result()
            source_stats[name] = len(rules)
            all_rules_set.update(rules)

    if not all_rules_set:
        print("No rules found. Exiting.")
        exit(1)

    # 排序
    sorted_rules = sorted(list(all_rules_set), key=rule_sort_key)
    current_count = len(sorted_rules)

    # 计算增量
    old_count = 0
    diff_msg = "(Init)"
    if os.path.exists(OUTPUT_FILENAME):
        try:
            with open(OUTPUT_FILENAME, 'r', encoding='utf-8') as f:
                old_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            diff = current_count - old_count
            if diff > 0: diff_msg = f"(+{diff})"
            elif diff < 0: diff_msg = f"({diff})"
            else: diff_msg = "(0)"
        except: pass

    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock All-in-One",
        f"# Updated: {now}",
        f"# Total: {current_count} {diff_msg}",
        f"#"
    ]
    for n, c in sorted(source_stats.items(), key=lambda x: x[1], reverse=True):
        header.append(f"# {n}: {c}")
    header.append("")

    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        f.write("\n")

    print(f"\nCompleted. Saved to {OUTPUT_FILENAME}")
    print(f"Total Rules: {current_count} | Diff: {diff_msg}")

if __name__ == "__main__":
    main()
