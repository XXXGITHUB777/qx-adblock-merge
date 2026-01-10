import requests
import pytz
import re
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# === 配置区域 ===
OUTPUT_FILENAME = "block.list"
MAX_WORKERS = 8  # 下载线程数
TIMEOUT = 30     # 请求超时时间

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

# QX 支持的规则类型映射
TYPE_MAP = {
    "DOMAIN": "HOST",
    "DOMAIN-SUFFIX": "HOST-SUFFIX",
    "DOMAIN-KEYWORD": "HOST-KEYWORD",
    "IP-CIDR": "IP-CIDR",
    "IP-CIDR6": "IP-CIDR6",
    "USER-AGENT": "USER-AGENT"
}

def get_source_name(url):
    """根据URL简单的判断源名称，用于日志显示"""
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
    """下载并解析单个URL的内容"""
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
            # 1. 基础清理：去注释、去首尾空格
            line = re.split(r'(#|;|//)', line)[0].strip()
            if not line: continue
            
            # 2. 排除非规则行
            if line.startswith(('[', '<', '!', 'no-alert', 'payload:')): continue

            # 3. 分割逻辑：支持逗号或空格分隔
            if ',' in line:
                parts = [p.strip() for p in line.split(',')]
            else:
                parts = line.split()

            if len(parts) < 2: continue

            # 4. 类型标准化
            raw_type = parts[0].upper()
            
            # 处理 "payload: - DOMAIN-SUFFIX,xxx" 这种奇怪格式
            if raw_type == "-" and len(parts) > 2:
                raw_type = parts[1].upper()
                target = parts[2]
            else:
                target = parts[1]

            # 映射到 QX 标准类型
            qx_type = TYPE_MAP.get(raw_type)
            if not qx_type:
                # 如果不是标准类型（如 PROCESS-NAME），直接忽略
                continue
            
            # 清理目标字符串的引号
            target = target.strip("'").strip('"')

            # 5. 生成最终规则
            # 策略统一为 reject，因为这是一个 block list
            # IP类规则强制添加 no-resolve
            if qx_type in ["IP-CIDR", "IP-CIDR6"]:
                rule = f"{qx_type},{target},reject,no-resolve"
            else:
                rule = f"{qx_type},{target},reject"
            
            rules_found.append(rule)
            
        print(f"✅ [{name}] Parsed {len(rules_found)}")
        return name, rules_found

    except Exception as e:
        print(f"❌ [{name}] Error: {e}")
        return name, []

def rule_sort_key(rule):
    """
    排序逻辑：
    1. HOST-SUFFIX (最常用)
    2. HOST-KEYWORD
    3. HOST
    4. USER-AGENT
    5. IP-CIDR / IP-CIDR6
    """
    parts = rule.split(',')
    rtype = parts[0]
    target = parts[1]
    
    priority = 100
    if rtype == "HOST-SUFFIX": priority = 1
    elif rtype == "HOST-KEYWORD": priority = 2
    elif rtype == "HOST": priority = 3
    elif rtype == "USER-AGENT": priority = 4
    elif rtype.startswith("IP"): priority = 5
    
    return (priority, target)

def main():
    print(f"--- Starting Download ({MAX_WORKERS} threads) ---")
    
    all_rules_set = set()
    source_stats = {}

    # 多线程下载
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

    # 统计变化
    old_count = 0
    diff_msg = "(Init)"
    if os.path.exists(OUTPUT_FILENAME):
        try:
            with open(OUTPUT_FILENAME, 'r', encoding='utf-8') as f:
                # 简单统计行数
                old_count = sum(1 for line in f if line.strip() and not line.startswith('#'))
            
            diff = current_count - old_count
            if diff > 0: diff_msg = f"(+{diff})"
            elif diff < 0: diff_msg = f"({diff})"
            else: diff_msg = "(0)"
        except:
            pass

    # 生成文件头
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock All-in-One",
        f"# Updated: {now}",
        f"# Total: {current_count} {diff_msg}",
        f"# Note: All rules are forced to 'reject'",
        f"# Note: IP rules include 'no-resolve'",
        f"#"
    ]
    
    # 按规则数量降序排列源统计
    for n, c in sorted(source_stats.items(), key=lambda item: item[1], reverse=True):
        header.append(f"# {n}: {c}")
    header.append("")

    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        f.write("\n") # EOF newline

    print(f"\nCompleted. Saved to {OUTPUT_FILENAME}")
    print(f"Total Rules: {current_count} | Diff: {diff_msg}")

if __name__ == "__main__":
    main()
