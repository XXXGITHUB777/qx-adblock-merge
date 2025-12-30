import requests
import pytz
from datetime import datetime

# ================= 配置区域 =================

# 请按优先级排列！排在上面的源，其规则策略（例如 reject-dict）会优先被保留
REMOTE_URLS = [
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list", # 秋风（通常质量很高，建议放前）
    "https://raw.githubusercontent.com/amiglistimo/Quantumult-X/main/Rewrite/ADBlock.list",
    "https://raw.githubusercontent.com/fmz200/wool_scripts/main/QuantumultX/filter/filter.list",
    "https://raw.githubusercontent.com/zirawell/R-Store/main/Rule/QuanX/Adblock/All/filter/allAdBlock.list",
    "https://limbopro.com/Adblock4limbo.list"
]

# 有效的拒绝策略集合 (只保留这些类型的规则，防止混入 DIRECT 或 PROXY)
VALID_POLICIES = {
    "reject", "reject-200", "reject-tinygif", "reject-img", 
    "reject-dict", "reject-array", "reject-video"
}

# ================= 逻辑区域 =================

def fetch_and_merge_rules():
    """
    智能合并：去重，但保留原始策略
    """
    # 使用字典来去重，Key是域名(target)，Value是完整的规则行
    # 这样可以确保同一个域名只保留一条规则（优先保留列表中排在前面的源的设置）
    unique_rules_map = {} 
    
    headers = {
        'User-Agent': 'Quantumult X/1.0.30 (iPhone; iOS 16.0; Scale/3.00)',
        'Accept': 'text/plain'
    }
    
    print(f"--- 开始执行 4.0 原味合并 ---")

    for url in REMOTE_URLS:
        try:
            source_name = url.split('/')[-1]
            print(f"正在处理: {source_name} ...", end="")
            
            resp = requests.get(url, headers=headers, timeout=20)
            if resp.status_code != 200:
                print(f" [失败] code: {resp.status_code}")
                continue

            lines = resp.text.splitlines()
            new_count = 0
            
            for line in lines:
                line = line.strip()
                
                # 1. 基础清理
                if not line or line.startswith(('#', ';', '//', '[')):
                    continue
                if "//" in line:
                    line = line.split("//")[0].strip()
                if ',' not in line:
                    continue
                    
                parts = [p.strip() for p in line.split(',')]
                
                # 2. 格式完整性检查
                if len(parts) < 3: 
                    # 有些规则可能只有 HOST,domain (缺省策略)，QX 默认reject
                    # 但为了安全，我们只收录明确写了策略的，或者手动补全
                    if len(parts) == 2:
                        parts.append("reject") # 默认补全
                    else:
                        continue

                rule_type = parts[0].upper()
                target = parts[1]
                policy = parts[2].lower() # 策略转小写以便比较

                # 3. 筛选有效类型 (只处理 Host/IP 相关)
                if rule_type not in ["HOST", "HOST-SUFFIX", "HOST-KEYWORD", "IP-CIDR", "IP-CIDR6", "USER-AGENT"]:
                    continue

                # 4. 筛选有效策略 (只保留拒绝类的，防止混入直连规则)
                # 有些大神源里可能会混入 "direct" 或 "proxy" 来修正误杀，
                # 如果你想完全信任大神修正误杀的操作，可以把下面这行注释掉。
                # 但既然是"AdBlock List"，我们原则上只收录 reject 类。
                if policy not in VALID_POLICIES:
                    # 有些特殊情况，比如 reject-no-drop，也算 reject
                    if "reject" not in policy: 
                        continue

                # 5. 核心去重逻辑
                # 生成唯一标识 Key。对于 USER-AGENT，Key 是整个 UA 字符串；对于 HOST，Key 是域名
                unique_key = f"{rule_type},{target}"

                # 如果这个域名之前没出现过，就添加进去
                # 因为我们是按 REMOTE_URLS 的顺序遍历的，所以排在前面的源优先级最高
                # 这就完美保留了"大神 A 觉得用 reject-dict 好"的设定
                if unique_key not in unique_rules_map:
                    # 重组为标准字符串，去除多余空格
                    clean_line = f"{rule_type},{target},{policy}"
                    unique_rules_map[unique_key] = clean_line
                    new_count += 1
            
            print(f" [录入 {new_count} 条]")
            
        except Exception as e:
            print(f" [出错] {e}")

    return list(unique_rules_map.values())

def sort_priority(line):
    # 依然保持 HOST 优先，提升匹配速度
    line = line.upper()
    if line.startswith("HOST,"): return 1
    if line.startswith("HOST-SUFFIX,"): return 2
    if line.startswith("HOST-KEYWORD,"): return 3
    if line.startswith("IP-CIDR"): return 4
    return 10

def main():
    rules = fetch_and_merge_rules()
    sorted_rules = sorted(rules, key=sort_priority)
    
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock Merged 4.0 (Preserve Policy)",
        f"# 更新时间: {now}",
        f"# 规则总数: {len(sorted_rules)}",
        f"# 说明: 已自动去重，并保留了原始源的 reject/reject-200/reject-dict 策略",
        ""
    ]
    
    with open("merged_ads.list", "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        
    print(f"\n合并完成，生成规则 {len(sorted_rules)} 条")

if __name__ == "__main__":
    main()
