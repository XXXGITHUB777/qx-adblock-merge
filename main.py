import requests
import pytz
import re
from datetime import datetime

# ================= 配置区域 =================

# 使用 GhProxy 代理 GitHub Raw 链接，这是目前最稳的方案
REMOTE_URLS = [
    # 1. 秋风
    "https://ghproxy.net/https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
    
    # 2. 毒奶 Limbopro
    "https://ghproxy.net/https://raw.githubusercontent.com/limbopro/Adblock4limbo/main/Adblock4limbo.list"
]

# ================= 逻辑区域 =================

def fetch_and_merge_rules():
    unique_rules = {} 
    source_stats = {} 
    
    # 伪装成浏览器，防止被拦截
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    }
    
    print(f"--- 开始执行 7.0 GhProxy 代理合并 ---")

    for url in REMOTE_URLS:
        if "AWAvenue" in url: name = "秋风(AWAvenue)"
        elif "limbopro" in url: name = "毒奶(Limbopro)"
        else: name = "Unknown"
            
        print(f"正在下载: {name} ...", end="")
        
        try:
            resp = requests.get(url, headers=headers, timeout=60)
            resp.encoding = 'utf-8' # 强制UTF-8
            
            if resp.status_code != 200:
                print(f" [失败] HTTP 状态码: {resp.status_code}")
                source_stats[name] = 0
                continue

            lines = resp.text.splitlines()
            current_count = 0
            
            # --- 核心逻辑 ---
            for line in lines:
                line = line.strip()
                # 过滤无效行
                if not line or line.startswith(('#', ';', '//', '[', '<', '!')):
                    continue
                if ',' not in line:
                    continue
                    
                parts = [p.strip() for p in line.split(',')]
                
                # 补全缺省策略
                if len(parts) == 2: parts.append("reject")
                
                if len(parts) < 3: continue

                rule_type = parts[0].upper()
                target = parts[1]
                policy = parts[2].lower()

                # 类型过滤
                if rule_type not in ["HOST", "HOST-SUFFIX", "HOST-KEYWORD", "IP-CIDR", "IP-CIDR6", "USER-AGENT"]:
                    continue

                # 存入
                unique_key = f"{rule_type},{target}".lower()
                if unique_key not in unique_rules:
                    # 确保策略包含 reject，否则强制修正
                    if "reject" not in policy: policy = "reject"
                    
                    final_rule = f"{rule_type},{target},{policy}"
                    unique_rules[unique_key] = final_rule
                    current_count += 1
            
            source_stats[name] = current_count
            print(f" [成功提取 {current_count} 条]")
            
            # === 死因报告：如果提取为0，打印原始内容供调试 ===
            if current_count == 0:
                print(f"\n[严重警告] {name} 下载成功但提取数为 0！")
                print("下载内容的前 10 行如下 (请检查是否为 HTML 报错页面):")
                print("-" * 30)
                for i in range(min(10, len(lines))):
                    print(lines[i])
                print("-" * 30)
            # ============================================
            
        except Exception as e:
            print(f" [出错] {e}")
            source_stats[name] = 0

    return list(unique_rules.values()), source_stats

def sort_priority(line):
    line = line.upper()
    if line.startswith("HOST,"): return 1
    if line.startswith("HOST-SUFFIX,"): return 2
    return 10

def main():
    rules, stats = fetch_and_merge_rules()
    
    # 只要规则总数少于 500 (即使其中一个源失败)，就报错，保护旧文件
    if len(rules) < 500:
        print(f"\n错误：最终生成的规则仅有 {len(rules)} 条，判定为异常，停止写入。")
        exit(1)

    sorted_rules = sorted(rules, key=sort_priority)
    
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock Merged 7.0",
        f"# 更新时间: {now}",
        f"# 规则总数: {len(sorted_rules)}",
        f"# --- 来源详情 ---"
    ]
    for n, c in stats.items():
        header.append(f"# {n}: {c}")
    header.append("")
    
    with open("merged_ads.list", "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        
    print(f"\n处理完成！merged_ads.list 已生成。")

if __name__ == "__main__":
    main()
