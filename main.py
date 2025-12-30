import requests
import pytz
import re
from datetime import datetime

# ================= 配置区域 =================

# 只有这两个源，秋风排第一（优先级最高）
REMOTE_URLS = [
    "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-QuantumultX.list",
    "https://limbopro.com/Adblock4limbo.list"
]

# ================= 逻辑区域 =================

def fetch_and_merge_rules():
    """
    抓取、清洗、去重（保留第一优先级的策略）
    """
    # 字典结构：Key = "类型,域名" -> Value = "完整规则行"
    unique_rules = {} 
    
    headers = {
        'User-Agent': 'Quantumult X/1.0.30 (iPhone; iOS 16.0; Scale/3.00)',
        'Accept': '*/*'
    }
    
    print(f"--- 开始执行抓取 (源数量: {len(REMOTE_URLS)}) ---")

    for url in REMOTE_URLS:
        source_name = url.split('/')[-1]
        print(f"正在处理: {source_name} ...", end="")
        
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            if resp.status_code != 200:
                print(f" [失败] HTTP 状态码: {resp.status_code}")
                continue

            lines = resp.text.splitlines()
            valid_count = 0
            
            for line in lines:
                line = line.strip()
                
                # 1. 基础清理：跳过空行、注释、HTML标签(防止抓到404页面)
                if not line or line.startswith(('#', ';', '//', '[', '<')):
                    continue
                
                # 2. 移除行尾注释 (例如: HOST, a.com, reject // 注释)
                if "//" in line:
                    line = line.split("//")[0].strip()
                
                # 3. 必须包含逗号
                if ',' not in line:
                    continue
                    
                parts = [p.strip() for p in line.split(',')]
                
                # 4. 关键修正：确保至少有2个部分 (类型, 域名)
                if len(parts) < 2:
                    continue

                rule_type = parts[0].upper()
                target = parts[1]
                
                # 5. 获取策略 (如果没有策略，默认为 reject)
                policy = "reject"
                if len(parts) >= 3:
                    policy = parts[2].lower()
                
                # 6. 类型白名单 (只抓取去广告相关的)
                if rule_type not in ["HOST", "HOST-SUFFIX", "HOST-KEYWORD", "IP-CIDR", "IP-CIDR6", "USER-AGENT"]:
                    continue

                # 7. 策略清洗：确保策略是有效的 reject 类型
                # 如果大神写了 direct，我们强制改成 reject，或者丢弃？
                # 既然是去广告列表，我们假设所有规则都是为了屏蔽。
                # 这里做一个宽松处理：只要包含 reject 就保留原样，否则强制 reject
                if "reject" not in policy:
                    policy = "reject"

                # 8. 生成唯一标识 (Key)
                # 比如: "HOST-SUFFIX,baidu.com"
                unique_key = f"{rule_type},{target}".lower() # 统一小写对比，防止重复

                # 9. 存入字典
                # 因为我们是按顺序遍历 URL 的，如果 Key 已经存在，说明优先级高的源已经添加过了
                # 所以这里只有 Key 不存在时才添加
                if unique_key not in unique_rules:
                    # 重组规则，保证格式整洁
                    final_rule = f"{rule_type},{target},{policy}"
                    unique_rules[unique_key] = final_rule
                    valid_count += 1
            
            print(f" [成功录入 {valid_count} 条]")
            
        except Exception as e:
            print(f" [出错] {e}")

    return list(unique_rules.values())

def sort_priority(line):
    # 排序：HOST > HOST-SUFFIX > 其他
    line = line.upper()
    if line.startswith("HOST,"): return 1
    if line.startswith("HOST-SUFFIX,"): return 2
    if line.startswith("HOST-KEYWORD,"): return 3
    if line.startswith("IP-CIDR"): return 4
    return 10

def main():
    rules = fetch_and_merge_rules()
    
    # 如果抓取结果为0，可能是网络问题，抛出错误防止生成空文件
    if len(rules) == 0:
        raise ValueError("严重错误：没有抓取到任何规则！请检查网络或源链接。")

    sorted_rules = sorted(rules, key=sort_priority)
    
    tz = pytz.timezone('Asia/Shanghai')
    now = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
    
    header = [
        f"# QX AdBlock Merged (AWAvenue + LimboPro)",
        f"# 更新时间: {now}",
        f"# 规则总数: {len(sorted_rules)}",
        f"# 策略: 优先保留秋风规则，毒奶作为补充",
        ""
    ]
    
    with open("merged_ads.list", "w", encoding="utf-8") as f:
        f.write("\n".join(header))
        f.write("\n".join(sorted_rules))
        
    print(f"\n--- 处理完成 ---")
    print(f"最终生成文件 merged_ads.list，共 {len(sorted_rules)} 条规则")

if __name__ == "__main__":
    main()
