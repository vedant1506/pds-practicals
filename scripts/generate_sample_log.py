import os
import random
import datetime

def generate_log_dataset(filename="data/raw/sample_logs.log", dataset_type="v1"):
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    user_agents_benign = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148"
    ]

    user_agents_bot = [
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Nikto/2.1.6 (EVS/2.1.6) (http://www.cirt.net/nikto)",
        "Gobuster/v3.5 (GitHub: OJ/gobuster)",
        "python-urllib/3.10",
        "curl/7.88.1",
        "Hydra/9.5 (https://github.com/vanhauser-thc/thc-hydra)",
        "DirBuster/1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"
    ]

    benign_paths = [
        "/home/index.html", "/about-us", "/products/catalog.php?id=102",
        "/contact", "/assets/css/style.css", "/assets/js/main.js",
        "/cart/checkout", "/api/v1/user/profile", "/login.php",
        "/blog/cybersecurity-best-practices", "/faq", "/support"
    ]

    sqli_payloads = [
        "/products.php?id=1' OR '1'='1",
        "/login.php?username=admin'--&password=foo",
        "/search?q=test' UNION SELECT null, username, password FROM users--",
        "/category.php?id=5; DROP TABLE web_logs;--",
        "/api/user?id=-1 OR 1=1",
        "/api/v2/items?filter=1 AND 1=CONVERT(int,@@version)",
        "/auth/reset?email=test%27%20OR%201=1--",
        "/items.php?id=1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--"
    ]

    traversal_payloads = [
        "/download.php?file=../../../../etc/passwd",
        "/view?doc=..\\..\\..\\windows\\system32\\cmd.exe",
        "/static/../../etc/shadow",
        "/include.php?path=../../boot.ini",
        "/files/../../../../proc/self/environ",
        "/admin/logs?file=../../../../var/log/syslog",
        "/image.php?file=....//....//....//etc/passwd"
    ]

    if dataset_type == "clean":
        ips_benign = ["192.168.1.10", "192.168.1.15", "10.0.0.45", "10.0.0.50", "172.16.0.12"]
        ips_sqli, ips_traversal, ips_brute = [], [], []
        n_benign, n_brute, n_sqli, n_trav = 1000, 0, 0, 0
        start_date = datetime.datetime(2024, 3, 1, 9, 0, 0)

    elif dataset_type == "v3":
        ips_benign = ["182.72.35.10", "49.207.218.45", "103.21.244.11", "157.32.35.29"]
        ips_sqli = ["45.142.214.78", "185.220.101.5", "194.26.29.200", "91.240.118.50"]
        ips_traversal = ["91.240.118.99", "185.220.102.15", "194.26.29.112"]
        ips_brute = ["212.60.12.222", "185.220.101.10", "103.111.33.197", "185.220.101.99"]
        n_benign, n_brute, n_sqli, n_trav = 1500, 2000, 800, 700
        start_date = datetime.datetime(2024, 2, 25, 12, 0, 0)

    elif dataset_type == "v4":
        ips_benign = ["182.72.35.10", "49.207.218.45", "103.21.244.11", "157.32.35.29", "199.188.238.77"]
        ips_sqli = ["45.142.214.78", "185.220.101.5", "194.26.29.200", "91.240.118.50", "185.220.101.4"]
        ips_traversal = ["91.240.118.99", "185.220.102.15", "194.26.29.112", "91.240.118.170"]
        ips_brute = ["212.60.12.222", "185.220.101.10", "103.111.33.197", "212.60.12.161"]
        n_benign, n_brute, n_sqli, n_trav = 3000, 4500, 1300, 1200
        start_date = datetime.datetime(2024, 3, 1, 0, 0, 0)

    elif dataset_type == "v2":
        ips_benign = ["182.72.35.10", "49.207.218.45", "103.21.244.11"]
        ips_sqli = ["45.142.214.78", "185.220.101.5", "194.26.29.200"]
        ips_traversal = ["91.240.118.99", "185.220.102.15"]
        ips_brute = ["212.60.12.222", "185.220.101.10"]
        n_benign, n_brute, n_sqli, n_trav = 800, 900, 450, 350
        start_date = datetime.datetime(2024, 2, 20, 14, 0, 0)

    else: # v1
        ips_benign = ["157.32.35.29", "199.188.238.77", "152.58.35.97", "103.111.33.197"]
        ips_sqli = ["185.220.101.4", "45.155.205.111"]
        ips_traversal = ["194.26.29.112", "91.240.118.170"]
        ips_brute = ["212.60.12.161", "103.111.33.197"]
        n_benign, n_brute, n_sqli, n_trav = 600, 600, 150, 150
        start_date = datetime.datetime(2024, 2, 15, 10, 0, 0)

    base_time = start_date
    records = []

    print(f"[*] Generating '{filename}' ({dataset_type.upper()}) log entries ({n_benign+n_brute+n_sqli+n_trav:,} records)...")

    # 1. Benign records
    for _ in range(n_benign):
        base_time += datetime.timedelta(seconds=random.randint(1, 20))
        ip = random.choice(ips_benign)
        ts = base_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = random.choice(benign_paths)
        method = "POST" if "login" in path or "checkout" in path else "GET"
        status = random.choice([200, 200, 200, 304, 404])
        bytes_sent = random.randint(500, 15000)
        ua = random.choice(user_agents_benign)
        log_line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'
        records.append((base_time, log_line))

    # 2. Brute-force bot scanner entries
    for _ in range(n_brute):
        base_time += datetime.timedelta(milliseconds=random.randint(10, 120))
        ip = random.choice(ips_brute)
        ts = base_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = random.choice(["/login.php", "/admin/login.php", "/wp-login.php", "/user/login", "/api/v1/auth"])
        method = "POST"
        status = random.choice([403, 404, 403])
        bytes_sent = random.randint(200, 500)
        ua = random.choice(user_agents_bot)
        log_line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'
        records.append((base_time, log_line))

    # 3. SQL Injection entries
    for _ in range(n_sqli):
        base_time += datetime.timedelta(seconds=random.randint(1, 4))
        ip = random.choice(ips_sqli)
        ts = base_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = random.choice(sqli_payloads)
        method = "GET"
        status = random.choice([200, 403, 500])
        bytes_sent = random.randint(1000, 8000)
        ua = random.choice(user_agents_bot + user_agents_benign)
        log_line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'
        records.append((base_time, log_line))

    # 4. Path Traversal entries
    for _ in range(n_trav):
        base_time += datetime.timedelta(seconds=random.randint(1, 5))
        ip = random.choice(ips_traversal)
        ts = base_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        path = random.choice(traversal_payloads)
        method = "GET"
        status = random.choice([403, 404, 500])
        bytes_sent = random.randint(300, 2000)
        ua = random.choice(user_agents_bot)
        log_line = f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"'
        records.append((base_time, log_line))

    records.sort(key=lambda x: x[0])

    with open(filename, "w") as f:
        for _, line in records:
            f.write(line + "\n")

    # Also copy to root workspace directory for convenience
    root_filename = os.path.basename(filename)
    with open(root_filename, "w") as f:
        for _, line in records:
            f.write(line + "\n")

    print(f"[+] Written {len(records):,} lines to '{filename}' and '{root_filename}' successfully.")

if __name__ == "__main__":
    generate_log_dataset("data/raw/sample_logs.log", "v1")
    generate_log_dataset("data/raw/sample_logs_v2.log", "v2")
    generate_log_dataset("data/raw/sample_logs_v3.log", "v3")
    generate_log_dataset("data/raw/sample_logs_v4.log", "v4")
    generate_log_dataset("data/raw/sample_logs_clean.log", "clean")
