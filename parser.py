import re

with open("sample.log") as f:
    logs = f.readlines()

ip_pattern = re.compile(r"from (\d+\.\d+\.\d+\.\d+)")
ips = {}

for line in logs:
    match = ip_pattern.search(line)
    if match:
        ip = match.group(1)
        ips[ip] = ips.get(ip, 0) + 1

print("Failed login attempts by IP:")
for ip, count in ips.items():
    print(f"{ip}: {count}")

