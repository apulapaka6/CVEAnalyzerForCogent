import requests, gzip, json
from io import BytesIO

# 1) Download the recent CVE feed (v1.1 JSON)    
url = "https://static.nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz"
resp = requests.get(url, stream=True)
resp.raise_for_status()

# 2) Decompress & load JSON
with gzip.GzipFile(fileobj=BytesIO(resp.content)) as f:
    feed = json.load(f)

items = feed["CVE_Items"]  # list of CVE entries

# 3) Extract the fields we care about
cve_list = []
for item in items:
    meta = item["cve"]
    metrics = item.get("impact", {}).get("baseMetricV3", {})
    score  = metrics.get("cvssV3", {}).get("baseScore", 0.0)

    desc = ""
    for d in meta["description"]["description_data"]:
        if d["lang"] == "en":
            desc = d["value"]
            break

    cve_list.append({
        "cve_id":  meta["CVE_data_meta"]["ID"],
        "desc":    desc,
        "cvss":    score,
        "aliases":[tok.lower() for tok in desc.split() if len(tok)>4]  # pick “meaty” tokens
    })

# 4) Pick the top 10 by CVSS
top10 = sorted(cve_list, key=lambda x: x["cvss"], reverse=True)[:10]

# 5) Write out your mock_cves.json
with open("mock_cves.json", "w") as f:
    json.dump(top10, f, indent=2)

print("Wrote mock_cves.json with these IDs:")
for c in top10:
    print(f"  • {c['cve_id']} (score={c['cvss']})")
