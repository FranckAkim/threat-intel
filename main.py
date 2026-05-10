import httpx
from dotenv import load_dotenv
import os

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY not found in .env file")


def fetch_cves():
    headers = {"apiKey": NVD_API_KEY}
    params = {"resultsPerPage": 5}

    response = httpx.get(NVD_URL, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Request failed with Status: {response.status_code}")
        return None


def print_cves(data):
    if data is None:
        print("No data received.")
        return

    vulnerabilities = data.get("vulnerabilities", [])

    for item in vulnerabilities:
        cve = item["cve"]
        cve_id = cve["id"]
        published = cve["published"]
        description = cve["descriptions"][0]["value"]

        # safely get severity score - not all CVEs have this
        score = "N/A"
        metrics = cve.get("metrics", {})
        if "cvssMetricV2" in metrics:
            score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV31" in metrics:
            score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

        print(f"\n{'='*60}")
        print(f"CVE ID:      {cve_id}")
        print(f"Published:   {published}")
        print(f"Severity:    {score}/10")
        print(f"Description: {description[:200]}...")


if __name__ == "__main__":
    print("Fetching latest CVEs from NVD...")
    data = fetch_cves()
    print_cves(data)


# =============================================================
# ARCHITECTURAL DECISION: How to run this every 15 minutes
# =============================================================
#
# OPTION 1 — External Scheduler (Windows Task Scheduler / cron)
#   - OS triggers the script every 15 minutes
#   - Python starts, does its job, exits cleanly
#   - Pattern: "fire and forget"
#   - Pro: lightweight, no process sitting in memory
#   - Con: requires OS-level configuration on every machine
#
# OPTION 2 — Python while loop with time.sleep(900)
#   - Script runs continuously, sleeps between cycles
#   - Pro: simple, no external setup needed
#   - Con: if the process crashes at 3am, nothing runs
#         until someone manually restarts it. Fragile.
#
# OPTION 3 — Docker container with built-in scheduler (chosen)
#   - Fetcher runs inside a container that auto-restarts on crash
#   - Works identically on any machine, no OS configuration
#   - Fits naturally into our Kafka pipeline architecture
#   - This is what we will build in Week 1
#
# =============================================================
