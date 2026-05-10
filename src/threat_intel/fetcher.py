import httpx
from dotenv import load_dotenv
import os
from threat_intel.models import ThreatEvent

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

if not NVD_API_KEY:
    raise ValueError("NVD_API_KEY not found in .env file")


def parse_severity(cve: dict) -> tuple[float, str]:
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        data = metrics["cvssMetricV31"][0]["cvssData"]
        return data["baseScore"], "3.1"
    elif "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        return data["baseScore"], "2.0"
    return 0.0, "unknown"


def parse_cve(raw: dict) -> ThreatEvent:
    cve = raw["cve"]
    severity, cvss_version = parse_severity(cve)

    return ThreatEvent(
        id=cve["id"],
        source="NVD",
        severity=severity,
        description=cve["descriptions"][0]["value"],
        published=cve["published"],
        raw_data=cve,
        cvss_version=cvss_version
    )


def fetch_cves(results_per_page: int = 5) -> list[ThreatEvent]:
    headers = {"apiKey": NVD_API_KEY}
    params = {"resultsPerPage": results_per_page}

    response = httpx.get(NVD_URL, headers=headers, params=params)

    if response.status_code != 200:
        print(f"Request failed with status: {response.status_code}")
        return []

    data = response.json()
    vulnerabilities = data.get("vulnerabilities", [])

    return [parse_cve(item) for item in vulnerabilities]
