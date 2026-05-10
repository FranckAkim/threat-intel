from threat_intel.fetcher import fetch_cves


def main():
    print("Fetching latest CVEs from NVD...")
    threats = fetch_cves()

    for threat in threats:
        print(f"\n{'='*60}")
        print(threat)

        if threat.is_critical():
            print("⚠️  CRITICAL THREAT - Immediate attention required")


if __name__ == "__main__":
    main()
