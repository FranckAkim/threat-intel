import time
import logging
from datetime import datetime
from threat_intel.fetcher import fetch_cves

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)


def run_polling_loop(interval_seconds: int = 900):
    logger.info("Starting threat intelligence poller...")
    logger.info(f"Polling every {interval_seconds} seconds")

    while True:
        try:
            logger.info("Fetching latest CVEs...")
            threats = fetch_cves()

            critical = [t for t in threats if t.is_critical()]

            logger.info(f"Fetched {len(threats)} threats, "
                        f"{len(critical)} critical")

            for threat in threats:
                logger.info(str(threat))
                if threat.is_critical():
                    logger.warning(
                        f"CRITICAL THREAT DETECTED: {threat.id}"
                    )

            logger.info(f"Next poll in {interval_seconds // 60} minutes")
            time.sleep(interval_seconds)

        except KeyboardInterrupt:
            logger.info("Poller stopped by user")
            break
        except Exception as e:
            logger.error(f"Error during polling: {e}")
            logger.info("Retrying in 60 seconds...")
            time.sleep(60)


if __name__ == "__main__":
    run_polling_loop(interval_seconds=30)
