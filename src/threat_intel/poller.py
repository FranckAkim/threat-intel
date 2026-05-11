import time
import logging
from threat_intel.fetcher import fetch_cves
from threat_intel.producer import publish_threats

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

            publish_threats(threats)

            logger.info(f"Next poll in {interval_seconds} seconds")
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
