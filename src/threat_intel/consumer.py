import json
import logging
from kafka import KafkaConsumer
from threat_intel.models import ThreatEvent


logger = logging.getLogger(__name__)

KAFKA_BROKER = "localhost:9092"
THREATS_TOPIC = "threats"
CONSUMER_GROUP = "threat-processors"


# CONSUMER PIPELINE - threat_intel/consumer.py
#
# Step 1: DESERIALIZE - convert Kafka bytes back to Python dict
# Step 2: HYDRATE - reconstruct ThreatEvent object from dict
# Step 3: CLASSIFY - inspect severity, check if critical
# Step 4: PROCESS - enrich with additional context if needed
# Step 5: PUBLISH - send alerts to Slack for critical threats
#
# This is the mirror of producer.py:
# producer: ThreatEvent → dict → bytes → Kafka
# consumer: Kafka → bytes → dict → ThreatEvent → action


def create_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        THREATS_TOPIC,
        bootstrap_servers=KAFKA_BROKER,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True
    )


def hydrate_threat(data: dict) -> ThreatEvent:
    return ThreatEvent(
        id=data["id"],
        source=data["source"],
        severity=data["severity"],
        description=data["description"],
        published=data["published"],
        raw_data=data,
        cvss_version=data.get("cvss_version")
    )


def process_threat(threat: ThreatEvent) -> None:
    logger.info(f"Processing: {threat.id} [{threat.severity}/10]")

    if threat.is_critical():
        logger.warning(
            f"CRITICAL THREAT: {threat.id} "
            f"severity={threat.severity} "
            f"description={threat.description[:100]}"
        )
        send_alert(threat)
    else:
        logger.info(f"Non-critical threat logged: {threat.id}")


def send_alert(threat: ThreatEvent) -> None:
    # Slack integration comes next session
    # For now we simulate with a clear log message
    logger.warning(
        f"\n{'='*60}"
        f"\n🚨 ALERT: {threat.id}"
        f"\nSeverity: {threat.severity}/10"
        f"\nPublished: {threat.published}"
        f"\nDescription: {threat.description[:200]}"
        f"\n{'='*60}"
    )


def run_consumer() -> None:
    logger.info("Starting threat consumer...")
    logger.info(f"Listening to topic: {THREATS_TOPIC}")
    logger.info(f"Consumer group: {CONSUMER_GROUP}")

    consumer = create_consumer()

    try:
        for message in consumer:
            data = message.value
            threat = hydrate_threat(data)
            process_threat(threat)

    except KeyboardInterrupt:
        logger.info("Consumer stopped by user")
    finally:
        consumer.close()
        logger.info("Consumer closed cleanly")
