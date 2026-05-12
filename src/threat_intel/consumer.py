import json
import logging
from threat_intel.alerting import send_slack_alert
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
    logger.warning(
        f"🚨 CRITICAL THREAT: {threat.id} "
        f"severity={threat.severity}/10"
    )
    send_slack_alert(threat)


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

# DEDUPLICATION STRATEGY (to implement with Elasticsearch):
#
# Problem: consumer restart re-reads Kafka from offset 0
#          causing duplicate Slack alerts for already-processed threats
#
# Solution: idempotency check before alerting
#   Step 1: when a threat is processed, store threat.id in Elasticsearch
#   Step 2: before send_slack_alert(), check if threat.id already exists
#   Step 3: if exists → skip alert (already handled)
#   Step 4: if not exists → send alert + store threat.id
#
# This makes our consumer idempotent — processing the same
# message twice produces the same result as processing it once.
