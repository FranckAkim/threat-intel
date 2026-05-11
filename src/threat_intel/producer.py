import json
import logging
from kafka import KafkaProducer
from threat_intel.models import ThreatEvent

logger = logging.getLogger(__name__)

KAFKA_BROKER = "localhost:9092"
THREATS_TOPIC = "threats"


def create_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=3
    )


def publish_threat(producer: KafkaProducer, threat: ThreatEvent) -> None:
    try:
        producer.send(
            THREATS_TOPIC,
            value=threat.to_dict()
        )
        logger.info(f"Published threat to Kafka: {threat.id}")
    except Exception as e:
        logger.error(f"Failed to publish {threat.id}: {e}")


def publish_threats(threats: list[ThreatEvent]) -> None:
    if not threats:
        logger.info("No threats to publish")
        return

    producer = create_producer()

    try:
        for threat in threats:
            publish_threat(producer, threat)
        producer.flush()
        logger.info(f"Successfully published {len(threats)} threats")
    finally:
        producer.close()
