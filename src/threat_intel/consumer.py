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
