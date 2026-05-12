import logging
from elasticsearch import Elasticsearch
from threat_intel.models import ThreatEvent

logger = logging.getLogger(__name__)

ES_HOST = "http://localhost:9200"
THREATS_INDEX = "threats"


def get_client() -> Elasticsearch:
    return Elasticsearch(ES_HOST)


def ensure_index(client: Elasticsearch) -> None:
    try:
        if not client.indices.exists(index=THREATS_INDEX):
            client.indices.create(
                index=THREATS_INDEX,
                mappings={
                    "properties": {
                        "id":           {"type": "keyword"},
                        "source":       {"type": "keyword"},
                        "severity":     {"type": "float"},
                        "description":  {"type": "text"},
                        "published":    {"type": "keyword"},
                        "cvss_version": {"type": "keyword"}
                    }
                }
            )
            logger.info(f"Created index: {THREATS_INDEX}")
        else:
            logger.info(f"Index already exists: {THREATS_INDEX}")
    except Exception as e:
        logger.error(f"Failed to ensure index: {e}")


def store_threat(client: Elasticsearch, threat: ThreatEvent) -> bool:
    try:
        client.index(
            index=THREATS_INDEX,
            id=threat.id,
            document=threat.to_dict()
        )
        logger.info(f"Stored threat: {threat.id}")
        return True
    except Exception as e:
        logger.error(f"Failed to store {threat.id}: {e}")
        return False


def threat_exists(client: Elasticsearch, threat_id: str) -> bool:
    try:
        return client.exists(
            index=THREATS_INDEX,
            id=threat_id
        )
    except Exception as e:
        logger.error(f"Failed to check existence of {threat_id}: {e}")
        return False


def search_threats(
    client: Elasticsearch,
    min_severity: float = 0.0,
    limit: int = 10
) -> list[dict]:
    try:
        response = client.search(
            index=THREATS_INDEX,
            body={
                "query": {
                    "range": {
                        "severity": {"gte": min_severity}
                    }
                },
                "sort": [{"severity": "desc"}],
                "size": limit
            }
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]
    except Exception as e:
        logger.error(f"Search failed: {e}")
        return []
