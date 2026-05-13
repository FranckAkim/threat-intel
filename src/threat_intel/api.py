import logging
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from elasticsearch import Elasticsearch
from threat_intel.storage import (
    get_client,
    ensure_index,
    search_threats,
    threat_exists
)
from threat_intel.models import ThreatEvent

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Threat Intelligence API",
    description="Real-time CVE threat intelligence powered by NVD and Kafka",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"]
)


def get_es() -> Elasticsearch:
    client = get_client()
    ensure_index(client)
    return client


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "threat-intel-api"}


@app.get("/threats/critical")
def get_critical_threats(limit: int = Query(default=10, le=100)):
    es = get_es()
    threats = search_threats(es, min_severity=9.0, limit=limit)
    return {
        "count": len(threats),
        "threats": threats
    }


@app.get("/threats/search")
def search(
    min_severity: float = Query(default=0.0, ge=0.0, le=10.0),
    limit: int = Query(default=10, le=100)
):
    es = get_es()
    threats = search_threats(es, min_severity=min_severity, limit=limit)
    return {
        "count": len(threats),
        "min_severity": min_severity,
        "threats": threats
    }


@app.get("/threats/stats")
def get_stats():
    es = get_es()
    all_threats = search_threats(es, min_severity=0.0, limit=1000)
    critical = [t for t in all_threats if t["severity"] >= 9.0]
    high = [t for t in all_threats if 7.0 <= t["severity"] < 9.0]
    medium = [t for t in all_threats if 4.0 <= t["severity"] < 7.0]
    low = [t for t in all_threats if t["severity"] < 4.0]

    return {
        "total": len(all_threats),
        "critical": len(critical),
        "high": len(high),
        "medium": len(medium),
        "low": len(low),
        "average_severity": round(
            sum(t["severity"] for t in all_threats) / len(all_threats), 2
        ) if all_threats else 0.0
    }


@app.get("/threats/exists/{cve_id}")
def check_exists(cve_id: str):
    es = get_es()
    exists = threat_exists(es, cve_id)
    return {"cve_id": cve_id, "exists": exists}


@app.get("/threats/{cve_id}")
def get_threat(cve_id: str):
    es = get_es()
    try:
        result = es.get(index="threats", id=cve_id)
        return result["_source"]
    except Exception:
        raise HTTPException(
            status_code=404,
            detail=f"Threat {cve_id} not found"
        )


@app.get("/threats")
def get_threats(limit: int = Query(default=10, le=100)):
    es = get_es()
    threats = search_threats(es, min_severity=0.0, limit=limit)
    return {
        "count": len(threats),
        "threats": threats
    }
