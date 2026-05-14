# Threat Intelligence Pipeline

> Real-time CVE threat intelligence powered by NVD, Apache Kafka, 
> Elasticsearch, and FastAPI

## What This Is
This project is a  real-time threat intelligence pipeline that continuously fetches the lastest CVEs from the  NVD API, streams them through Apache Kafka, processes tthem with consumers, and stored them in Elasticsearch for fast seaching and analysis. The System detects high-severity vulnerabilities, prevents duplicate processing, and sends real-time slack alerts while exposing a REST API built with FastAPI for querying threats, statistics and historical data.

**Built to stimulate a modern SOC-style event-driven cybersecurity architecture.**

## Architecture
** Data Flow:**
1. Fetcher polls NVD API every 15 minutes for recent CVEs
2. Each CVE normalized into a " ThreatEvent" object
3. Producer publiches 'ThreatEvent' to Kafka' 'threats' topic
4. Consumer reads from Kafka, checks Elasticsearch for duplicates
5. New threats are stored permanently in Elasticsearch
6. Critical threats (severity > 9.0) trigger real-time slack alerts
7. FastAPI exposes all stored threats vai REST endpoints.


## Tech Stack

| Technology | Purpose |
|---|---|
| Python 3.14 | Core language |
| Apache Kafka | Event streaming and message queue |
| Elasticsearch 8.11 | Threat storage and full-text search |
| FastAPI | REST API framework |
| Docker + Compose | Infrastructure orchestration |
| httpx | Async HTTP client for NVD API |
| Slack Webhooks | Real-time critical threat alerting |
| uv | Python package management |



## Getting Started

### Prerequisites
- Python 3.11+
- Docker Desktop
- Git

### Installation

1. Clone the repository
```bash
git clone https://github.com/FranckAkim/threat-intel.git
cd threat-intel
```

2. Install dependencies
```bash
uv sync
```

3. Create your `.env` file
```bash
# Create .env in project root
NVD_API_KEY=your_nvd_api_key_here
SLACK_WEBHOOK_URL=your_slack_webhook_url_here
```

Get your free NVD API key at: https://nvd.nist.gov/developers/request-an-api-key

4. Start infrastructure
```bash
docker compose up -d
```

5. Run the pipeline
```bash
# Terminal 1 - Start the API
uv run python run_api.py

# Terminal 2 - Start the consumer
uv run python run_consumer.py

# Terminal 3 - Start the poller
uv run python main.py
```

6. View the API docs
```
http://localhost:8000/docs
```


## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | Service health check |
| GET | `/threats` | Get latest threats |
| GET | `/threats/{cve_id}` | Get specific CVE by ID |
| GET | `/threats/critical` | Get critical threats (severity ≥ 9.0) |
| GET | `/threats/search` | Search by severity and filters |
| GET | `/threats/stats` | Threat statistics and distribution |
| GET | `/threats/exists/{cve_id}` | Check if CVE exists |

Interactive API documentation available at `http://localhost:8000/docs`



## Project Structure

```
threat-intel/
├── src/
│   └── threat_intel/
│       ├── __init__.py      # Package declaration
│       ├── models.py        # ThreatEvent data model
│       ├── fetcher.py       # NVD API integration
│       ├── producer.py      # Kafka message publisher
│       ├── consumer.py      # Threat processor and classifier
│       ├── storage.py       # Elasticsearch operations
│       └── api.py           # FastAPI REST endpoints
├── main.py                  # Poller entry point
├── run_consumer.py          # Consumer entry point
├── run_api.py               # API entry point
├── docker-compose.yml       # Infrastructure (Kafka, Elasticsearch)
├── pyproject.toml           # Project dependencies
└── .env                     # Secrets (never committed)
```


## Key Engineering Decisions

**Why Kafka instead of direct processing?**
Kafka decouples the fetcher from the consumer. The fetcher publishes 
at its own pace, the consumer processes at its own pace. If the consumer 
crashes, messages are preserved in Kafka and processed when it restarts. 
This makes the system resilient and scalable.

**Why Elasticsearch instead of a traditional database?**
Elasticsearch provides millisecond full-text search across thousands of 
threat records. Querying "find all CVEs mentioning Apache with severity 
above 7.0" is a single query. A traditional SQL database would require 
complex indexing to achieve the same performance.

**Why the src/ layout?**
The src/ layout prevents accidental imports and enforces proper package 
installation. It's the professional Python standard recommended by the 
Python Packaging Authority and signals engineering maturity to reviewers.

**Why Docker Compose for infrastructure?**
A single `docker compose up -d` command starts Kafka, Zookeeper, and 
Elasticsearch identically on any machine. No manual installation, no 
OS-specific configuration, no "works on my machine" problems. Any 
recruiter can clone this repo and have the full stack running in minutes.

**Why idempotent consumers?**
Kafka's at-least-once delivery means a message can be delivered more 
than once. By checking Elasticsearch before processing each threat, 
the consumer is idempotent — processing the same CVE twice produces 
the same result as processing it once. This prevents duplicate Slack 
alerts and duplicate database records.



## What I Learned

- **Event-driven architecture** — designing systems where components 
  communicate through events rather than direct calls, enabling loose 
  coupling and independent scaling

- **Stream processing** — building producers and consumers that process 
  data in real time as it arrives rather than in batches

- **Distributed systems concepts** — message queues, consumer groups, 
  offset management, at-least-once delivery, and idempotency

- **Search and storage** — designing Elasticsearch index mappings, 
  understanding the difference between keyword and text fields, and 
  building range queries for severity filtering

- **Production engineering** — structured logging, error handling, 
  circuit breakers, connection pooling, and failing fast

- **API design** — building RESTful endpoints with FastAPI, understanding 
  route ordering, query parameter validation, and automatic documentation 
  generation

- **Containerization** — orchestrating multi-service infrastructure with 
  Docker Compose, understanding port mapping, volumes, and service 
  dependencies

- **Security mindset** — protecting API keys with .env files, 
  understanding prompt injection in LLM systems, and designing 
  deduplication to prevent alert fatigue