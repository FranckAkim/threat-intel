# THREAT INTELLIGENCE REST API
# Built with FastAPI
#
# Endpoints:
# GET /health                    → service health check
# GET /threats                   → latest threats (paginated)
# GET /threats/{cve_id}          → specific CVE details
# GET /threats/search            → filter by severity, keywords, dates
# GET /threats/critical          → severity >= 9.0 only
# GET /threats/recent            → last 24 hours
# GET /threats/stats             → counts, trends, severity distribution
# GET /threats/exists/{cve_id}   → deduplication check
