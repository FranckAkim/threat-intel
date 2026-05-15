FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
COPY uv.lock .
COPY README.md .
COPY dashboard.html .


RUN pip install uv
RUN uv sync --frozen --no-dev

COPY src/ src/
COPY run_api.py .

EXPOSE 8080

CMD ["uv", "run", "uvicorn", "threat_intel.api:app", "--host", "0.0.0.0", "--port", "8080"]

