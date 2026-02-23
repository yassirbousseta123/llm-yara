FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY pyproject.toml README.md /app/
COPY llmyara /app/llmyara
COPY baselines /app/baselines
COPY configs /app/configs
COPY start.sh /app/start.sh

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir ".[runtime,ml]"

RUN chmod +x /app/start.sh

USER 10001

ENTRYPOINT ["/app/start.sh"]
