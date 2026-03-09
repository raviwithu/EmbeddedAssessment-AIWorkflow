FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openssh-client \
        nmap \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY collector/ /app/collector/
COPY parsers/ /app/parsers/
COPY report/ /app/report/
COPY config/ /app/config/

EXPOSE 8000

CMD ["python", "-m", "collector.api"]
