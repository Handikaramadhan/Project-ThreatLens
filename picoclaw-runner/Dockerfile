FROM python:3.12-slim

ARG PICOCLAW_VERSION=0.2.9

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && curl -fsSL \
      "https://github.com/sipeed/picoclaw/releases/download/v${PICOCLAW_VERSION}/picoclaw_${PICOCLAW_VERSION}_checksums.txt" \
      -o /tmp/picoclaw_checksums.txt \
    && curl -fsSL \
      "https://github.com/sipeed/picoclaw/releases/download/v${PICOCLAW_VERSION}/picoclaw_Linux_x86_64.tar.gz" \
      -o /tmp/picoclaw_Linux_x86_64.tar.gz \
    && grep "picoclaw_Linux_x86_64.tar.gz" /tmp/picoclaw_checksums.txt \
      | sed 's#picoclaw_Linux_x86_64.tar.gz#/tmp/picoclaw_Linux_x86_64.tar.gz#' \
      | sha256sum -c - \
    && tar -xzf /tmp/picoclaw_Linux_x86_64.tar.gz -C /usr/local/bin picoclaw \
    && chmod 0755 /usr/local/bin/picoclaw \
    && rm -rf /var/lib/apt/lists/* /tmp/picoclaw*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV PICOCLAW_HOME=/data
ENV PICOCLAW_CONFIG=/data/config.json
EXPOSE 8090

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8090", "--no-access-log"]
