# Contained HexStrike server. Loopback-only publish from the host.
# Do NOT mount targets/ or secrets into this image.
FROM python:3.12-slim-bookworm

WORKDIR /opt/hexstrike

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY hexstrike_server.py hexstrike_mcp.py ./

ENV HEXSTRIKE_HOST=0.0.0.0
EXPOSE 8888
# Publish only on host loopback: 127.0.0.1:8888:8888 (see docker-compose.yml)
CMD ["python", "hexstrike_server.py", "--port", "8888"]
