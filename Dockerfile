# syntax=docker/dockerfile:1
FROM python:3.12-slim

LABEL org.opencontainers.image.title="IP Port Tester" \
      org.opencontainers.image.source="https://github.com/mackolzjj/ip-port-tester"

WORKDIR /app
COPY ip_tester.py ./

ENV IPTESTER_TOKEN="" \
    PYTHONUNBUFFERED=1

EXPOSE 8765
VOLUME ["/app/output"]

# --keep-alive：容器里必须常驻，否则最后一个页面关掉进程就退
ENTRYPOINT ["python3", "ip_tester.py", "--host", "0.0.0.0", "--port", "8765", "--keep-alive", "--no-browser"]
