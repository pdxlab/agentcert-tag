# TAG verify sidecar — tiny, stdlib-only HTTP wrapper around the verify core.
FROM python:3.12-slim

WORKDIR /app
COPY core/ /app/core/
COPY sidecar/server.py /app/server.py
RUN pip install --no-cache-dir "cryptography>=42"

ENV TAG_MODE=shadow \
    TAG_FAIL_MODE=closed \
    TAG_PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=2s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8080/healthz').status==200 else 1)"
CMD ["python", "/app/server.py"]
