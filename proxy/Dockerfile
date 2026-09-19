# MCP Trust Proxy — trust-first proxy in front of MCP servers (TRUS-2032).
FROM python:3.12-slim
WORKDIR /app
COPY core/ /app/core/
COPY proxy/mcp_trust_proxy.py /app/proxy/mcp_trust_proxy.py
RUN pip install --no-cache-dir "cryptography>=42"
ENV TAG_MODE=shadow TAG_FAIL_MODE=closed MCP_PROXY_PORT=8081
EXPOSE 8081
HEALTHCHECK --interval=10s --timeout=2s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8081/healthz').status==200 else 1)"
CMD ["python", "/app/proxy/mcp_trust_proxy.py"]
