# API image. The MCP tool servers run inside it as subprocesses of the app
# (python -m mcp_servers.<name>.server), so both packages live under /app.
# Provider settings and DATABASE_URL are supplied at run time, never here.
FROM docker.io/library/python:3.14-slim

# apt fetches over HTTPS; tesseract is the OCR tool server's binary.
RUN sed -i 's|^URIs: http://|URIs: https://|' /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/
COPY mcp_servers/ mcp_servers/
# Default intake directory; a host directory is mounted over it to submit files.
RUN mkdir samples

RUN useradd --system --no-create-home charon
USER charon

EXPOSE 8000

# One worker: the startup sweep assumes a single server process.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
