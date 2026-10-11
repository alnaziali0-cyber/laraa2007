FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HOSTPANEL_DATA_DIR=/var/lib/nawahost COOKIE_SECURE=1
WORKDIR /app
ARG INSTALL_DOCKER_CLI=false
RUN if [ "$INSTALL_DOCKER_CLI" = "true" ]; then apt-get update && apt-get install -y --no-install-recommends docker.io && rm -rf /var/lib/apt/lists/*; fi
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --create-home --uid 10001 appuser && mkdir -p /var/lib/nawahost && chown -R appuser:appuser /var/lib/nawahost
COPY --chown=appuser:appuser . .
USER appuser
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)" || exit 1
CMD ["uvicorn","app:app","--host","0.0.0.0","--port","8000"]
