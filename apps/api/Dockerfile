FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN addgroup --system sentinelforge && adduser --system --ingroup sentinelforge sentinelforge

COPY pyproject.toml README.md LICENSE alembic.ini ./
COPY apps ./apps
COPY detections ./detections
COPY evaluators ./evaluators
COPY telemetry ./telemetry
COPY soar ./soar
COPY scripts ./scripts

RUN pip install --no-cache-dir --no-compile .

USER sentinelforge
EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health', timeout=3)"

CMD ["sh", "-c", "alembic upgrade head && exec uvicorn apps.api.sentinelforge_api.main:app --host 0.0.0.0 --port 8000 --limit-concurrency 100 --timeout-keep-alive 5"]
