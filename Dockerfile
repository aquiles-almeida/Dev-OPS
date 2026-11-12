FROM python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORTA=8231
WORKDIR /app
RUN apk upgrade --no-cache && addgroup -g 10001 market && adduser -D -H -u 10001 -G market market
COPY requirements.txt /app/requirements.txt
COPY worker/requirements.txt /app/worker/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt -r worker/requirements.txt
COPY --chown=10001:10001 app.py /app/app.py
COPY --chown=10001:10001 loja /app/loja
COPY --chown=10001:10001 worker /app/worker
COPY --chown=10001:10001 templates /app/templates
COPY --chown=10001:10001 arquivos /app/arquivos
USER 10001:10001
EXPOSE 8231
HEALTHCHECK --interval=20s --timeout=3s --start-period=10s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8231/health', timeout=2)"
CMD ["gunicorn", "--bind", "0.0.0.0:8231", "--workers", "1", "--threads", "4", "--timeout", "30", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
