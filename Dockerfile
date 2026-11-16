FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && groupadd -g 10001 sentinelcore \
    && useradd -u 10001 -g 10001 -M sentinelcore \
    && mkdir data && chown sentinelcore:sentinelcore data

COPY backend ./backend
COPY frontend ./frontend
COPY protected_app ./protected_app
COPY monitoring ./monitoring
COPY lab ./lab
USER sentinelcore
