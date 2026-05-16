FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Системные зависимости для cryptography (на slim иногда нет ffi headers)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Гарантия что payload-зависимости стоят, даже если requirements.txt не обновился
# в репозитории (страховка от Railway build cache).
RUN pip install --no-cache-dir "boto3==1.34.131" "cryptography==42.0.8"

COPY . .

# start.sh раскроет $PORT через shell
RUN echo '#!/bin/sh\nexec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}' > /start.sh \
    && chmod +x /start.sh

CMD ["/start.sh"]
