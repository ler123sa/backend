FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# start.sh раскроет $PORT через shell
RUN echo '#!/bin/sh\nexec uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}' > /start.sh \
    && chmod +x /start.sh

CMD ["/start.sh"]
