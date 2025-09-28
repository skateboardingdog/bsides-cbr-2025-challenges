FROM python:3.13-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY app.py .
COPY templates ./templates

RUN pip install flask gunicorn

RUN useradd --shell /bin/bash app
USER app

EXPOSE 1337

CMD ["gunicorn", "--bind", "0.0.0.0:1337", "--workers", "4", "--timeout", "30", "app:app"]