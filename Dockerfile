FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY analyzer ./analyzer

USER 10001:10001
ENTRYPOINT ["python", "-m", "analyzer"]
CMD ["--help"]
