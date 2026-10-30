# Build the React dashboard, then package it with the Flask application.
FROM node:22-alpine AS frontend-build
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime
WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=5000 \
    FLASK_DEBUG=false

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY config/ ./config/
COPY src/ ./src/
COPY main.py README.md ./
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

RUN mkdir -p data/db data/logs
EXPOSE 5000
VOLUME ["/app/data"]

CMD ["python", "-m", "src.dashboard.app"]
