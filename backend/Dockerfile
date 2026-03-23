FROM python:3.11-slim

WORKDIR /app

# Prevent pyc + buffering
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend
COPY backend /app/backend

ENV PYTHONPATH=/app

EXPOSE 8000

# Change this if you're using FastAPI
CMD ["python", "backend/main.py"]