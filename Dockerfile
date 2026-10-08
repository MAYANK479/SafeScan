FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY safescan/ ./safescan/
COPY server.py .

EXPOSE 8080
ENV PORT=8080 PYTHONUNBUFFERED=1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8080"]
