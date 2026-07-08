FROM python:3.12-slim

# Install system dependencies including nmap
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
ENV PYTHONPATH=/app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories for scan results and reports
RUN mkdir -p /app/scan_results /app/reports /app/yara_rules

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
