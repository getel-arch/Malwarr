# Build frontend
FROM node:18-alpine as frontend-build

WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Build backend
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    file \
    libmagic1 \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY config/ ./config/
COPY alembic/ ./alembic/
COPY alembic.ini ./

# Copy built frontend from previous stage
COPY --from=frontend-build /frontend/build ./app/static

# Copy setup script
COPY setup_capa_resources.py ./

# Create data directory
RUN mkdir -p /data/samples /data/capa-rules /data/capa-explorer

# Download CAPA Explorer and rules using the existing Python managers
RUN python setup_capa_resources.py

# Expose port (using 8686 to follow Arr convention)
EXPOSE 8686

# Run the application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8686"]
