# Malwarr 🦠

A malware repository management system inspired by the Arr family (Sonarr, Radarr, Lidarr). Organize, catalog, and manage malware samples with automated analysis and a modern web UI.

## Features

- **Modern Web UI**: Dark-themed dashboard with drag-and-drop upload, real-time search, and sample management
- **Automated Analysis**: Hash calculation, PE/ELF metadata extraction, entropy analysis, and string extraction
- **CAPA Integration**: Malware capability detection with FLARE CAPA, MITRE ATT&CK mapping, and interactive CAPA Explorer
- **RESTful API**: Complete API for programmatic access with API key authentication
- **Docker Support**: Fully containerized deployment with PostgreSQL backend

## Quick Start

1. **Clone and configure**:
   ```bash
   git clone https://github.com/getel-arch/Malwarr.git
   cd Malwarr
   cp .env.example .env
   # Edit .env and set your API_KEY
   ```

2. **Start with Docker**:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**:
   - Web UI: http://localhost:8686
   - API Docs: http://localhost:8686/docs

4. **Configure in Settings**:
   - Enter your API key
   - Download CAPA Explorer and Rules for malware analysis

## Usage

### Web UI
- **Dashboard**: View statistics and recent samples
- **Upload**: Drag-and-drop files with optional metadata (family, tags, classification)
- **Samples**: Browse, search, filter, and manage samples
- **Settings**: Configure API key, download CAPA Explorer/Rules

### CAPA Analysis
1. Go to Settings → Download CAPA Explorer and CAPA Rules
2. Upload a PE or ELF sample
3. Click "Run CAPA Analysis" on the sample detail page
4. View results in the integrated CAPA Explorer

### API Examples

**Upload sample**:
```bash
curl -X POST "http://localhost:8686/api/v1/samples" \
  -H "X-API-Key: your-api-key" \
  -F "file=@malware.exe" \
  -F "family=Emotet" \
  -F "tags=trojan,banking"
```

**Get sample**:
```bash
curl "http://localhost:8686/api/v1/samples/{sha512}"
```

**Download sample**:
```bash
curl -X GET "http://localhost:8686/api/v1/samples/{sha512}/download" \
  -H "X-API-Key: your-api-key" --output sample.bin
```

**Search**:
```bash
curl "http://localhost:8686/api/v1/samples/search?q=emotet"
```

See API documentation at http://localhost:8686/docs for all endpoints.


## Development

**Backend**:
```bash
python -m venv venv && venv\Scripts\activate
pip install -r requirements.txt
$env:DATABASE_URL="sqlite:///./malwarr.db"; $env:API_KEY="dev-key"
uvicorn app.main:app --reload --port 8686
```

**Frontend**:
```bash
cd frontend
npm install && npm start
```

## Configuration

Set via environment variables in `.env`:

- `DATABASE_URL`: Database connection (default: PostgreSQL in Docker)
- `STORAGE_PATH`: Sample storage path (default: `/data/samples`)
- `API_KEY`: API authentication key (required)

## License

MIT License

---

Inspired by the Arr family (Sonarr, Radarr, Lidarr) • Port 8686
