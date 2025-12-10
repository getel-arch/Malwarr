# Malwarr 🦠

A malware repository management system inspired by the Arr family (Sonarr, Radarr, Lidarr). Organize, catalog, and manage malware samples with automated analysis and a modern web UI.

## Features

- **Modern Web UI**: Dark-themed dashboard with drag-and-drop upload, real-time search, and sample management
- **Automated Analysis**: Hash calculation, PE/ELF metadata extraction, entropy analysis, and string extraction
- **CAPA Integration**: Malware capability detection with FLARE CAPA, MITRE ATT&CK mapping, and interactive CAPA Explorer
- **RESTful API**: Complete API for programmatic access with API key authentication
- **Docker Support**: Fully containerized deployment with PostgreSQL backend

## Quick Start

### Production Deployment

1. **Clone and configure**:
   ```bash
   git clone https://github.com/getel-arch/Malwarr.git
   cd Malwarr
   cp .env.example .env
   # Edit .env and set your API_KEY
   ```

2. **Start with Docker** (uses pre-built images from registry):
   ```bash
   docker compose up -d
   ```

3. **Access the application**:
   - Web UI: http://localhost:8686
   - API Docs: http://localhost:8686/docs

4. **Configure in Settings**:
   - Enter your API key
   - Download CAPA Explorer and Rules for malware analysis

### Development Setup

For local development with live code changes:

1. **Clone and configure**:
   ```bash
   git clone https://github.com/getel-arch/Malwarr.git
   cd Malwarr
   cp .env.example .env
   # Edit .env and set your API_KEY
   ```

2. **Start with development compose file** (builds images locally):
   ```bash
   docker compose -f docker-compose.dev.yml up -d --build
   ```

3. **Access the application**:
   - Web UI: http://localhost:8686
   - API Docs: http://localhost:8686/docs

4. **Development workflow**:
   - Make code changes in your local files
   - Rebuild containers: `docker compose -f docker-compose.dev.yml up -d --build`
   - View logs: `docker compose -f docker-compose.dev.yml logs -f`

## Usage

### Web UI
- **Dashboard**: View statistics and recent samples
- **Upload**: Drag-and-drop files with optional metadata (family, tags, classification)
- **Samples**: Browse, search, filter, and manage samples
- **Settings**: Configure API key, download CAPA Explorer/Rules

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

## Configuration

Set via environment variables in `.env`:

- `DATABASE_URL`: Database connection (default: PostgreSQL in Docker)
- `STORAGE_PATH`: Sample storage path (default: `/data/samples`)
- `API_KEY`: API authentication key (required)
- `VIRUSTOTAL_API_KEY`: VirusTotal API key for hash lookups (optional, get from https://www.virustotal.com/gui/my-apikey)

### VirusTotal Integration

To enable VirusTotal analysis:

1. Sign up for a VirusTotal account at https://www.virustotal.com
2. Get your API key from https://www.virustotal.com/gui/my-apikey
3. Set the `VIRUSTOTAL_API_KEY` environment variable in `.env`
4. Restart the application
5. VT analysis will automatically run for all uploaded samples

Note: The free VirusTotal API has rate limits. VT analysis only checks file hashes (no file upload).

## License

MIT License

---

Inspired by the Arr family (Sonarr, Radarr, Lidarr)
