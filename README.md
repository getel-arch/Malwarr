# Malwarr 🦠

A malware repository management system inspired by the Arr family (Sonarr, Radarr, Lidarr). Malwarr provides an organized way to store, catalog, and manage malware samples with comprehensive metadata extraction and a beautiful web UI.

## Features

- **Modern Web UI**: Beautiful, responsive interface inspired by Sonarr/Radarr
  - Dark theme optimized for security operations
  - Dashboard with statistics and charts
  - Sample management with detailed views
  - Drag-and-drop file upload
  - Real-time search and filtering

- **Automatic Metadata Extraction**: Extracts comprehensive metadata from uploaded samples
  - Hash calculations (MD5, SHA1, SHA256, SHA512)
  - PE file analysis (imports, exports, sections, compilation timestamp, imphash)
  - ELF file analysis (architecture, entry point, sections)
  - File type detection and MIME type identification
  - Entropy calculation and string extraction

- **CAPA Capability Analysis**: 🆕 Automatic malware capability detection
  - Identifies malware behaviors and capabilities using FLARE CAPA
  - MITRE ATT&CK technique mapping
  - Malware Behavior Catalog (MBC) classification
  - Automatic analysis on upload (PE/ELF files)
  - **Local CAPA Explorer Integration**: Interactive web-based analysis viewer
  - **Automatic JSON Loading**: No manual file uploads needed
  - Detailed capability reports and exploration
  - See [CAPA_INTEGRATION.md](CAPA_INTEGRATION.md) for details

- **Organized Storage**: Files stored using SHA512-based hierarchical directory structure
- **RESTful API**: Complete API for upload, download, search, and metadata management
- **Docker Support**: Fully containerized with Docker Compose
- **PostgreSQL Database**: Robust metadata storage
- **File Type Support**: PE (exe, dll), ELF, Mach-O, scripts, archives, documents, and more
- **Search & Filter**: Search by hash, filename, family, or tags
- **API Key Protection**: Secure endpoints with API key authentication

## Quick Start

### Prerequisites

- Docker and Docker Compose
- (Optional) Python 3.11+ for local development

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd Malwarr
```

2. Copy the example environment file:
```bash
cp .env.example .env
```

3. Edit `.env` and set your API key:
```
API_KEY=your-secure-random-api-key-here
```

4. Start the services:
```bash
docker-compose up -d
```

5. Access the application:
- **Web UI & API**: http://localhost:8686
- **API Documentation**: http://localhost:8686/docs

6. Configure your API key:
- Open the Web UI at http://localhost:8686
- Go to Settings
- Enter your API key from the `.env` file
- Save settings

## Web UI Usage

### Dashboard
- View system statistics and storage usage
- See file type distribution charts
- Browse top malware families
- Quick access to recent samples

### Upload Samples
1. Navigate to the Upload page
2. Drag and drop a file or click to browse
3. Optionally add metadata (family, tags, classification, notes)
4. Click "Upload Sample"

### Manage Samples
- Browse all samples with filters (type, family, tags)
- Search by hash, filename, or family name
- View detailed sample information
- Edit metadata, download samples, or delete them
- View PE/ELF analysis results

### Settings
- Configure your API key for protected operations
- **Download and manage CAPA Explorer**: Install local CAPA Explorer for automatic data loading
- **Download and manage CAPA Rules**: Required for malware capability analysis
- View API endpoint documentation
- Check system information

## CAPA Explorer Integration 🔍

Malwarr now features **automatic CAPA Explorer integration** for interactive malware analysis:

### Features
- **Local CAPA Explorer**: Download and host CAPA Explorer directly in Malwarr
- **Automatic JSON Loading**: Analysis results are automatically pre-loaded into the explorer
- **One-Click Analysis**: View detailed capability analysis without manual file uploads
- **Offline Support**: Works completely offline once installed

### Quick Setup
1. Go to **Settings** → **CAPA Explorer Management**
2. Click **"Download CAPA Explorer"** (downloads from official GitHub repo)
3. Go to **Settings** → **CAPA Rules Management** 
4. Click **"Download CAPA Rules"** (required for analysis)
5. Upload a PE or ELF sample
6. Click **"Run CAPA Analysis"** on the sample detail page
7. Click **"View in CAPA Explorer"** when analysis completes - data loads automatically! ✨

For detailed documentation, see [CAPA_INTEGRATION.md](CAPA_INTEGRATION.md)

## API Usage

### Upload a Sample

```bash
curl -X POST "http://localhost:8686/api/v1/samples" \
  -H "X-API-Key: your-api-key" \
  -F "file=@malware.exe" \
  -F "tags=trojan,banking" \
  -F "family=Emotet" \
  -F "classification=malicious"
```

### Get Sample Metadata

```bash
curl "http://localhost:8686/api/v1/samples/{sha512}"
```

### Download a Sample

```bash
curl -X GET "http://localhost:8686/api/v1/samples/{sha512}/download" \
  -H "X-API-Key: your-api-key" \
  --output sample.bin
```

### Search Samples

```bash
curl "http://localhost:8686/api/v1/samples/search?q=emotet"
```

### List Samples with Filters

```bash
# Filter by file type
curl "http://localhost:8686/api/v1/samples?file_type=pe&limit=50"

# Filter by family
curl "http://localhost:8686/api/v1/samples?family=Emotet"

# Filter by tag
curl "http://localhost:8686/api/v1/samples?tag=trojan"
```

### Update Sample Metadata

```bash
curl -X PATCH "http://localhost:8686/api/v1/samples/{sha512}" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "family": "Emotet",
    "tags": ["trojan", "banking", "loader"],
    "virustotal_link": "https://www.virustotal.com/gui/file/..."
  }'
```

### Delete a Sample

```bash
curl -X DELETE "http://localhost:8686/api/v1/samples/{sha512}" \
  -H "X-API-Key: your-api-key"
```

### Get Statistics

```bash
# File type distribution
curl "http://localhost:8686/api/v1/stats/types"

# Top malware families
curl "http://localhost:8686/api/v1/stats/families"

# System information
curl "http://localhost:8686/api/v1/system"
```

## API Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/` | Root endpoint | No |
| GET | `/health` | Health check | No |
| GET | `/api/v1/system` | System information | No |
| POST | `/api/v1/samples` | Upload sample | Yes |
| GET | `/api/v1/samples` | List samples | No |
| GET | `/api/v1/samples/search` | Search samples | No |
| GET | `/api/v1/samples/{sha512}` | Get sample metadata | No |
| GET | `/api/v1/samples/{sha512}/download` | Download sample | Yes |
| PATCH | `/api/v1/samples/{sha512}` | Update metadata | Yes |
| DELETE | `/api/v1/samples/{sha512}` | Delete sample | Yes |
| GET | `/api/v1/stats/types` | File type statistics | No |
| GET | `/api/v1/stats/families` | Family statistics | No |

## Metadata Extracted

### All Files
- Hashes: MD5, SHA1, SHA256, SHA512
- File size and type
- MIME type
- Magic description
- Shannon entropy
- String count
- Upload timestamp

### PE Files (Windows executables)
- Import hash (imphash)
- Compilation timestamp
- Entry point
- Sections with entropy
- Imported DLLs and functions
- Exported functions

### ELF Files (Linux executables)
- Machine architecture
- Entry point
- Sections information

## Storage Structure

Files are stored in a hierarchical directory structure based on their SHA512 hash:

```
/data/samples/
  ├── ab/
  │   └── cd/
  │       └── abcd1234...sha512hash.../
  ├── ef/
  │   └── gh/
  │       └── efgh5678...sha512hash.../
  ...
```

This prevents filesystem limitations with too many files in a single directory.

## Development

### Backend Development

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up a local PostgreSQL database or use SQLite:
```bash
export DATABASE_URL="sqlite:///./malwarr.db"
export STORAGE_PATH="./data/samples"
export API_KEY="dev-api-key"
```

4. Run the application:
```bash
uvicorn app.main:app --reload --port 8686
```

### Frontend Development

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm start
```

The frontend will be available at http://localhost:3000 and will proxy API requests to the backend at http://localhost:8686.

### Running Tests

```bash
pytest
```

## Configuration

All configuration is done through environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://malwarr:malwarr@db:5432/malwarr` |
| `STORAGE_PATH` | Path to store malware samples | `/data/samples` |
| `API_KEY` | API key for protected endpoints | `your-api-key-here` |
| `APP_NAME` | Application name | `Malwarr` |
| `APP_VERSION` | Application version | `1.0.0` |
| `DEBUG` | Enable debug mode | `false` |

## Documentation

- [CAPA Service Guide](docs/CAPA_SERVICE.md) - Complete guide for CAPA capability analysis
- [CAPA Quick Reference](docs/CAPA_QUICKREF.md) - Quick reference for CAPA features
- [Web UI Guide](docs/WEB_UI_GUIDE.md) - Frontend usage instructions
- [Windows Installation](docs/WINDOWS_INSTALL.md) - Windows-specific setup guide

## Future Features

- [x] CAPA capability analysis integration
- [ ] Integration with VirusTotal API
- [ ] Integration with MalwareBazaar API
- [ ] Automatic sample download from threat intelligence sources
- [ ] YARA rule scanning
- [ ] Similarity analysis and clustering
- [ ] Automated dynamic analysis integration
- [ ] Multi-user support with role-based access control
- [ ] Export to MISP and other threat intelligence platforms
- [ ] Bulk operations (upload, delete, tag)
- [ ] Advanced filtering and saved searches
- [ ] Sample relationships and campaign tracking
- [ ] CAPA results visualization in web UI
- [ ] Asynchronous CAPA analysis with Celery

## Security Considerations

⚠️ **Warning**: This application is designed to handle malware samples. Please observe proper security practices:

- Run in isolated environments only
- Use strong API keys
- Implement network segmentation
- Consider running in a separate VLAN or air-gapped network
- Regularly backup the database and samples
- Monitor access logs
- Enable additional authentication mechanisms for production use

## Port Selection

Malwarr uses port **8686** to follow the Arr family convention:
- Sonarr: 8989
- Radarr: 7878
- Lidarr: 8686 (we're using the same port space)

## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

Inspired by the Arr family of applications (Sonarr, Radarr, Lidarr) and the need for organized malware sample management in security research.
