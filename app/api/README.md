# API Structure Documentation

## Overview

The API code has been reorganized into a clean, modular structure under the `app/api/` directory.

## Directory Structure

```
app/
├── api/
│   ├── __init__.py
│   ├── dependencies/           # Shared dependencies
│   │   ├── __init__.py
│   │   ├── auth.py            # Authentication (verify_api_key)
│   │   └── database.py        # Database dependencies (get_db)
│   ├── schemas/               # Pydantic schemas organized by domain
│   │   ├── __init__.py
│   │   ├── samples.py         # Sample-related schemas
│   │   └── system.py          # System-related schemas
│   └── routes/                # API route handlers
│       ├── __init__.py
│       ├── analysis.py        # CAPA analysis endpoints
│       ├── capa_management.py # CAPA rules & explorer management
│       ├── samples.py         # Sample CRUD operations
│       ├── stats.py           # Statistics endpoints
│       ├── system.py          # System info, version, health
│       └── tasks.py           # Celery task monitoring
├── main.py                    # Clean FastAPI app with router includes
├── schemas.py                 # Backward compatibility shim
└── ... (other modules)
```

## Route Organization

### System Routes (`system.py`)
- `GET /api/v1/version` - Application version
- `GET /api/v1/system` - System information and statistics
- `GET /api/v1/health` - Health check endpoint

### Sample Routes (`samples.py`)
- `POST /api/v1/samples` - Upload malware sample
- `POST /api/v1/samples/from-url` - Upload from URL
- `GET /api/v1/samples` - List samples with filtering
- `GET /api/v1/samples/search` - Search samples
- `GET /api/v1/samples/{sha512}` - Get sample metadata
- `GET /api/v1/samples/{sha512}/download` - Download sample
- `PATCH /api/v1/samples/{sha512}` - Update sample metadata
- `DELETE /api/v1/samples/{sha512}` - Delete sample

### Analysis Routes (`analysis.py`)
- `POST /api/v1/samples/{sha512}/analyze/capa` - Queue CAPA analysis
- `POST /api/v1/samples/{sha512}/rescan` - Rescan with all analyzers
- `GET /api/v1/samples/{sha512}/analyze/status` - Get analysis status
- `POST /api/v1/samples/batch/analyze/capa` - Batch CAPA analysis
- `GET /api/v1/samples/{sha512}/capa` - Get CAPA results
- `GET /api/v1/samples/{sha512}/capa/document` - Get CAPA document
- `GET /api/v1/samples/{sha512}/capa/explorer` - Serve CAPA Explorer
- `GET /api/v1/samples/{sha512}/capa/explorer-wrapped` - Wrapped CAPA Explorer
- `GET /api/v1/samples/{sha512}/capa/download` - Download CAPA JSON

### Statistics Routes (`stats.py`)
- `GET /api/v1/stats/types` - File type statistics
- `GET /api/v1/stats/families` - Malware family statistics

### CAPA Management Routes (`capa_management.py`)
- `GET /api/v1/capa/rules/status` - Rules installation status
- `POST /api/v1/capa/rules/download` - Download rules from GitHub
- `POST /api/v1/capa/rules/upload` - Upload rules ZIP
- `DELETE /api/v1/capa/rules` - Delete all rules
- `GET /api/v1/capa/explorer/status` - Explorer installation status
- `POST /api/v1/capa/explorer/download` - Download explorer from GitHub
- `DELETE /api/v1/capa/explorer` - Delete explorer

### Task Routes (`tasks.py`)
- `GET /api/v1/tasks/running` - Get running Celery tasks
- `GET /api/v1/tasks/queue` - Get queued tasks

## Backward Compatibility

The old `app/schemas.py` has been replaced with a compatibility shim that re-exports from `app/api/schemas/`. This ensures existing code continues to work without modification.

## Benefits of New Structure

1. **Separation of Concerns**: Each route file handles a specific domain
2. **Maintainability**: Easier to locate and modify specific functionality
3. **Scalability**: New routes can be added without modifying existing files
4. **Testability**: Each router can be tested independently
5. **Clean Main**: The `main.py` is now minimal and focused on app setup

## Migration Notes

- Old `main.py` backed up to `main_old.py`
- Old `schemas.py` backed up to `schemas_old.py`
- All imports of `app.schemas` continue to work via the compatibility shim
- No changes needed in workers, analyzers, or other modules
