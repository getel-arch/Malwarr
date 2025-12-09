"""
Malwarr version information
"""

__version__ = "0.5.2"
__version_info__ = tuple(int(i) for i in __version__.split("."))

# Application metadata
APP_NAME = "Malwarr"
APP_DESCRIPTION = "A malware repository management system"
APP_AUTHOR = "getel-arch"
APP_LICENSE = "MIT"

def get_version() -> str:
    """Get the current version string."""
    return __version__

def get_version_info() -> tuple:
    """Get the version as a tuple of integers."""
    return __version_info__

def get_full_version() -> str:
    """Get the full version string with app name."""
    return f"{APP_NAME} v{__version__}"
