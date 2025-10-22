"""backend package"""

import importlib.metadata

try:
    __version__ = importlib.metadata.version(__name__)
except importlib.metadata.PackageNotFoundError:
    __version__ = "unknown"

from . import src

__all__ = ["src"]
