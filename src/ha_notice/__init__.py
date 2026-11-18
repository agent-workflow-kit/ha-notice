"""ha-notice: send one notification through the Home Assistant REST notify service."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("ha-notice")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0.0.0"
